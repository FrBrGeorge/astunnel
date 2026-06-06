export interface CodeFile {
  name: string;
  path: string;
  language: "python" | "toml" | "yaml" | "markdown";
  content: string;
}

export const CODEBASE_FILES: CodeFile[] = [
  {
    name: "common.py",
    path: "astunnel/common.py",
    language: "python",
    content: `"""
Common utilities and protocol definitions for the asyncio SSL TCP packet-tunneling suite.
Handles serialization, packet parsing, DSCP check, and dynamic packet bunching/padding.
"""

import sys
import struct
import random
import logging
from pathlib import Path
from typing import List, Tuple, Optional

# Protocol Constants
VERSION_MGMT = 0
VERSION_IPV4 = 4
VERSION_IPV6 = 6
VERSION_PADDING = 15

# Management Packet Subtypes
MGMT_HANDSHAKE = 1
MGMT_ERROR = 2

# Padding Modes
PADDING_NONE = 1
PADDING_FULL = 2
PADDING_RANDOM = 3

# High Priority DSCP Values (VoIP, Telephony, Interactive SSH - e.g., EF, CS5, CS6, CS7)
HIGH_PRIORITY_DSCPS = {32, 34, 40, 46, 48, 56}


class Packet:
    """
    Representation of a tunnel packet.
    If it is IPv4 (version 4) or IPv6 (version 6), the payload is passed as is.
    If it is Management (version 0) or Padding (version 15), it is structured as:
    - 1 octet: High 4 bits = Version, Low 4 bits = Subtype
    - 2 octets: Payload size in Big-Endian unsigned short
    - N octets: Payload data
    """

    def __init__(self, version: int, subtype: int, payload: bytes):
        if not (0 <= version <= 15):
            raise ValueError("Version must be between 0 and 15")
        if not (0 <= subtype <= 15):
            raise ValueError("Subtype must be between 0 and 15")
        self.version = version
        self.subtype = subtype
        self.payload = payload

        if version == VERSION_IPV4 or version == VERSION_IPV6:
            self.raw_bytes = payload
        else:
            first_byte = (version << 4) | subtype
            header = struct.pack("!BH", first_byte, len(payload))
            self.raw_bytes = header + payload

    def to_bytes(self) -> bytes:
        """Serialize Packet into bytes."""
        return self.raw_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple[Optional["Packet"], int]:
        """
        Parses one Packet from raw bytes.
        Returns a tuple of (Packet, bytes_consumed).
        If not enough data is available to parse a complete packet, returns (None, 0).
        """
        if len(data) < 1:
            return None, 0

        first_byte = data[0]
        version = first_byte >> 4
        subtype = first_byte & 0x0F

        if version == VERSION_IPV4:
            # Need at least 4 bytes to check total length
            if len(data) < 4:
                return None, 0
            total_len = struct.unpack("!H", data[2:4])[0]
            if len(data) < total_len:
                return None, 0
            payload = data[:total_len]
            return cls(version, 0, payload), total_len

        elif version == VERSION_IPV6:
            # Need at least 6 bytes to check payload length
            if len(data) < 6:
                return None, 0
            payload_len = struct.unpack("!H", data[4:6])[0]
            total_len = payload_len + 40
            if len(data) < total_len:
                return None, 0
            payload = data[:total_len]
            return cls(version, 0, payload), total_len

        elif version == VERSION_MGMT or version == VERSION_PADDING:
            # 3 bytes header: 1 octet ver/subtype, 2 octets length
            if len(data) < 3:
                return None, 0
            length = struct.unpack("!H", data[1:3])[0]
            if len(data) < 3 + length:
                return None, 0
            payload = data[3 : 3 + length]
            return cls(version, subtype, payload), 3 + length

        else:
            raise ValueError(f"Invalid packet version parsed from stream: {version}")

    def is_high_priority(self) -> bool:
        """
        Extract DSCP field and check if it requires immediate transmission.
        - IPv4: ToS is 2nd byte (idx 1) of IP header. DSCP is high 6 bits.
        - IPv6: Traffic class spans 1st and 2nd bytes of IP header (bits 4 to 11).
                DSCP is the high 6 bits of Traffic Class.
        """
        if self.version == VERSION_IPV4:
            if len(self.payload) >= 20:  # Minimum IPv4 header length
                tos = self.payload[1]
                dscp = tos >> 2
                return dscp in HIGH_PRIORITY_DSCPS
        elif self.version == VERSION_IPV6:
            if len(self.payload) >= 40:  # Minimum IPv6 header length
                traffic_class = ((self.payload[0] & 0x0F) << 4) | (self.payload[1] >> 4)
                dscp = traffic_class >> 2
                return dscp in HIGH_PRIORITY_DSCPS
        return False
`
  },
  {
    name: "client.py",
    path: "astunnel/client.py",
    language: "python",
    content: `"""
Asyncio client implementation for the SSL TCP packet-tunneling suite.
Manages connection handshakes, 3 SSL security models, and client-side bunching.
"""

import ssl
import struct
import asyncio
import logging
import hashlib
from typing import Dict, Optional, Tuple, Any

from astunnel.common import (
    Packet,
    Buncher,
    setup_logger,
    VERSION_MGMT,
    VERSION_PADDING,
    MGMT_HANDSHAKE,
    MGMT_ERROR,
    PADDING_NONE,
)

class TunnelClient:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 18443,
        requested_client_id: bytes = b"\\x00\\x00\\x00\\x00",
        padding_mode: int = PADDING_NONE,
        sync_timeout: float = 0.5,
        backend_name: str = "echo",
        backend_options: Optional[Dict[str, Any]] = None,
        ssl_mode: str = "secure",  # "insecure", "trusted", "secure"
        trusted_fingerprint: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.requested_client_id = requested_client_id
        self.padding_mode = padding_mode
        self.sync_timeout = sync_timeout
        self.backend_name = backend_name
        self.ssl_mode = ssl_mode
        self.trusted_fingerprint = trusted_fingerprint.lower().replace(":", "") if trusted_fingerprint else None

    def get_ssl_context(self) -> ssl.SSLContext:
        """Configures SSLContext based on specified client mode."""
        if self.ssl_mode in ("insecure", "trusted"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        else:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = True
            return ctx

    def verify_fingerprint(self, ssl_obj: Any) -> None:
        """Verifies peer certificate's SHA-256 fingerprint in trusted mode."""
        if self.ssl_mode != "trusted" or not self.trusted_fingerprint:
            return
        der_cert = ssl_obj.getpeercert(binary_form=True)
        current_hash = hashlib.sha256(der_cert).hexdigest()
        if current_hash != self.trusted_fingerprint:
            raise ssl.SSLError("Certificate fingerprint mismatch!")
`
  },
  {
    name: "server.py",
    path: "astunnel/server.py",
    language: "python",
    content: `"""
Asyncio server implementation for the SSL TCP packet-tunneling suite.
Manages multiple client sessions, Client ID assignment, SSL context, and echo backend.
"""

import ssl
import struct
import asyncio
import logging
import ipaddress
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from astunnel.common import (
    Packet,
    Buncher,
    setup_logger,
    VERSION_MGMT,
    VERSION_PADDING,
    MGMT_HANDSHAKE,
    MGMT_ERROR,
    PADDING_NONE,
)

class TunnelServer:
    def __init__(
        self,
        bind: str = "0.0.0.0",
        port: int = 18443,
        pem_path: str = "server.pem",
        pool: str = "10.0.0.0/24",
    ):
        self.bind = bind
        self.port = port
        self.pem_path = Path(pem_path)
        self.pool = ipaddress.ip_network(pool)
        self.server_id = self.pool[0].packed
        self.sessions = {}

    def generate_self_signed_pem(self) -> None:
        """Generates a combined self-signed cert+key using openssl subcommand."""
        if self.pem_path.exists():
            return
        try:
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(self.pem_path), "-out", str(self.pem_path),
                "-nodes", "-days", "365", "-subj", "/CN=localhost"
            ]
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except Exception:
            # Fallback mock cert writing
            self.pem_path.write_text("-----BEGIN PRIVATE KEY-----\n...", encoding="ascii")

    def get_ssl_context(self) -> ssl.SSLContext:
        self.generate_self_signed_pem()
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=self.pem_path)
        return ctx
`
  },
  {
    name: "echo.py",
    path: "astunnel/backends/echo.py",
    language: "python",
    content: `"""
Test Echo Backend Implementation.
Bounces packets back to the client after performing Client ID management and optional packet filtering.
"""

from typing import Dict, Any
from astunnel.backends.base import BaseBackend
from astunnel.common import Packet

class EchoBackend(BaseBackend):
    """
    Echo backend: bounces received packets back to the sender.
    Supports a packet-type filter option: 0 = none, 4 = IPv4, 6 = IPv6.
    """
    backend_name = "echo"

    def __init__(self, options: Dict[str, Any]):
        super().__init__(options)
        self.packet_type_filter = int(options.get("packet_type_filter", 0))

    def parse_handshake_extra(self, extra_bytes: bytes) -> Dict[str, Any]:
        """Expects 1 octet indicating packet_type_filter."""
        parsed = {}
        if len(extra_bytes) >= 1:
            parsed["packet_type_filter"] = int(extra_bytes[0])
        else:
            parsed["packet_type_filter"] = 0
        return parsed

    def compile_handshake_extra(self, config: Dict[str, Any]) -> bytes:
        """Compile filter configuration into 1 octet."""
        filt = int(config.get("packet_type_filter", 0))
        if filt not in (0, 4, 6):
            filt = 0
        return bytes([filt])

    def should_echo_packet(self, version: int) -> bool:
        if self.packet_type_filter == 0:
            return True
        return version == self.packet_type_filter

    def process_packet(self, pkt: Packet, client_id: bytes) -> Any:
        """
        Processes an incoming packet and returns the response Packet to send
        back if it matches the filtering rules. Otherwise returns None.
        """
        if self.should_echo_packet(pkt.version):
            response_payload = pkt.payload
            # In reply, inject client ID back to payload just to be sure
            response_payload = self.inject_client_id(
                response_payload, pkt.version, client_id
            )
            return Packet(pkt.version, pkt.subtype, response_payload)
        return None
`
  },
  {
    name: "tun.py",
    path: "astunnel/backends/tun.py",
    language: "python",
    content: `"""
Linux TUN backend implementing raw IP packet transmission over TCP SSL.
Acquires a free tun device and sets peer-to-peer IPv4/IPv6 addresses.
"""

import os
import fcntl
import struct
import asyncio
import subprocess
import ipaddress
from typing import Dict, Any, Optional

from astunnel.backends.base import BaseBackend
from astunnel.common import Packet

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class TunBackend(BaseBackend):
    backend_name = "tun"

    def __init__(self, options: Dict[str, Any]):
        super().__init__(options)
        self.fd = None
        self.ifname = None
        self.send_cb = None
        self.client_id = None
        self.logger = None
        self._loop = None
        self.is_server = False

    def compile_handshake_extra(self, config: Dict[str, Any]) -> bytes:
        server_id = config.get("server_id", b"\\x00\\x00\\x00\\x00")
        if len(server_id) != 4:
            server_id = b"\\x00\\x00\\x00\\x00"
        return server_id

    def parse_handshake_extra(self, extra_bytes: bytes) -> Dict[str, Any]:
        if len(extra_bytes) >= 4:
            return {"server_id": extra_bytes[:4]}
        return {"server_id": b"\\x00\\x00\\x00\\x00"}

    def start(self, send_cb, client_id, logger, is_server=False):
        self.send_cb = send_cb
        self.client_id = client_id
        self.logger = logger
        self._loop = asyncio.get_event_loop()
        self.is_server = is_server

        try:
            self.fd, self.ifname = self._open_tun()
            self._configure_interface()
            # Register read callback on event loop
            self._loop.add_reader(self.fd, self._on_tun_readable)
            self.logger.warning("TUN Backend started successfully on device %s (is_server=%s)", self.ifname, self.is_server)
        except Exception as e:
            if self.logger:
                self.logger.error("Failed to start TUN backend: %s. Direct device setup skipped.", e)
            self.stop()
            raise

    def stop(self):
        if self.fd is not None:
            if self._loop:
                try:
                    self._loop.remove_reader(self.fd)
                except Exception:
                    pass
            try:
                os.close(self.fd)
            except Exception:
                pass
            if self.logger and self.ifname:
                self.logger.warning("TUN Backend stopped on device %s", self.ifname)
            self.fd = None
            self.ifname = None

    def receive_packet(self, pkt: Packet) -> None:
        """Called on client side when a packet is received from the server."""
        if self.fd is not None and pkt.version in (4, 6):
            try:
                os.write(self.fd, pkt.payload)
            except Exception as e:
                if self.logger:
                    self.logger.error("Error writing packet to TUN device on client: %s", e)

    def process_packet(self, pkt: Packet, client_id: bytes) -> Any:
        """Called on server side when a packet is received from the client."""
        if self.fd is not None and pkt.version in (4, 6):
            try:
                os.write(self.fd, pkt.payload)
            except Exception as e:
                if self.logger:
                    self.logger.error("Error writing packet to TUN device on server: %s", e)
        return None

    def _open_tun(self) -> tuple:
        fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", b"tun%d", IFF_TUN | IFF_NO_PI)
        res = fcntl.ioctl(fd, TUNSETIFF, ifr)
        ifname = res[:16].strip(b"\\x00").decode("utf-8")
        return fd, ifname

    def _run_cmd(self, cmd: list):
        if self.logger:
            self.logger.info("Executing: %s", " ".join(cmd))
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            if res.stdout and self.logger:
                self.logger.debug("Stdout: %s", res.stdout.strip())
        except subprocess.CalledProcessError as e:
            if self.logger:
                self.logger.error("Command '%s' failed with exit code %d\\nStdout: %s\\nStderr: %s",
                                  " ".join(cmd), e.returncode, e.stdout, e.stderr)
            raise

    def _configure_interface(self):
        server_id_bytes = self.options.get("server_id", b"\\x00\\x00\\x00\\x00")
        
        # Format IPv4 addresses
        client_ip_str = ".".join(str(b) for b in self.client_id)
        server_ip_str = ".".join(str(b) for b in server_id_bytes)

        if self.is_server:
            local_ip = server_ip_str
            peer_ip = client_ip_str
        else:
            local_ip = client_ip_str
            peer_ip = server_ip_str

        # Format IPv6 addresses using base class helper
        client_ipv6 = self.convert_client_id_to_ipv6(self.client_id)
        server_ipv6 = self.convert_client_id_to_ipv6(server_id_bytes)

        if self.is_server:
            local_ipv6 = server_ipv6
            peer_ipv6 = client_ipv6
        else:
            local_ipv6 = client_ipv6
            peer_ipv6 = server_ipv6

        # 1. Bring the link UP
        self._run_cmd(["ip", "link", "set", "dev", self.ifname, "up"])
        
        # 2. Add IPv4 peer address
        self._run_cmd(["ip", "addr", "add", f"{local_ip}/32", "peer", peer_ip, "dev", self.ifname])

        # 3. Add IPv6 peer address
        try:
            self._run_cmd(["ip", "addr", "add", f"{local_ipv6}/128", "peer", peer_ipv6, "dev", self.ifname])
        except Exception as e:
            if self.logger:
                self.logger.warning("Could not set IPv6 peer option, trying standard subnet addition: %s", e)
            try:
                self._run_cmd(["ip", "addr", "add", f"{local_ipv6}/64", "dev", self.ifname])
            except Exception as e2:
                if self.logger:
                    self.logger.error("Failed to add IPv6 address: %s", e2)

    def _on_tun_readable(self):
        try:
            packet = os.read(self.fd, 2048)
            if not packet:
                return
            
            # Determine IP version: first nibble of the IP header (IPv4/6)
            version = packet[0] >> 4
            if version not in (4, 6):
                return

            if self.send_cb:
                # Schedule sending as an async task
                self._loop.create_task(self.send_cb(version, 0, packet))
        except Exception as e:
            if self.logger:
                self.logger.error("Error reading from TUN device: %s", e)
`
  },
  {
    name: "base.py",
    path: "astunnel/backends/base.py",
    language: "python",
    content: `"""
Base class definition for packet-tunneling backends.
Provides interfaces for Client ID extraction, conversion, and injections.
"""

import ipaddress
from typing import Dict, Any

class BaseBackend:
    backend_name = "base"

    def __init__(self, options: Dict[str, Any]):
        self.options = options

    def extract_client_id(self, payload: bytes, version: int) -> bytes:
        if version == 4 and len(payload) >= 20:
            return payload[12:16]
        elif version == 6 and len(payload) >= 40:
            return payload[20:24]
        if len(payload) >= 4:
            return payload[:4]
        return b"\\x00\\x00\\x00\\x00"

    def inject_client_id(self, payload: bytes, version: int, client_id: bytes) -> bytes:
        if len(client_id) != 4:
            raise ValueError("Client ID must be 4 bytes")
        payload_mut = bytearray(payload)
        if version == 4 and len(payload_mut) >= 20:
            payload_mut[12:16] = client_id
            return bytes(payload_mut)
        elif version == 6 and len(payload_mut) >= 40:
            payload_mut[20:24] = client_id
            return bytes(payload_mut)
        if len(payload_mut) >= 4:
            payload_mut[:4] = client_id
            return bytes(payload_mut)
        return payload

    def convert_client_id_to_ipv6(self, client_id: bytes) -> str:
        if len(client_id) != 4:
            return "fd00::1"
        addr_bytes = b"\\xfd\\x00" + b"\\x00" * 10 + client_id
        return str(ipaddress.IPv6Address(addr_bytes))

    def process_packet(self, pkt: Any, client_id: bytes) -> Any:
        return None
`
  },
  {
    name: "test_tun.py",
    path: "tests/test_tun.py",
    language: "python",
    content: `import unittest
from unittest.mock import MagicMock, patch
from astunnel.backends.tun import TunBackend
from astunnel.common import Packet


class TestTunBackend(unittest.TestCase):
    def test_handshake_extra(self):
        backend = TunBackend({"server_id": bytes([10, 0, 0, 1])})
        extra = backend.compile_handshake_extra(backend.options)
        self.assertEqual(extra, bytes([10, 0, 0, 1]))

        parsed_opts = backend.parse_handshake_extra(extra)
        self.assertEqual(parsed_opts["server_id"], bytes([10, 0, 0, 1]))

    def test_address_conversion_ula(self):
        backend = TunBackend({})
        cid = bytes([192, 168, 1, 5])
        ipv6_str = backend.convert_client_id_to_ipv6(cid)
        self.assertEqual(ipv6_str, "fd00::c0a8:105")

    @patch("os.open")
    @patch("fcntl.ioctl")
    @patch("subprocess.run")
    def test_start_and_configure(self, mock_run, mock_ioctl, mock_open):
        mock_open.return_value = 42
        mock_ioctl.return_value = b"tun99\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"

        # Mock event loop inside TunBackend
        mock_loop = MagicMock()
        with patch("asyncio.get_event_loop", return_value=mock_loop):
            backend = TunBackend({"server_id": bytes([10, 0, 0, 1])})
            send_cb_mock = MagicMock()
            logger_mock = MagicMock()
            
            backend.start(send_cb_mock, bytes([10, 0, 0, 5]), logger_mock, is_server=False)

            self.assertEqual(backend.fd, 42)
            self.assertEqual(backend.ifname, "tun99")
            self.assertFalse(backend.is_server)

            # Check that commands are called to set up link and addresses
            self.assertTrue(mock_run.called)
            # The last command or some command should have "tun99" in it
            args_list = [call.args[0] for call in mock_run.call_args_list]
            self.assertTrue(any("tun99" in cmd for cmd in args_list))
            self.assertTrue(any("ip" in cmd for cmd in args_list))

            # Stop the backend
            backend.stop()
            self.assertIsNone(backend.fd)
            self.assertIsNone(backend.ifname)
            mock_loop.remove_reader.assert_called_with(42)

    @patch("os.write")
    def test_receive_and_process_packet(self, mock_write):
        backend = TunBackend({})
        backend.fd = 99
        pkt = Packet(4, 0, b"mock_ipv4_payload")
        backend.receive_packet(pkt)
        mock_write.assert_called_with(99, b"mock_ipv4_payload")

        mock_write.reset_mock()
        backend.process_packet(pkt, b"\\x0a\\x00\\x00\\x05")
        mock_write.assert_called_with(99, b"mock_ipv4_payload")


if __name__ == "__main__":
    unittest.main()
`
  },
  {
    name: "test_tunnel.py",
    path: "tests/test_tunnel.py",
    language: "python",
    content: `"""
Unittests for Packet framing, serialization, DSCP priority checks, and Buncher operations.
"""

import unittest
import struct
from astunnel.common import (
    Packet,
    Buncher,
    PADDING_NONE,
    PADDING_FULL,
    PADDING_RANDOM,
    VERSION_IPV4,
    VERSION_IPV6,
    VERSION_PADDING,
    VERSION_MGMT,
)

def make_mock_ipv4(total_len=20, tos=0) -> bytes:
    header = bytearray(total_len)
    header[0] = 0x45
    header[1] = tos
    header[2:4] = struct.pack("!H", total_len)
    return bytes(header)

def make_mock_ipv6(payload_len=10, traffic_class=0) -> bytes:
    header = bytearray(payload_len + 40)
    header[0] = (6 << 4) | (traffic_class >> 4)
    header[1] = (traffic_class & 0x0F) << 4
    header[4:6] = struct.pack("!H", payload_len)
    return bytes(header)


class TestTunnelProtocol(unittest.TestCase):
    """Verifies low-level Packet framing and serialization states."""

    def test_packet_serialization_ipv4(self):
        """Verifies ipv4 packet serialization and deserialization symmetry."""
        payload = make_mock_ipv4(total_len=30)
        pkt = Packet(version=VERSION_IPV4, subtype=0, payload=payload)
        raw_bytes = pkt.to_bytes()

        self.assertEqual(len(raw_bytes), 30)
        self.assertEqual(raw_bytes[0] >> 4, 4)

        # Deserialize
        parsed, consumed = Packet.from_bytes(raw_bytes)
        self.assertIsNotNone(parsed)
        self.assertEqual(consumed, 30)
        self.assertEqual(parsed.version, VERSION_IPV4)
        self.assertEqual(parsed.payload, payload)

    def test_packet_serialization_ipv6(self):
        """Verifies ipv6 packet serialization and deserialization symmetry."""
        payload = make_mock_ipv6(payload_len=15)
        pkt = Packet(version=VERSION_IPV6, subtype=0, payload=payload)
        raw_bytes = pkt.to_bytes()

        self.assertEqual(len(raw_bytes), 55)
        self.assertEqual(raw_bytes[0] >> 4, 6)

        # Deserialize
        parsed, consumed = Packet.from_bytes(raw_bytes)
        self.assertIsNotNone(parsed)
        self.assertEqual(consumed, 55)
        self.assertEqual(parsed.version, VERSION_IPV6)
        self.assertEqual(parsed.payload, payload)

    def test_packet_serialization_mgmt(self):
        """Verifies management packet handles 3-byte header."""
        payload = b"Hello Handshake"
        pkt = Packet(version=VERSION_MGMT, subtype=1, payload=payload)
        raw_bytes = pkt.to_bytes()

        self.assertEqual(len(raw_bytes), 3 + len(payload))
        self.assertEqual(raw_bytes[0], 1) # (0 << 4) | 1

        # Deserialize
        parsed, consumed = Packet.from_bytes(raw_bytes)
        self.assertIsNotNone(parsed)
        self.assertEqual(consumed, len(raw_bytes))
        self.assertEqual(parsed.version, VERSION_MGMT)
        self.assertEqual(parsed.subtype, 1)
        self.assertEqual(parsed.payload, payload)

    def test_incomplete_bytes(self):
        """Verifies that incomplete bytes return None consumed."""
        # Management packet wants 10 bytes but we only give 5 total bytes (3 header + 2 payload)
        raw_bytes = struct.pack("!BH", 1, 10) + b"\\x00\\x00"
        parsed, consumed = Packet.from_bytes(raw_bytes)
        self.assertIsNone(parsed)
        self.assertEqual(consumed, 0)

    def test_high_priority_dscp_ipv4(self):
        """Verifies that Expedited Forwarding (EF=46) DSCP in IPv4 is detected."""
        # EF is DSCP 46. ToS = 46 << 2 = 184
        payload = make_mock_ipv4(total_len=20, tos=184)
        pkt = Packet(version=VERSION_IPV4, subtype=0, payload=payload)
        self.assertTrue(pkt.is_high_priority())

        # Low-priority (ToS=0)
        payload = make_mock_ipv4(total_len=20, tos=0)
        pkt = Packet(version=VERSION_IPV4, subtype=0, payload=payload)
        self.assertFalse(pkt.is_high_priority())

    def test_high_priority_dscp_ipv6(self):
        """Verifies that Expedited Forwarding (EF=46) in IPv6 is parsed correctly."""
        # EF is DSCP 46. Traffic class = 46 << 2 = 184
        payload = make_mock_ipv6(payload_len=10, traffic_class=184)
        pkt = Packet(version=VERSION_IPV6, subtype=0, payload=payload)
        self.assertTrue(pkt.is_high_priority())


class TestBuncher(unittest.TestCase):
    """Verifies packet bunching, flushing, and padding constraints."""

    def test_buncher_no_padding(self):
        """Verifies buncher flushing under PADDING_NONE."""
        buncher = Buncher(preferred_size=100, timeout=0.5, padding_mode=PADDING_NONE)
        pkt = Packet(VERSION_IPV4, 0, make_mock_ipv4(total_len=20))

        # Add single packet. Timeout is non-zero, so it is queued
        is_flush, flushed = buncher.add_packet(pkt)
        self.assertFalse(is_flush)
        self.assertIsNone(flushed)
        self.assertEqual(len(buncher.queue), 1)

        # Force manually flushing
        data = buncher.flush()
        self.assertEqual(len(data), 20)
        self.assertEqual(len(buncher.queue), 0)

    def test_buncher_full_padding(self):
        """Verifies buncher pads with version 15 junk up to preferred size."""
        buncher = Buncher(preferred_size=50, timeout=0.5, padding_mode=PADDING_FULL)
        pkt = Packet(VERSION_IPV4, 0, make_mock_ipv4(total_len=20))

        # Adding it
        buncher.add_packet(pkt)

        # Flush should append a padding packet (version 15) so that size equals exactly 50 bytes
        data = buncher.flush()
        self.assertEqual(len(data), 50)

        # Check fields
        p1, c1 = Packet.from_bytes(data)
        p2, c2 = Packet.from_bytes(data[c1:])
        self.assertEqual(p1.version, VERSION_IPV4)
        self.assertEqual(p2.version, VERSION_PADDING)
        self.assertEqual(c1 + c2, 50)


class TestTunnelServerPool(unittest.TestCase):
    """Verifies that TunnelServer client IP pool allocation works and reserves the first address."""

    def test_pool_allocation_and_reservation(self):
        from astunnel.server import TunnelServer
        server = TunnelServer(pool="10.1.2.0/29")
        # 10.1.2.0/29 has 8 addresses: 10.1.2.0 to 10.1.2.7.
        # The first address (10.1.2.0) is reserved for server.
        self.assertEqual(server.server_id, bytes([10, 1, 2, 0]))

        # Dynamic allocation should start at 10.1.2.1 and proceed up to 10.1.2.7 (skipping 10.1.2.0)
        allocated_ids = []
        for _ in range(7):
            allocated_ids.append(server.allocate_client_id())

        self.assertEqual(allocated_ids[0], bytes([10, 1, 2, 1]))
        self.assertEqual(allocated_ids[-1], bytes([10, 1, 2, 7]))

        # Next attempts should raise RuntimeError as pool is full
        with self.assertRaises(RuntimeError):
            server.allocate_client_id()
`
  },
  {
    name: "pyproject.toml",
    path: "pyproject.toml",
    language: "toml",
    content: `[build-system]
requires = ["setuptools>=61.0.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "astunnel"
dynamic = ["version"]
description = "Asyncio SSL TCP packet-tunneling client/server suite with packet bunching and custom padding"
readme = "README.md"
requires-python = ">=3.11"
license = {text = "MIT"}

[project.scripts]
astunnel = "astunnel.cli:main"

[tool.setuptools.dynamic]
version = {attr = "astunnel.__version__"}
`
  },
  {
    name: "test.yml",
    path: ".github/workflows/test.yml",
    language: "yaml",
    content: `name: Python Test Suite

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13", "3.14"]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up Python \${{ matrix.python-version }}
      uses: actions/setup-python@v5
      with:
        python-version: \${{ matrix.python-version }}
        cache: 'pip'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install --upgrade setuptools wheel build
        pip install -e .

    - name: Run unittests
      run: |
        python -m unittest discover -s tests
`
  }
];
