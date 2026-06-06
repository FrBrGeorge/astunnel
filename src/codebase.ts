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
        host: str = "0.0.0.0",
        port: int = 18443,
        pem_path: str = "server.pem",
    ):
        self.host = host
        self.port = port
        self.pem_path = Path(pem_path)
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
    name: "base.py",
    path: "astunnel/backends/base.py",
    language: "python",
    content: `"""
Base class definition for packet-tunneling backends.
Provides interfaces for Client ID extraction, conversion, and injections.
"""

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
            return "::1"
        ip_str = f"{client_id[0]}.{client_id[1]}.{client_id[2]}.{client_id[3]}"
        return f"::ffff:{ip_str}"

    def process_packet(self, pkt: Any, client_id: bytes) -> Any:
        return None
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
