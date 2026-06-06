"""
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
        server_id = config.get("server_id", b"\x00\x00\x00\x00")
        if len(server_id) != 4:
            server_id = b"\x00\x00\x00\x00"
        return server_id

    def parse_handshake_extra(self, extra_bytes: bytes) -> Dict[str, Any]:
        if len(extra_bytes) >= 4:
            return {"server_id": extra_bytes[:4]}
        return {"server_id": b"\x00\x00\x00\x00"}

    def start(self, send_cb, client_id, logger, is_server=False):
        self.send_cb = send_cb
        self.client_id = client_id
        self.logger = logger
        self._loop = asyncio.get_event_loop()
        self.is_server = is_server

        if self.logger:
            self.logger.debug("Starting TUN Backend (is_server=%s) with Client ID: %s", self.is_server, self.client_id.hex() if self.client_id else "None")

        try:
            self.fd, self.ifname = self._open_tun()
            if self.logger:
                self.logger.debug("Successfully opened TUN device fd=%d name=%s", self.fd, self.ifname)
            
            self._configure_interface()
            
            # Register read callback on event loop
            self._loop.add_reader(self.fd, self._on_tun_readable)
            self.logger.warning("TUN Backend started successfully on device %s (is_server=%s)", self.ifname, self.is_server)
        except Exception as e:
            if self.logger:
                self.logger.error("Failed to start TUN backend: %s. Direct device setup skipped.", e, exc_info=True)
            self.stop()
            raise

    def stop(self):
        if self.logger:
            self.logger.debug("Stopping TUN backend. Current state: fd=%s, ifname=%s", self.fd, self.ifname)
        if self.fd is not None:
            if self._loop:
                try:
                    self._loop.remove_reader(self.fd)
                    if self.logger:
                        self.logger.debug("Removed fd=%d reader from event loop", self.fd)
                except Exception as e:
                    if self.logger:
                        self.logger.debug("Error removing reader from loop: %s", e)
            try:
                os.close(self.fd)
                if self.logger:
                    self.logger.debug("Closed TUN fd=%d", self.fd)
            except Exception as e:
                if self.logger:
                    self.logger.debug("Error closing TUN fd: %s", e)
            if self.logger and self.ifname:
                self.logger.warning("TUN Backend stopped on device %s", self.ifname)
            self.fd = None
            self.ifname = None

    def receive_packet(self, pkt: Packet) -> None:
        """Called on client side when a packet is received from the server."""
        if self.fd is not None and pkt.version in (4, 6):
            if self.logger:
                self.logger.debug("TUN Client writing packet to interface %s: version=%d payload_size=%d", self.ifname, pkt.version, len(pkt.payload))
            try:
                os.write(self.fd, pkt.payload)
            except Exception as e:
                if self.logger:
                    self.logger.error("Error writing packet to TUN device on client: %s", e, exc_info=True)

    def process_packet(self, pkt: Packet, client_id: bytes) -> Any:
        """Called on server side when a packet is received from the client."""
        if self.fd is not None and pkt.version in (4, 6):
            if self.logger:
                self.logger.debug("TUN Server writing packet to interface %s: client_id=%s version=%d payload_size=%d", self.ifname, client_id.hex(), pkt.version, len(pkt.payload))
            try:
                os.write(self.fd, pkt.payload)
            except Exception as e:
                if self.logger:
                    self.logger.error("Error writing packet to TUN device on server: %s", e, exc_info=True)
        return None

    def _open_tun(self) -> tuple:
        if self.logger:
            self.logger.debug("Attempting to open TUN device at /dev/net/tun...")
        try:
            fd = os.open("/dev/net/tun", os.O_RDWR)
        except FileNotFoundError:
            if self.logger:
                self.logger.error("/dev/net/tun not found. Are you currently running on a platform supporting virtual network interfaces? Note: root privileges are required.")
            raise
        except PermissionError:
            if self.logger:
                self.logger.error("Permission denied when opening /dev/net/tun. Administrator/root privileges are required.")
            raise

        ifr = struct.pack("16sH", b"tun%d", IFF_TUN | IFF_NO_PI)
        try:
            res = fcntl.ioctl(fd, TUNSETIFF, ifr)
        except Exception as e:
            if self.logger:
                self.logger.error("ioctl TUNSETIFF call failed: %s", e)
            raise
        ifname = res[:16].strip(b"\x00").decode("utf-8")
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
                self.logger.error("Command '%s' failed with exit code %d\nStdout: %s\nStderr: %s",
                                  " ".join(cmd), e.returncode, e.stdout, e.stderr)
            raise

    def _configure_interface(self):
        server_id_bytes = self.options.get("server_id", b"\x00\x00\x00\x00")
        
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

        if self.logger:
            self.logger.debug("Configuring TUN interface %s. local_ip=%s, peer_ip=%s, local_ipv6=%s, peer_ipv6=%s",
                              self.ifname, local_ip, peer_ip, local_ipv6, peer_ipv6)

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
                    self.logger.error("Failed to add IPv6 address: %s", e2, exc_info=True)

    def _on_tun_readable(self):
        try:
            packet = os.read(self.fd, 2048)
            if not packet:
                if self.logger:
                    self.logger.debug("TUN read returned EOF / empty packet.")
                return
            
            # Determine IP version: first nibble of the IP header (IPv4/6)
            version = packet[0] >> 4
            if version not in (4, 6):
                if self.logger:
                    self.logger.debug("Discarding packet with invalid IP version: %d (payload length: %d)", version, len(packet))
                return

            if self.logger:
                self.logger.debug("Read %d bytes from TUN device (version %d)", len(packet), version)

            if self.send_cb:
                # Schedule sending as an async task
                self._loop.create_task(self.send_cb(version, 0, packet))
        except Exception as e:
            if self.logger:
                self.logger.error("Error reading from TUN device: %s", e, exc_info=True)
