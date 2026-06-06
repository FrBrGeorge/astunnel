"""
Asyncio client implementation for the SSL TCP packet-tunneling suite.
Manages connection handshakes, 3 SSL security models, and client-side bunching/timeout queues.
"""

import ssl
import struct
import asyncio
import logging
import hashlib
from pathlib import Path
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
from astunnel.backends import get_backend_class

# Client Defaults
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18443
DEFAULT_PEM_FILE = "server.pem"
DEFAULT_BUNCH_SIZE = 1400
DEFAULT_SYNC_TIMEOUT = 0.5


class TunnelClient:
    """Asyncio SSL TCP client executing packet tunnels."""

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        requested_client_id: bytes = b"\x00\x00\x00\x00",
        padding_mode: int = PADDING_NONE,
        sync_timeout: float = DEFAULT_SYNC_TIMEOUT,
        backend_name: str = "echo",
        backend_options: Optional[Dict[str, Any]] = None,
        ssl_mode: str = "secure",  # "insecure", "trusted", or "secure"
        trusted_fingerprint: Optional[str] = None,  # For 'trusted' mode
        console_level: str = "WARNING",
        logfile: Optional[str] = None,
        file_level: str = "INFO",
    ):
        self.host = host
        self.port = port
        self.requested_client_id = requested_client_id
        self.padding_mode = padding_mode
        self.sync_timeout = sync_timeout
        self.backend_name = backend_name
        self.backend_options = backend_options or {}
        self.ssl_mode = ssl_mode
        self.trusted_fingerprint = trusted_fingerprint.lower().replace(":", "") if trusted_fingerprint else None
        self.logger = setup_logger(console_level, logfile, file_level)

        # Tunnel state
        self.client_id = b"\x00\x00\x00\x00"
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.buncher: Optional[Buncher] = None
        self.last_packet_time = 0.0
        self.is_connected = False
        self._flusher_task: Optional[asyncio.Task] = None
        self._reader_task: Optional[asyncio.Task] = None
        self.backend_inst = None

    def get_ssl_context(self) -> ssl.SSLContext:
        """Configures SSLContext based on specified client mode (insecure, trusted, or secure)."""
        if self.ssl_mode == "insecure" or self.ssl_mode == "trusted":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        else:
            # Secure mode: fully trust CAs
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = True
            return ctx

    def verify_fingerprint(self, ssl_obj: Any) -> None:
        """Extracts SHA256 bytes of peer cert and validates it in trusted mode."""
        if self.ssl_mode != "trusted" or not self.trusted_fingerprint:
            return

        der_cert = ssl_obj.getpeercert(binary_form=True)
        if not der_cert:
            raise ssl.SSLError("Could not retrieve peer certificate in trusted mode.")

        current_hash = hashlib.sha256(der_cert).hexdigest()
        self.logger.debug("Server Certificate fingerprint: %s", current_hash)

        if current_hash != self.trusted_fingerprint:
            self.logger.error(
                "Certificate fingerprint mismatch! Expected %s, got %s",
                self.trusted_fingerprint,
                current_hash,
            )
            raise ssl.SSLError("Certificate fingerprint unauthorized (untrusted).")
        self.logger.info("Fingerprint verification succeeded.")

    async def connect(self) -> None:
        """Establishes SSL handshakes and connects to the tunnel server."""
        ssl_ctx = self.get_ssl_context()
        self.logger.warning("Connecting to SSL TCP Tunnel Server at %s:%d (mode: %s)...", self.host, self.port, self.ssl_mode)

        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port, ssl=ssl_ctx
            )
            self.logger.debug("Socket connection succeeded. Extra context: %s", self.writer.get_extra_info("peername"))
        except Exception as e:
            self.logger.error("Failed to establish TCP socket connection to %s:%d: %s", self.host, self.port, e, exc_info=True)
            raise

        ssl_obj = self.writer.get_extra_info("ssl_object")
        if self.ssl_mode == "trusted":
            self.logger.debug("Verifying server certificate fingerprint...")
            self.verify_fingerprint(ssl_obj)

        self.logger.info("TCP SSL Connection established. Initiating handshakes suggestion...")

        # Initialize temporary backend placeholder to get custom parameters
        backend_cls = get_backend_class(self.backend_name)
        self.backend_interim = backend_cls(self.backend_options)
        extra_fields = self.backend_interim.compile_handshake_extra(self.backend_options)
        self.logger.debug("Compiled backend extra fields (%d bytes) for handshake", len(extra_fields))

        # Build Handshake Suggestion Packet:
        # - 4 octets: Client ID (suggested bytes)
        # - 1 octet: Padding mode
        # - 4 octets: Sync timeout (float)
        # - 1 octet: Backend name length
        # - n octets: Backend name (string)
        # - remaining: custom backend parameters
        handshake_payload = (
            self.requested_client_id
            + bytes([self.padding_mode])
            + struct.pack("!f", self.sync_timeout)
            + bytes([len(self.backend_name)])
            + self.backend_name.encode("utf-8")
            + extra_fields
        )

        suggestion_pkt = Packet(VERSION_MGMT, MGMT_HANDSHAKE, handshake_payload)
        self.logger.debug("Sending handshake suggestion packet to server: payload_size=%d", len(handshake_payload))
        self.writer.write(suggestion_pkt.to_bytes())
        await self.writer.drain()
        self.logger.debug("Handshake suggestion packet drained successfully.")

        # Read Server handshake reply (management packet has 3-byte header)
        self.logger.debug("Waiting for server handshake response (3 bytes header)...")
        try:
            header = await self.reader.readexactly(3)
        except asyncio.IncompleteReadError as e:
            self.logger.error("Server closed the connection during handshakes. Partial content: %s", e.partial, exc_info=True)
            raise RuntimeError("Server closed connection during handshake.") from e

        first_byte = header[0]
        payload_len = struct.unpack("!H", header[1:3])[0]
        version = first_byte >> 4
        subtype = first_byte & 0x0F
        self.logger.debug("Received response header from server: version=%d, subtype=%d, payload_len=%d", version, subtype, payload_len)

        self.logger.debug("Reading server handshake response payload (%d bytes)...", payload_len)
        try:
            srv_payload = await self.reader.readexactly(payload_len)
        except asyncio.IncompleteReadError as e:
            self.logger.error("Server closed connection while reading handshake payload: partial=%s", e.partial, exc_info=True)
            raise RuntimeError("Server closed connection while reading handshake payload.") from e

        if version == VERSION_MGMT and subtype == MGMT_ERROR:
            self.logger.error("Server handshake error: %s", srv_payload.decode("utf-8"))
            raise RuntimeError(f"Server handshakes error: {srv_payload.decode('utf-8')}")

        if version != VERSION_MGMT or subtype != MGMT_HANDSHAKE:
            self.logger.error("Unexpected packet type during handshake: version=%d, subtype=%d", version, subtype)
            raise RuntimeError("Invalid server handshake protocol response.")

        # Parse finalized Server Config
        self.client_id = srv_payload[0:4]
        negotiated_padding = srv_payload[4]
        (negotiated_timeout,) = struct.unpack("!f", srv_payload[5:9])
        backend_name_len = srv_payload[9]
        negotiated_backend = srv_payload[10 : 10 + backend_name_len].decode("utf-8")
        server_extra = srv_payload[10 + backend_name_len :]

        self.logger.warning(
            "Negotiated configuration from Server: ID=%s, Padding=%d, Timeout=%.3fs, Backend=%s",
            self.client_id.hex(),
            negotiated_padding,
            negotiated_timeout,
            negotiated_backend,
        )

        # Configure Client State
        self.backend_inst = backend_cls(self.backend_options)
        server_options = self.backend_inst.parse_handshake_extra(server_extra)
        self.backend_inst.options.update(server_options)
        self.logger.debug("Configured backend state with server extras. Backend Options: %s", self.backend_inst.options)

        self.buncher = Buncher(
            preferred_size=DEFAULT_BUNCH_SIZE,
            timeout=negotiated_timeout,
            padding_mode=negotiated_padding,
        )
        self.is_connected = True

        # Start the backend if capable
        if hasattr(self.backend_inst, "start"):
            self.logger.debug("Starting client-side backend...")
            try:
                self.backend_inst.start(self.send_packet, self.client_id, self.logger, is_server=False)
            except Exception as e:
                self.logger.error("Failed to start client-side backend: %s", e, exc_info=True)

        # Launch background tasks
        self.logger.debug("Launching background Tasks: flusher, read loop")
        self._flusher_task = asyncio.create_task(self._bunch_timeout_flusher())
        self._reader_task = asyncio.create_task(self._read_tunnel_loop())

    async def send_packet(self, version: int, subtype: int, payload: bytes) -> None:
        """Sends a packet by queuing it to the client buncher."""
        if not self.is_connected or not self.buncher:
            self.logger.warning("Attempted to send packet while tunnel is inactive. is_connected=%s", self.is_connected)
            raise RuntimeError("Tunnel is not active.")

        # Inject Client ID to payload for normal IPv4/IPv6 packet if available
        if version in (4, 6) and self.backend_inst:
            payload = self.backend_inst.inject_client_id(payload, version, self.client_id)

        pkt = Packet(version, subtype, payload)
        self.logger.debug("Client sending packet into queue: %s (payload length=%d)", pkt, len(payload))

        should_flush, flushed_bytes = self.buncher.add_packet(pkt)
        self.last_packet_time = asyncio.get_event_loop().time()
        if should_flush and flushed_bytes and self.writer:
            self.logger.debug("Client buncher size threshold reached. Flushing %d bytes to server stream.", len(flushed_bytes))
            self.writer.write(flushed_bytes)
            await self.writer.drain()

    async def _read_tunnel_loop(self) -> None:
        """Background coroutine parsing server packets arriving over SSL."""
        self.logger.debug("Client reader loop started.")
        buffer = b""
        try:
            while self.is_connected and self.reader:
                data = await self.reader.read(4096)
                if not data:
                    self.logger.warning("Client reader loop received empty bytes (EOF). Server likely closed the connection.")
                    break
                self.logger.debug("Client reader loop received %d raw bytes from SSL stream.", len(data))
                buffer += data

                while True:
                    pkt, consumed = Packet.from_bytes(buffer)
                    if not pkt:
                        self.logger.debug("Incomplete packet in buffer (buffer size: %d bytes). Awaiting more data.", len(buffer))
                        break
                    buffer = buffer[consumed:]

                    if pkt.version == VERSION_PADDING:
                        self.logger.debug("Client received padding. Discarded.")
                        continue

                    # Delegate to handler
                    self.logger.debug("Client received packet over tunnel: %s", pkt)
                    self.handle_received_packet(pkt)
        except asyncio.CancelledError:
            self.logger.debug("Client reader task was cancelled.")
        except Exception as err:
            self.logger.error("Exception in client reader coroutine: %s", err, exc_info=True)
        finally:
            self.logger.debug("Exiting client reader loop. Disconnecting.")
            await self.disconnect()

    def handle_received_packet(self, pkt: Packet) -> None:
        """Prints or pipes parsed packets or forwards to backend."""
        if self.backend_inst and hasattr(self.backend_inst, "receive_packet"):
            self.backend_inst.receive_packet(pkt)
        else:
            self.logger.info("Tunnel Packet Rx: [Version %d / Sub %d] Payload size=%d", pkt.version, pkt.subtype, len(pkt.payload))

    async def _bunch_timeout_flusher(self) -> None:
        """Routine performing syncing-timeout flushes."""
        while self.is_connected and self.buncher:
            await asyncio.sleep(0.02)
            now = asyncio.get_event_loop().time()
            if self.buncher.timeout > 0:
                if self.buncher.queue:
                    elapsed = now - self.last_packet_time
                    if elapsed >= self.buncher.timeout:
                        flushed_bytes = self.buncher.flush()
                        if flushed_bytes and self.writer:
                            try:
                                self.writer.write(flushed_bytes)
                                await self.writer.drain()
                            except Exception:
                                pass

    async def disconnect(self) -> None:
        """Gracefully tears down the client tunnel."""
        if not self.is_connected:
            return
        self.is_connected = False
        self.logger.warning("Terminating client tunnel connection.")

        # Stop backend if needed
        if self.backend_inst and hasattr(self.backend_inst, "stop"):
            self.backend_inst.stop()

        # Cancel background tasks
        if self._flusher_task:
            self._flusher_task.cancel()
        if self._reader_task:
            self._reader_task.cancel()

        # Flush bunch remaining
        if self.buncher and self.buncher.queue:
            flushed = self.buncher.flush()
            if flushed and self.writer:
                try:
                    self.writer.write(flushed)
                    await self.writer.drain()
                except Exception:
                    pass

        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
