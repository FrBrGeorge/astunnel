"""
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

    def __repr__(self) -> str:
        return f"<Packet ver={self.version} sub={self.subtype} len={len(self.payload)}>"


class Buncher:
    """
    Accumulates packets into a single TCP bunch based on:
    - Preferred bunch size (TCP segment target size, e.g., 1400)
    - Timeout: wait up to syncing timeout (float seconds) before forcing flush
    - High-integrity check: DSCP field of IPv4/v6 requiring immediate flushing
    - Padding modes:
      1: No padding
      2: Pad to preferred bunch size (using Version 15 padding packets with 3-byte headers)
      3: Random padding between (1) and (2)
    """

    def __init__(self, preferred_size: int = 1400, timeout: float = 0.5, padding_mode: int = PADDING_NONE):
        self.preferred_size = preferred_size
        self.timeout = timeout
        self.padding_mode = padding_mode
        self.queue: List[Packet] = []
        self.current_serialized_length = 0

    def add_packet(self, packet: Packet) -> Tuple[bool, Optional[bytes]]:
        """
        Adds a packet to the bunching queue.
        Returns (should_flush, flushed_bytes).
        If immediate flushing is triggered (e.g., due to size exceedance or high-priority DSCP),
        returns (True, serialized_bunch_bytes) and clears the queue.
        """
        packet_len = len(packet.to_bytes())

        # Check if packet by itself exceeds preferred size, or check if next packet doesn't fit
        # If queue is not empty, and packet would exceed preferred_size: flush existing first
        if self.queue and (self.current_serialized_length + packet_len > self.preferred_size):
            flushed = self.flush()
            # Start a new bunch with current packet
            self.queue = [packet]
            self.current_serialized_length = packet_len
            # Check if this packet itself triggers an immediate flush
            if packet.is_high_priority():
                return True, flushed + self.flush()
            return True, flushed

        # Add to current queue
        self.queue.append(packet)
        self.current_serialized_length += packet_len

        # If incoming packet requires immediate transmission (DSCP)
        if packet.is_high_priority():
            return True, self.flush()

        # If timeout is 0, we sync immediately
        if self.timeout == 0.0:
            return True, self.flush()

        return False, None

    def flush(self) -> bytes:
        """
        Converts accumulated packets into a single byte stream, adding padding if configured.
        Clears the current queue.
        """
        if not self.queue:
            return b""

        # Perform padding logic according to self.padding_mode
        if self.padding_mode == PADDING_FULL:
            target_padding = self.preferred_size - self.current_serialized_length
            if target_padding >= 3:
                # pad header size is 3 (1 byte first_byte + 2 bytes len)
                pad_payload_size = target_padding - 3
                pad_pkt = Packet(VERSION_PADDING, 0, bytes(random.getrandbits(8) for _ in range(pad_payload_size)))
                self.queue.append(pad_pkt)
        elif self.padding_mode == PADDING_RANDOM:
            max_padding = self.preferred_size - self.current_serialized_length
            if max_padding >= 3:
                pad_size_target = random.randint(0, max_padding)
                if pad_size_target >= 3:
                    pad_payload_size = pad_size_target - 3
                    pad_pkt = Packet(VERSION_PADDING, 0, bytes(random.getrandbits(8) for _ in range(pad_payload_size)))
                    self.queue.append(pad_pkt)

        # Serialize everything
        chunk = b"".join(pkt.to_bytes() for pkt in self.queue)

        # Reset states
        self.queue = []
        self.current_serialized_length = 0
        return chunk


def setup_logger(console_level: str = "WARNING", logfile: Optional[str] = None, file_level: str = "INFO") -> logging.Logger:
    """
    Sets up a standardized logging configuration:
    - Console handler with high level (default WARNING / WARN)
    - Optional file handler with standard logs (default INFO)
    Uses structured formatting suited to command-line interactions.
    """
    logger = logging.getLogger("SSL_Tunnel")
    logger.setLevel(logging.DEBUG)  # Root level set to lowest to allow cascades
    logger.handlers = []  # Clear prior handlers

    # Console Logger setup
    c_handler = logging.StreamHandler(sys.stdout)
    c_level = getattr(logging, console_level.upper(), logging.WARNING)
    c_handler.setLevel(c_level)
    c_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [CONSOLE] %(message)s", datefmt="%H:%M:%S"
    )
    c_handler.setFormatter(c_formatter)
    logger.addHandler(c_handler)

    # File Logger setup if path supplied
    if logfile:
        f_path = Path(logfile)
        # Ensure directories exist
        f_path.parent.mkdir(parents=True, exist_ok=True)
        f_handler = logging.FileHandler(f_path, encoding="utf-8")
        f_level = getattr(logging, file_level.upper(), logging.INFO)
        f_handler.setLevel(f_level)
        f_formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s"
        )
        f_handler.setFormatter(f_formatter)
        logger.addHandler(f_handler)

    return logger
