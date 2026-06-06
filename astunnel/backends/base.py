"""
Base class definition for packet-tunneling backends.
Provides interface for Client ID extraction, conversion, injection, and custom handshake structures.
"""

import socket
import struct
from typing import Dict, Any, Tuple


class BaseBackend:
    """
    Subclasses of BaseBackend provide packet routing, ID translations,
    and handshake configurations specific to each tunneling type.
    """

    backend_name = "base"

    def __init__(self, options: Dict[str, Any]):
        self.options = options

    def extract_client_id(self, payload: bytes, version: int) -> bytes:
        """
        Extracts a 4-octet client ID resembling IPv4 from a packet payload.
        - IPv4 (ver 4): can extract source IP address (bytes 12-15) as the Client ID.
        - IPv6 (ver 6): can extract low 4 bytes of source IPv6 address (bytes 12-15 or similar)
          or use a custom backend format.
        """
        if version == 4:
            if len(payload) >= 20:
                # Source address occupies octets 12-15 of standard IPv4 header
                return payload[12:16]
        elif version == 6:
            if len(payload) >= 40:
                # Let's extract bytes 28-32 of IPv6 header (last 4 octets of source IPv6)
                # IPv6 Source address spans bytes 8 to 23. Let's take the last 4 bytes (20-23).
                return payload[20:24]

        # Fallback or generic packet payload: assume first 4 bytes of raw payload contains Client ID
        if len(payload) >= 4:
            return payload[:4]
        return b"\x00\x00\x00\x00"

    def inject_client_id(self, payload: bytes, version: int, client_id: bytes) -> bytes:
        """
        Encodes or injects a client ID back into a packet's payload.
        - IPv4 (ver 4): replaces source IP address (bytes 12-15) with client_id.
        - IPv6 (ver 6): replaces the custom mapped block (last 4 octets of source IP) with client_id.
        """
        if len(client_id) != 4:
            raise ValueError("Client ID must be exactly 4 bytes")

        payload_mut = bytearray(payload)
        if version == 4 and len(payload_mut) >= 20:
            payload_mut[12:16] = client_id
            return bytes(payload_mut)
        elif version == 6 and len(payload_mut) >= 40:
            payload_mut[20:24] = client_id
            return bytes(payload_mut)

        # Fallback or custom package: overwrite first 4 bytes
        if len(payload_mut) >= 4:
            payload_mut[:4] = client_id
            return bytes(payload_mut)
        return payload

    def convert_client_id_to_ipv6(self, client_id: bytes) -> str:
        """
        Translates a 4-octet Client ID into its corresponding IPv6 address.
        Uses standard mapping (e.g., embedding the client ID in RFC 4291 IPv4-mapped IPv6,
        or a custom prefix like `2001:db8::/32`).
        For example, c0a8:0105 (192.168.1.5) -> 2001:db8::192.168.1.5 or mapped ::ffff:192.168.1.5
        """
        if len(client_id) != 4:
            return "::1"
        # Map to an IPv4-mapped IPv6 address "::ffff:A.B.C.D"
        ip_str = f"{client_id[0]}.{client_id[1]}.{client_id[2]}.{client_id[3]}"
        return f"::ffff:{ip_str}"

    def parse_handshake_extra(self, extra_bytes: bytes) -> Dict[str, Any]:
        """
        Parse custom fields contributed by this backend from the handshake packet payload.
        By default, does nothing and returns empty dictionary.
        """
        return {}

    def compile_handshake_extra(self, config: Dict[str, Any]) -> bytes:
        """
        Compile custom parameters into bytes to append to the client handshake packet.
        By default, returns empty bytes.
        """
        return b""

    def process_packet(self, pkt: Any, client_id: bytes) -> Any:
        """
        Process an incoming packet. Returns an optional Packet to send back
        or route, or None if the packet is consumed or filtered out.
        By default on BaseBackend, returns None (no response/routing).
        """
        return None
