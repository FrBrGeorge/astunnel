"""
Test Echo Backend Implementation.
Bounces packets back to the client after performing Client ID management and optional packet-type filtering.
"""

from typing import Dict, Any
from astunnel.backends.base import BaseBackend
from astunnel.common import Packet


class EchoBackend(BaseBackend):
    """
    Echo backend: returns received packets back to the sender.
    Supports a packet-type filter option (1-byte int code: 0 = no filter, 4 = IPv4-only, 6 = IPv6-only).
    Extra payload format:
    - 1 octet: Filter type (0, 4, or 6) as an unsigned byte
    """

    backend_name = "echo"

    def __init__(self, options: Dict[str, Any]):
        super().__init__(options)
        # Default filter to 0 (no filtering) if not specified
        self.packet_type_filter = int(options.get("packet_type_filter", 0))

    def parse_handshake_extra(self, extra_bytes: bytes) -> Dict[str, Any]:
        """
        Parse custom fields from the echo backend.
        We expect 1 octet indicating packet_type_filter.
        """
        parsed = {}
        if len(extra_bytes) >= 1:
            parsed["packet_type_filter"] = int(extra_bytes[0])
        else:
            parsed["packet_type_filter"] = 0
        return parsed

    def compile_handshake_extra(self, config: Dict[str, Any]) -> bytes:
        """
        Compile custom parameters. We write 1 octet for packet_type_filter.
        """
        filt = int(config.get("packet_type_filter", 0))
        if filt not in (0, 4, 6):
            filt = 0
        return bytes([filt])

    def should_echo_packet(self, version: int) -> bool:
        """
        Determines if a packet should be bounced back based on the filter rules.
        """
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
