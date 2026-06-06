"""
Unittests for the Test Echo Backend, Client ID translation/mappings, and multi-client runs.
"""

import unittest
from astunnel.backends import get_backend_class
from astunnel.backends.echo import EchoBackend
from astunnel.common import (
    Packet,
    VERSION_IPV4,
    VERSION_IPV6,
)


class TestEchoBackend(unittest.TestCase):
    """Verifies backend client ID parsing, IPv6 mapping, and packet filters."""

    def setUp(self):
        self.backend = EchoBackend({"packet_type_filter": 0})

    def test_extract_client_id_ipv4(self):
        """Verifies Client ID extraction from IPv4 source address field (bytes 12-15)."""
        # Minimum IPv4 header length is 20 bytes
        payload = bytearray(20)
        # Set source IP to 192.168.10.25 (idx 12: 192, 13: 168, 14: 10, 15: 25)
        payload[12] = 192
        payload[13] = 168
        payload[14] = 10
        payload[15] = 25

        cid = self.backend.extract_client_id(bytes(payload), VERSION_IPV4)
        self.assertEqual(cid, bytes([192, 168, 10, 25]))

    def test_extract_client_id_ipv6(self):
        """Verifies Client ID extraction from IPv6 source address fields (last 4 bytes of source)."""
        # Minimum IPv6 header is 40 bytes. Source IP occupies bytes 8 to 23.
        # Last 4 octets of source are bytes 20-23.
        payload = bytearray(40)
        payload[20] = 10
        payload[21] = 0
        payload[22] = 1
        payload[23] = 99

        cid = self.backend.extract_client_id(bytes(payload), VERSION_IPV6)
        self.assertEqual(cid, bytes([10, 0, 1, 99]))

    def test_convert_client_id_to_ipv6(self):
        """Checks API functions converting 4-octet Client ID to dynamic ULA (fc00::/7) IPv6 address."""
        cid = bytes([192, 168, 1, 5])
        ipv6_str = self.backend.convert_client_id_to_ipv6(cid)
        self.assertEqual(ipv6_str, "fd00::c0a8:105")

    def test_inject_client_id(self):
        """Verifies Client ID gets correctly written back into the IP payload header bytes."""
        payload = bytearray(20)
        cid = bytes([172, 16, 0, 4])
        modified_payload = self.backend.inject_client_id(bytes(payload), VERSION_IPV4, cid)

        # Source IP at bytes 12-15 should match
        self.assertEqual(modified_payload[12:16], cid)

    def test_packet_type_filter(self):
        """Checks packet filtering. If filter option is suggested, drops unmatching types."""
        # Backend 1: Filter set to IPv4 (4)
        bk_v4 = EchoBackend({"packet_type_filter": 4})
        self.assertTrue(bk_v4.should_echo_packet(VERSION_IPV4))
        self.assertFalse(bk_v4.should_echo_packet(VERSION_IPV6))

        # Backend 2: Filter set to IPv6 (6)
        bk_v6 = EchoBackend({"packet_type_filter": 6})
        self.assertFalse(bk_v6.should_echo_packet(VERSION_IPV4))
        self.assertTrue(bk_v6.should_echo_packet(VERSION_IPV6))

        # Backend 3: Filter set to None (0)
        bk_none = EchoBackend({"packet_type_filter": 0})
        self.assertTrue(bk_none.should_echo_packet(VERSION_IPV4))
        self.assertTrue(bk_none.should_echo_packet(VERSION_IPV6))

    def test_handshake_extra_compilation(self):
        """Verifies that extra filter configs can get serialized to handshake packet."""
        bk = EchoBackend({"packet_type_filter": 6})
        extra_bytes = bk.compile_handshake_extra(bk.options)
        self.assertEqual(extra_bytes, bytes([6]))

        # Parsing back
        parsed_opts = bk.parse_handshake_extra(extra_bytes)
        self.assertEqual(parsed_opts.get("packet_type_filter"), 6)


if __name__ == "__main__":
    unittest.main()
