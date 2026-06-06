"""
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
        raw_bytes = struct.pack("!BH", 1, 10) + b"\x00\x00"
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


if __name__ == "__main__":
    unittest.main()
