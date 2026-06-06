import unittest
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
        mock_ioctl.return_value = b"tun99\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

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
        backend.process_packet(pkt, b"\x0a\x00\x00\x05")
        mock_write.assert_called_with(99, b"mock_ipv4_payload")


if __name__ == "__main__":
    unittest.main()
