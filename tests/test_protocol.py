import unittest
from pylan.core.protocol import pack_message, unpack_header, HEADER_SIZE

class TestProtocols(unittest.TestCase):

    def test_pack_message_with_dict(self):
        msg_type = 1
        payload = {"user": "aryan"}

        result = pack_message(msg_type, payload)

        self.assertIsInstance(result, bytes)
        self.assertIn(b'{"user": "aryan"}', result)

    def test_pack_message_with_bytes(self):
        msg_type = 2
        payload = b"raw binary data"

        result = pack_message(msg_type, payload)

        self.assertIsInstance(result, bytes)
        self.assertTrue(result.endswith(payload))

    def test_unpack_header(self):
        expected_msg_type = 5
        payload = {"status": "ok"}

        packed_data = pack_message(expected_msg_type, payload)

        header_bytes = packed_data[:HEADER_SIZE]

        msg_type, payload_length = unpack_header(header_bytes)

        self.assertEqual(msg_type, expected_msg_type)
        self.assertEqual(payload_length, len(b'{"status": "ok"}'))

    def test_invalid_payload_raises(self):
        with self.assertRaises(TypeError):
            pack_message(1, 12345)