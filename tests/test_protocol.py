"""Unit tests for the protocol framing utility functions.

This module validates that message framing correctly serializes both structured
dictionary payloads and raw byte streams with matching binary headers, throws
appropriate errors on bad inputs, and unpacks structural metadata reliably.
"""

import unittest
from pylan.core.protocol import pack_message, unpack_header, HEADER_SIZE


class TestProtocols(unittest.TestCase):
    """Test suite targeting the message packing and header unpacking
    functionality.
    """

    def test_pack_message_with_dict(self):
        """Verify that a dictionary payload is correctly JSON-serialized.

        Ensures that passing a valid Python dictionary yields a bytes stream
        containing the encoded JSON string alongside its prepended header.
        """
        msg_type = 1
        payload = {"user": "aryan"}

        result = pack_message(msg_type, payload)

        self.assertIsInstance(result, bytes)
        self.assertIn(b'{"user": "aryan"}', result)

    def test_pack_message_with_bytes(self):
        """Verify that a raw bytes payload is cleanly appended without
        modification.

        Ensures that byte streams bypass serialization logic and are appended
        verbatim onto the end of the packed header array.
        """
        msg_type = 2
        payload = b"raw binary data"

        result = pack_message(msg_type, payload)

        self.assertIsInstance(result, bytes)
        self.assertTrue(result.endswith(payload))

    def test_unpack_header(self):
        """Verify structural symmetry between packed headers and unpacked
        metadata.

        Extracts the fixed-size binary slice from a packed message stream and
        confirms that unpacker extraction yields the correct application
        message identifier code and identical downstream byte length figures.
        """
        expected_msg_type = 5
        payload = {"status": "ok"}

        packed_data = pack_message(expected_msg_type, payload)

        header_bytes = packed_data[:HEADER_SIZE]

        msg_type, payload_length = unpack_header(header_bytes)

        self.assertEqual(msg_type, expected_msg_type)
        self.assertEqual(payload_length, len(b'{"status": "ok"}'))

    def test_invalid_payload_raises(self):
        """Verify that unsupported payload data types trigger a TypeError
        exception.

        Checks that input types like integers or floats fail fast inside the
        packer, preventing malformed messages from ever hitting the network
        interface.
        """
        with self.assertRaises(TypeError):
            pack_message(1, 12345)
