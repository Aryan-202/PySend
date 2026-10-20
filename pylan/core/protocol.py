"""Module for framing network messages with a binary header and variable
payload.

This module provides utility functions to pack structured message data (either
JSON-serializable dictionaries or raw bytes) along with a fixed-size binary
header, and to unpack the header back into its component metadata values.
"""

import json
import struct

# "!BI" translates to:
# ! = Network byte order (Big-endian)
# B = 1-byte unsigned char (Message Type)
# I = 4-byte unsigned int (Payload Length)
HEADER_FORMAT = "!BI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

MSG_TYPE_TRANSFER_REQUEST = 20
MSG_TYPE_TRANSFER_ACCEPT = 21
MSG_TYPE_TRANSFER_REJECT = 22
MSG_TYPE_TRANSFER_CHUNK = 23
MSG_TYPE_TRANSFER_COMPLETE = 24


def pack_message(msg_type: int, payload: dict | bytes) -> bytes:
    """Serializes a payload and prepends a fixed-size binary header.

    Args:
        msg_type: An integer representing the application-defined message type.
        payload: The message body, which can be either a Python dictionary
            (will be converted to JSON bytes) or raw bytes.

    Returns:
        A bytes object containing the packed header immediately followed by
        the serialized payload bytes.

    Raises:
        TypeError: If the payload is neither a dictionary nor a bytes object.
    """
    if isinstance(payload, dict):
        payload_bytes = json.dumps(payload).encode("utf-8")
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        raise TypeError(f"Unsupported payload type: {type(payload)}")

    payload_length = len(payload_bytes)

    header = struct.pack(HEADER_FORMAT, msg_type, payload_length)

    return header + payload_bytes


def unpack_header(header_bytes: bytes) -> tuple[int, int]:
    """Unpacks a raw byte stream into message metadata values.

    Args:
        header_bytes: A bytes object of exact length `HEADER_SIZE` (5 bytes).

    Returns:
        A tuple containing:
            - msg_type (int): The application-defined message identifier.
            - payload_length (int): The length of the upcoming payload in
            bytes.

    Raises:
        struct.error: If `header_bytes` is not exactly equal to `HEADER_SIZE`.
    """
    msg_type, payload_length = struct.unpack(HEADER_FORMAT, header_bytes)
    return msg_type, payload_length
