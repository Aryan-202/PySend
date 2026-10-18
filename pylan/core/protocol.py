import json 
import struct

HEADER_FORMAT = "!BI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def pack_message(msg_type: int, payload: dict | bytes) -> bytes:
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
    msg_type, payload_length = struct.unpack(HEADER_FORMAT, header_bytes)
    return msg_type, payload_length