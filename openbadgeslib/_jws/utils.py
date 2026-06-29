import base64
import json

from typing import Any, Union


def base64url_decode(data: bytes) -> bytes:
    # JWS/JWT base64url strips the '=' padding; restore it before decoding.
    # The required pad count is (-len) % 4, which is 0 when the length is
    # already a multiple of 4 (the old `4 - len % 4` wrongly added 4 there).
    data += b'=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


def base64url_encode(input: bytes) -> bytes:
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def to_json(a: Any) -> bytes:
    return json.dumps(a).encode('utf-8')


def from_json(a: Union[str, bytes]) -> Any:
    if isinstance(a, (bytes, bytearray)):
        a = a.decode('utf-8')
    return json.loads(a)


def to_base64(a: bytes) -> bytes: return base64url_encode(a)
def from_base64(a: bytes) -> bytes: return base64url_decode(a)
def encode(a: Any) -> bytes: return to_base64(to_json(a))
def decode(a: bytes) -> Any: return from_json(from_base64(a))
