import base64
import json


def base64url_decode(data):
    # JWS/JWT base64url strips the '=' padding; restore it before decoding.
    # The required pad count is (-len) % 4, which is 0 when the length is
    # already a multiple of 4 (the old `4 - len % 4` wrongly added 4 there).
    data += b'=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def to_json(a):
    return json.dumps(a).encode('utf-8')


def from_json(a):
    if isinstance(a, (bytes, bytearray)):
        a = a.decode('utf-8')
    return json.loads(a)


def to_base64(a): return base64url_encode(a)
def from_base64(a): return base64url_decode(a)
def encode(a): return to_base64(to_json(a))
def decode(a): return from_json(from_base64(a))
