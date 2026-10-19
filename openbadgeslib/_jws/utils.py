import base64
import binascii
import json
import re

from typing import Any, Union

from .._safejson import loads as _loads_untrusted

_B64URL_ALPHABET = re.compile(rb'[A-Za-z0-9_-]*')


def base64url_decode(data: Union[str, bytes]) -> bytes:
    # Strict, canonical RFC 4648 §5: the URL-safe alphabet, then either no
    # padding (JWS/JWT strip it) or exactly the canonical (-len) % 4 '='
    # characters, with zero unused trailing bits (§3.5). urlsafe_b64decode()
    # silently drops other characters, takes '+'/'/' as aliases of '-'/'_'
    # (Python 3.15 warns that this will change), and ignores extra '=' and
    # the trailing bits, so the same bytes had many accepted encodings. Every
    # caller feeds it untrusted input, so anything else raises binascii.Error
    # (a ValueError); a non-str/bytes argument raises TypeError.
    if isinstance(data, str):
        if not data.isascii():
            raise binascii.Error('base64url data must be ASCII')
        data = data.encode('ascii')
    elif isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    elif not isinstance(data, bytes):
        raise TypeError('base64url data must be str or bytes, not %s'
                        % type(data).__name__)
    stripped = data.rstrip(b'=')
    pad = -len(stripped) % 4
    if (not _B64URL_ALPHABET.fullmatch(stripped) or len(stripped) % 4 == 1
            or len(data) - len(stripped) not in (0, pad)):
        raise binascii.Error('invalid base64url data')
    raw = base64.urlsafe_b64decode(stripped + b'=' * pad)
    if base64.urlsafe_b64encode(raw).rstrip(b'=') != stripped:
        raise binascii.Error('non-canonical base64url data (non-zero pad bits)')
    return raw


def base64url_encode(input: bytes) -> bytes:
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def to_json(a: Any) -> bytes:
    return json.dumps(a).encode('utf-8')


def from_json(a: Union[str, bytes]) -> Any:
    # Every caller parses a token segment or a document a remote host served.
    # A ValueError for what json.loads takes but nothing downstream survives:
    # nesting past the bound (a RecursionError otherwise), a lone surrogate,
    # a number that is not finite (see _safejson).
    return _loads_untrusted(a)


def to_base64(a: bytes) -> bytes: return base64url_encode(a)
def from_base64(a: bytes) -> bytes: return base64url_decode(a)
def encode(a: Any) -> bytes: return to_base64(to_json(a))
def decode(a: bytes) -> Any: return from_json(from_base64(a))
