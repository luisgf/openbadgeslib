"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es

        All rights reserved.

        This library is free software; you can redistribute it and/or
        modify it under the terms of the GNU Lesser General Public
        License as published by the Free Software Foundation; either
        version 3.0 of the License, or (at your option) any later version.

        This library is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
        Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public
        License along with this library.
"""

# Every secret the OID4VCI flow mints, generated in one place.
#
# RFC 6749 §10.10 sets the bar: a generated credential must be no easier to
# guess than 2^-128, and preferably 2^-160. OID4VCI 1.0's pre-authorized code
# security considerations add that the code must be short-lived and that the
# tx_code must travel out of band with the issuer limiting attempts.
#
# Centralising this is not tidiness. Entropy bugs are invisible in tests and
# fatal in production — the classic being `randbelow(900000) + 100000` for a
# 6-digit PIN, which looks like it avoids awkward leading zeros and actually
# discards a tenth of the space and biases the rest. One generator means one
# place to audit and one place to stub in tests.

import hashlib
import hmac
import secrets

#: Bytes of entropy behind a pre-authorized code or an access token. RFC 6749
#: demands 16; 32 costs nothing and leaves margin. 43 base64url characters,
#: which still fits comfortably in an offer QR code.
_SECRET_BYTES = 32

#: Bytes behind an internal identifier (grant id, transaction id). These are
#: not capabilities — holding one grants nothing without the matching token —
#: so 128 bits is ample.
_ID_BYTES = 16

#: scrypt work factor for a tx_code digest. A 6-digit PIN has ~20 bits of
#: entropy, so a plain SHA-256 store would surrender every live PIN to anyone
#: who reads the database: 10^6 preimages fall in microseconds. At n=2^14 each
#: guess costs ~50 ms and 16 MiB, which is bounded here by the attempt counter
#: and by the fact that guessing needs a 256-bit pre-authorized code first.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16

#: The digest algorithm identifier stored alongside a tx_code hash, so a future
#: change of KDF can be rolled out without invalidating live grants.
TX_CODE_KDF = 'scrypt-n16384-r8-p1'


def new_secret() -> str:
    """Mint a bearer secret: a pre-authorized code or an access token."""
    return secrets.token_urlsafe(_SECRET_BYTES)


def new_id() -> str:
    """Mint an internal identifier (grant id, transaction id)."""
    return secrets.token_urlsafe(_ID_BYTES)


def secret_id(value: str) -> str:
    """The lookup key for a bearer secret: its SHA-256, hex.

    Secrets are never stored in the clear. The store indexes this instead, so
    reading the database yields no usable code or token, and the B-tree
    comparisons happen over digests rather than over the secret itself.
    """
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def new_tx_code(length: int, input_mode: str = 'numeric') -> str:
    """Mint an out-of-band transaction code of *length* characters.

    ``numeric`` produces digits with leading zeros preserved — every value in
    ``0`` to ``10**length - 1`` is equally likely, which is exactly what
    trimming leading zeros would break. ``text`` uses a Crockford-style base32
    alphabet with the characters people misread (I, L, O, U) removed, since a
    tx_code is transcribed by hand from one channel to another.

    A short numeric code is weak on purpose: it has to be readable over the
    phone. Its security comes from the attempt counter and the offer TTL, not
    from its entropy — see :func:`verify_tx_code`.
    """
    if length < 1:
        raise ValueError('tx_code length must be at least 1')
    if input_mode == 'numeric':
        return str(secrets.randbelow(10 ** length)).zfill(length)
    if input_mode == 'text':
        alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    raise ValueError('unknown tx_code input mode %r' % (input_mode,))


def hash_tx_code(tx_code: str) -> tuple[str, bytes, bytes]:
    """Derive a storable digest of *tx_code*: ``(kdf, salt, digest)``."""
    salt = secrets.token_bytes(_SALT_BYTES)
    return TX_CODE_KDF, salt, _scrypt(tx_code, salt)


def verify_tx_code(tx_code: str, kdf: str, salt: bytes, digest: bytes) -> bool:
    """Check *tx_code* against a stored digest, in constant time.

    An unknown *kdf* returns False rather than raising: a store written by a
    newer version must fail closed, not crash the token endpoint.
    """
    if kdf != TX_CODE_KDF:
        return False
    return hmac.compare_digest(_scrypt(tx_code, salt), digest)


def dummy_tx_verification() -> None:
    """Burn the same work a real tx_code check costs, and discard it.

    Called on the path where no grant matched. Without it the token endpoint
    answers an unknown pre-authorized code in microseconds and a known one in
    ~50 ms, which turns response latency into an oracle for enumerating live
    codes — the attacker learns which codes exist without ever guessing a PIN.
    """
    _scrypt('0' * 6, b'\x00' * _SALT_BYTES)


def _scrypt(value: str, salt: bytes) -> bytes:
    return hashlib.scrypt(value.encode('utf-8'), salt=salt, n=_SCRYPT_N,
                          r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
