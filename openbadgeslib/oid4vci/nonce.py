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

# The c_nonce a wallet must echo inside its key proof.
#
# WHY MINTING IS STATELESS. OID4VCI's nonce endpoint is unauthenticated by
# design — a wallet needs a nonce before it has anything to authenticate with.
# If issuing one wrote a row, anyone on the internet could drive writes into
# the issuer's database as fast as they could send requests, and the natural
# defence (rate limiting) is exactly the thing this library leaves to the
# integrator. So a nonce carries its own expiry and a MAC over itself:
#
#     c_nonce = b64url( exp_be8 || rand16 || HMAC-SHA256(K, exp||rand)[:16] )
#
# Minting touches nothing. Only nonces that are actually SPENT occupy a row,
# and spending happens behind a valid access token. An attacker with no token
# cannot make the store grow at all.
#
# WHY SPENDING IS STILL STATEFUL. A MAC proves the nonce is one the issuer
# minted and has not expired. It cannot prove it has not been used before —
# that is a fact about history, and history is state. The burn list holds
# exactly that one bit, for exactly as long as the nonce could still be
# replayed, and nothing else.

import base64
import binascii
import hashlib
import hmac
import struct
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

#: exp (8 bytes, big endian) + 16 random + 16-byte truncated HMAC tag.
_EXP_BYTES = 8
_RAND_BYTES = 16
_TAG_BYTES = 16
_NONCE_BYTES = _EXP_BYTES + _RAND_BYTES + _TAG_BYTES

#: Truncating SHA-256 to 128 bits keeps the nonce short enough to be an opaque
#: string in a JSON body while leaving forgery at 2^-128.
_MAC_BODY_BYTES = _EXP_BYTES + _RAND_BYTES


class NonceIssuer:
    """Mints and spends the ``c_nonce`` values wallet key proofs must carry.

    Construct one per issuer and share it: :meth:`consume` is the
    ``check_nonce`` callable openvc requires, and its single-use guarantee is
    only as strong as the store behind it.
    """

    def __init__(self, store: Any, *, ttl_s: int = 120) -> None:
        if ttl_s < 1:
            raise ValueError('nonce ttl must be at least 1 second')
        self._store = store
        self._ttl_s = ttl_s
        self._secret = store.nonce_secret()

    @property
    def ttl_s(self) -> int:
        return self._ttl_s

    def mint(self, *, now: Optional[datetime] = None) -> str:
        """A fresh single-use nonce. Writes nothing."""
        moment = now or datetime.now(tz=timezone.utc)
        expires = moment + timedelta(seconds=self._ttl_s)
        body = struct.pack('>Q', int(expires.timestamp())) + \
            _random_bytes(_RAND_BYTES)
        return base64.urlsafe_b64encode(body + self._tag(body)).decode(
            'ascii').rstrip('=')

    def consume(self, nonce: str) -> bool:
        """Spend *nonce*: True if and only if THIS call spent it.

        The signature openvc's ``ConsumeNonce`` expects, so a
        ``NonceIssuer.consume`` bound method is passed straight to
        ``verify_credential_request_proofs(check_nonce=...)``.

        Every rejection is a plain False — malformed, forged, expired and
        already-spent alike — because the wallet's remedy is the same in all
        four cases: fetch a new nonce and retry. Distinguishing them would only
        tell an attacker which of their guesses was structurally valid.
        """
        raw = _decode(nonce)
        if raw is None or len(raw) != _NONCE_BYTES:
            return False
        body, tag = raw[:_MAC_BODY_BYTES], raw[_MAC_BODY_BYTES:]
        if not hmac.compare_digest(tag, self._tag(body)):
            return False
        expires_at = datetime.fromtimestamp(struct.unpack('>Q', body[:8])[0],
                                            tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        # Expiry is checked BEFORE the burn, so an expired nonce never takes a
        # row — and so the GC, which only removes expired rows, can never race
        # with a live one.
        if expires_at <= now:
            return False
        nonce_id = hashlib.sha256(raw).hexdigest()
        return bool(self._store.burn_nonce(nonce_id, expires_at=expires_at,
                                           now=now))

    def _tag(self, body: bytes) -> bytes:
        return hmac.new(self._secret, body, hashlib.sha256).digest()[:_TAG_BYTES]


def _decode(nonce: str) -> Optional[bytes]:
    if not isinstance(nonce, str) or not nonce:
        return None
    try:
        return base64.urlsafe_b64decode(nonce + '=' * (-len(nonce) % 4))
    except (binascii.Error, ValueError):
        return None


def _random_bytes(count: int) -> bytes:
    import secrets
    return secrets.token_bytes(count)


__all__ = ['NonceIssuer']
