"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014-2026, Jesús Cea Avión, jcea@jcea.es

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

from xml.dom.minidom import parseString

import jwt
import jwt.exceptions
from png import Reader

from .credential import OpenBadgeCredential, _SUPPORTED_ALGORITHMS
from ..errors import ErrorParsingFile


class OB3VerificationError(Exception):
    """Raised when a JWT-VC credential fails verification."""


def _to_pem(key):
    """Convert a pycryptodome or ecdsa key object to PEM bytes; pass through bytes/str."""
    try:
        from Crypto.PublicKey import RSA as _RSA
        if isinstance(key, _RSA.RsaKey):
            return key.export_key('PEM')
    except ImportError:
        pass
    try:
        from ecdsa import VerifyingKey as _VK
        if isinstance(key, _VK):
            return key.to_pem()
    except ImportError:
        pass
    if isinstance(key, (bytes, str)):
        return key
    raise TypeError(f"Unsupported key type: {type(key)}")


class OB3Verifier:
    """Verifies OpenBadges 3.0 JWT-VC credentials.

    Args:
        pubkey_pem: PEM-encoded public key (bytes, str, or a pycryptodome /
                    ecdsa key object).
    """

    def __init__(self, pubkey_pem) -> None:
        self.pubkey_pem = _to_pem(pubkey_pem)

    # ── verification ───────────────────────────────────────────────────────────

    def verify(self, token: str) -> OpenBadgeCredential:
        """Verify a JWT-VC token.

        Returns the decoded :class:`OpenBadgeCredential` on success.
        Raises :class:`OB3VerificationError` for any failure (invalid
        signature, expired token, malformed payload, …).
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError as exc:
            raise OB3VerificationError(f"Invalid JWT: {exc}") from exc

        alg = header.get('alg', 'RS256')
        if alg not in _SUPPORTED_ALGORITHMS:
            raise OB3VerificationError(
                f"Unsupported algorithm in token header: {alg!r}"
            )

        try:
            payload = jwt.decode(
                token,
                self.pubkey_pem,
                algorithms=[alg],
                options={"verify_aud": False},
            )
        except jwt.exceptions.ExpiredSignatureError as exc:
            raise OB3VerificationError("Credential has expired") from exc
        except jwt.exceptions.InvalidSignatureError as exc:
            raise OB3VerificationError("Invalid signature") from exc
        except jwt.exceptions.InvalidKeyError as exc:
            raise OB3VerificationError(f"Invalid key for algorithm {alg!r}: {exc}") from exc
        except jwt.exceptions.InvalidTokenError as exc:
            raise OB3VerificationError(str(exc)) from exc

        if "vc" not in payload:
            raise OB3VerificationError(
                "JWT payload does not contain a 'vc' claim — "
                "this may be an OB 2.0 JWS token, not an OB 3.0 JWT-VC"
            )

        try:
            return OpenBadgeCredential.from_jwt_payload(payload)
        except (KeyError, ValueError, TypeError) as exc:
            raise OB3VerificationError(f"Malformed credential payload: {exc}") from exc

    # ── token extraction ───────────────────────────────────────────────────────

    @staticmethod
    def extract_token_from_svg(svg_bytes: bytes) -> str:
        """Extract the JWT-VC token embedded in a baked SVG badge."""
        try:
            doc = parseString(svg_bytes)
            nodes = doc.getElementsByTagName('openbadges:assertion')
            if not nodes:
                raise OB3VerificationError("No openbadges:assertion element found in SVG")
            token = nodes[0].attributes['verify'].nodeValue
            doc.unlink()
            return token
        except OB3VerificationError:
            raise
        except Exception as exc:
            raise ErrorParsingFile(f"Could not parse SVG: {exc}") from exc

    @staticmethod
    def extract_token_from_png(png_bytes: bytes) -> str:
        """Extract the JWT-VC token embedded in a baked PNG badge."""
        for tag, data in Reader(bytes=png_bytes).chunks():
            tag_str = tag.decode('ascii') if isinstance(tag, bytes) else tag
            if tag_str == 'iTXt' and data.startswith(b'openbadges'):
                # Structure: 'openbadges' (10) + 5 NUL bytes + token
                return data[15:].decode('utf-8')
        raise OB3VerificationError("No openbadges iTXt chunk found in PNG")
