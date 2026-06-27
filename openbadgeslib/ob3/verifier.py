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

    def verify(self, token: str, expected_recipient: str = None) -> OpenBadgeCredential:
        """Verify a JWT-VC token.

        Returns the decoded :class:`OpenBadgeCredential` on success.
        Raises :class:`OB3VerificationError` for any failure (invalid
        signature, expired token, malformed payload, …).

        Security note: by default this validates only the cryptographic
        signature, expiry and structure — it does NOT bind the credential to a
        particular recipient. Pass ``expected_recipient`` (an email, a
        ``mailto:`` URI, or a DID) to additionally require that
        ``credentialSubject.id`` matches; otherwise the caller MUST compare
        ``credential.recipient_id`` itself.
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

        vc_types = payload["vc"].get("type", [])
        if isinstance(vc_types, str):
            vc_types = [vc_types]
        if "OpenBadgeCredential" not in vc_types:
            raise OB3VerificationError(
                "JWT 'vc' claim is not an OpenBadgeCredential (type=%r)" % (vc_types,)
            )

        try:
            credential = OpenBadgeCredential.from_jwt_payload(payload)
        except (KeyError, ValueError, TypeError) as exc:
            raise OB3VerificationError(f"Malformed credential payload: {exc}") from exc

        if expected_recipient is not None:
            expected = expected_recipient
            if not expected.startswith('mailto:') and '@' in expected:
                expected = 'mailto:' + expected
            if credential.recipient_id != expected:
                raise OB3VerificationError(
                    "Recipient mismatch: credential is for %s, expected %s"
                    % (credential.recipient_id, expected)
                )

        return credential

    # ── token extraction ───────────────────────────────────────────────────────

    @staticmethod
    def extract_token_from_svg(svg_bytes: bytes) -> str:
        """Extract the JWT-VC token embedded in a baked SVG badge."""
        doc = None
        try:
            doc = parseString(svg_bytes)
            nodes = doc.getElementsByTagName('openbadges:assertion')
            if not nodes:
                raise OB3VerificationError("No openbadges:assertion element found in SVG")
            return nodes[0].attributes['verify'].nodeValue
        except OB3VerificationError:
            raise
        except Exception as exc:
            raise ErrorParsingFile(f"Could not parse SVG: {exc}") from exc
        finally:
            if doc is not None:
                doc.unlink()

    @staticmethod
    def extract_token_from_png(png_bytes: bytes) -> str:
        """Extract the JWT-VC token embedded in a baked PNG badge.

        Parses the iTXt chunk structure properly (keyword, compression flag and
        method, language tag, translated keyword, then text) rather than relying
        on a fixed byte offset, so tokens baked by other conformant tools — with
        a non-empty language tag or compressed text — are also recovered.
        """
        for tag, data in Reader(bytes=png_bytes).chunks():
            tag_str = tag.decode('ascii') if isinstance(tag, bytes) else tag
            if tag_str != 'iTXt':
                continue

            # iTXt layout: keyword \0 comp_flag comp_method lang \0 trans \0 text
            keyword, sep, rest = data.partition(b'\x00')
            if sep != b'\x00' or keyword != b'openbadges' or len(rest) < 2:
                continue
            compression_flag = rest[0]
            _, sep_lang, rest = rest[2:].partition(b'\x00')   # drop language tag
            _, sep_trans, text = rest.partition(b'\x00')      # drop translated keyword
            if sep_lang != b'\x00' or sep_trans != b'\x00':
                continue
            if compression_flag:
                import zlib
                text = zlib.decompress(text)
            return text.decode('utf-8')

        raise OB3VerificationError("No openbadges iTXt chunk found in PNG")
