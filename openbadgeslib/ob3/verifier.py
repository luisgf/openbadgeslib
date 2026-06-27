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

import jwt
import jwt.exceptions

from .credential import OpenBadgeCredential
from ..errors import ErrorParsingFile, UnknownKeyType, LibOpenBadgesException
from ..keys import KeyType, detect_key_type, key_to_pem
from ..util import normalize_recipient_id
from .. import baking

# Signature algorithms accepted per key family. The signer only ever emits the
# 256-bit variant, but we accept the whole family for interop while still
# binding the algorithm to the key type (an RSA key can never validate an ES*
# token and vice-versa).
_ALGORITHMS_BY_KEY_TYPE = {
    KeyType.RSA: ['RS256', 'RS384', 'RS512'],
    KeyType.ECC: ['ES256', 'ES384', 'ES512'],
}


class OB3VerificationError(LibOpenBadgesException):
    """Raised when a JWT-VC credential fails verification.

    Inherits from LibOpenBadgesException so callers can catch every library
    error (OB2 and OB3) with a single ``except``.
    """


class OB3Verifier:
    """Verifies OpenBadges 3.0 JWT-VC credentials.

    Args:
        pubkey_pem: PEM-encoded public key (bytes, str, or a pycryptodome /
                    ecdsa key object).
    """

    def __init__(self, pubkey_pem) -> None:
        self.pubkey_pem = key_to_pem(pubkey_pem)
        # Pin the accepted algorithms to this key's type so the token header
        # cannot dictate the algorithm (alg:none / HMAC downgrade / cross-type
        # confusion are all rejected up front rather than trusted).
        try:
            key_type = detect_key_type(self.pubkey_pem)
        except UnknownKeyType as exc:
            raise OB3VerificationError(
                "Unsupported verification key type: %s" % exc) from exc
        self._allowed_algorithms = _ALGORITHMS_BY_KEY_TYPE[key_type]

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

        alg = header.get('alg')
        if alg not in self._allowed_algorithms:
            raise OB3VerificationError(
                "Algorithm %r in token header is not allowed for this key "
                "(expected one of %s)" % (alg, self._allowed_algorithms)
            )

        try:
            payload = jwt.decode(
                token,
                self.pubkey_pem,
                algorithms=self._allowed_algorithms,
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

        # Cross-check the JWT registered claims against the vc body (when the
        # token carries them) so a verified signature cannot pair an iss/sub
        # with a mismatched credential issuer/subject.
        vc = payload["vc"]
        iss = payload.get("iss")
        if iss is not None and iss != (vc.get("issuer") or {}).get("id"):
            raise OB3VerificationError(
                "JWT 'iss' does not match the credential issuer")
        sub = payload.get("sub")
        if sub is not None and sub != (vc.get("credentialSubject") or {}).get("id"):
            raise OB3VerificationError(
                "JWT 'sub' does not match the credentialSubject id")

        if expected_recipient is not None:
            expected = normalize_recipient_id(expected_recipient)
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
        try:
            token = baking.extract_svg(svg_bytes)
        except Exception as exc:
            raise ErrorParsingFile(f"Could not parse SVG: {exc}") from exc
        if token is None:
            raise OB3VerificationError("No openbadges:assertion element found in SVG")
        return token

    @staticmethod
    def extract_token_from_png(png_bytes: bytes) -> str:
        """Extract the JWT-VC token embedded in a baked PNG badge.

        Parses the iTXt chunk structure properly (keyword, compression flag and
        method, language tag, translated keyword, then text) rather than relying
        on a fixed byte offset, so tokens baked by other conformant tools — with
        a non-empty language tag or compressed text — are also recovered.
        """
        try:
            token = baking.extract_png(png_bytes)
        except baking.DecompressionLimitExceeded as exc:
            raise OB3VerificationError(str(exc)) from exc
        if token is None:
            raise OB3VerificationError("No openbadges iTXt chunk found in PNG")
        return token
