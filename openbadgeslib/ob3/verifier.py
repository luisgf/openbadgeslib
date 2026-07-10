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

from datetime import datetime, timezone
from typing import Any, Optional, Union

import jwt
import jwt.exceptions

from .credential import OpenBadgeCredential, _parse_iso
from ..errors import ErrorParsingFile, UnknownKeyType, LibOpenBadgesException
from ..keys import KeyType, detect_key_type, key_to_pem
from ..util import (CLOCK_SKEW_LEEWAY, normalize_recipient_id,
                    recipient_ids_match)
from .. import baking

# Signature algorithms accepted per key family. The signer only ever emits the
# 256-bit variant, but we accept the whole family for interop while still
# binding the algorithm to the key type (an RSA key can never validate an ES*
# token and vice-versa).
_ALGORITHMS_BY_KEY_TYPE = {
    KeyType.RSA: ['RS256', 'RS384', 'RS512'],
    KeyType.ECC: ['ES256', 'ES384', 'ES512'],
    KeyType.ED25519: ['EdDSA'],
}


def _claim_object_id(value: Any) -> Any:
    """Return the ``id`` of a vc sub-object that may be a single object or a
    (non-empty) array, mirroring OpenBadgeCredential.from_jwt_payload.

    Returns None for any other shape, so the iss/sub cross-checks below simply
    fail the comparison rather than raising a raw AttributeError on, e.g.,
    ``[ {…} ].get("id")``.
    """
    if isinstance(value, str):
        return value                     # issuer/subject given as a bare IRI
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, dict):
        return value.get("id")
    return None


class OB3VerificationError(LibOpenBadgesException):
    """Raised when a JWT-VC credential fails verification.

    Inherits from LibOpenBadgesException so callers can catch every library
    error (OB2 and OB3) with a single ``except``.
    """


def _check_vc_types(vc: dict[str, Any]) -> None:
    """Require the credential ``type`` array to declare an OB3 credential.

    OpenBadgeCredential and AchievementCredential are aliases in the OB v3
    context; accept either. VerifiableCredential must also be present. Shared
    by the JWT verifier below and the Data Integrity verifier (ob3.ldp).
    """
    vc_types = vc.get("type", [])
    if isinstance(vc_types, str):
        vc_types = [vc_types]
    elif not isinstance(vc_types, list):
        vc_types = []
    if not ({"OpenBadgeCredential", "AchievementCredential"} & set(vc_types)):
        raise OB3VerificationError(
            "credential is not an OpenBadgeCredential/AchievementCredential "
            "(type=%r) — this may be an OB 2.0 JWS token, not an OB 3.0 credential"
            % (vc_types,)
        )
    if "VerifiableCredential" not in vc_types:
        raise OB3VerificationError(
            "credential type must include 'VerifiableCredential' (type=%r)"
            % (vc_types,)
        )


def _check_validity_window(credential: OpenBadgeCredential) -> None:
    """Validate vc-level validFrom/validUntil against wall-clock time.

    Shared by the JWT verifier and the Data Integrity verifier (ob3.ldp), so
    both enforce the same window semantics on the credential body itself.
    """
    now = datetime.now(timezone.utc)
    if credential.expiration_date is not None \
            and credential.expiration_date < now - CLOCK_SKEW_LEEWAY:
        raise OB3VerificationError(
            "Credential has expired (validUntil %s)" % credential.expiration_date.isoformat())
    if credential.issuance_date is not None \
            and credential.issuance_date > now + CLOCK_SKEW_LEEWAY:
        raise OB3VerificationError(
            "Credential is not yet valid (validFrom %s)" % credential.issuance_date.isoformat())


def _check_recipient(credential: OpenBadgeCredential,
                     expected_recipient: Optional[str]) -> None:
    """Opt-in recipient binding, shared by both OB3 verifiers. No-op when the
    caller passes no expected recipient (the caller must then compare
    credential.recipient_id itself)."""
    if expected_recipient is None:
        return
    expected = normalize_recipient_id(expected_recipient)
    if not recipient_ids_match(credential.recipient_id, expected):
        raise OB3VerificationError(
            "Recipient mismatch: credential is for %s, expected %s"
            % (credential.recipient_id, expected)
        )


class OB3Verifier:
    """Verifies OpenBadges 3.0 JWT-VC credentials.

    Args:
        pubkey_pem: PEM-encoded public key (bytes, str, or a pycryptodome /
                    ecdsa key object).
    """

    def __init__(self, pubkey_pem: Any, issuer_did: Optional[str] = None) -> None:
        self.pubkey_pem = key_to_pem(pubkey_pem)
        # When the key was obtained by resolving a DID, remember that DID so
        # verify() can bind the credential's stated issuer to it (see verify()).
        self._anchored_did = issuer_did
        # The full did:web document, when anchored to one: for_issuer_did stores
        # it so verify() can select the exact key the token's 'kid' names (a
        # multi-key / rotating issuer). None for a fixed key or a did:key, where
        # pubkey_pem below is the single verification key.
        self._did_document: Optional[dict[str, Any]] = None
        # Pin the accepted algorithms to this key's type so the token header
        # cannot dictate the algorithm (alg:none / HMAC downgrade / cross-type
        # confusion are all rejected up front rather than trusted).
        self._allowed_algorithms = self._pin_algorithms(self.pubkey_pem)

    @staticmethod
    def _pin_algorithms(pubkey_pem: Union[str, bytes]) -> list[str]:
        """Return the signature algorithms this key type may validate, so a
        token header can never dictate the algorithm."""
        try:
            key_type = detect_key_type(pubkey_pem)
        except UnknownKeyType as exc:
            raise OB3VerificationError(
                "Unsupported verification key type: %s" % exc) from exc
        return _ALGORITHMS_BY_KEY_TYPE[key_type]

    @classmethod
    def for_issuer_did(cls, did: str, download: Any = None) -> "OB3Verifier":
        """Construct a verifier by resolving an issuer DID to its public key.

        Supports did:key (offline) and did:web (one HTTPS fetch). Raises
        OB3VerificationError for an unsupported method or a resolution failure.
        Imported lazily so DID resolution (and its network path) is only pulled
        in when a caller actually anchors trust on a DID.

        The resulting verifier is anchored to ``did``: verify() additionally
        requires the credential's own issuer id to equal ``did``, so a token
        signed by the resolved key but *claiming* a different issuer is
        rejected. For did:key this is implied by the key being the identifier;
        for did:web (not self-certifying) it is the check that stops an issuer
        from being spoofed once its document has been fetched.

        A did:web issuer may publish several verification keys (rotation, or a
        key per badge). Its document is fetched once here and remembered, so
        verify() can select the exact key the JWT ``kid`` header names instead
        of assuming the first one; a token with no kid still uses the first
        method, the prior behaviour.
        """
        from .did import fetch_did_web_document, pem_for_kid, resolve_did
        if did.startswith('did:web:'):
            document = fetch_did_web_document(did, download)
            verifier = cls(pubkey_pem=pem_for_kid(document, did),
                           issuer_did=did)
            verifier._did_document = document
            return verifier
        return cls(pubkey_pem=resolve_did(did, download=download), issuer_did=did)

    # ── verification ───────────────────────────────────────────────────────────

    def verify(self, token: str,
               expected_recipient: Optional[str] = None,
               check_status: bool = False, *,
               verify_status_list: bool = True) -> OpenBadgeCredential:
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

        Issuer binding: when this verifier was built via ``for_issuer_did``, the
        credential's issuer id is additionally required to equal the anchored
        DID, so a token signed by the resolved key but claiming a different
        issuer is rejected. A verifier built directly from a public key performs
        no issuer binding — the caller vouches for the key's owner.

        Pass ``check_status=True`` to also check the credential's
        ``credentialStatus`` (revocation) — this performs an HTTPS fetch of the
        referenced status list and fails closed if the credential is revoked or
        its status cannot be determined. It is off by default because
        verification is otherwise offline.

        When status is checked, the status list's own JWT-VC signature is
        verified too (bound to this credential's issuer), so a compromised
        status host cannot silently un-revoke a badge — ``openbadges-publish``
        signs the list with the same key that signed the credential, which this
        verifier reuses. Set ``verify_status_list=False`` only to interoperate
        with an issuer that serves an unsigned status list, accepting that its
        revocation bit is then trusted on the host's word alone.
        """
        payload = self._decode_payload(token)
        credential = self._build_credential(payload)

        # Bind the credential to the DID this verifier was anchored to (if any).
        # for_issuer_did resolves a DID to a key; without this check verify()
        # would accept a token signed by that key even when the credential
        # claims a *different* issuer (a did:web is not self-certifying, so its
        # fetched key is otherwise decoupled from the credential's issuer id).
        if self._anchored_did is not None and credential.issuer.id != self._anchored_did:
            raise OB3VerificationError(
                "Credential issuer %r does not match the DID the verifier was "
                "anchored to (%r)" % (credential.issuer.id, self._anchored_did))

        # The JWT 'exp'/'iat' claims (checked above by PyJWT) are attacker-
        # supplied and can be decoupled from vc.validUntil/validFrom, which is
        # what downstream consumers actually read. Re-validate the vc-level
        # dates against wall-clock time independently, mirroring OB2Verifier's
        # check_expiration().
        _check_validity_window(credential)

        if check_status:
            self.check_status(credential, verify_list=verify_status_list)

        _check_recipient(credential, expected_recipient)

        return credential

    def check_status(self, credential: OpenBadgeCredential,
                     *, verify_list: bool = False) -> None:
        """Check the credential's ``credentialStatus`` (revocation) over the
        network, raising :class:`OB3VerificationError` if it is revoked/
        suspended or if the status cannot be determined (fail-closed). A
        credential carrying no credentialStatus is a no-op. The status list's
        validFrom/validUntil window is always enforced.

        Pass ``verify_list=True`` to also verify each status list credential's
        own JWT-VC proof and bind its issuer to the badge's — this verifier's
        key is reused, since ``openbadges-publish`` signs the list with the same
        badge key that signed the credential.

        Imported lazily so the (network-touching) status module is only pulled
        in when a caller actually opts into status checking.
        """
        from .status import check_credential_status
        check_credential_status(
            credential, verify_list=verify_list,
            list_pubkey_pem=self.pubkey_pem if verify_list else None)

    def _key_for_token(
            self, header: dict[str, Any]) -> tuple[Union[str, bytes], list[str]]:
        """Resolve the (public key PEM, allowed algorithms) to verify this
        token with.

        A verifier built from a fixed key (or a did:key) uses it unchanged. One
        anchored to a did:web issuer selects the verificationMethod the JWT
        ``kid`` header names — supporting multi-key issuers and key rotation —
        and falls back to the first method when the token carries no kid. A kid
        that names a missing method, or one of a different DID, fails closed
        (see did.pem_for_kid). The algorithms are re-pinned to the selected
        key's type so the header still cannot dictate the algorithm.
        """
        if self._did_document is None:
            return self.pubkey_pem, self._allowed_algorithms
        kid = header.get('kid')
        if kid is None:
            return self.pubkey_pem, self._allowed_algorithms
        from .did import pem_for_kid
        assert self._anchored_did is not None   # set whenever _did_document is
        pubkey_pem = pem_for_kid(self._did_document, self._anchored_did, kid)
        return pubkey_pem, self._pin_algorithms(pubkey_pem)

    def _decode_payload(self, token: str) -> dict[str, Any]:
        """Verify the signature (algorithm pinned to the key type) and return
        the decoded JWT payload."""
        # A baked OB3 credential may instead be a JSON document secured with an
        # embedded Data Integrity proof (OB 3.0 Linked Data Proof format).
        # That is a different verification model — point the caller at the
        # right tool instead of failing with a cryptic "invalid JWT".
        if isinstance(token, str) and token.lstrip().startswith('{'):
            raise OB3VerificationError(
                "this looks like a Data Integrity (Linked Data Proof) "
                "credential, not a compact JWT — verify it with "
                "OB3LdpVerifier (requires: pip install openbadgeslib[ldp])")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError as exc:
            raise OB3VerificationError(f"Invalid JWT: {exc}") from exc

        pubkey_pem, allowed_algorithms = self._key_for_token(header)

        alg = header.get('alg')
        if alg not in allowed_algorithms:
            raise OB3VerificationError(
                "Algorithm %r in token header is not allowed for this key "
                "(expected one of %s)" % (alg, allowed_algorithms)
            )

        try:
            return jwt.decode(
                token,
                pubkey_pem,
                algorithms=allowed_algorithms,
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

    @staticmethod
    def _build_credential(payload: dict[str, Any]) -> OpenBadgeCredential:
        """Validate the credential structure and registered claims, returning
        the reconstructed credential.

        OB 3.0 native VC-JWT (§8.2.4.1): the JWT payload IS the credential, so
        it is read directly — there is no ``vc`` claim wrapper.
        """
        if not isinstance(payload, dict):
            raise OB3VerificationError(
                "JWT payload must be a JSON object, got %s" % type(payload).__name__)
        vc = payload   # native: the payload is the credential body

        _check_vc_types(vc)

        try:
            credential = OpenBadgeCredential.from_jwt_payload(payload)
        except (KeyError, ValueError, TypeError) as exc:
            raise OB3VerificationError(f"Malformed credential payload: {exc}") from exc

        # OB3 §8.2.6.1: iss and nbf are REQUIRED registered claims, and iss MUST
        # equal the credential issuer id. sub is required (and must match) when
        # the subject carries an id. Enforcing presence — not only cross-checking
        # when present — stops a token that omits these claims from verifying.
        iss = payload.get("iss")
        if iss is None:
            raise OB3VerificationError("JWT payload is missing the required 'iss' claim")
        if iss != _claim_object_id(vc.get("issuer")):
            raise OB3VerificationError("JWT 'iss' does not match the credential issuer")
        if payload.get("nbf") is None:
            raise OB3VerificationError("JWT payload is missing the required 'nbf' claim")
        sub = payload.get("sub")
        subject_id = _claim_object_id(vc.get("credentialSubject"))
        if subject_id is not None and sub is None:
            raise OB3VerificationError("JWT payload is missing the required 'sub' claim")
        if sub is not None and sub != subject_id:
            raise OB3VerificationError("JWT 'sub' does not match the credentialSubject id")
        # jti is the registered claim bound to the credential id (OB3 §8.2); the
        # signer always emits it. Require it whenever the body carries an id, and
        # reject any mismatch, so a token cannot claim one id and carry another.
        jti = payload.get("jti")
        vc_id = vc.get("id")
        if vc_id is not None and jti is None:
            raise OB3VerificationError("JWT payload is missing the required 'jti' claim")
        if jti is not None and jti != vc_id:
            raise OB3VerificationError("JWT 'jti' does not match the credential id")

        return credential

    # ── token extraction ───────────────────────────────────────────────────────

    @staticmethod
    def _decode_unverified(token: str) -> dict[str, Any]:
        """Decode a JWT payload without checking the signature (to read the
        issuer before the key is resolved). Raises OB3VerificationError on a
        malformed token."""
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except jwt.exceptions.DecodeError as exc:
            raise OB3VerificationError("malformed JWT: %s" % exc) from exc
        if not isinstance(payload, dict):
            raise OB3VerificationError("JWT payload is not an object")
        return payload

    @staticmethod
    def extract_token_from_svg(svg_bytes: bytes) -> str:
        """Extract the embedded credential from a baked SVG badge.

        Returns either a compact JWT-VC (baked in the ``verify`` attribute) or
        the JSON document of a Data Integrity credential (baked as the
        element's text content per OB 3.0 §5.3) — the caller decides how to
        verify based on the shape.
        """
        try:
            token = baking.extract_svg(svg_bytes, element=baking.SVG_ELEMENT_OB3,
                                       text_fallback=True)
        except Exception as exc:
            raise ErrorParsingFile(f"Could not parse SVG: {exc}") from exc
        if token is None:
            raise OB3VerificationError("No openbadges:credential element found in SVG")
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
            token = baking.extract_png(png_bytes, keyword=baking.ITXT_KEYWORD_OB3)
        except baking.DecompressionLimitExceeded as exc:
            raise OB3VerificationError(str(exc)) from exc
        except Exception as exc:
            raise ErrorParsingFile(f"Could not parse PNG: {exc}") from exc
        if token is None:
            raise OB3VerificationError("No openbadgecredential iTXt chunk found in PNG")
        return token


# ── endorsements (OB 3.0 endorsementJwt, errata v1.6) ────────────────────────

def verify_endorsement_jwt(token: str, download: Any = None,
                           endorser_pubkey_pem: Any = None) -> dict[str, Any]:
    """Verify a compact EndorsementCredential JWT (OB 3.0 ``endorsementJwt``).

    An endorsement is a Verifiable Credential a **third party** (the endorser,
    not the badge issuer) signs to vouch for an achievement, issuer or
    credential. This verifies its signature under the endorser's key — resolved
    from the endorsement's own issuer DID (``did:web``/``did:key``), or
    ``endorser_pubkey_pem`` when the endorser is not a DID — checks it is an
    ``EndorsementCredential`` whose validFrom/validUntil window is current, and
    returns ``{id, issuer, endorses, comment}``.

    Raises :class:`OB3VerificationError` on any failure (malformed token, bad
    signature, wrong type, expired, or an endorser that is neither a DID nor
    covered by ``endorser_pubkey_pem``). The verifier machinery is reused, but
    OB3Verifier.verify() cannot: an EndorsementCredential is not an
    OpenBadgeCredential, so its type check would reject it.
    """
    if not isinstance(token, str) or token.lstrip().startswith('{'):
        raise OB3VerificationError(
            "endorsementJwt must be a compact JWT string")

    unverified = OB3Verifier._decode_unverified(token)
    endorser = _claim_object_id(unverified.get("issuer")) or unverified.get("iss")

    if endorser_pubkey_pem is not None:
        verifier = OB3Verifier(pubkey_pem=endorser_pubkey_pem)
    elif isinstance(endorser, str) and endorser.startswith("did:"):
        verifier = OB3Verifier.for_issuer_did(endorser, download=download)
    else:
        raise OB3VerificationError(
            "cannot verify endorsement: its issuer %r is not a DID — pass "
            "endorser_pubkey_pem" % (endorser,))

    payload = verifier._decode_payload(token)     # signature + algorithm pin

    types = payload.get("type", [])
    if isinstance(types, str):
        types = [types]
    if "EndorsementCredential" not in (types if isinstance(types, list) else []):
        raise OB3VerificationError(
            "not an EndorsementCredential (type=%r)" % (payload.get("type"),))

    _check_endorsement_window(payload)

    subject = payload.get("credentialSubject")
    if isinstance(subject, list):
        subject = subject[0] if subject else {}
    if not isinstance(subject, dict):
        subject = {}
    return {
        "id": payload.get("id"),
        "issuer": endorser,
        "endorses": subject.get("id"),
        "comment": subject.get("endorsementComment"),
    }


def _check_endorsement_window(vc: dict[str, Any]) -> None:
    """Reject an endorsement whose validFrom/validUntil window is not current.

    Fails closed on a malformed date, mirroring the credential body and status
    list windows — treating an unparseable bound as "no bound" would let a
    corrupt date silently widen the window (the JWT exp is also checked in
    _decode_payload, but a producer may set a vc-level bound without the
    registered claim)."""
    now = datetime.now(timezone.utc)
    valid_until = vc.get("validUntil")
    if isinstance(valid_until, str):
        try:
            expires = _parse_iso(valid_until)
        except Exception as exc:
            raise OB3VerificationError(
                "endorsement has an invalid validUntil %r: %s"
                % (valid_until, exc)) from exc
        if expires < now - CLOCK_SKEW_LEEWAY:
            raise OB3VerificationError(
                "endorsement expired (validUntil %s)" % valid_until)
    valid_from = vc.get("validFrom")
    if isinstance(valid_from, str):
        try:
            starts = _parse_iso(valid_from)
        except Exception as exc:
            raise OB3VerificationError(
                "endorsement has an invalid validFrom %r: %s"
                % (valid_from, exc)) from exc
        if starts > now + CLOCK_SKEW_LEEWAY:
            raise OB3VerificationError(
                "endorsement is not yet valid (validFrom %s)" % valid_from)
