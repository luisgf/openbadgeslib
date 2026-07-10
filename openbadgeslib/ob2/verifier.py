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

import logging
from datetime import datetime, timezone
from typing import Any, List, Optional, Union
from urllib.parse import urlparse

from .models import Assertion, CryptographicKey, hash_identity, _parse_iso
from ..errors import ErrorParsingFile, UnknownKeyType, LibOpenBadgesException
from ..keys import detect_key_type, key_to_pem
from ..util import CLOCK_SKEW_LEEWAY, download_file
from .._jws import utils as jws_utils
from .._jws import verify_block as jws_verify_block
from .._jws.exceptions import JWSException
from .. import baking

logger = logging.getLogger(__name__)


class OB2VerificationError(LibOpenBadgesException):
    """Raised when an OpenBadges 2.0 assertion fails verification.

    Inherits from LibOpenBadgesException so callers can catch every library
    error (OB1/OB2/OB3) with a single ``except``.
    """


class OB2Verifier:
    """Verifies strict OpenBadges 2.0 assertions (JWS compact serialization).

    Two verification models are supported, selected by the assertion's
    ``verification.type``:

    * **SignedBadge** — the baked JWS is verified. The verification key is
      either the operator-supplied trusted key (recommended), or, when none is
      given, resolved from ``verification.creator`` (a CryptographicKey
      document) whose ``owner``/``publicKey`` back-link to the issuer Profile is
      checked. A key resolved from the badge itself proves internal consistency
      only, not issuer identity.
    * **HostedBadge** — the assertion is fetched over HTTPS from its own ``id``;
      that retrieval (scoped to the issuer's origin) is the trust anchor, per
      the OB 2.0 hosted model. The baked JWS is verified as non-gating
      defence-in-depth only.

    Args:
        pubkey_pem: Optional PEM-encoded trusted public key. When supplied it is
                    used to verify SignedBadge assertions and skips resolving the
                    badge-declared key.
    """

    def __init__(self, pubkey_pem: Optional[Any] = None) -> None:
        self.trusted_pubkey_pem: Optional[Union[str, bytes]] = None
        if pubkey_pem is not None:
            pem = key_to_pem(pubkey_pem)
            try:
                detect_key_type(pem)
            except UnknownKeyType as exc:
                raise OB2VerificationError(
                    "Unsupported verification key type: %s" % exc) from exc
            self.trusted_pubkey_pem = pem

    # ── verification ─────────────────────────────────────────────────────────────

    def verify(self, token: str, expected_recipient: Optional[str] = None,
               check_revocation: bool = False) -> Assertion:
        """Verify a compact-JWS OB 2.0 assertion token.

        Returns the decoded :class:`~openbadgeslib.ob2.models.Assertion` on
        success; raises :class:`OB2VerificationError` on any failure.

        ``expected_recipient`` (an email) additionally binds the assertion to a
        recipient by re-hashing it with the embedded salt. ``check_revocation``
        (network) fetches the issuer's RevocationList and rejects a revoked
        assertion.
        """
        body = self._decode_body(token)
        try:
            assertion = Assertion.from_dict(body)
        except ValueError as exc:
            raise OB2VerificationError("Malformed OB 2.0 assertion: %s" % exc) from exc

        if assertion.verification.type == "HostedBadge":
            self._verify_hosted(assertion, token)
        else:
            self._verify_signed(assertion, token)

        self._check_expiration(assertion)

        if expected_recipient is not None:
            self._check_identity(assertion, expected_recipient)

        if check_revocation:
            self._check_revocation(assertion)

        return assertion

    # ── signed path ──────────────────────────────────────────────────────────────

    def _verify_signed(self, assertion: Assertion, token: str) -> None:
        """Verify the baked JWS of a SignedBadge assertion."""
        if self.trusted_pubkey_pem is not None:
            # Operator vouches for this key; verify against it directly.
            self._verify_jws(token, self.trusted_pubkey_pem)
            return

        # No trusted key: resolve the key the badge itself points to. This only
        # proves internal consistency (the caller/CLI marks it untrusted).
        creator = assertion.verification.creator
        if not creator:
            raise OB2VerificationError(
                "SignedBadge assertion has no verification.creator and no trusted "
                "key was supplied; cannot resolve a verification key")
        key = self._resolve_creator(creator)
        self._verify_jws(token, key.public_key_pem.encode('utf-8'))
        self._check_key_ownership(assertion, key)

    def _resolve_creator(self, creator_url: str) -> CryptographicKey:
        """Fetch and parse the CryptographicKey document at ``creator_url``."""
        data = self._fetch_json(creator_url, "CryptographicKey")
        try:
            return CryptographicKey.from_dict(data)
        except ValueError as exc:
            raise OB2VerificationError(
                "Malformed CryptographicKey at %s: %s" % (creator_url, exc)) from exc

    def _check_key_ownership(self, assertion: Assertion, key: CryptographicKey) -> None:
        """Verify the CryptographicKey ↔ issuer Profile bidirectional link.

        The key's ``owner`` must be the issuer Profile, and that Profile's
        ``publicKey`` must list this key's ``id`` — otherwise an attacker could
        point ``creator`` at a self-hosted key unrelated to the issuer.
        """
        issuer = self._fetch_issuer(assertion)
        issuer_id = issuer.get("id")
        if not isinstance(issuer_id, str) or issuer_id != key.owner:
            raise OB2VerificationError(
                "CryptographicKey owner %r does not match the issuer Profile id %r"
                % (key.owner, issuer_id))
        public_keys = _public_key_ids(issuer.get("publicKey"))
        if key.id not in public_keys:
            raise OB2VerificationError(
                "Issuer Profile %r does not list the CryptographicKey %r in its "
                "publicKey" % (issuer_id, key.id))

    # ── hosted path ──────────────────────────────────────────────────────────────

    def _verify_hosted(self, assertion: Assertion, token: str) -> None:
        """Verify a HostedBadge assertion by fetching its ``id`` over HTTPS.

        The fetched document is the authoritative copy; its origin must fall
        within the issuer's scope (default: same origin as the issuer Profile
        ``id``; or the issuer's ``verification.startsWith`` / ``allowedOrigins``
        when declared). The baked JWS is verified only as non-gating
        defence-in-depth.
        """
        assert assertion.id is not None
        fetched = self._fetch_json(assertion.id, "hosted assertion")

        # The fetched copy must match the local (baked) claims, so a tampered
        # local file cannot claim an id that legitimately hosts something else.
        local = assertion.to_dict()
        for field_name in ("id", "recipient", "badge"):
            if fetched.get(field_name) != local.get(field_name):
                raise OB2VerificationError(
                    "Hosted assertion at %s does not match the badge's local "
                    "claims (field %r differs)" % (assertion.id, field_name))

        # issuedOn is compared as a timestamp, not a raw string, so a
        # conformant host serving the semantically-identical form (a +00:00
        # offset instead of Z, or microseconds) is not falsely rejected.
        try:
            same_issued = (_parse_iso(fetched.get("issuedOn"), "hosted issuedOn")
                           == _parse_iso(local.get("issuedOn"), "assertion.issuedOn"))
        except ValueError:
            same_issued = False
        if not same_issued:
            raise OB2VerificationError(
                "Hosted assertion at %s does not match the badge's local "
                "claims (field 'issuedOn' differs)" % (assertion.id,))

        # expires governs validity, so the authoritative hosted copy must agree
        # with the local claim; otherwise a holder could strip or extend the
        # local expires (the baked JWS is non-gating for a hosted badge) to
        # defeat the expiration check. Compared as a timestamp like issuedOn;
        # present on only one side is a mismatch.
        fetched_expires = fetched.get("expires")
        local_expires = local.get("expires")
        expires_ok = (fetched_expires is None) == (local_expires is None)
        if expires_ok and fetched_expires is not None:
            try:
                expires_ok = (_parse_iso(fetched_expires, "hosted expires")
                              == _parse_iso(local_expires, "assertion.expires"))
            except ValueError:
                expires_ok = False
        if not expires_ok:
            raise OB2VerificationError(
                "Hosted assertion at %s does not match the badge's local "
                "claims (field 'expires' differs)" % (assertion.id,))

        issuer = self._fetch_issuer(assertion)
        self._check_hosted_scope(assertion.id, issuer)

        # Defence-in-depth: if the baked token also carries a resolvable key,
        # verify it, but never fail the hosted verdict on it (a hosted badge is
        # not required to be signed at all).
        try:
            if self.trusted_pubkey_pem is not None:
                self._verify_jws(token, self.trusted_pubkey_pem)
            elif assertion.verification.creator:
                key = self._resolve_creator(assertion.verification.creator)
                self._verify_jws(token, key.public_key_pem.encode('utf-8'))
        except OB2VerificationError as exc:
            logger.debug("Hosted assertion %s: baked JWS did not verify (%s); "
                         "hosted trust comes from the HTTPS fetch, not the signature.",
                         assertion.id, exc)

    def _check_hosted_scope(self, assertion_id: str, issuer: dict[str, Any]) -> None:
        """Enforce the OB 2.0 hosted-verification scope for ``assertion_id``."""
        verification = issuer.get("verification")
        if isinstance(verification, dict):
            starts_with = _as_str_list(verification.get("startsWith"))
            allowed_origins = _as_str_list(verification.get("allowedOrigins"))
            if starts_with:
                if not any(assertion_id.startswith(prefix) for prefix in starts_with):
                    raise OB2VerificationError(
                        "Hosted assertion id %s is outside the issuer's declared "
                        "startsWith scope" % assertion_id)
                return
            if allowed_origins:
                host = urlparse(assertion_id).hostname or ""
                if host not in allowed_origins:
                    raise OB2VerificationError(
                        "Hosted assertion id %s origin is not in the issuer's "
                        "allowedOrigins" % assertion_id)
                return

        # Default scope: same origin as the issuer Profile id.
        issuer_id = issuer.get("id")
        if not isinstance(issuer_id, str) or not _same_origin(assertion_id, issuer_id):
            raise OB2VerificationError(
                "Hosted assertion id %s is not same-origin with the issuer Profile "
                "id %r (no startsWith/allowedOrigins declared)" % (assertion_id, issuer_id))

    # ── shared checks ────────────────────────────────────────────────────────────

    def _check_expiration(self, assertion: Assertion) -> None:
        now = datetime.now(timezone.utc)
        if assertion.expires is not None \
                and assertion.expires < now - CLOCK_SKEW_LEEWAY:
            raise OB2VerificationError(
                "Assertion has expired (expires %s)" % assertion.expires.isoformat())
        if assertion.issued_on is not None \
                and assertion.issued_on > now + CLOCK_SKEW_LEEWAY:
            raise OB2VerificationError(
                "Assertion is not yet valid (issuedOn %s)" % assertion.issued_on.isoformat())

    def _check_identity(self, assertion: Assertion, expected_recipient: str) -> None:
        recipient = assertion.recipient
        if recipient.hashed:
            expected = hash_identity(expected_recipient, recipient.salt)
        else:
            expected = expected_recipient
        if expected != recipient.identity:
            raise OB2VerificationError(
                "Recipient mismatch: assertion is not for %s" % expected_recipient)

    def _check_revocation(self, assertion: Assertion) -> None:
        issuer = self._fetch_issuer(assertion)
        revocation_url = issuer.get("revocationList")
        if not revocation_url:
            return   # issuer publishes no revocations → not revoked
        if not isinstance(revocation_url, str):
            raise OB2VerificationError("issuer.revocationList must be a string URL")
        revocation = self._fetch_json(revocation_url, "RevocationList")
        revoked = revocation.get("revokedAssertions")
        if not isinstance(revoked, list):
            return   # empty/absent list → not revoked
        for entry in revoked:
            if isinstance(entry, str):
                if entry == assertion.id:
                    raise OB2VerificationError("Assertion %s has been revoked" % assertion.id)
            elif isinstance(entry, dict):
                if entry.get("id") == assertion.id:
                    reason = entry.get("revocationReason")
                    raise OB2VerificationError(
                        "Assertion %s has been revoked%s"
                        % (assertion.id, ": %s" % reason if reason else ""))

    # ── network / decode helpers ─────────────────────────────────────────────────

    def _fetch_issuer(self, assertion: Assertion) -> dict[str, Any]:
        """Resolve the issuer Profile via the assertion's BadgeClass ``badge`` URL."""
        badge = self._fetch_json(assertion.badge, "BadgeClass")
        issuer_url = badge.get("issuer")
        if isinstance(issuer_url, dict):
            # BadgeClass.issuer may be an embedded Profile object.
            return issuer_url
        if not isinstance(issuer_url, str) or not issuer_url:
            raise OB2VerificationError(
                "BadgeClass at %s has no valid 'issuer'" % assertion.badge)
        return self._fetch_json(issuer_url, "issuer Profile")

    def _fetch_json(self, url: str, where: str) -> dict[str, Any]:
        try:
            raw = download_file(url)
        except Exception as exc:
            raise OB2VerificationError(
                "Could not fetch %s at %s: %s" % (where, url, exc)) from exc
        if not raw:
            raise OB2VerificationError("Empty %s document at %s" % (where, url))
        try:
            data = jws_utils.from_json(raw)
        except Exception as exc:
            raise OB2VerificationError(
                "%s at %s is not valid JSON: %s" % (where, url, exc)) from exc
        if not isinstance(data, dict):
            raise OB2VerificationError("%s at %s is not a JSON object" % (where, url))
        return data

    def _decode_body(self, token: str) -> Any:
        """Split a compact JWS and return its decoded (JSON) payload."""
        try:
            _, payload_b64, _ = token.split(".")
        except ValueError as exc:
            raise OB2VerificationError(
                "Malformed JWS: expected header.payload.signature") from exc
        try:
            return jws_utils.decode(payload_b64.encode("ascii"))
        except Exception as exc:
            raise OB2VerificationError("Malformed JWS payload: %s" % exc) from exc

    def _verify_jws(self, token: str, key: Any) -> None:
        """Verify a compact JWS signature, raising OB2VerificationError on failure."""
        try:
            jws_verify_block(token.encode("utf-8"), key)
        except JWSException as exc:
            raise OB2VerificationError("Invalid signature: %s" % exc) from exc

    # ── token extraction ─────────────────────────────────────────────────────────

    @staticmethod
    def extract_token_from_svg(svg_bytes: bytes) -> str:
        """Extract the JWS token embedded in a baked OB 2.0 SVG badge."""
        try:
            token = baking.extract_svg(svg_bytes)
        except Exception as exc:
            raise ErrorParsingFile("Could not parse SVG: %s" % exc) from exc
        if token is None:
            raise OB2VerificationError("No openbadges:assertion element found in SVG")
        return token

    @staticmethod
    def extract_token_from_png(png_bytes: bytes) -> str:
        """Extract the JWS token embedded in a baked OB 2.0 PNG badge."""
        try:
            token = baking.extract_png(png_bytes)
        except baking.DecompressionLimitExceeded as exc:
            raise OB2VerificationError(str(exc)) from exc
        except Exception as exc:
            raise ErrorParsingFile("Could not parse PNG: %s" % exc) from exc
        if token is None:
            raise OB2VerificationError("No openbadges iTXt chunk found in PNG")
        return token


def _as_str_list(value: Any) -> List[str]:
    """Normalise a value that may be a single string or a list into a str list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _public_key_ids(value: Any) -> List[str]:
    """The CryptographicKey ids declared in a Profile's ``publicKey``.

    ``publicKey`` may be a single value or a list, and each entry may be a
    string IRI or an embedded ``CryptographicKey`` object (both conformant OB
    2.0). Returns the ids, taking an embedded object's ``id``.
    """
    ids: List[str] = []
    for item in (value if isinstance(value, list) else [value]):
        if isinstance(item, str):
            ids.append(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            ids.append(item["id"])
    return ids


def _same_origin(a: str, b: str) -> bool:
    """Return True if two URLs share scheme + host + port (their origin)."""
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)
