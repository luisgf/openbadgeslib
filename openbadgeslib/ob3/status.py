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

# OpenBadges 3.0 credential status (revocation) checking.
#
# Implements the W3C Bitstring Status List v1.0 mechanism (and the older
# StatusList2021 shape) used to express revocation/suspension in the Verifiable
# Credentials data model. This is the OB3 counterpart of OB2's revocation-list
# check: without it, an issuer's revocation has no effect on the verdict.
#
# Trust note: by default this checks the *published* status bit and the list's
# validFrom/validUntil window (a lapsed list is rejected, so a replayed old
# copy cannot resurrect a revoked badge). It does NOT, by default, verify the
# status-list credential's own proof/signature — that is a separate trust
# chain. Pass verify_list=True (with the issuer's key or a DID issuer) to also
# verify the list's JWT-VC proof and bind its issuer to the badge's, closing
# the gap where a compromised status host could silently un-revoke.

import base64
import json
import zlib

from datetime import datetime, timezone
from typing import Any, Callable, List, Optional, Union

from .credential import OpenBadgeCredential, _parse_iso
from .verifier import OB3VerificationError
from ..util import download_file

_SUPPORTED_ENTRY_TYPES = {"BitstringStatusListEntry", "StatusList2021Entry"}

#: Upper bound on a decompressed status-list bitstring. A conformant list is at
#: least 131072 bits (16 KiB); real lists reach a few hundred KiB. Cap well
#: above that to stop a crafted gzip bomb from exhausting memory (the list is
#: attacker-influenced: it is fetched from a URL named in an untrusted VC).
MAX_STATUS_LIST_BYTES = 5 * 1024 * 1024  # 5 MiB


def check_credential_status(
        credential: OpenBadgeCredential,
        download: Optional[Callable[[str], bytes]] = None,
        *,
        verify_list: bool = False,
        list_pubkey_pem: Optional[Union[str, bytes]] = None) -> None:
    """Check every credentialStatus entry, raising OB3VerificationError if the
    credential is revoked/suspended or if its status cannot be determined.

    Fail-closed: a fetch or parse failure raises rather than silently passing.
    A credential with no credentialStatus is a no-op. ``download`` defaults to
    util.download_file (HTTPS-only, size-capped); it is injectable for testing.

    The list's ``validFrom``/``validUntil`` window is always enforced (a lapsed
    or not-yet-valid list is rejected). Pass ``verify_list=True`` to also verify
    the status-list credential's own JWT-VC proof and require its issuer to
    equal the badge's issuer — supply ``list_pubkey_pem`` (the issuer's public
    key, e.g. the one that verified the badge), or rely on DID resolution when
    the badge issuer is a ``did:web``/``did:key``. Off by default so a status
    check stays a single offline-friendly fetch.
    """
    fetch = download if download is not None else download_file
    badge_issuer = credential.issuer.id if credential.issuer else None
    for entry in credential.credential_status:
        _check_entry(entry, fetch, badge_issuer=badge_issuer,
                     verify_list=verify_list, list_pubkey_pem=list_pubkey_pem)


def _check_entry(entry: dict[str, Any], download: Callable[[str], bytes],
                 *, badge_issuer: Optional[str] = None,
                 verify_list: bool = False,
                 list_pubkey_pem: Optional[Union[str, bytes]] = None) -> None:
    types = set(_as_list(entry.get("type")))
    if not (types & _SUPPORTED_ENTRY_TYPES):
        raise OB3VerificationError(
            "unsupported credentialStatus type: %r" % (entry.get("type"),))

    purpose = entry.get("statusPurpose", "revocation")
    list_url = entry.get("statusListCredential")
    if not isinstance(list_url, str) or not list_url:
        raise OB3VerificationError(
            "credentialStatus is missing a statusListCredential URL")
    index = _parse_index(entry.get("statusListIndex"))

    try:
        raw = download(list_url)
    except Exception as exc:
        # HTTPS enforcement / size cap / network errors all fail closed.
        raise OB3VerificationError(
            "could not fetch status list %s: %s" % (list_url, exc)) from exc

    try:
        doc = _status_list_document(raw)
        subject = _subject_of(doc)
        # Bitstring Status List v1.0 allows statusSize > 1 (multi-bit entries).
        # _bit_set below assumes exactly one bit per entry, so honouring a
        # larger statusSize would read the wrong bits and could misreport a
        # revoked credential as valid. Fail closed on an unsupported size rather
        # than silently returning the wrong verdict. Absent/1 keeps 1-bit logic.
        status_size = subject.get("statusSize", 1)
        try:
            status_size = int(status_size)
        except (TypeError, ValueError):
            raise OB3VerificationError("invalid statusSize: %r" % (status_size,))
        if status_size != 1:
            raise OB3VerificationError(
                "unsupported statusSize %d: only single-bit status entries are "
                "supported" % status_size)
        encoded = subject.get("encodedList")
        if not isinstance(encoded, str) or not encoded:
            raise OB3VerificationError("status list credential has no encodedList")
        bitstring = _decode_encoded_list(encoded)
        list_purposes = set(_as_list(subject.get("statusPurpose")))
    except OB3VerificationError:
        raise
    except Exception as exc:
        raise OB3VerificationError(
            "malformed status list %s: %s" % (list_url, exc)) from exc

    # Reject a stale (or not-yet-valid) list so a replayed old copy cannot
    # resurrect a revoked badge. A list with no validUntil is not expired.
    _check_list_window(doc, list_url)

    # Opt-in: verify the list credential's OWN proof and bind its issuer to the
    # badge's, so a compromised status host cannot silently un-revoke.
    if verify_list:
        _verify_list_proof(raw, doc, list_url, badge_issuer, download,
                           list_pubkey_pem)

    # The entry's statusPurpose MUST be one the fetched status list declares,
    # otherwise the entry points at the wrong list (fail closed).
    if purpose not in list_purposes:
        raise OB3VerificationError(
            "credentialStatus statusPurpose %r is not declared by the status list "
            "%s (declares %r)" % (purpose, list_url, subject.get("statusPurpose")))

    if not _bit_set(bitstring, index):
        return

    # A set bit only invalidates the credential for revocation/suspension.
    # Any other purpose (e.g. 'message') is informational and MUST NOT fail
    # verification — statusPurpose decides the meaning of the bit.
    if purpose in ("revocation", "suspension"):
        raise OB3VerificationError(
            "Credential status '%s' is set at index %d in %s"
            % (purpose, index, list_url))


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _parse_index(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise OB3VerificationError("invalid statusListIndex: %r" % (value,)) from None


def _status_list_document(raw: bytes) -> dict[str, Any]:
    """Return the status-list credential document (its top-level claims) served
    either as a JSON-LD VC document or as a compact JWT-VC string."""
    text = raw.decode('utf-8').strip()

    if text.startswith('{'):
        doc = json.loads(text)
        # A JWT payload wrapper ({"vc": {...}}) or a bare VC document.
        if isinstance(doc, dict) and "credentialSubject" not in doc \
                and isinstance(doc.get("vc"), dict):
            doc = doc["vc"]
    elif text.count('.') == 2:                       # compact JWS: h.p.s
        payload = json.loads(_b64url_decode(text.split('.')[1]))
        doc = payload.get("vc", payload)
    else:
        raise OB3VerificationError("status list is neither JSON nor a JWT")

    if not isinstance(doc, dict):
        raise OB3VerificationError("status list credential is not an object")
    return doc


def _subject_of(doc: dict[str, Any]) -> dict[str, Any]:
    subject = doc.get("credentialSubject")
    if isinstance(subject, list):
        subject = subject[0] if subject else None
    if not isinstance(subject, dict):
        raise OB3VerificationError(
            "status list credential has no credentialSubject object")
    return subject


def _issuer_id(issuer: Any) -> Optional[str]:
    """The issuer identifier of a VC, whether given as a bare IRI or an object
    with an ``id`` (matches OpenBadgeCredential's issuer handling)."""
    if isinstance(issuer, str):
        return issuer
    if isinstance(issuer, dict):
        value = issuer.get("id")
        return value if isinstance(value, str) else None
    return None


def _check_list_window(doc: dict[str, Any], list_url: str) -> None:
    """Enforce the status list's validFrom/validUntil against wall-clock time.

    A ``validUntil`` in the past means the served list is stale — an issuer that
    stopped republishing, or a replayed old copy — so it is rejected rather than
    trusted (an old revocation.jwt would otherwise silently un-revoke). A
    ``validFrom`` in the future is likewise rejected. Absent bounds are fine.
    """
    now = datetime.now(timezone.utc)
    valid_until = doc.get("validUntil")
    if isinstance(valid_until, str):
        try:
            expires = _parse_iso(valid_until)
        except Exception as exc:
            raise OB3VerificationError(
                "status list %s has an invalid validUntil %r: %s"
                % (list_url, valid_until, exc)) from exc
        if expires < now:
            raise OB3VerificationError(
                "status list %s expired (validUntil %s); the issuer must "
                "republish it" % (list_url, valid_until))
    valid_from = doc.get("validFrom")
    if isinstance(valid_from, str):
        try:
            starts = _parse_iso(valid_from)
        except Exception as exc:
            raise OB3VerificationError(
                "status list %s has an invalid validFrom %r: %s"
                % (list_url, valid_from, exc)) from exc
        if starts > now:
            raise OB3VerificationError(
                "status list %s is not yet valid (validFrom %s)"
                % (list_url, valid_from))


def _verify_list_proof(raw: bytes, doc: dict[str, Any], list_url: str,
                       badge_issuer: Optional[str],
                       download: Callable[[str], bytes],
                       list_pubkey_pem: Optional[Union[str, bytes]]) -> None:
    """Verify a status list credential's own JWT-VC proof and bind its issuer.

    Two checks: (1) the list's ``issuer`` must equal the badge's issuer — a
    list published by anyone else is not authoritative for this badge; (2) the
    list's JWT signature must verify under the issuer's key (``list_pubkey_pem``
    if given, else resolved from a ``did:web``/``did:key`` issuer). Fails closed.
    """
    from .verifier import OB3Verifier

    list_issuer = _issuer_id(doc.get("issuer"))
    if badge_issuer is not None and list_issuer != badge_issuer:
        raise OB3VerificationError(
            "status list %s issuer %r does not match the badge issuer %r"
            % (list_url, list_issuer, badge_issuer))

    text = raw.decode('utf-8').strip()
    if text.count('.') != 2 or text.startswith('{'):
        raise OB3VerificationError(
            "status list %s is not a signed JWT-VC, so its proof cannot be "
            "verified (verify_list=True requires a signed list)" % list_url)

    if list_pubkey_pem is not None:
        verifier = OB3Verifier(pubkey_pem=list_pubkey_pem)
    elif isinstance(list_issuer, str) and list_issuer.startswith('did:'):
        verifier = OB3Verifier.for_issuer_did(list_issuer, download=download)
    else:
        raise OB3VerificationError(
            "cannot verify status list %s: its issuer %r is not a DID — pass "
            "list_pubkey_pem" % (list_url, list_issuer))

    # _decode_payload verifies the signature with the algorithm pinned to the
    # key type; it does not enforce OB3 credential *types* (this is a
    # BitstringStatusListCredential, not an OpenBadgeCredential), which is
    # exactly what we want here. The issuer binding above is the trust anchor.
    try:
        verifier._decode_payload(text)
    except OB3VerificationError as exc:
        raise OB3VerificationError(
            "status list %s proof is invalid: %s" % (list_url, exc)) from exc


def _b64url_decode(value: str) -> bytes:
    value += '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode(value)


def _decode_encoded_list(encoded: str) -> bytes:
    """Decode encodedList: optional multibase base64url ('u') prefix, base64url,
    then a bounded GZIP inflate to the raw bitstring."""
    if encoded.startswith('u'):          # multibase base64url-no-pad (Bitstring SL)
        encoded = encoded[1:]
    compressed = _b64url_decode(encoded)
    inflator = zlib.decompressobj(wbits=31)   # 31 => gzip framing
    out = inflator.decompress(compressed, MAX_STATUS_LIST_BYTES)
    if inflator.unconsumed_tail:
        raise OB3VerificationError(
            "status list bitstring exceeds the %d-byte limit" % MAX_STATUS_LIST_BYTES)
    return out


def _bit_set(bitstring: bytes, index: int) -> bool:
    """Return the bit at *index* in a big-endian (MSB-first) bitstring, matching
    the Bitstring Status List / StatusList2021 bit ordering."""
    if index < 0:
        raise OB3VerificationError("negative statusListIndex %d" % index)
    byte_index = index // 8
    if byte_index >= len(bitstring):
        raise OB3VerificationError(
            "statusListIndex %d is out of range for the status list" % index)
    return bool(bitstring[byte_index] & (0x80 >> (index % 8)))
