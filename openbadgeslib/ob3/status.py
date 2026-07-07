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
# Trust note: this checks the *published* status bit only. It does NOT verify
# the status-list credential's own proof/signature — that is a separate trust
# chain (often a different key). A caller needing that guarantee must verify
# the status-list credential independently.

import base64
import json
import zlib

from typing import Any, Callable, List, Optional

from .credential import OpenBadgeCredential
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
        download: Optional[Callable[[str], bytes]] = None) -> None:
    """Check every credentialStatus entry, raising OB3VerificationError if the
    credential is revoked/suspended or if its status cannot be determined.

    Fail-closed: a fetch or parse failure raises rather than silently passing.
    A credential with no credentialStatus is a no-op. ``download`` defaults to
    util.download_file (HTTPS-only, size-capped); it is injectable for testing.
    """
    fetch = download if download is not None else download_file
    for entry in credential.credential_status:
        _check_entry(entry, fetch)


def _check_entry(entry: dict[str, Any], download: Callable[[str], bytes]) -> None:
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
        subject = _status_list_subject(raw)
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


def _status_list_subject(raw: bytes) -> dict[str, Any]:
    """Return the credentialSubject of a status-list credential served either as
    a JSON-LD VC document or as a compact JWT-VC string."""
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
    subject = doc.get("credentialSubject")
    if isinstance(subject, list):
        subject = subject[0] if subject else None
    if not isinstance(subject, dict):
        raise OB3VerificationError(
            "status list credential has no credentialSubject object")
    return subject


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
