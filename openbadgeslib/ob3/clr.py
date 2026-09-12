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

# 1EdTech Comprehensive Learner Record 2.0 (Final v1.1) ClrCredential assembly.
#
# Builds an unsigned JSON-LD envelope whose credentialSubject.verifiableCredential
# array embeds already-signed member documents by value. Email hashing and
# member-count caps are product policy and stay downstream: this module copies
# the identifier objects and members it is given.
#
# The CLR JSON-LD context is pinned to the VERSIONED 2.0.1 revision. 1EdTech's
# unversioned …/clr/v2p0/context.json endpoint serves a stub whose ClrSubject
# scope defines no ``identifier`` term — signing against it silently drops the
# learner binding from the RDF. The versioned bytes are bundled next to the
# other contexts and hash-checked on every load so a bad bundle fails closed.

import copy
import hashlib
import json

from datetime import datetime, timezone
from importlib import resources
from typing import Any, Mapping, Optional, Sequence, Union

from ..errors import LibOpenBadgesException
from . import contexts as _contexts
from .credential import _iso

VCDM_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
OB_V3_CONTEXT = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
CLR_CONTEXT_URL = "https://purl.imsglobal.org/spec/clr/v2p0/context-2.0.1.json"
CLR_CONTEXT_SHA256 = "880f1902d4158f2f33ce06af41b90719977cd1ea337a9de2e41edb3ff5e543d6"

_CLR_CONTEXT_RESOURCE = "clr_context_2.0.1.json"
_ENVELOPE_CONTEXTS = (VCDM_V2_CONTEXT, OB_V3_CONTEXT, CLR_CONTEXT_URL)


def _bundled_context_bytes() -> bytes:
    """Raw bytes of the bundled CLR context file (split out so tests can stub)."""
    return resources.files(_contexts).joinpath(_CLR_CONTEXT_RESOURCE).read_bytes()


def bundled_clr_contexts() -> dict[str, dict[str, Any]]:
    """Pinned CLR 2.0.1 context mapping for Data Integrity ``extra_contexts``.

    Hashes the bundled file's raw bytes against :data:`CLR_CONTEXT_SHA256` on
    every call and raises :class:`LibOpenBadgesException` if they do not match
    — a context is signing input, so a bad bundle must fail closed.
    """
    try:
        raw = _bundled_context_bytes()
    except (OSError, FileNotFoundError) as exc:
        raise LibOpenBadgesException(
            "bundled CLR context is unreadable") from exc
    if hashlib.sha256(raw).hexdigest() != CLR_CONTEXT_SHA256:
        raise LibOpenBadgesException(
            "bundled CLR context does not match its pinned hash")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise LibOpenBadgesException("bundled CLR context is not an object")
    return {CLR_CONTEXT_URL: document}


def build_clr_credential(
        issuer: Union[str, Mapping[str, Any]],
        identifier: Sequence[Mapping[str, Any]],
        members: Sequence[Mapping[str, Any]],
        *,
        credential_id: str,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        status: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    """Build an unsigned CLR 2.0 ``ClrCredential`` JSON-LD document.

    *identifier* is a list of IdentityObject dicts (already hashed — this
    function does not hash emails). *members* are already-signed member
    credential documents, copied into ``credentialSubject.verifiableCredential``.
    *issuer* may be a Profile dict or a string URL. *status*, when given, is
    copied onto ``credentialStatus``.

    Raises ValueError if *members* is not a non-empty list of dicts, if
    *credential_id* is empty, or if both *valid_from* and *valid_until* are
    timezone-aware and *valid_until* is not strictly after *valid_from*.
    """
    if not isinstance(credential_id, str) or not credential_id:
        raise ValueError("credential_id must be a non-empty string")
    if not isinstance(members, list) or not members:
        raise ValueError("members must be a non-empty list of credential dicts")
    if not isinstance(identifier, list):
        raise ValueError("identifier must be a list of IdentityObject dicts")

    issued = valid_from if valid_from is not None else datetime.now(timezone.utc)
    if (valid_until is not None
            and issued.tzinfo is not None and valid_until.tzinfo is not None
            and valid_until <= issued):
        raise ValueError("validUntil must be after validFrom")

    if isinstance(issuer, str):
        if not issuer:
            raise ValueError("issuer must be a non-empty string or a dict")
        issuer_value: Union[str, dict[str, Any]] = issuer
    elif isinstance(issuer, dict):
        issuer_value = copy.deepcopy(dict(issuer))
    else:
        raise ValueError("issuer must be a string URL or a dict")

    copied_ids: list[dict[str, Any]] = []
    for i, item in enumerate(identifier):
        if not isinstance(item, dict):
            raise ValueError("identifier[%d] must be a JSON object" % i)
        copied_ids.append(copy.deepcopy(item))

    issuer_id = issuer_value if isinstance(issuer_value, str) else issuer_value.get("id")
    copied_members: list[dict[str, Any]] = []
    for i, member in enumerate(members):
        if not isinstance(member, dict):
            raise ValueError("members[%d] must be a JSON object" % i)
        member_id = member.get("id", member.get("@id"))
        if isinstance(member_id, str) and member_id in (credential_id, issuer_id):
            raise ValueError(
                "members[%d] id collides with the CLR envelope or issuer id" % i)
        copied_members.append(copy.deepcopy(member))

    document: dict[str, Any] = {
        "@context": list(_ENVELOPE_CONTEXTS),
        "type": ["VerifiableCredential", "ClrCredential"],
        "id": credential_id,
        "issuer": issuer_value,
        "validFrom": _iso(issued),
        "credentialSubject": {
            "type": "ClrSubject",
            "identifier": copied_ids,
            "verifiableCredential": copied_members,
        },
    }
    if valid_until is not None:
        document["validUntil"] = _iso(valid_until)
    if status is not None:
        if not isinstance(status, dict):
            raise ValueError("credentialStatus must be a JSON object")
        document["credentialStatus"] = copy.deepcopy(dict(status))
    return document


def sign_clr_credential(document: dict[str, Any], signing_key_pem: Any,
                        verification_method: str) -> dict[str, Any]:
    """Sign a ``ClrCredential`` with an eddsa-rdfc-2022 Data Integrity proof.

    Thin wrapper around :func:`add_data_integrity_proof` that injects the
    hash-pinned CLR context via ``extra_contexts`` — the library never fetches
    remote contexts, so without this injection canonicalization cannot see the
    CLR terms. Requires the optional ``[ldp]`` extra.
    """
    from .ldp import add_data_integrity_proof
    return add_data_integrity_proof(
        document, signing_key_pem, verification_method,
        extra_contexts=bundled_clr_contexts())
