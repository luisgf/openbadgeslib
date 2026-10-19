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

# OpenBadges 3.0 credentials secured with a W3C Data Integrity proof (the
# OB 3.0 "Linked Data Proof" format) — issuance and verification, the
# counterpart of the JWT-VC signer/verifier for the other proof format the
# spec allows.
#
# Cryptosuites: eddsa-rdfc-2022 (W3C Recommendation vc-di-eddsa) is issued and
# verified natively here. ecdsa-sd-2023 (selective disclosure, vc-di-ecdsa) is
# VERIFY-only and delegated to openvc-core's audited EcdsaSdProofSuite — the
# large, security-sensitive selective-disclosure machinery (CBOR base/derived
# proofs, HMAC label maps, per-statement signatures) lives there rather than
# duplicated here; it needs the optional [ldp-sd] extra. openbadgeslib keeps the
# OB3 model, trust binding and lifecycle checks around it. Issuing ecdsa-sd-2023
# stays out of scope until there is named demand (verify-only for Displayer
# parity per the 1EdTech certification requirement).
#
# The algorithm, shared by both directions: RDFC-1.0-canonicalize the
# document without its proof and the proof options without proofValue (with
# the document's @context injected); hashData = SHA-256(proof config) ||
# SHA-256(document); the 64-byte Ed25519 signature over hashData travels as
# a multibase base58btc proofValue.
#
# What is signed is the RDF DATASET the JSON expands to, while the model and
# every policy check read the JSON. OB3LdpVerifier therefore runs context
# validation (VC Data Integrity 2.4.1, ob3/_context_validation.py) before it
# reads anything: the JSON must be exactly the compacted form of what was
# signed, every member a pinned context defines spelled by its term.
# OB3LdpSigner applies the same check to what it emits. The
# schema-agnostic verify_data_integrity_proof / add_data_integrity_proof
# building blocks do NOT (they also serve the W3C vectors and CLR).
#
# JSON-LD canonicalization needs a JSON-LD processor, so this module depends
# on the optional [ldp] extra (pyld) — imported lazily with an actionable
# error, everything else in the package works without it. @context documents
# are NEVER fetched from the network: canonicalization uses the bundled
# allowlisted contexts (see ob3/contexts).

import copy
import hashlib
import json
import re

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple, Union

from .. import baking
from .._safejson import JSONTooDeepError, check as check_json, loads as loads_untrusted
from ..errors import ErrorSigningFile
from ..keys import KeyType, detect_key_type, key_to_pem
from ..util import __version__
from ._canon_guard import (PYLD_LOCK, CanonicalizationGuardUnavailable,
                           CanonicalizationWorkExceeded, WorkBudget, canonize)
from ._context_validation import validate_document
from .contexts import UnknownContextError, bundled_contexts, document_loader
from .credential import OpenBadgeCredential, _iso, _parse_iso
from .did import (_b58btc_decode, _b58btc_encode, _public_key_to_pem,
                  did_key_from_pem, resolve_verification_method)
from .verifier import (OB3VerificationError, _check_recipient,
                       _check_validity_window, _check_vc_types)

#: Upper bound on a Data Integrity credential document. It bounds the input
#: of every linear pass (parsing, context validation, RDF conversion) and is
#: coherent with baking.MAX_ITXT_DECOMPRESSED. It does NOT bound RDF
#: canonicalization, whose cost on hostile blank-node graphs ("poison graphs")
#: is factorial in the size of the input: a few KB suffice. That is bounded by
#: its own work and CPU-time budget, ob3/_canon_guard.py (MAX_CANON_WORK,
#: MAX_CANON_SECONDS), and the duplicate checks of the JSON-LD to RDF
#: conversion by MAX_NODE_MAP_PAIRS. The verifier measures the document as
#: received; add_data_integrity_proof, which has no "as received", measures
#: its compact UTF-8 form.
MAX_LDP_DOCUMENT_BYTES = 256 * 1024


#: Oldest openvc-core the delegated ecdsa-sd-2023 verify accepts: earlier
#: releases do not validate the JSON-LD form of the documents they verify, or
#: let nested arrays, re-spelled policy terms or a derived proof that merges
#: blank nodes through (GHSA-vrxg-57v4-85mc, GHSA-h9rq-wxcw-4rjc; see
#: ob3/_context_validation.py), so the JSON they report could differ from
#: what the issuer signed. This is the security minimum of the delegated
#: verify path, deliberately below the ``>=1.35.0`` the extras declare (that
#: floor adds the SD-JWT VC issuer-JWT ``aud`` check, which this path does not
#: use): it refuses a hand-installed release that is unsafe here, not one that
#: is merely older than the tested pin.
_OPENVC_MIN_VERSION = (1, 33, 2)


class OB3GuardUnavailable(OB3VerificationError):
    """The RDF canonicalization guard (ob3/_canon_guard.py) cannot run safely
    with the installed pyld, so no Data Integrity credential can be verified
    or signed until pyld or openbadgeslib is changed. A deployment should
    alert on this apart from an ordinary ``OB3VerificationError``, which says
    a credential is bad; this says the verifier is down. (When signing, the
    :class:`ErrorSigningFile` raised has this as its ``__cause__``.)"""


def _require_jsonld() -> Any:
    """Import pyld lazily, failing with an actionable message without it."""
    try:
        from pyld import jsonld
    except ImportError as exc:
        raise OB3VerificationError(
            "Data Integrity (Linked Data Proof) support requires the "
            "optional 'pyld' dependency; install it with: "
            "pip install openbadgeslib[ldp]") from exc
    return jsonld


def _check_json_ld_form(document: dict[str, Any], proof: dict[str, Any],
                        loader: Any) -> None:
    """Context validation (VC Data Integrity 2.4.1) of a secured document.

    The RDF-canonicalized cryptosuites sign the RDF dataset the JSON expands
    to, while every OB3 policy check reads the JSON. This requires the
    document (without ``proof``) and *proof*'s configuration to be exactly the
    compacted form of what they expand to under the pinned contexts, with
    nothing dropped by the RDF conversion — see ob3/_context_validation.py.
    Raises :class:`OB3VerificationError`.

    It does not bound the size: the verifier has already bounded the
    untrusted input as received (``_parse_document``), and the signer bounds
    what it signs (``add_data_integrity_proof``, before any JSON-LD work) and
    the text it emits — re-measuring a parsed document here would measure a
    different serialization than either.
    """
    jsonld = _require_jsonld()
    try:
        json.dumps(document)
    except (TypeError, ValueError, RecursionError) as exc:
        raise OB3VerificationError(
            "credential document is not plain JSON: %s" % exc) from exc
    unsecured = {k: v for k, v in document.items() if k != 'proof'}
    proof_config = {k: v for k, v in proof.items() if k != 'proofValue'}
    # As in canonicalization: the proof options are read in the context of
    # the secured document.
    proof_config['@context'] = document.get('@context')
    with PYLD_LOCK:                 # pyld's context caches are not thread-safe
        validate_document(unsecured, proof_config, loader, jsonld)


def _select_proof(document: dict[str, Any]) -> dict[str, Any]:
    """Pick the single supported DataIntegrityProof from ``proof``.

    ``proof`` may be an object or an array. Exactly one entry with a
    supported cryptosuite must be present: none fails closed naming what was
    found, and more than one is rejected as ambiguous rather than guessing
    which signature speaks for the credential.
    """
    raw = document.get('proof')
    proofs = raw if isinstance(raw, list) else [raw] if raw is not None else []
    # Only a string names a cryptosuite: a JSON array or object is unhashable,
    # so testing it for membership would raise a bare TypeError.
    candidates = [
        p for p in proofs
        if isinstance(p, dict) and p.get('type') == 'DataIntegrityProof'
        and isinstance(p.get('cryptosuite'), str)
        and p['cryptosuite'] in _CRYPTOSUITES
    ]
    if not candidates:
        found = sorted({
            str(name) for name in (
                p.get('cryptosuite') or p.get('type')
                for p in proofs if isinstance(p, dict))
            if isinstance(name, str)
        })
        raise OB3VerificationError(
            "credential carries no supported Data Integrity proof "
            "(found: %s; supported cryptosuites: %s)"
            % (', '.join(found) or 'none', ', '.join(sorted(_CRYPTOSUITES))))
    if len(candidates) > 1:
        raise OB3VerificationError(
            "credential carries multiple supported Data Integrity proofs; "
            "refusing to guess which one speaks for it")
    return candidates[0]


def _validate_proof(proof: dict[str, Any], expected_proof_purpose: str) -> None:
    """Structural validation of a DataIntegrityProof entry (fail-closed)."""
    purpose = proof.get('proofPurpose')
    if purpose != expected_proof_purpose:
        raise OB3VerificationError(
            "proofPurpose %r does not match the expected %r"
            % (purpose, expected_proof_purpose))
    vm = proof.get('verificationMethod')
    if not isinstance(vm, str) or not vm:
        raise OB3VerificationError("proof has no verificationMethod")
    created = proof.get('created')
    if created is not None:
        try:
            _parse_iso(created)
        except (ValueError, TypeError, AttributeError) as exc:
            raise OB3VerificationError(
                "invalid proof.created date: %r" % (created,)) from exc
    expires = proof.get('expires')
    if expires is not None:
        try:
            expires_dt = _parse_iso(expires)
        except (ValueError, TypeError, AttributeError) as exc:
            raise OB3VerificationError(
                "invalid proof.expires date: %r" % (expires,)) from exc
        if expires_dt < datetime.now(timezone.utc):
            raise OB3VerificationError("the Data Integrity proof has expired")
    # domain/challenge are for interactive presentation flows; a badge is a
    # long-lived artefact, so they are ignored here (documented behaviour).


def _decode_proof_value(value: Any) -> bytes:
    """Decode a multibase base58btc proofValue into a 64-byte signature."""
    if not isinstance(value, str) or not value.startswith('z'):
        raise OB3VerificationError(
            "proofValue must be a multibase base58btc string ('z…')")
    try:
        signature = _b58btc_decode(value[1:])
    except OB3VerificationError:
        raise
    except Exception as exc:
        raise OB3VerificationError("malformed proofValue: %s" % exc) from exc
    if len(signature) != 64:
        raise OB3VerificationError(
            "proofValue must decode to a 64-byte Ed25519 signature, got %d bytes"
            % len(signature))
    return signature


def _canonize(document: dict[str, Any], loader: Any,
              budget: Optional[WorkBudget] = None) -> str:
    """RDFC-1.0-canonicalize a JSON-LD document to N-Quads via pyld, within a
    work budget (ob3/_canon_guard.py).

    pyld implements the algorithm under its pre-standardisation name
    URDNA2015; the W3C renamed it RDFC-1.0 with unchanged output. The input
    is untrusted when verifying: RDFC-1.0 is factorial on groups of blank
    nodes it cannot tell apart, so a few KB of hostile JSON-LD would pin a CPU
    for minutes. *budget* is shared by the canonicalizations of one signature
    check; omitted, this call gets a fresh one. A document over budget, and a
    pyld the guard cannot meter, both fail closed (the latter as
    :class:`OB3GuardUnavailable`).
    """
    jsonld = _require_jsonld()
    try:
        return canonize(jsonld, document, loader, budget)
    except CanonicalizationWorkExceeded as exc:
        raise OB3VerificationError(
            "refusing to canonicalize the credential: %s" % exc) from exc
    except CanonicalizationGuardUnavailable as exc:
        raise OB3GuardUnavailable(
            "cannot canonicalize safely: %s" % exc) from exc
    except Exception as exc:
        cause: Optional[BaseException] = exc
        while cause is not None:                    # unwrap pyld's JsonLdError
            if isinstance(cause, UnknownContextError):
                raise OB3VerificationError(str(cause)) from exc
            cause = cause.__cause__
        raise OB3VerificationError(
            "could not canonicalize the credential: %s" % exc) from exc


def _hash_data(unsecured_doc: dict[str, Any], proof_config: dict[str, Any], loader: Any) -> bytes:
    """hashData per vc-di-eddsa: SHA-256(proof config) || SHA-256(document).

    Both canonicalizations draw on one work budget: what a signature check may
    spend is bounded as a whole, not twice."""
    budget = WorkBudget()
    config_hash = hashlib.sha256(
        _canonize(proof_config, loader, budget).encode('utf-8')).digest()
    doc_hash = hashlib.sha256(
        _canonize(unsecured_doc, loader, budget).encode('utf-8')).digest()
    return config_hash + doc_hash


def _verify_eddsa_rdfc_2022(document: dict[str, Any], proof: dict[str, Any], pubkey_pem: bytes,
                            loader: Any) -> None:
    """Verify one eddsa-rdfc-2022 proof over *document* with *pubkey_pem*."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        if detect_key_type(pubkey_pem) is not KeyType.ED25519:
            raise OB3VerificationError(
                "eddsa-rdfc-2022 requires an Ed25519 verification key")
    except OB3VerificationError:
        raise
    except Exception as exc:
        raise OB3VerificationError(
            "unusable verification key: %s" % exc) from exc

    signature = _decode_proof_value(proof.get('proofValue'))

    unsecured = copy.deepcopy(document)
    unsecured.pop('proof', None)
    proof_config = {k: v for k, v in proof.items() if k != 'proofValue'}
    # vc-di-eddsa: the proof options are canonicalized in the context of the
    # secured document, so its @context is injected into the proof config.
    proof_config['@context'] = document.get('@context')

    data = _hash_data(unsecured, proof_config, loader)

    try:
        pub = load_pem_public_key(pubkey_pem)
        pub.verify(signature, data)                  # type: ignore[union-attr, call-arg]
    except InvalidSignature:
        raise OB3VerificationError(
            "Invalid Data Integrity proof (signature mismatch)") from None
    except OB3VerificationError:
        raise
    except Exception as exc:
        raise OB3VerificationError(
            "could not verify the Data Integrity proof: %s" % exc) from exc


def _require_openvc_ecdsa_sd() -> tuple[Any, Any]:
    """Import openvc-core's ecdsa-sd-2023 suite (and its error root), or fail
    with an actionable hint. The selective-disclosure crypto is delegated, not
    reimplemented — see the module docstring."""
    try:
        import openvc
        from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
        from openvc.proof.errors import ProofError
    except ImportError as exc:
        raise OB3VerificationError(
            "verifying ecdsa-sd-2023 (selective-disclosure) Data Integrity "
            "proofs requires the optional openvc-core dependency; install it "
            "with: pip install openbadgeslib[ldp-sd]") from exc
    # Fail closed on an openvc-core too old to validate the JSON-LD form of
    # what it verifies (read at call time: the installed package can change).
    version = getattr(openvc, '__version__', None)
    match = re.match(r'(\d+)\.(\d+)\.(\d+)', version) \
        if isinstance(version, str) else None
    if match is None or tuple(int(g) for g in match.groups()) < _OPENVC_MIN_VERSION:
        raise OB3VerificationError(
            "verifying ecdsa-sd-2023 Data Integrity proofs requires "
            "openvc-core >= %s, found %r; upgrade it with: "
            "pip install -U openbadgeslib[ldp-sd]"
            % ('.'.join(map(str, _OPENVC_MIN_VERSION)), version))
    return EcdsaSdProofSuite, ProofError


def _p256_pem_to_jwk(pubkey_pem: bytes) -> dict[str, str]:
    """A NIST P-256 public-key PEM as the JWK openvc-core's ecdsa-sd-2023
    verifier takes. Rejects any non-P-256 key (the cryptosuite is P-256 only)
    before it reaches the suite."""
    import base64

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        pub = load_pem_public_key(pubkey_pem)
    except Exception as exc:
        raise OB3VerificationError(
            "unusable verification key: %s" % exc) from exc
    if not (isinstance(pub, ec.EllipticCurvePublicKey)
            and isinstance(pub.curve, ec.SECP256R1)):
        raise OB3VerificationError(
            "ecdsa-sd-2023 requires a NIST P-256 verification key")
    numbers = pub.public_numbers()

    def _b64u(value: int) -> str:
        return base64.urlsafe_b64encode(
            value.to_bytes(32, 'big')).rstrip(b'=').decode('ascii')

    return {'kty': 'EC', 'crv': 'P-256',
            'x': _b64u(numbers.x), 'y': _b64u(numbers.y)}


def _prescreen_canonicalization(document: dict[str, Any], proof: dict[str, Any],
                                loader: Any) -> None:
    """Refuse, before openvc-core spends it, a document whose RDF
    canonicalization is over the work budget.

    openvc-core's ecdsa-sd-2023 suite canonicalizes the credential and the
    proof options with pyld directly, without a work bound (the poison-graph
    cost of ob3/_canon_guard.py). Canonicalizing the same document and proof
    options here first, discarding the result, costs about as much as one of
    openvc's own passes for a document that is cheap and refuses one that is
    not. It is a screen, not a bound: openvc also canonicalizes the
    mandatory and selectively disclosed subsets under its own blank-node
    labels, and a different labelling prunes a different part of the
    permutation search. The bound has to come from openvc-core itself."""
    budget = WorkBudget()
    proof_config = {k: v for k, v in proof.items() if k != 'proofValue'}
    proof_config['@context'] = document.get('@context')
    _canonize(proof_config, loader, budget)
    _canonize({k: v for k, v in document.items() if k != 'proof'}, loader,
              budget)


def _verify_ecdsa_sd_2023(document: dict[str, Any], proof: dict[str, Any],
                          pubkey_pem: bytes, loader: Any) -> None:
    """Verify one ecdsa-sd-2023 derived proof by delegating to openvc-core.

    openvc-core owns the whole selective-disclosure verification — its own RDF
    canonicalization plus the base and per-statement P-256 signatures;
    openbadgeslib only resolves/pins the key and feeds its pinned OB3 @context
    allowlist, so canonicalization is fail-closed and never touches the network.
    The delegate canonicalizes with pyld's unbounded URDNA2015, so before
    handing the document over it is canonicalized HERE, within the work budget
    (:func:`_prescreen_canonicalization`).
    """
    EcdsaSdProofSuite, ProofError = _require_openvc_ecdsa_sd()
    public_key_jwk = _p256_pem_to_jwk(pubkey_pem)
    _prescreen_canonicalization(document, proof, loader)
    try:
        EcdsaSdProofSuite().verify(
            document,
            public_key_jwk=public_key_jwk,
            expected_proof_purpose=proof.get('proofPurpose'),
            extra_contexts=bundled_contexts(),
        )
    except ProofError as exc:
        raise OB3VerificationError(
            "Invalid ecdsa-sd-2023 Data Integrity proof: %s" % exc) from exc
    except OB3VerificationError:
        raise
    except Exception as exc:
        raise OB3VerificationError(
            "could not verify the ecdsa-sd-2023 proof: %s" % exc) from exc


#: Registry of supported cryptosuites -> verify callback. eddsa-rdfc-2022 is
#: verified natively; ecdsa-sd-2023 (selective disclosure) is VERIFY-only and
#: delegated to openvc-core (needs the [ldp-sd] extra — see the module
#: docstring). An unknown suite fails closed naming the supported ones.
_CRYPTOSUITES: Dict[str, Callable[[dict[str, Any], dict[str, Any], bytes, Any], None]] = {
    'eddsa-rdfc-2022': _verify_eddsa_rdfc_2022,
    'ecdsa-sd-2023': _verify_ecdsa_sd_2023,
}


def verify_data_integrity_proof(
        document: dict[str, Any], pubkey_pem: Any, *,
        expected_proof_purpose: str = 'assertionMethod',
        extra_contexts: Optional[Mapping[str, dict[str, Any]]] = None) -> None:
    """Verify the embedded Data Integrity proof of a JSON-LD document.

    Low-level building block: checks ONLY the proof (canonicalization,
    hashing, signature) against *pubkey_pem*, imposing no OB3 schema — which
    lets it run e.g. the official W3C vc-di-eddsa test vectors. Most callers
    want :class:`OB3LdpVerifier` instead, which adds the OpenBadgeCredential
    validation, trust binding, validity window, status and recipient checks.

    *extra_contexts* extends the bundled @context allowlist for this call
    only (contexts are never fetched from the network); it is ignored for the
    ecdsa-sd-2023 cryptosuite, which is delegated to openvc-core with the
    bundled pinned contexts only. Raises :class:`OB3VerificationError` on any
    failure.

    .. warning:: The proof covers the **RDF dataset** the document expands
       to, not its JSON. Two different JSON documents can expand to the same
       dataset (a member re-keyed to its IRI, an inline alias, a node under
       ``@included``, a term or node id the RDF conversion drops, ...), so a
       successful call proves nothing about any particular JSON member. Do
       not read policy (validity dates, status, subject, issuer) from the
       JSON after this call alone: :class:`OB3LdpVerifier` additionally
       validates that the JSON is the compacted form of what was signed
       before it reads anything.
    """
    if not isinstance(document, dict):
        raise OB3VerificationError("credential document must be a JSON object")
    try:
        # Nesting, lone surrogates and non-finite numbers: copy.deepcopy below
        # and the hash (UTF-8 encode) would otherwise raise RecursionError or
        # UnicodeEncodeError. OB3LdpVerifier has checked this on parse already.
        check_json(document)
    except ValueError as exc:
        raise OB3VerificationError(
            "credential document is not usable JSON: %s" % exc) from exc
    proof = _select_proof(document)
    _validate_proof(proof, expected_proof_purpose)
    loader = document_loader(extra_contexts)
    pem = key_to_pem(pubkey_pem)
    pem_bytes = pem.encode('utf-8') if isinstance(pem, str) else pem
    _CRYPTOSUITES[proof['cryptosuite']](document, proof, pem_bytes, loader)


def add_data_integrity_proof(
        document: dict[str, Any], privkey_pem: Any, verification_method: str, *,
        proof_purpose: str = 'assertionMethod',
        created: Optional[datetime] = None,
        extra_contexts: Optional[Mapping[str, dict[str, Any]]] = None) -> dict[str, Any]:
    """Return a deep copy of *document* secured with an eddsa-rdfc-2022
    DataIntegrityProof — the signing counterpart of
    :func:`verify_data_integrity_proof`, and like it schema-agnostic: it
    imposes no OB3 shape, which lets it reproduce the official W3C
    vc-di-eddsa test vectors. Most callers want :class:`OB3LdpSigner`
    instead, which signs an :class:`OpenBadgeCredential` and bakes images.

    *verification_method* is embedded verbatim in the proof (a did:key or
    did:web URL the verifier can resolve). *created* defaults to now (UTC);
    it is injectable so tests can produce deterministic proofs. The input
    document is never mutated. *extra_contexts* extends the bundled
    @context allowlist for this call only (contexts are never fetched from
    the network).

    Fails closed with :class:`ErrorSigningFile` on a non-Ed25519 key, a
    document that already carries a proof (never produce a proof set the
    verifier would reject as ambiguous), or a missing [ldp] extra.

    .. warning:: The proof signs the **RDF dataset** the document expands to,
       not its JSON: a member whose term no pinned context defines, or whose
       IRI the RDF conversion drops, is silently left unsigned, and this
       low-level function does not check for it. :class:`OB3LdpSigner`
       refuses to emit such a document (and :class:`OB3LdpVerifier` refuses
       to accept one).
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if not isinstance(document, dict):
        raise ErrorSigningFile('credential document must be a JSON object')
    if 'proof' in document:
        raise ErrorSigningFile('document already carries a proof; refusing '
                               'to add a second one')
    try:
        # Before any JSON-LD processing: the cost of expansion and RDF
        # conversion grows with the input, and a caller may sign data a third
        # party supplied. The compact UTF-8 form is the smallest text the
        # document can be sent as, so a document over the limit even there is
        # one no verifier accepts (ensure_ascii escapes and spaced separators
        # would refuse genuine non-ASCII credentials at a third of it).
        size = len(json.dumps(document, ensure_ascii=False,
                              separators=(',', ':')).encode('utf-8'))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ErrorSigningFile(
            'credential document is not plain JSON: %s' % exc) from exc
    if size > MAX_LDP_DOCUMENT_BYTES:
        raise ErrorSigningFile(
            'credential document is %d bytes, over the %d-byte limit'
            % (size, MAX_LDP_DOCUMENT_BYTES))
    if not isinstance(verification_method, str) or not verification_method:
        raise ErrorSigningFile('a proof needs a verificationMethod URL')

    pem = key_to_pem(privkey_pem)
    pem_bytes = pem.encode('utf-8') if isinstance(pem, str) else pem
    try:
        key_type = detect_key_type(pem_bytes)
    except Exception as exc:
        raise ErrorSigningFile('unusable signing key: %s' % exc) from exc
    if key_type is not KeyType.ED25519:
        raise ErrorSigningFile(
            'eddsa-rdfc-2022 requires an Ed25519 signing key, got %s'
            % key_type.value)

    proof: Dict[str, Any] = {
        'type': 'DataIntegrityProof',
        'cryptosuite': 'eddsa-rdfc-2022',
        'created': _iso(created if created is not None
                        else datetime.now(timezone.utc)),
        'verificationMethod': verification_method,
        'proofPurpose': proof_purpose,
    }
    # vc-di-eddsa: the proof options are canonicalized in the context of the
    # secured document; the @context is injected for hashing only and the
    # embedded proof carries none.
    proof_config = dict(proof)
    proof_config['@context'] = document.get('@context')

    loader = document_loader(extra_contexts)
    try:
        data = _hash_data(document, proof_config, loader)
    except OB3VerificationError as exc:
        # Signing-path callers expect signer-family errors; the message
        # (e.g. the [ldp] extra install hint) is preserved.
        raise ErrorSigningFile(str(exc)) from exc

    priv = load_pem_private_key(pem_bytes, password=None)
    signature = priv.sign(data)                # type: ignore[union-attr, call-arg]

    signed = copy.deepcopy(document)
    signed['proof'] = dict(proof, proofValue='z' + _b58btc_encode(signature))
    return signed


def _reject_unsigned_ldp_aliases(doc: dict[str, Any]) -> None:
    """Reject VC 1.1 / legacy members the model or status checker reads but an
    RDF-canonicalized Data Integrity proof cannot cover.

    eddsa-rdfc-2022 (and the delegated ecdsa-sd-2023) sign the JSON-LD
    canonicalization, which drops any term the bundled @contexts do not define.
    The credential model still reads the VC 1.1 date aliases
    (``expirationDate``/``issuanceDate``) and the status checker still accepts
    the legacy ``StatusList2021Entry`` — none of which are in the pinned
    contexts, so in the LDP path they are UNSIGNED: a holder could rewrite them
    (un-expire / un-revoke) with the proof still verifying. Here a credential
    must use the VC 2.0 terms (validUntil/validFrom, BitstringStatusListEntry);
    fail closed on the legacy shapes. (Their full-IRI spellings, which a VC
    1.1 badge re-compacted onto the VC 2.0 context carries, are refused by
    context validation: see _POLICY_TERMS in ob3/_context_validation.py.)

    Every ``credentialStatus`` entry must also be a JSON object: the model and
    the status checker read only objects, so an entry spelled any other way
    (a bare IRI reference, or an object wrapped in a nested array, which
    expansion flattens into the very same signed dataset) would be skipped —
    a status the checker cannot read must not pass as "no status".
    """
    for alias in ("expirationDate", "issuanceDate"):
        if alias in doc:
            raise OB3VerificationError(
                "Data Integrity credential carries %r, which the RDF-"
                "canonicalized proof does not sign; use validUntil/validFrom"
                % alias)
    if "credentialStatus" not in doc:
        return
    status = doc["credentialStatus"]
    for entry in (status if isinstance(status, list) else [status]):
        if not isinstance(entry, dict):
            raise OB3VerificationError(
                "Data Integrity credential has a credentialStatus entry that "
                "is not a JSON object (%s); the status checker could not read "
                "it" % type(entry).__name__)
        types = entry.get("type")
        types = types if isinstance(types, list) else [types]
        if "StatusList2021Entry" in types:
            raise OB3VerificationError(
                "Data Integrity credential uses the legacy StatusList2021Entry "
                "status type, whose pointer the RDF-canonicalized proof does "
                "not sign; use BitstringStatusListEntry")


def _reject_hidden_sd_lifecycle(doc: dict[str, Any], proof: dict[str, Any]) -> None:
    """Fail closed when an ecdsa-sd-2023 presentation omits lifecycle claims.

    Selective disclosure lets a holder drop statements the issuer signed.
    ``validFrom``, ``validUntil`` and ``credentialStatus`` are the ones that
    bound a badge's life: hiding them makes a not-yet-valid, expired or
    revoked credential look valid (the model takes a missing ``validFrom``
    as "now"). eddsa-rdfc-2022 signs the whole document, so this only
    applies to ecdsa-sd-2023. The low-level ``verify_data_integrity_proof``
    does not enforce it (it checks the proof alone); ``OB3LdpVerifier.verify``
    does (#328). A key that is there may still hold only part of what the
    issuer signed: _reject_selective_sd_lifecycle covers that, once the
    proof has verified.
    """
    if proof.get('cryptosuite') != 'ecdsa-sd-2023':
        return
    if 'validFrom' not in doc:
        raise OB3VerificationError(
            "ecdsa-sd-2023 presentation omitted validFrom, which a holder "
            "could hide to make a not-yet-valid badge look valid; disclose "
            "validFrom")
    if 'validUntil' not in doc:
        raise OB3VerificationError(
            "ecdsa-sd-2023 presentation omitted validUntil, which a holder "
            "could hide to un-expire the badge; disclose validUntil")
    if 'credentialStatus' not in doc:
        raise OB3VerificationError(
            "ecdsa-sd-2023 presentation omitted credentialStatus, which a "
            "holder could hide to un-revoke the badge; disclose credentialStatus")


_CRED = 'https://www.w3.org/2018/credentials#'
_SD_STATUS = '<%scredentialStatus>' % _CRED
_SD_LIFECYCLE = frozenset({_SD_STATUS, '<%svalidFrom>' % _CRED,
                           '<%svalidUntil>' % _CRED})


def _reject_selective_sd_lifecycle(doc: dict[str, Any], proof: dict[str, Any]) -> None:
    """Fail closed unless every disclosed ecdsa-sd-2023 statement about the
    credential's lifecycle is MANDATORY.

    _reject_hidden_sd_lifecycle only sees that the ``validFrom``,
    ``validUntil`` and ``credentialStatus`` keys are there. A holder can
    disclose any subset of the statements the issuer left selective, so with
    status selective a presentation could reveal one ``credentialStatus``
    entry of two (the clear one), or an entry without its ``statusSize``,
    and pass the status check; and an issuer that left ``validFrom``
    selective lets a holder hide a future one from any presentation. A
    verifier cannot count the statements a holder withheld; it can only rely
    on those the issuer's base signature covers as a whole, the mandatory
    ones. So every disclosed statement with the credential as subject and
    ``credentialStatus``, ``validFrom`` or ``validUntil`` as predicate, and
    every statement about one of its status entries, must be mandatory:
    issuers mark ``/validFrom``, ``/validUntil`` and ``/credentialStatus`` as
    mandatory pointers. Runs after the proof verified (the mandatory indexes
    are then the issuer's).

    Limit: a statement the issuer left selective and the holder withheld is
    invisible here. An issuer who marks only ``/credentialStatus/0`` (or only
    some members of an entry) mandatory leaves the rest hideable, and no
    verifier can detect it: mark ``/credentialStatus`` whole.
    """
    if proof.get('cryptosuite') != 'ecdsa-sd-2023':
        return
    statements, mandatory = _sd_disclosed_statements(doc, proof)
    credential_id = doc.get('id')
    subject = '<%s>' % credential_id if isinstance(credential_id, str) else None
    terms = [statement.split(' ', 2) for statement in statements]
    if subject is None or not any(t[0] == subject for t in terms):
        raise OB3VerificationError(
            "cannot find the statements about the credential (id %r) among "
            "those the ecdsa-sd-2023 proof discloses; its id must be an IRI"
            % (credential_id,))
    status_nodes = {_nquad_node(t[2]) for t in terms
                    if len(t) == 3 and t[0] == subject and t[1] == _SD_STATUS}
    for index, term in enumerate(terms):
        lifecycle = len(term) != 3 or term[0] in status_nodes or (
            term[0] == subject and term[1] in _SD_LIFECYCLE)
        if lifecycle and index not in mandatory:
            raise OB3VerificationError(
                "ecdsa-sd-2023 credential discloses validFrom, validUntil or "
                "credentialStatus statements its issuer did not make "
                "mandatory, so a holder could have withheld others (a "
                "status entry, or a member of one such as statusSize) "
                "undetected; the issuer must list /validFrom, /validUntil "
                "and /credentialStatus as mandatory pointers")


def _nquad_node(rest: str) -> Optional[str]:
    """The object of an N-Quad (everything after its predicate) when it is
    a node -- ``<iri>`` or a ``_:label`` -- spelled as in the subject
    position, else None (a literal)."""
    if rest.startswith('<'):
        return rest[:rest.find('>') + 1]
    if rest.startswith('_:'):
        return rest.split(' ', 1)[0]
    return None


def _sd_disclosed_statements(doc: dict[str, Any], proof: dict[str, Any]
                             ) -> Tuple[List[str], Set[int]]:
    """The statements a derived ecdsa-sd-2023 proof discloses, exactly as
    openvc-core's verify indexes them (canonical N-Quads, blank nodes
    relabeled through the proof's label map, sorted), and the indexes of
    the mandatory ones. openvc's own helpers, so the indexes cannot drift
    from what its verify checked; if it stops exposing them, fail closed."""
    _require_openvc_ecdsa_sd()
    try:
        from openvc.proof import ecdsa_sd
        from openvc.proof.contexts import document_loader as openvc_loader
        decode = ecdsa_sd.decode_derived_proof
        to_nquads = ecdsa_sd._to_nquads
        deskolemize = ecdsa_sd._deskolemize_nquads
        canonicalize = ecdsa_sd._canonicalize
        relabel = ecdsa_sd._relabel
    except (ImportError, AttributeError) as exc:
        raise OB3VerificationError(
            "this openvc-core does not expose the ecdsa-sd-2023 statement "
            "indexing the mandatory-statement check needs (%s); install a "
            "supported release: pip install -U openbadgeslib[ldp-sd]"
            % (exc,)) from exc
    try:
        parsed = decode(proof['proofValue'])
        unsecured = {k: v for k, v in doc.items() if k != 'proof'}
        loader = openvc_loader(bundled_contexts())
        lines, _ = canonicalize(deskolemize(to_nquads(unsecured, loader)))
        statements = list(relabel(lines, {
            '_:' + k: '_:' + v for k, v in parsed['label_map'].items()}))
        mandatory = set(parsed['mandatory_indexes'])
        signatures = len(parsed['signatures'])
    except Exception as exc:
        raise OB3VerificationError(
            "cannot read the mandatory statements of the ecdsa-sd-2023 "
            "proof: %s" % (str(exc)[:300],)) from exc
    # The delegate verified the mandatory statements by index and one
    # signature per other statement: a view with an index outside it, or
    # that disagrees on that count, is not the one it verified.
    if (not all(isinstance(i, int) and 0 <= i < len(statements)
                for i in mandatory)
            or len(statements) - len(mandatory) != signatures):
        raise OB3VerificationError(
            "the ecdsa-sd-2023 statements do not match what the proof signs")
    return statements, mandatory


class OB3LdpVerifier:
    """Verifies OpenBadges 3.0 credentials secured with a Data Integrity
    (Linked Data Proof) embedded proof — cryptosuites eddsa-rdfc-2022 and,
    for selective-disclosure credentials, ecdsa-sd-2023 (verify delegated to
    openvc-core). A derived ecdsa-sd-2023 proof reveals only the mandatory plus
    holder-disclosed statements, so the reconstructed credential reflects just
    what the holder chose to show -- except for ``validFrom``, ``validUntil``
    and ``credentialStatus``, which must be disclosed and mandatory.

    Mirrors :class:`OB3Verifier` (the JWT-VC verifier) in API and trust
    model, for the other proof format OB 3.0 allows:

    * With ``pubkey_pem`` the proof must verify against that operator-trusted
      key; the proof's ``verificationMethod`` is not resolved.
    * Without it, the key is resolved from ``proof.verificationMethod``
      (did:key offline, did:web over HTTPS). A did:key is self-asserted — it
      proves internal consistency, not issuer identity — so callers should
      treat it as untrusted unless the DID itself is trusted.

    eddsa-rdfc-2022 needs the optional ``[ldp]`` extra (pyld); ecdsa-sd-2023
    needs ``[ldp-sd]`` (openvc-core). The required extra is imported lazily at
    verification time; constructing the verifier works without either.
    """

    def __init__(self, pubkey_pem: Any = None,
                 issuer_did: Optional[str] = None) -> None:
        self.pubkey_pem: Optional[Union[str, bytes]] = \
            key_to_pem(pubkey_pem) if pubkey_pem is not None else None
        self._anchored_did = issuer_did
        # verificationMethod -> resolved PEM, memoized per instance so verifying
        # many credentials from the same issuer does not re-fetch the did:web
        # document each time (the JWT verifier already memoizes its did doc).
        self._vm_pem_cache: Dict[str, bytes] = {}

    @classmethod
    def for_issuer_did(cls, did: str, download: Any = None) -> "OB3LdpVerifier":
        """Anchor verification to an issuer DID: the credential's issuer and
        the proof's verificationMethod must both belong to *did*, whose key
        material is resolved at verify() time (the proof names the concrete
        verification method)."""
        del download   # resolution happens per-proof in verify()
        return cls(pubkey_pem=None, issuer_did=did)

    def verify(self, document: Union[str, bytes, dict[str, Any]],
               expected_recipient: Optional[str] = None,
               check_status: bool = False,
               download: Any = None, *,
               verify_status_list: bool = True) -> OpenBadgeCredential:
        """Verify a Data Integrity OB3 credential document.

        *document* is the credential as a JSON string/bytes (e.g. extracted
        from a baked image) or an already-parsed dict. Returns the
        reconstructed :class:`OpenBadgeCredential`; raises
        :class:`OB3VerificationError` on any failure. ``expected_recipient``,
        ``check_status`` and ``verify_status_list`` behave exactly as in
        :meth:`OB3Verifier.verify` — when status is checked the status list's
        own signature is verified too (reusing a pinned key, or resolving the
        issuer DID), unless ``verify_status_list=False``. ``download`` resolves
        a did:web verificationMethod and status list issuer DID (injectable for
        testing). An ``ecdsa-sd-2023`` presentation that omits ``validFrom``,
        ``validUntil`` or ``credentialStatus`` is rejected so a holder cannot
        hide a future start, expiry or revocation (#328), and so is one whose
        disclosed ``validFrom``, ``validUntil`` or ``credentialStatus``
        statements the issuer did not make mandatory: a holder could
        otherwise withhold them, one status entry, or a member of one,
        undetected. Issuers must list ``/validFrom``, ``/validUntil`` and
        ``/credentialStatus`` as mandatory pointers.

        Before reading anything from the JSON, the document must be exactly
        the compacted form of the RDF dataset its proof signs, under the
        pinned contexts alone (context validation): an inline ``@context``
        object, a member re-keyed to its IRI, a value its term cannot carry
        (an untyped ``validUntil``, kept under the full IRI by compaction
        itself), a member the policy reads spelled by its IRI because its
        context is not bundled (a VC 1.1 ``expirationDate``, a
        ``StatusList2021Entry``), ``@included``/``@reverse``/a
        top-level ``@graph``, a re-description of the credential's own node,
        or anything the RDF conversion drops (relative or malformed IRIs,
        undefined terms) is rejected.
        """
        doc = self._parse_document(document)

        _check_vc_types(doc)
        # Fields the RDF-canonicalized proof cannot cover (VC 1.1 date aliases,
        # legacy StatusList2021Entry) are unsigned in this path — reject them so
        # a holder cannot un-expire / un-revoke a signed credential (#205).
        _reject_unsigned_ldp_aliases(doc)

        proof = _select_proof(doc)
        _validate_proof(proof, 'assertionMethod')
        # Before resolving keys or running crypto: an SD presentation that hid
        # its start/expiry/revocation is already a fail, regardless of the
        # proof.
        _reject_hidden_sd_lifecycle(doc, proof)

        # The proof signs the RDF dataset; the model and every policy check
        # below read the JSON. Require the JSON to be exactly the compacted
        # form of what is signed (no re-keyed or aliased member, no dropped
        # node or term, no @included/@reverse/re-described credential node)
        # BEFORE reading anything from it — for both cryptosuites, ahead of
        # the ecdsa-sd-2023 delegation too. It also runs before the key is
        # resolved, deliberately: a malformed document never triggers a
        # did:web fetch. The cost is CPU on unauthenticated input, bounded by
        # MAX_LDP_DOCUMENT_BYTES and near-linear in the document: every
        # @context the JSON-LD processor applies, at any depth, is bounded
        # before it runs, and the embedded credentials, each validated again
        # on its own, by number, depth and total size (_context_validation),
        # so at most about twice the passes over the document itself. (RDF
        # canonicalization, which verify_data_integrity_proof runs below, is
        # NOT near-linear: it has its own work budget, _canon_guard.py.)
        _check_json_ld_form(doc, proof, document_loader())

        try:
            credential = OpenBadgeCredential.from_vc_document(doc)
        except (KeyError, ValueError, TypeError) as exc:
            raise OB3VerificationError(
                "Malformed credential document: %s" % exc) from exc

        vm = proof['verificationMethod']
        vm_did = vm.partition('#')[0]
        if self._anchored_did is not None:
            if credential.issuer.id != self._anchored_did:
                raise OB3VerificationError(
                    "Credential issuer %r does not match the DID the verifier "
                    "was anchored to (%r)"
                    % (credential.issuer.id, self._anchored_did))
            if vm_did != self._anchored_did:
                raise OB3VerificationError(
                    "proof verificationMethod %r does not belong to the "
                    "anchored DID %r" % (vm, self._anchored_did))

        if self.pubkey_pem is not None:
            pem: Union[str, bytes] = self.pubkey_pem
        else:
            # No pinned key: the proof's verificationMethod is the key source,
            # so it must be bound to the credential's issuer — otherwise any
            # keyholder could re-sign someone else's credential and it would
            # verify. A DID issuer must own the method. A non-DID issuer (an
            # https:/urn: id) offers nothing to bind the method to, so there is
            # no trust anchor at all: resolving and trusting whatever key the
            # proof names would prove internal consistency, not who issued the
            # credential. Fail closed — the caller must pin a key or use a DID.
            issuer_id = credential.issuer.id
            if not issuer_id.startswith('did:'):
                raise OB3VerificationError(
                    "cannot verify a Data Integrity credential whose issuer %r "
                    "is not a DID without a pinned key: the proof's "
                    "verificationMethod %r cannot be bound to the issuer — pass "
                    "pubkey_pem or use a DID issuer" % (issuer_id, vm))
            if vm_did != issuer_id:
                raise OB3VerificationError(
                    "proof verificationMethod %r does not belong to the "
                    "credential issuer %r" % (vm, issuer_id))
            pem = self._resolve_vm(vm, download)

        verify_data_integrity_proof(doc, pem)
        # ecdsa-sd-2023: the disclosed lifecycle statements must be ones the
        # base signature covers as a whole, or a holder could have withheld
        # part of them (a status entry, a statusSize) undetected.
        _reject_selective_sd_lifecycle(doc, proof)

        _check_validity_window(credential)

        if check_status:
            from .status import check_credential_status
            # Verify the status list's own signature by default, binding it to
            # the badge issuer. A pinned key is reused (publish signs the list
            # with the same key); otherwise the list issuer DID is resolved.
            check_credential_status(
                credential, download=download, verify_list=verify_status_list,
                list_pubkey_pem=self.pubkey_pem)

        _check_recipient(credential, expected_recipient)

        return credential

    def _resolve_vm(self, vm: str, download: Any) -> bytes:
        """Resolve a verificationMethod to a PEM key, memoized per instance.

        Keyed by the exact vm id. The vm↔issuer binding is checked by the
        caller before this runs, so only methods already authorised for this
        credential's issuer are ever resolved or cached — a verifier reused
        across issuers keeps a separate entry per method."""
        cached = self._vm_pem_cache.get(vm)
        if cached is not None:
            return cached
        pem = resolve_verification_method(vm, download=download)
        self._vm_pem_cache[vm] = pem
        return pem

    @staticmethod
    def _parse_document(document: Union[str, bytes, dict[str, Any]]) -> dict[str, Any]:
        """Normalize/parse the input document, bounding its size first.

        A document nested deeper than the interpreter can recurse fails with
        :class:`OB3VerificationError`, never a bare ``RecursionError``."""
        if isinstance(document, dict):
            try:
                # Before json.dumps and the copy below: nesting past
                # _safejson's bound, a lone surrogate (UnicodeEncodeError when
                # hashed) or a non-finite number.
                check_json(document)
                raw_len = len(json.dumps(document))
            except (TypeError, ValueError, RecursionError) as exc:
                raise OB3VerificationError(
                    "credential document is not plain JSON: %s" % exc) from exc
        else:
            raw_len = len(document)
        if raw_len > MAX_LDP_DOCUMENT_BYTES:
            raise OB3VerificationError(
                "credential document exceeds the %d-byte limit"
                % MAX_LDP_DOCUMENT_BYTES)

        if isinstance(document, dict):
            try:
                return copy.deepcopy(document)
            except RecursionError as exc:
                raise OB3VerificationError(
                    "credential document is nested too deeply") from exc
        try:
            text = document.decode('utf-8') if isinstance(document, bytes) \
                else document
            parsed = loads_untrusted(text)
        except (RecursionError, JSONTooDeepError) as exc:
            raise OB3VerificationError(
                "credential document is nested too deeply") from exc
        except (ValueError, UnicodeDecodeError) as exc:
            raise OB3VerificationError(
                "credential document is not valid JSON: %s" % exc) from exc
        if not isinstance(parsed, dict):
            raise OB3VerificationError(
                "credential document must be a JSON object")
        return parsed


class OB3LdpSigner:
    """Signs OpenBadges 3.0 credentials with an embedded Data Integrity
    proof (cryptosuite eddsa-rdfc-2022) — the issuance counterpart of
    :class:`OB3LdpVerifier`, and the Linked-Data sibling of
    :class:`OB3Signer` (which produces compact JWT-VCs).

    Args:
        privkey_pem: PEM-encoded Ed25519 private key (bytes, str, or a
                     cryptography key object). eddsa-rdfc-2022 admits no
                     other key type, so anything else fails here, at
                     construction, not at first sign.
        verification_method:
                     proof ``verificationMethod`` URL embedded in every
                     proof. ``None`` derives a did:key from the signing
                     key's public half — self-asserted: it proves the proof
                     matches the key, not who owns it. Issuers publishing a
                     DID document (did:web) should pass the method id it
                     publishes, e.g. ``did:web:host#badge_1``, so verifiers
                     resolve a trusted key.

    Requires the optional ``[ldp]`` extra (``pip install openbadgeslib[ldp]``)
    at signing time; constructing the signer works without it.
    """

    def __init__(self, privkey_pem: Any,
                 verification_method: Optional[str] = None) -> None:
        pem = key_to_pem(privkey_pem)
        pem_bytes = pem.encode('utf-8') if isinstance(pem, str) else pem
        try:
            key_type = detect_key_type(pem_bytes)
        except Exception as exc:
            raise ErrorSigningFile('unusable signing key: %s' % exc) from exc
        if key_type is not KeyType.ED25519:
            raise ErrorSigningFile(
                'eddsa-rdfc-2022 requires an Ed25519 signing key, got %s'
                % key_type.value)
        self.privkey_pem: bytes = pem_bytes
        if verification_method is None:
            verification_method = self._did_key_vm(pem_bytes)
        self.verification_method = verification_method

    @staticmethod
    def _did_key_vm(privkey_pem: bytes) -> str:
        """did:key verification method of the key's public half. Derived
        from the PRIVATE key, so a stale public-key file on disk can never
        produce an unverifiable badge."""
        from cryptography.hazmat.primitives.serialization import \
            load_pem_private_key
        pub = load_pem_private_key(privkey_pem, password=None).public_key()
        did = did_key_from_pem(_public_key_to_pem(pub))
        # The did:key method spec: the only valid fragment is the multibase
        # identifier itself (resolve_verification_method enforces this).
        return '%s#%s' % (did, did[len('did:key:'):])

    # ── core signing ─────────────────────────────────────────────────────────

    def sign(self, credential: OpenBadgeCredential, *,
             created: Optional[datetime] = None) -> dict[str, Any]:
        """Sign a credential and return the secured VC document (dict) —
        the credential JSON with the DataIntegrityProof embedded under
        ``proof``. *created* defaults to now (UTC).

        Raises :class:`ErrorSigningFile` rather than emit a document whose
        JSON the proof does not fully cover (e.g. an id that is not an
        absolute IRI, or a member no pinned context defines) — the same
        context validation :class:`OB3LdpVerifier` applies — or one larger,
        as :meth:`sign_to_json` serializes it, than the
        ``MAX_LDP_DOCUMENT_BYTES`` verifiers accept."""
        signed = add_data_integrity_proof(
            credential.to_vc(), self.privkey_pem, self.verification_method,
            created=created)
        # Measure exactly the text sign_to_json emits (and baking embeds), so
        # anything issued here is within the limit the verifier applies to it.
        size = len(json.dumps(signed, sort_keys=True, ensure_ascii=True))
        if size > MAX_LDP_DOCUMENT_BYTES:
            raise ErrorSigningFile(
                'credential exceeds the %d-byte limit verifiers accept '
                '(%d bytes serialized)' % (MAX_LDP_DOCUMENT_BYTES, size))
        try:
            _check_json_ld_form(signed, signed['proof'], document_loader())
        except OB3VerificationError as exc:
            raise ErrorSigningFile(
                'refusing to issue a Data Integrity credential whose JSON its '
                'proof does not cover: %s' % exc) from exc
        return signed

    def sign_to_json(self, credential: OpenBadgeCredential, *,
                     created: Optional[datetime] = None) -> str:
        """Sign and serialize — exactly the text a baked image carries."""
        return json.dumps(self.sign(credential, created=created),
                          sort_keys=True, ensure_ascii=True)

    # ── image baking ─────────────────────────────────────────────────────────

    def sign_into_svg(self, credential: OpenBadgeCredential,
                      svg_bytes: bytes) -> bytes:
        """Embed a Data-Integrity-signed credential into an SVG badge image.

        The JSON document is stored as the text content of the OB 3.0
        ``<openbadges:credential>`` element (a JWT-VC travels in its
        ``verify`` attribute instead); the verifier auto-detects the format.
        """
        text = self.sign_to_json(credential)
        try:
            return baking.bake_svg(
                svg_bytes, text,
                comment=' Signed with OpenBadgesLib %s (OB 3.0 Data '
                        'Integrity) ' % __version__,
                element=baking.SVG_ELEMENT_OB3, namespace=baking.SVG_NS_OB3,
                as_text=True)
        except Exception as exc:
            raise ErrorSigningFile(
                'Unable to bake SVG credential: %s' % exc) from exc

    def sign_into_png(self, credential: OpenBadgeCredential,
                      png_bytes: bytes) -> bytes:
        """Embed a Data-Integrity-signed credential into a PNG badge image,
        as an ``iTXt`` chunk with the OB 3.0 keyword ``openbadgecredential``
        (same carrier as a JWT-VC; the content format tells them apart)."""
        text = self.sign_to_json(credential)
        try:
            return baking.bake_png(png_bytes, text,
                                   keyword=baking.ITXT_KEYWORD_OB3)
        except Exception as exc:
            raise ErrorSigningFile(
                'Unable to bake PNG credential: %s' % exc) from exc
