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

# Verification of OpenBadges 3.0 credentials secured with a W3C Data
# Integrity proof (the OB 3.0 "Linked Data Proof" format) — the counterpart
# of the JWT-VC verifier for the other proof format the spec allows.
#
# Verify-only by design: openbadgeslib issues VC-JWT. Supported cryptosuite:
# eddsa-rdfc-2022 (W3C Recommendation vc-di-eddsa). The verification
# algorithm: RDFC-1.0-canonicalize the document without its proof and the
# proof options without proofValue (with the document's @context); hashData =
# SHA-256(proof config) || SHA-256(document); Ed25519-verify the 64-byte
# multibase proofValue signature over hashData.
#
# JSON-LD canonicalization needs a JSON-LD processor, so this module depends
# on the optional [ldp] extra (pyld) — imported lazily with an actionable
# error, everything else in the package works without it. @context documents
# are NEVER fetched from the network: canonicalization uses the bundled
# allowlisted contexts (see ob3/contexts).

import copy
import hashlib
import json

from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Union

from ..keys import KeyType, detect_key_type, key_to_pem
from .contexts import UnknownContextError, document_loader
from .credential import OpenBadgeCredential, _parse_iso
from .did import _b58btc_decode, resolve_verification_method
from .verifier import (OB3VerificationError, _check_recipient,
                       _check_validity_window, _check_vc_types)

#: Upper bound on a Data Integrity credential document. RDF canonicalization
#: cost grows super-linearly on hostile blank-node graphs ("poison graphs"),
#: and the document is untrusted input — cap it well above any real badge
#: (coherent with baking.MAX_ITXT_DECOMPRESSED).
MAX_LDP_DOCUMENT_BYTES = 256 * 1024


def _require_jsonld() -> Any:
    """Import pyld lazily, failing with an actionable message without it."""
    try:
        from pyld import jsonld
    except ImportError as exc:
        raise OB3VerificationError(
            "Data Integrity (Linked Data Proof) verification requires the "
            "optional 'pyld' dependency; install it with: "
            "pip install openbadgeslib[ldp]") from exc
    return jsonld


def _select_proof(document: dict) -> dict:
    """Pick the single supported DataIntegrityProof from ``proof``.

    ``proof`` may be an object or an array. Exactly one entry with a
    supported cryptosuite must be present: none fails closed naming what was
    found, and more than one is rejected as ambiguous rather than guessing
    which signature speaks for the credential.
    """
    raw = document.get('proof')
    proofs = raw if isinstance(raw, list) else [raw] if raw is not None else []
    candidates = [
        p for p in proofs
        if isinstance(p, dict) and p.get('type') == 'DataIntegrityProof'
        and p.get('cryptosuite') in _CRYPTOSUITES
    ]
    if not candidates:
        found = sorted({
            str(p.get('cryptosuite') or p.get('type'))
            for p in proofs if isinstance(p, dict)
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


def _validate_proof(proof: dict, expected_proof_purpose: str) -> None:
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
        except (ValueError, TypeError) as exc:
            raise OB3VerificationError(
                "invalid proof.created date: %r" % (created,)) from exc
    expires = proof.get('expires')
    if expires is not None:
        try:
            expires_dt = _parse_iso(expires)
        except (ValueError, TypeError) as exc:
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


def _canonize(document: dict, loader: Any) -> str:
    """RDFC-1.0-canonicalize a JSON-LD document to N-Quads via pyld.

    pyld implements the algorithm under its pre-standardisation name
    URDNA2015; the W3C renamed it RDFC-1.0 with unchanged output.
    """
    jsonld = _require_jsonld()
    try:
        return str(jsonld.normalize(document, {
            'algorithm': 'URDNA2015',
            'format': 'application/n-quads',
            'documentLoader': loader,
        }))
    except Exception as exc:
        cause: Optional[BaseException] = exc
        while cause is not None:                    # unwrap pyld's JsonLdError
            if isinstance(cause, UnknownContextError):
                raise OB3VerificationError(str(cause)) from exc
            cause = cause.__cause__
        raise OB3VerificationError(
            "could not canonicalize the credential: %s" % exc) from exc


def _hash_data(unsecured_doc: dict, proof_config: dict, loader: Any) -> bytes:
    """hashData per vc-di-eddsa: SHA-256(proof config) || SHA-256(document)."""
    config_hash = hashlib.sha256(
        _canonize(proof_config, loader).encode('utf-8')).digest()
    doc_hash = hashlib.sha256(
        _canonize(unsecured_doc, loader).encode('utf-8')).digest()
    return config_hash + doc_hash


def _verify_eddsa_rdfc_2022(document: dict, proof: dict, pubkey_pem: bytes,
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


#: Registry of supported cryptosuites. ecdsa-sd-2023 (selective disclosure)
#: is deliberately absent — deferred until there is real interop demand; an
#: unknown suite fails closed naming the supported ones.
_CRYPTOSUITES: Dict[str, Callable[[dict, dict, bytes, Any], None]] = {
    'eddsa-rdfc-2022': _verify_eddsa_rdfc_2022,
}


def verify_data_integrity_proof(
        document: dict, pubkey_pem: Any, *,
        expected_proof_purpose: str = 'assertionMethod',
        extra_contexts: Optional[Mapping[str, dict]] = None) -> None:
    """Verify the embedded Data Integrity proof of a JSON-LD document.

    Low-level building block: checks ONLY the proof (canonicalization,
    hashing, signature) against *pubkey_pem*, imposing no OB3 schema — which
    lets it run e.g. the official W3C vc-di-eddsa test vectors. Most callers
    want :class:`OB3LdpVerifier` instead, which adds the OpenBadgeCredential
    validation, trust binding, validity window, status and recipient checks.

    *extra_contexts* extends the bundled @context allowlist for this call
    only (contexts are never fetched from the network). Raises
    :class:`OB3VerificationError` on any failure.
    """
    if not isinstance(document, dict):
        raise OB3VerificationError("credential document must be a JSON object")
    proof = _select_proof(document)
    _validate_proof(proof, expected_proof_purpose)
    loader = document_loader(extra_contexts)
    pem = key_to_pem(pubkey_pem)
    pem_bytes = pem.encode('utf-8') if isinstance(pem, str) else pem
    _CRYPTOSUITES[proof['cryptosuite']](document, proof, pem_bytes, loader)


class OB3LdpVerifier:
    """Verifies OpenBadges 3.0 credentials secured with a Data Integrity
    (Linked Data Proof) embedded proof — cryptosuite eddsa-rdfc-2022.

    Mirrors :class:`OB3Verifier` (the JWT-VC verifier) in API and trust
    model, for the other proof format OB 3.0 allows:

    * With ``pubkey_pem`` the proof must verify against that operator-trusted
      key; the proof's ``verificationMethod`` is not resolved.
    * Without it, the key is resolved from ``proof.verificationMethod``
      (did:key offline, did:web over HTTPS). A did:key is self-asserted — it
      proves internal consistency, not issuer identity — so callers should
      treat it as untrusted unless the DID itself is trusted.

    Requires the optional ``[ldp]`` extra (``pip install openbadgeslib[ldp]``)
    at verification time; constructing the verifier works without it.
    """

    def __init__(self, pubkey_pem: Any = None,
                 issuer_did: Optional[str] = None) -> None:
        self.pubkey_pem: Optional[Union[str, bytes]] = \
            key_to_pem(pubkey_pem) if pubkey_pem is not None else None
        self._anchored_did = issuer_did

    @classmethod
    def for_issuer_did(cls, did: str, download: Any = None) -> "OB3LdpVerifier":
        """Anchor verification to an issuer DID: the credential's issuer and
        the proof's verificationMethod must both belong to *did*, whose key
        material is resolved at verify() time (the proof names the concrete
        verification method)."""
        del download   # resolution happens per-proof in verify()
        return cls(pubkey_pem=None, issuer_did=did)

    def verify(self, document: Union[str, bytes, dict],
               expected_recipient: Optional[str] = None,
               check_status: bool = False,
               download: Any = None) -> OpenBadgeCredential:
        """Verify a Data Integrity OB3 credential document.

        *document* is the credential as a JSON string/bytes (e.g. extracted
        from a baked image) or an already-parsed dict. Returns the
        reconstructed :class:`OpenBadgeCredential`; raises
        :class:`OB3VerificationError` on any failure. ``expected_recipient``
        and ``check_status`` behave exactly as in :meth:`OB3Verifier.verify`.
        ``download`` is used only to resolve a did:web verificationMethod
        (injectable for testing).
        """
        doc = self._parse_document(document)

        _check_vc_types(doc)
        try:
            credential = OpenBadgeCredential.from_vc_document(doc)
        except (KeyError, ValueError, TypeError) as exc:
            raise OB3VerificationError(
                "Malformed credential document: %s" % exc) from exc

        proof = _select_proof(doc)
        _validate_proof(proof, 'assertionMethod')

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
            # No pinned key: the proof's verificationMethod is the key source.
            # If the credential names a DID issuer, the method must belong to
            # it — otherwise any keyholder could re-sign someone's credential.
            if credential.issuer.id.startswith('did:') \
                    and vm_did != credential.issuer.id:
                raise OB3VerificationError(
                    "proof verificationMethod %r does not belong to the "
                    "credential issuer %r" % (vm, credential.issuer.id))
            pem = resolve_verification_method(vm, download=download)

        verify_data_integrity_proof(doc, pem)

        _check_validity_window(credential)

        if check_status:
            from .status import check_credential_status
            check_credential_status(credential)

        _check_recipient(credential, expected_recipient)

        return credential

    @staticmethod
    def _parse_document(document: Union[str, bytes, dict]) -> dict:
        """Normalize/parse the input document, bounding its size first."""
        if isinstance(document, dict):
            raw_len = len(json.dumps(document))
        else:
            raw_len = len(document)
        if raw_len > MAX_LDP_DOCUMENT_BYTES:
            raise OB3VerificationError(
                "credential document exceeds the %d-byte limit"
                % MAX_LDP_DOCUMENT_BYTES)

        if isinstance(document, dict):
            return copy.deepcopy(document)
        try:
            text = document.decode('utf-8') if isinstance(document, bytes) \
                else document
            parsed = json.loads(text)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OB3VerificationError(
                "credential document is not valid JSON: %s" % exc) from exc
        if not isinstance(parsed, dict):
            raise OB3VerificationError(
                "credential document must be a JSON object")
        return parsed
