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

from .. import baking
from ..errors import ErrorSigningFile
from ..keys import KeyType, detect_key_type, key_to_pem
from ..util import __version__
from .contexts import UnknownContextError, bundled_contexts, document_loader
from .credential import OpenBadgeCredential, _iso, _parse_iso
from .did import (_b58btc_decode, _b58btc_encode, _public_key_to_pem,
                  did_key_from_pem, resolve_verification_method)
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
            "Data Integrity (Linked Data Proof) support requires the "
            "optional 'pyld' dependency; install it with: "
            "pip install openbadgeslib[ldp]") from exc
    return jsonld


def _select_proof(document: dict[str, Any]) -> dict[str, Any]:
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


def _canonize(document: dict[str, Any], loader: Any) -> str:
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


def _hash_data(unsecured_doc: dict[str, Any], proof_config: dict[str, Any], loader: Any) -> bytes:
    """hashData per vc-di-eddsa: SHA-256(proof config) || SHA-256(document)."""
    config_hash = hashlib.sha256(
        _canonize(proof_config, loader).encode('utf-8')).digest()
    doc_hash = hashlib.sha256(
        _canonize(unsecured_doc, loader).encode('utf-8')).digest()
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
        from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
        from openvc.proof.errors import ProofError
    except ImportError as exc:
        raise OB3VerificationError(
            "verifying ecdsa-sd-2023 (selective-disclosure) Data Integrity "
            "proofs requires the optional openvc-core dependency; install it "
            "with: pip install openbadgeslib[ldp-sd]") from exc
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


def _verify_ecdsa_sd_2023(document: dict[str, Any], proof: dict[str, Any],
                          pubkey_pem: bytes, loader: Any) -> None:
    """Verify one ecdsa-sd-2023 derived proof by delegating to openvc-core.

    openvc-core owns the whole selective-disclosure verification — its own RDF
    canonicalization plus the base and per-statement P-256 signatures;
    openbadgeslib only resolves/pins the key and feeds its pinned OB3 @context
    allowlist, so canonicalization is fail-closed and never touches the network.
    *loader* (openbadgeslib's own pyld loader) is unused here — the delegate
    canonicalizes with its engine.
    """
    del loader
    EcdsaSdProofSuite, ProofError = _require_openvc_ecdsa_sd()
    public_key_jwk = _p256_pem_to_jwk(pubkey_pem)
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
    """
    if not isinstance(document, dict):
        raise OB3VerificationError("credential document must be a JSON object")
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
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if not isinstance(document, dict):
        raise ErrorSigningFile('credential document must be a JSON object')
    if 'proof' in document:
        raise ErrorSigningFile('document already carries a proof; refusing '
                               'to add a second one')
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
    fail closed on the legacy shapes.
    """
    for alias in ("expirationDate", "issuanceDate"):
        if alias in doc:
            raise OB3VerificationError(
                "Data Integrity credential carries %r, which the RDF-"
                "canonicalized proof does not sign; use validUntil/validFrom"
                % alias)
    status = doc.get("credentialStatus")
    for entry in (status if isinstance(status, list) else [status]):
        if not isinstance(entry, dict):
            continue
        types = entry.get("type")
        types = types if isinstance(types, list) else [types]
        if "StatusList2021Entry" in types:
            raise OB3VerificationError(
                "Data Integrity credential uses the legacy StatusList2021Entry "
                "status type, whose pointer the RDF-canonicalized proof does "
                "not sign; use BitstringStatusListEntry")


class OB3LdpVerifier:
    """Verifies OpenBadges 3.0 credentials secured with a Data Integrity
    (Linked Data Proof) embedded proof — cryptosuites eddsa-rdfc-2022 and,
    for selective-disclosure credentials, ecdsa-sd-2023 (verify delegated to
    openvc-core). A derived ecdsa-sd-2023 proof reveals only the mandatory plus
    holder-disclosed statements, so the reconstructed credential reflects just
    what the holder chose to show.

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
        testing).
        """
        doc = self._parse_document(document)

        _check_vc_types(doc)
        # Fields the RDF-canonicalized proof cannot cover (VC 1.1 date aliases,
        # legacy StatusList2021Entry) are unsigned in this path — reject them so
        # a holder cannot un-expire / un-revoke a signed credential (#205).
        _reject_unsigned_ldp_aliases(doc)
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
        ``proof``. *created* defaults to now (UTC)."""
        return add_data_integrity_proof(
            credential.to_vc(), self.privkey_pem, self.verification_method,
            created=created)

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
