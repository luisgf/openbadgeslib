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

# DID resolution for OB3 issuer identity. Turns an issuer's DID into a PEM
# public verification key, so a JWT-VC can be verified without the operator
# supplying the key out-of-band.
#
# Supported methods:
#   did:key  — self-certifying: the public key IS encoded in the identifier
#              (multibase base58btc of a multicodec-prefixed key). No network.
#   did:web  — trusts DNS + TLS for the host: fetches the DID document over
#              HTTPS and reads its first verification method.
#
# Trust note: did:key needs no external trust (the key is the identifier).
# did:web is only as trustworthy as the host's DNS and TLS. Neither is a
# ledger/anchored method; did:ion, did:ethr, etc. are out of scope.

import json

from typing import Any

from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwt.algorithms import OKPAlgorithm, ECAlgorithm, RSAAlgorithm

from .verifier import OB3VerificationError
from ..util import download_file

# multicodec codes (unsigned varint) for the public key types we accept.
_MULTICODEC_ED25519_PUB = 0xed    # followed by 32 raw bytes
_MULTICODEC_P256_PUB = 0x1200     # followed by a 33-byte compressed point

_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def resolve_did(did: str, download: Any = None) -> bytes:
    """Resolve a DID to a PEM-encoded public key.

    Supports did:key (offline) and did:web (one HTTPS fetch). Raises
    OB3VerificationError for an unsupported method or any resolution failure.
    ``download`` defaults to util.download_file; it is injectable for testing.
    """
    if not isinstance(did, str) or not did.startswith('did:'):
        raise OB3VerificationError("not a DID: %r" % (did,))
    fetch = download if download is not None else download_file
    if did.startswith('did:key:'):
        return _resolve_did_key(did)
    if did.startswith('did:web:'):
        return _resolve_did_web(did, fetch)
    raise OB3VerificationError("unsupported DID method: %r" % did)


# ── did:key ──────────────────────────────────────────────────────────────────

def _resolve_did_key(did: str) -> bytes:
    ident = did[len('did:key:'):]
    if not ident.startswith('z'):
        raise OB3VerificationError("did:key must use base58btc multibase (z…)")
    return _multicodec_pubkey_to_pem(_b58btc_decode(ident[1:]))


def _multicodec_pubkey_to_pem(data: bytes) -> bytes:
    """Decode a multicodec-prefixed public key (as used by did:key and
    publicKeyMultibase) into a SubjectPublicKeyInfo PEM."""
    code, rest = _read_varint(data)
    try:
        if code == _MULTICODEC_ED25519_PUB:
            return _public_key_to_pem(Ed25519PublicKey.from_public_bytes(rest))
        if code == _MULTICODEC_P256_PUB:
            return _public_key_to_pem(
                ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), rest))
    except ValueError as exc:
        raise OB3VerificationError("malformed did:key public key: %s" % exc) from exc
    raise OB3VerificationError("unsupported did:key multicodec 0x%x" % code)


def _b58btc_decode(value: str) -> bytes:
    num = 0
    for ch in value:
        idx = _B58_INDEX.get(ch)
        if idx is None:
            raise OB3VerificationError("invalid base58btc character %r" % ch)
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
    n_pad = len(value) - len(value.lstrip('1'))   # leading '1' => leading 0x00
    return b'\x00' * n_pad + body


def _read_varint(data: bytes) -> Any:
    result = shift = 0
    for i, byte in enumerate(data):
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, data[i + 1:]
        shift += 7
    raise OB3VerificationError("truncated multicodec varint")


# ── did:web ──────────────────────────────────────────────────────────────────

def _resolve_did_web(did: str, fetch: Any) -> bytes:
    from urllib.parse import unquote
    ident = did[len('did:web:'):]
    if not ident:
        raise OB3VerificationError("empty did:web identifier")
    parts = [unquote(p) for p in ident.split(':')]
    host, path_segments = parts[0], parts[1:]
    if path_segments:
        url = 'https://%s/%s/did.json' % (host, '/'.join(path_segments))
    else:
        url = 'https://%s/.well-known/did.json' % host

    try:
        raw = fetch(url)
    except Exception as exc:
        raise OB3VerificationError(
            "could not fetch DID document %s: %s" % (url, exc)) from exc
    try:
        doc = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as exc:
        raise OB3VerificationError(
            "malformed DID document at %s: %s" % (url, exc)) from exc
    return _pem_from_did_document(doc)


def _pem_from_did_document(doc: Any) -> bytes:
    if not isinstance(doc, dict):
        raise OB3VerificationError("DID document is not a JSON object")
    methods = doc.get('verificationMethod')
    if not isinstance(methods, list) or not methods:
        raise OB3VerificationError("DID document has no verificationMethod")
    vm = methods[0]
    if not isinstance(vm, dict):
        raise OB3VerificationError("verificationMethod entry is not an object")

    jwk = vm.get('publicKeyJwk')
    if isinstance(jwk, dict):
        return _jwk_to_pem(jwk)
    multibase = vm.get('publicKeyMultibase')
    if isinstance(multibase, str) and multibase.startswith('z'):
        return _multicodec_pubkey_to_pem(_b58btc_decode(multibase[1:]))
    raise OB3VerificationError(
        "verificationMethod has no supported public key encoding "
        "(publicKeyJwk or z-base58 publicKeyMultibase)")


def _jwk_to_pem(jwk: dict) -> bytes:
    kty = jwk.get('kty')
    jwk_json = json.dumps(jwk)
    key: Any
    try:
        if kty == 'OKP':
            key = OKPAlgorithm.from_jwk(jwk_json)
        elif kty == 'EC':
            key = ECAlgorithm.from_jwk(jwk_json)
        elif kty == 'RSA':
            key = RSAAlgorithm.from_jwk(jwk_json)
        else:
            raise OB3VerificationError("unsupported JWK kty: %r" % (kty,))
    except OB3VerificationError:
        raise
    except Exception as exc:
        raise OB3VerificationError("malformed publicKeyJwk: %s" % exc) from exc
    # A public JWK yields a public key; guard against a private one just in case.
    if hasattr(key, 'public_bytes'):
        return _public_key_to_pem(key)
    return _public_key_to_pem(key.public_key())


def _public_key_to_pem(key: Any) -> bytes:
    return key.public_bytes(
        _serialization.Encoding.PEM,
        _serialization.PublicFormat.SubjectPublicKeyInfo)
