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

from typing import Any, Sequence, Tuple

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


#: Bound on base58btc input length. Decoding is O(n^2) in the length (big-int
#: accumulation), and a hostile did:key / publicKeyMultibase in a fetched
#: document could be hundreds of KB; no real multikey exceeds ~70 characters.
_MAX_B58_LEN = 128


def _b58btc_decode(value: str) -> bytes:
    if len(value) > _MAX_B58_LEN:
        raise OB3VerificationError(
            "base58btc value too long: %d characters (max %d)"
            % (len(value), _MAX_B58_LEN))
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


def _b58btc_encode(data: bytes) -> str:
    num = int.from_bytes(data, 'big')
    out = ''
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    n_pad = len(data) - len(data.lstrip(b'\x00'))   # leading 0x00 => leading '1'
    return '1' * n_pad + out


def _write_varint(code: int) -> bytes:
    if code < 0:
        raise ValueError('varint codes are unsigned, got %d' % code)
    out = bytearray()
    while True:
        byte = code & 0x7f
        code >>= 7
        out.append(byte | 0x80 if code else byte)
        if not code:
            return bytes(out)


def multikey_from_pem(pubkey_pem: Any) -> str:
    """Encode a public key PEM as a Multikey ``publicKeyMultibase`` string:
    'z' + base58btc(multicodec varint + raw key bytes) — the exact inverse of
    the did:key/publicKeyMultibase decoding above. Supports Ed25519 (0xed)
    and NIST P-256 (0x1200, compressed point); raises ValueError otherwise
    (this runs issuer-side, on the operator's own key material).
    """
    if isinstance(pubkey_pem, str):
        pubkey_pem = pubkey_pem.encode('utf-8')
    pub = _serialization.load_pem_public_key(pubkey_pem)
    if isinstance(pub, Ed25519PublicKey):
        prefixed = _write_varint(_MULTICODEC_ED25519_PUB) + pub.public_bytes(
            _serialization.Encoding.Raw, _serialization.PublicFormat.Raw)
    elif isinstance(pub, ec.EllipticCurvePublicKey) \
            and isinstance(pub.curve, ec.SECP256R1):
        prefixed = _write_varint(_MULTICODEC_P256_PUB) + pub.public_bytes(
            _serialization.Encoding.X962,
            _serialization.PublicFormat.CompressedPoint)
    else:
        raise ValueError('multikey encoding supports Ed25519 and NIST P-256 '
                         'public keys, got %s' % type(pub).__name__)
    return 'z' + _b58btc_encode(prefixed)


def did_key_from_pem(pubkey_pem: Any) -> str:
    """Derive the did:key identifier of a public key PEM (Ed25519 or P-256).

    Self-certifying: the key IS the identifier, so resolving the returned DID
    with :func:`resolve_did` yields the same key back. Raises ValueError for
    unsupported key types.
    """
    return 'did:key:' + multikey_from_pem(pubkey_pem)


# ── did:web ──────────────────────────────────────────────────────────────────

def _resolve_did_web(did: str, fetch: Any) -> bytes:
    return _pem_from_did_document(_fetch_did_web_document(did, fetch))


def _fetch_did_web_document(did: str, fetch: Any) -> dict:
    """Fetch and parse the DID document a did:web identifier resolves to."""
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
    if not isinstance(doc, dict):
        raise OB3VerificationError("DID document is not a JSON object")
    return doc


def resolve_verification_method(vm_url: str, download: Any = None) -> bytes:
    """Resolve a proof ``verificationMethod`` URL to a PEM public key.

    Unlike :func:`resolve_did` — which takes a bare DID and (for did:web)
    reads the FIRST verification method — this resolves the specific method a
    Data Integrity proof names, typically ``did:...#fragment``:

    * ``did:key``: the key is the identifier itself; a fragment, when present,
      must equal the multibase identifier (per the did:key method spec) or
      resolution fails closed.
    * ``did:web``: the DID document is fetched and the verificationMethod
      entry whose ``id`` equals *vm_url* exactly is used — no match fails
      closed rather than silently trusting a different key.

    Raises OB3VerificationError for unsupported methods or any failure.
    ``download`` defaults to util.download_file; injectable for testing.
    """
    if not isinstance(vm_url, str) or not vm_url.startswith('did:'):
        raise OB3VerificationError(
            "unsupported verificationMethod (expected a did: URL): %r" % (vm_url,))
    fetch = download if download is not None else download_file
    did, _, fragment = vm_url.partition('#')

    if did.startswith('did:key:'):
        ident = did[len('did:key:'):]
        if fragment and fragment != ident:
            raise OB3VerificationError(
                "did:key fragment %r does not name the key %r" % (fragment, ident))
        return _resolve_did_key(did)

    if did.startswith('did:web:'):
        doc = _fetch_did_web_document(did, fetch)
        methods = doc.get('verificationMethod')
        if not isinstance(methods, list) or not methods:
            raise OB3VerificationError("DID document has no verificationMethod")
        for method in methods:
            if isinstance(method, dict) and method.get('id') == vm_url:
                return _pem_from_vm(method)
        raise OB3VerificationError(
            "DID document has no verificationMethod with id %r" % (vm_url,))

    raise OB3VerificationError("unsupported DID method: %r" % did)


def did_web_from_url(url: str) -> str:
    """Derive the did:web identifier whose DID document lives under *url*.

    Exact inverse of the resolution above: the host keeps any port
    percent-encoded, path segments join with ':', and a bare host resolves
    at ``/.well-known/did.json`` while a path resolves at ``<path>/did.json``.
    Raises ValueError for a non-HTTPS or hostless URL — did:web trusts TLS,
    so there is nothing an http:// identifier could safely mean — and for a
    URL carrying userinfo, which a did:web authority must not contain (and
    which would otherwise leak a ``user:password@`` credential into the DID
    embedded in every issued credential).
    """
    from urllib.parse import quote, urlsplit
    parts = urlsplit(url)
    if parts.scheme != 'https':
        raise ValueError('did:web requires an https URL, got %r' % (url,))
    if parts.username or parts.password:
        raise ValueError('did:web URL must not contain userinfo (user:pass@)')
    if not parts.hostname:
        raise ValueError('URL %r has no host' % (url,))
    authority = parts.hostname
    if parts.port is not None:
        authority += ':%d' % parts.port
    pieces = [quote(authority, safe='')]
    pieces += [quote(seg, safe='') for seg in parts.path.split('/') if seg]
    return 'did:web:' + ':'.join(pieces)


def build_did_document(did: str,
                       verification_methods: Sequence[Tuple[str, dict]]
                       ) -> dict:
    """Build a DID document publishing *verification_methods*, given as
    ``(fragment, public JWK)`` pairs (see keys.public_jwk_from_pem).

    Order matters: this resolver — like several others — only reads
    ``verificationMethod[0]``, so the key most verifications need should
    come first.
    """
    if not verification_methods:
        raise ValueError('a DID document needs at least one verification '
                         'method')
    methods = []
    for fragment, jwk in verification_methods:
        methods.append({
            'id': '%s#%s' % (did, fragment),
            'type': 'JsonWebKey2020',
            'controller': did,
            'publicKeyJwk': jwk,
        })
    return {
        '@context': ['https://www.w3.org/ns/did/v1',
                     'https://w3id.org/security/suites/jws-2020/v1'],
        'id': did,
        'verificationMethod': methods,
        'assertionMethod': [m['id'] for m in methods],
    }


def _pem_from_did_document(doc: Any) -> bytes:
    if not isinstance(doc, dict):
        raise OB3VerificationError("DID document is not a JSON object")
    methods = doc.get('verificationMethod')
    if not isinstance(methods, list) or not methods:
        raise OB3VerificationError("DID document has no verificationMethod")
    return _pem_from_vm(methods[0])


def _pem_from_vm(vm: Any) -> bytes:
    """Extract the public key of one verificationMethod entry as PEM."""
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
