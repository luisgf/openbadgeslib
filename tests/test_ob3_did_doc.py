"""Tests for did:web document generation — ob3.did (write side) and
keys.public_jwk_from_pem."""
import json

import pytest

from cryptography.hazmat.primitives import serialization

from openbadgeslib.errors import PublicKeyReadError
from openbadgeslib.keys import public_jwk_from_pem
from openbadgeslib.ob3.did import (
    _resolve_did_web,
    build_did_document,
    did_web_from_url,
    resolve_did,
)


# ── did_web_from_url ─────────────────────────────────────────────────────────

class TestDidWebFromUrl:
    @pytest.mark.parametrize('url,expected', [
        ('https://example.com', 'did:web:example.com'),
        ('https://example.com/', 'did:web:example.com'),
        ('https://example.com/badges/', 'did:web:example.com:badges'),
        ('https://example.com/a/b', 'did:web:example.com:a:b'),
        ('https://example.com:8443/badges/',
         'did:web:example.com%3A8443:badges'),
    ])
    def test_derivation(self, url, expected):
        assert did_web_from_url(url) == expected

    @pytest.mark.parametrize('url', ['http://example.com/', 'ftp://x/', '',
                                     'https://'])
    def test_rejects_non_https(self, url):
        with pytest.raises(ValueError):
            did_web_from_url(url)

    @pytest.mark.parametrize('url', [
        'https://user:secret@example.com/',
        'https://user@example.com/badges/',
    ])
    def test_rejects_userinfo(self, url):
        # A user:pass@ credential must never be embedded into the DID (which
        # is carried by every issued credential); reject rather than leak it.
        with pytest.raises(ValueError):
            did_web_from_url(url)

    @pytest.mark.parametrize('url,doc_url', [
        ('https://example.com', 'https://example.com/.well-known/did.json'),
        ('https://example.com/badges/', 'https://example.com/badges/did.json'),
    ])
    def test_resolver_fetches_expected_document_url(self, url, doc_url,
                                                    rsa_pub_pem):
        """did_web_from_url must be the exact inverse of _resolve_did_web."""
        doc = build_did_document(
            did_web_from_url(url),
            [('badge_1', public_jwk_from_pem(rsa_pub_pem))])
        seen = []

        def fetch(u):
            seen.append(u)
            return json.dumps(doc).encode('utf-8')

        resolve_did(did_web_from_url(url), download=fetch)
        assert seen == [doc_url]


# ── public_jwk_from_pem ──────────────────────────────────────────────────────

class TestPublicJwkFromPem:
    def test_rsa(self, rsa_pub_pem):
        jwk = public_jwk_from_pem(rsa_pub_pem)
        assert jwk['kty'] == 'RSA'
        assert 'd' not in jwk

    def test_ecc(self, ecc_pub_pem):
        jwk = public_jwk_from_pem(ecc_pub_pem)
        assert jwk['kty'] == 'EC'
        assert jwk['crv'] == 'P-256'
        assert 'd' not in jwk

    def test_ed25519(self, ed25519_pub_pem):
        jwk = public_jwk_from_pem(ed25519_pub_pem)
        assert jwk['kty'] == 'OKP'
        assert jwk['crv'] == 'Ed25519'
        assert 'd' not in jwk

    def test_garbage_rejected(self):
        with pytest.raises(PublicKeyReadError):
            public_jwk_from_pem(b'not a pem')

    def test_private_pem_rejected(self, rsa_priv_pem):
        with pytest.raises(PublicKeyReadError):
            public_jwk_from_pem(rsa_priv_pem)


# ── build_did_document + round-trip through the resolver ────────────────────

def _spki(pem):
    return serialization.load_pem_public_key(pem).public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


class TestBuildDidDocument:
    def test_document_shape(self, rsa_pub_pem, ecc_pub_pem):
        did = 'did:web:example.com:badges'
        doc = build_did_document(did, [
            ('badge_1', public_jwk_from_pem(rsa_pub_pem)),
            ('badge_2', public_jwk_from_pem(ecc_pub_pem)),
        ])
        assert doc['id'] == did
        assert [m['id'] for m in doc['verificationMethod']] == \
            [did + '#badge_1', did + '#badge_2']
        assert all(m['controller'] == did and m['type'] == 'JsonWebKey2020'
                   for m in doc['verificationMethod'])
        assert doc['assertionMethod'] == [did + '#badge_1', did + '#badge_2']

    def test_empty_methods_rejected(self):
        with pytest.raises(ValueError):
            build_did_document('did:web:example.com', [])

    @pytest.mark.parametrize('pub_fixture', ['rsa_pub_pem', 'ecc_pub_pem',
                                             'ed25519_pub_pem'])
    def test_round_trip_through_resolver(self, request, pub_fixture):
        """The generated document must hand the badge key back to the
        existing did:web resolver, byte-identical as SubjectPublicKeyInfo."""
        pub_pem = request.getfixturevalue(pub_fixture)
        did = did_web_from_url('https://example.com/badges/')
        doc = build_did_document(did, [('badge_1', public_jwk_from_pem(pub_pem))])
        resolved = _resolve_did_web(
            did, lambda url: json.dumps(doc).encode('utf-8'))
        assert _spki(resolved) == _spki(pub_pem)
