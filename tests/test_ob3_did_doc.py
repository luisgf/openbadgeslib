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
        'https://@example.com/',
    ])
    def test_rejects_userinfo(self, url):
        # A user:pass@ credential must never be embedded into the DID (which
        # is carried by every issued credential); reject rather than leak it.
        with pytest.raises(ValueError):
            did_web_from_url(url)

    @pytest.mark.parametrize('url', [
        'http://user:hunter2-zzz@example.com/',   # fails the scheme check too
        'https://user:hunter2-zzz@',              # fails the host check too
        'ftp://user:hunter2-zzz@example.com/',
        'user:hunter2-zzz@example.com/',          # schemeless: "scheme" == user
    ])
    def test_no_message_echoes_the_password(self, url):
        # The userinfo check must run *before* the scheme and host checks: a
        # CLI prints the ValueError to stdout (and into the 'error' field of
        # --json), so a password reaching those messages would be published by
        # the very error meant to reject it.
        with pytest.raises(ValueError) as exc:
            did_web_from_url(url)
        assert 'hunter2-zzz' not in str(exc.value)
        assert 'hunter2-zzz' not in repr(exc.value)

    @pytest.mark.parametrize('url,secret', [
        # urlsplit only reports userinfo when the '@' sits inside the
        # authority. A password holding a '/', '?' or '#' pushes it into the
        # path, and the credential then resurfaced two ways: percent-encoded
        # into the returned DID when what precedes the ':' parses as a port
        # (this yielded 'did:web:user%3A12345:x%40host'), or through
        # parts.port's own ValueError, which quotes the value verbatim.
        ('https://user:12345/x@host/', '12345'),
        ('https://user:hunter2-zzz/x@host/', 'hunter2-zzz'),
        ('https://user:hunter2-zzz?q@host/', 'hunter2-zzz'),
        ('https://user:hunter2-zzz#f@host/', 'hunter2-zzz'),
        ('https://user%40host/badges/', 'user%40host'),      # '@' written %40
    ])
    def test_at_sign_outside_the_authority_is_refused(self, url, secret):
        with pytest.raises(ValueError) as exc:
            did_web_from_url(url)
        assert secret not in str(exc.value)
        assert secret not in repr(exc.value)

    def test_invalid_port_does_not_quote_the_value(self):
        # urllib's own "Port could not be cast to integer value as 'x'" quotes
        # what it could not parse — which on a 'user:password/...' URL is the
        # password. The parse must be wrapped and re-raised without it.
        with pytest.raises(ValueError) as exc:
            did_web_from_url('https://host:hunter2-zzz/badges/')
        assert 'hunter2-zzz' not in str(exc.value)

    def test_at_sign_in_path_is_refused_even_when_innocent(self):
        # Deliberate false positive, documented on the function: after parsing,
        # 'https://host/@name/' is the same shape as one hiding a credential.
        with pytest.raises(ValueError):
            did_web_from_url('https://example.com/@name/')

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
