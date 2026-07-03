"""Tests for DID resolution (did:key, did:web) — ob3.did."""
import base64
import json

import pytest

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openbadgeslib.ob3 import resolve_did, OB3Verifier, OB3VerificationError
from openbadgeslib.keys import detect_key_type, KeyType


_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    out = ''
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b'\x00'))
    return '1' * pad + out


def _did_key_ed25519(pub) -> str:
    raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return 'did:key:z' + _b58encode(b'\xed\x01' + raw)


def _did_key_p256(pub) -> str:
    point = pub.public_bytes(ser.Encoding.X962, ser.PublicFormat.CompressedPoint)
    return 'did:key:z' + _b58encode(b'\x80\x24' + point)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def _did_web_doc(vm_public):
    return {
        "id": "did:web:issuer.example",
        "verificationMethod": [
            {"id": "did:web:issuer.example#key-1",
             "type": "JsonWebKey2020",
             "controller": "did:web:issuer.example",
             **vm_public},
        ],
    }


# ── did:key ──────────────────────────────────────────────────────────────────

class TestDidKey:
    def test_ed25519_resolves_to_matching_pem(self, ed25519_pub_pem):
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        pem = resolve_did(_did_key_ed25519(pub))
        assert detect_key_type(pem) is KeyType.ED25519
        assert pem == ed25519_pub_pem

    def test_p256_resolves_to_ecc(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        pem = resolve_did(_did_key_p256(priv.public_key()))
        assert detect_key_type(pem) is KeyType.ECC

    def test_bad_base58_rejected(self):
        with pytest.raises(OB3VerificationError, match='base58'):
            resolve_did('did:key:z0OIl')   # 0, O, I, l are not in the alphabet

    def test_non_z_multibase_rejected(self):
        with pytest.raises(OB3VerificationError, match='base58btc'):
            resolve_did('did:key:Qabc')

    def test_unsupported_multicodec_rejected(self):
        # multicodec 0x99 0x01 (arbitrary/unsupported) + junk
        raw = bytes([0x99, 0x01]) + b'\x00' * 32
        with pytest.raises(OB3VerificationError, match='multicodec'):
            resolve_did('did:key:z' + _b58encode(raw))


# ── did:web ──────────────────────────────────────────────────────────────────

class TestDidWeb:
    def _fetch(self, doc, expected_url):
        def _dl(url):
            assert url == expected_url, url
            return json.dumps(doc).encode('utf-8')
        return _dl

    def test_well_known_path(self, ed25519_pub_pem):
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
        doc = _did_web_doc({"publicKeyJwk": jwk})
        fetch = self._fetch(doc, 'https://issuer.example/.well-known/did.json')
        pem = resolve_did('did:web:issuer.example', download=fetch)
        assert pem == ed25519_pub_pem

    def test_path_based(self, ed25519_pub_pem):
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
        doc = _did_web_doc({"publicKeyJwk": jwk})
        fetch = self._fetch(doc, 'https://issuer.example/users/alice/did.json')
        pem = resolve_did('did:web:issuer.example:users:alice', download=fetch)
        assert detect_key_type(pem) is KeyType.ED25519

    def test_public_key_multibase(self, ed25519_pub_pem):
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        mb = _did_key_ed25519(pub).split('did:key:')[1]  # 'z...'
        doc = _did_web_doc({"publicKeyMultibase": mb})
        fetch = self._fetch(doc, 'https://issuer.example/.well-known/did.json')
        pem = resolve_did('did:web:issuer.example', download=fetch)
        assert pem == ed25519_pub_pem

    def test_rsa_jwk(self, rsa_pub_pem):
        from jwt.algorithms import RSAAlgorithm
        jwk = json.loads(RSAAlgorithm.to_jwk(ser.load_pem_public_key(rsa_pub_pem)))
        doc = _did_web_doc({"publicKeyJwk": jwk})
        fetch = self._fetch(doc, 'https://issuer.example/.well-known/did.json')
        pem = resolve_did('did:web:issuer.example', download=fetch)
        assert detect_key_type(pem) is KeyType.RSA

    def test_fetch_error_wrapped(self):
        def _boom(url):
            raise ValueError('insecure scheme')
        with pytest.raises(OB3VerificationError, match='could not fetch'):
            resolve_did('did:web:issuer.example', download=_boom)

    def test_no_verification_method(self):
        fetch = self._fetch({"id": "did:web:issuer.example"},
                            'https://issuer.example/.well-known/did.json')
        with pytest.raises(OB3VerificationError, match='verificationMethod'):
            resolve_did('did:web:issuer.example', download=fetch)

    def test_malformed_document(self):
        with pytest.raises(OB3VerificationError, match='malformed'):
            resolve_did('did:web:issuer.example', download=lambda url: b'not json')


# ── method dispatch ──────────────────────────────────────────────────────────

class TestResolveDidDispatch:
    def test_non_did_rejected(self):
        with pytest.raises(OB3VerificationError, match='not a DID'):
            resolve_did('https://issuer.example/key.pem')

    def test_unsupported_method_rejected(self):
        with pytest.raises(OB3VerificationError, match='unsupported DID method'):
            resolve_did('did:ion:EiClk...')


# ── resolve_verification_method (proof verificationMethod URLs) ──────────────

def _jwk(pub_pem):
    from openbadgeslib.keys import public_jwk_from_pem
    return public_jwk_from_pem(pub_pem)


class TestResolveVerificationMethod:
    def test_did_key_with_matching_fragment(self, ed25519_pub_pem):
        from openbadgeslib.ob3 import resolve_verification_method
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        did = _did_key_ed25519(pub)
        ident = did[len('did:key:'):]
        pem = resolve_verification_method('%s#%s' % (did, ident))
        assert ser.load_pem_public_key(pem).public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw) == pub.public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw)

    def test_did_key_without_fragment(self, ed25519_pub_pem):
        from openbadgeslib.ob3 import resolve_verification_method
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        did = _did_key_ed25519(pub)
        assert resolve_verification_method(did)

    def test_did_key_fragment_mismatch_fails_closed(self, ed25519_pub_pem):
        from openbadgeslib.ob3 import resolve_verification_method
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        did = _did_key_ed25519(pub)
        with pytest.raises(OB3VerificationError, match='fragment'):
            resolve_verification_method(did + '#other-key')

    def test_did_web_selects_entry_by_exact_id(self, rsa_pub_pem, ed25519_pub_pem):
        from openbadgeslib.ob3 import resolve_verification_method
        # Two methods; the SECOND is the one the proof names — [0] must not win.
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        doc = {
            "id": "did:web:issuer.example",
            "verificationMethod": [
                {"id": "did:web:issuer.example#rsa",
                 "type": "JsonWebKey2020",
                 "controller": "did:web:issuer.example",
                 "publicKeyJwk": _jwk(rsa_pub_pem)},
                {"id": "did:web:issuer.example#ed",
                 "type": "Multikey",
                 "controller": "did:web:issuer.example",
                 "publicKeyMultibase": 'z' + _b58encode(b'\xed\x01' + raw)},
            ],
        }
        pem = resolve_verification_method(
            'did:web:issuer.example#ed',
            download=lambda url: json.dumps(doc).encode('utf-8'))
        assert detect_key_type(pem) is KeyType.ED25519

    def test_did_web_unknown_id_fails_closed(self, ed25519_pub_pem):
        from openbadgeslib.ob3 import resolve_verification_method
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        doc = {"id": "did:web:issuer.example",
               "verificationMethod": [
                   {"id": "did:web:issuer.example#key-1", "type": "Multikey",
                    "controller": "did:web:issuer.example",
                    "publicKeyMultibase": 'z' + _b58encode(b'\xed\x01' + raw)}]}
        with pytest.raises(OB3VerificationError, match='no verificationMethod with id'):
            resolve_verification_method(
                'did:web:issuer.example#nope',
                download=lambda url: json.dumps(doc).encode('utf-8'))

    def test_non_did_rejected(self):
        from openbadgeslib.ob3 import resolve_verification_method
        with pytest.raises(OB3VerificationError, match='did: URL'):
            resolve_verification_method('https://issuer.example/keys/1')


# ── end-to-end through OB3Verifier.for_issuer_did ────────────────────────────

class TestForIssuerDid:
    def test_verify_token_signed_by_did_key(self, ed25519_priv_pem, ed25519_pub_pem):
        from openbadgeslib.ob3 import OB3Signer, Achievement, Issuer, OpenBadgeCredential
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        did = _did_key_ed25519(pub)

        credential = OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-0000000000cc',
            issuer=Issuer(id=did, name='DID Issuer'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
        )
        token = OB3Signer(privkey_pem=ed25519_priv_pem, algorithm='EdDSA').sign(credential)

        verifier = OB3Verifier.for_issuer_did(did)     # did:key, offline
        cred = verifier.verify(token)
        assert cred.issuer.id == did

    def test_wrong_did_key_fails_verification(self, ed25519_priv_pem):
        from openbadgeslib.ob3 import OB3Signer, Achievement, Issuer, OpenBadgeCredential
        # Sign with our key but hand for_issuer_did a DIFFERENT did:key.
        other = Ed25519PrivateKey.generate().public_key()
        wrong_did = _did_key_ed25519(other)
        credential = OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-0000000000cd',
            issuer=Issuer(id=wrong_did, name='I'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
        )
        token = OB3Signer(privkey_pem=ed25519_priv_pem, algorithm='EdDSA').sign(credential)
        verifier = OB3Verifier.for_issuer_did(wrong_did)
        with pytest.raises(OB3VerificationError):
            verifier.verify(token)

    def _did_web_key_doc(self, ed25519_pub_pem, did):
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
        return {
            "id": did,
            "verificationMethod": [
                {"id": did + "#key-1", "type": "JsonWebKey2020",
                 "controller": did, "publicKeyJwk": jwk},
            ],
        }

    def test_did_web_issuer_spoofing_rejected(self, ed25519_priv_pem, ed25519_pub_pem):
        # did:web is NOT self-certifying: an attacker who controls
        # did:web:attacker.example (and its key) signs a credential that CLAIMS
        # a trusted issuer. Anchoring on the attacker DID resolves their key and
        # the signature is valid, so binding the credential's issuer id to the
        # anchored DID is the only thing that rejects the forgery.
        from openbadgeslib.ob3 import OB3Signer, Achievement, Issuer, OpenBadgeCredential
        attacker_did = 'did:web:attacker.example'
        doc = self._did_web_key_doc(ed25519_pub_pem, attacker_did)
        credential = OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-0000000000ce',
            issuer=Issuer(id='did:web:trusted-university.example', name='Trusted'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
        )
        token = OB3Signer(privkey_pem=ed25519_priv_pem, algorithm='EdDSA').sign(credential)
        verifier = OB3Verifier.for_issuer_did(
            attacker_did, download=lambda url: json.dumps(doc).encode('utf-8'))
        with pytest.raises(OB3VerificationError, match='issuer'):
            verifier.verify(token)

    def test_did_web_matching_issuer_verifies(self, ed25519_priv_pem, ed25519_pub_pem):
        # The honest case: the credential's issuer id equals the anchored DID.
        from openbadgeslib.ob3 import OB3Signer, Achievement, Issuer, OpenBadgeCredential
        did = 'did:web:issuer.example'
        doc = self._did_web_key_doc(ed25519_pub_pem, did)
        credential = OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-0000000000cf',
            issuer=Issuer(id=did, name='Issuer'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
        )
        token = OB3Signer(privkey_pem=ed25519_priv_pem, algorithm='EdDSA').sign(credential)
        verifier = OB3Verifier.for_issuer_did(
            did, download=lambda url: json.dumps(doc).encode('utf-8'))
        cred = verifier.verify(token)
        assert cred.issuer.id == did

    def test_direct_pubkey_verifier_does_not_bind_issuer(
        self, ed25519_priv_pem, ed25519_pub_pem
    ):
        # A verifier built straight from a key (no DID anchor) performs no
        # issuer binding — the caller vouches for the key's owner.
        from openbadgeslib.ob3 import OB3Signer, Achievement, Issuer, OpenBadgeCredential
        credential = OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-0000000000d0',
            issuer=Issuer(id='did:web:anything.example', name='Whoever'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
        )
        token = OB3Signer(privkey_pem=ed25519_priv_pem, algorithm='EdDSA').sign(credential)
        cred = OB3Verifier(pubkey_pem=ed25519_pub_pem).verify(token)
        assert cred.issuer.id == 'did:web:anything.example'
