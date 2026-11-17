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


def _did_web_doc(vm_public, did="did:web:issuer.example"):
    return {
        "id": did,
        "verificationMethod": [
            {"id": did + "#key-1",
             "type": "JsonWebKey2020",
             "controller": did,
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

    def test_overlong_base58_rejected(self):
        # A hostile did:key must be length-bounded before the O(n^2) decode; no
        # real multikey exceeds ~70 chars.
        with pytest.raises(OB3VerificationError, match='too long'):
            resolve_did('did:key:z' + 'a' * 200)

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
        # The document a path-based DID resolves to carries that DID as its id
        # (#338); this fixture used to serve the bare-host document here.
        doc = _did_web_doc({"publicKeyJwk": jwk},
                           did='did:web:issuer.example:users:alice')
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


# ── encoders (issuance side) ─────────────────────────────────────────────────

class TestEncoders:
    def test_b58btc_encode_decode_roundtrip(self):
        from openbadgeslib.ob3.did import _b58btc_decode, _b58btc_encode
        for raw in (b'', b'\x00', b'\x00\x00ab', b'\xff' * 33, bytes(range(64))):
            assert _b58btc_decode(_b58btc_encode(raw)) == raw

    def test_write_varint_matches_read_varint(self):
        from openbadgeslib.ob3.did import _read_varint, _write_varint
        for code in (0x00, 0x7f, 0xed, 0x1200, 0xffff):
            assert _read_varint(_write_varint(code) + b'rest') == (code, b'rest')

    def test_write_varint_known_encodings(self):
        from openbadgeslib.ob3.did import _write_varint
        assert _write_varint(0xed) == b'\xed\x01'      # Ed25519 multicodec
        assert _write_varint(0x1200) == b'\x80\x24'    # P-256 multicodec

    def test_multikey_ed25519_roundtrip(self, ed25519_pub_pem):
        from openbadgeslib.ob3.did import (_b58btc_decode, multikey_from_pem,
                                           _multicodec_pubkey_to_pem)
        mb = multikey_from_pem(ed25519_pub_pem)
        assert mb.startswith('z')
        assert _multicodec_pubkey_to_pem(_b58btc_decode(mb[1:])) == ed25519_pub_pem

    def test_multikey_p256_roundtrip(self):
        from openbadgeslib.keys import detect_key_type, KeyType
        from openbadgeslib.ob3.did import (_b58btc_decode, multikey_from_pem,
                                           _multicodec_pubkey_to_pem)
        priv = ec.generate_private_key(ec.SECP256R1())
        pem = priv.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        mb = multikey_from_pem(pem)
        decoded = _multicodec_pubkey_to_pem(_b58btc_decode(mb[1:]))
        assert detect_key_type(decoded) is KeyType.ECC

    def test_multikey_rejects_rsa(self, rsa_pub_pem):
        from openbadgeslib.ob3.did import multikey_from_pem
        with pytest.raises(ValueError, match='Ed25519'):
            multikey_from_pem(rsa_pub_pem)

    def test_did_key_from_pem_resolves_back(self, ed25519_pub_pem):
        from openbadgeslib.ob3 import did_key_from_pem
        did = did_key_from_pem(ed25519_pub_pem)
        assert resolve_did(did) == ed25519_pub_pem

    def test_did_key_from_pem_matches_test_helper(self, ed25519_pub_pem):
        from openbadgeslib.ob3 import did_key_from_pem
        pub = ser.load_pem_public_key(ed25519_pub_pem)
        assert did_key_from_pem(ed25519_pub_pem) == _did_key_ed25519(pub)


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


# ── #163: multi-key did:web issuers — JWT 'kid' selects the key ──────────────

def _doc_download(doc):
    """A download callable that serves *doc* as the did:web document."""
    def download(url):
        return json.dumps(doc).encode('utf-8')
    return download


class TestForIssuerDidKid:
    """A did:web issuer may publish several verification keys (rotation, or a
    key per badge). The JWT ``kid`` header selects which one validates the
    token; no kid falls back to the first method (the prior behaviour)."""

    def _two_key_doc(self, did, pub1_pem, pub2_pem):
        from openbadgeslib.keys import public_jwk_from_pem
        from openbadgeslib.ob3.did import build_did_document
        return build_did_document(did, [
            ('badge_1', public_jwk_from_pem(pub1_pem)),
            ('badge_2', public_jwk_from_pem(pub2_pem)),
        ])

    def _setup(self, ed25519_keypair):
        from openbadgeslib.keys import KeyEd25519
        priv1, pub1 = ed25519_keypair
        priv2, pub2 = KeyEd25519().generate_keypair()
        did = 'did:web:issuer.example'
        doc = self._two_key_doc(did, pub1, pub2)
        return did, doc, priv1, priv2

    def _token(self, priv_pem, issuer_did, kid=None):
        from openbadgeslib.ob3 import (OB3Signer, Achievement, Issuer,
                                       OpenBadgeCredential)
        credential = OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-0000000000e1',
            issuer=Issuer(id=issuer_did, name='Issuer'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'))
        token = OB3Signer(privkey_pem=priv_pem, algorithm='EdDSA').sign(credential)
        if kid is None:
            return token
        # Our signer embeds a 'jwk' header, not a 'kid'; re-header the same
        # payload with the kid an interop issuer would emit.
        import jwt as pyjwt
        payload = pyjwt.decode(token, options={'verify_signature': False})
        return pyjwt.encode(payload, priv_pem, algorithm='EdDSA',
                            headers={'kid': kid})

    def test_kid_selects_the_second_key(self, ed25519_keypair):
        did, doc, _priv1, priv2 = self._setup(ed25519_keypair)
        token = self._token(priv2, did, kid=did + '#badge_2')
        cred = OB3Verifier.for_issuer_did(
            did, download=_doc_download(doc)).verify(token)
        assert cred.issuer.id == did

    def test_bare_fragment_kid_resolves_against_issuer(self, ed25519_keypair):
        did, doc, _priv1, priv2 = self._setup(ed25519_keypair)
        token = self._token(priv2, did, kid='#badge_2')   # relative kid
        cred = OB3Verifier.for_issuer_did(
            did, download=_doc_download(doc)).verify(token)
        assert cred.issuer.id == did

    def test_no_kid_uses_the_first_method(self, ed25519_keypair):
        did, doc, priv1, _priv2 = self._setup(ed25519_keypair)
        token = self._token(priv1, did)          # no kid, signed by first key
        cred = OB3Verifier.for_issuer_did(
            did, download=_doc_download(doc)).verify(token)
        assert cred.issuer.id == did

    def test_no_kid_second_key_fails(self, ed25519_keypair):
        # Without a kid the first method is assumed, so a token signed by the
        # second key does not verify — exactly the gap #163 closes.
        did, doc, _priv1, priv2 = self._setup(ed25519_keypair)
        token = self._token(priv2, did)          # no kid, signed by second key
        with pytest.raises(OB3VerificationError, match='signature'):
            OB3Verifier.for_issuer_did(
                did, download=_doc_download(doc)).verify(token)

    def test_kid_with_wrong_signing_key_fails(self, ed25519_keypair):
        # kid names badge_2 but the token is signed by badge_1's key.
        did, doc, priv1, _priv2 = self._setup(ed25519_keypair)
        token = self._token(priv1, did, kid=did + '#badge_2')
        with pytest.raises(OB3VerificationError, match='signature'):
            OB3Verifier.for_issuer_did(
                did, download=_doc_download(doc)).verify(token)

    def test_kid_names_missing_method_fails_closed(self, ed25519_keypair):
        did, doc, priv1, _priv2 = self._setup(ed25519_keypair)
        token = self._token(priv1, did, kid=did + '#badge_99')
        with pytest.raises(OB3VerificationError, match='no verificationMethod'):
            OB3Verifier.for_issuer_did(
                did, download=_doc_download(doc)).verify(token)

    def test_kid_pointing_at_another_did_fails_closed(self, ed25519_keypair):
        # A kid naming a DIFFERENT DID must not redirect trust, even though the
        # token is signed by a key present in our document.
        did, doc, priv1, _priv2 = self._setup(ed25519_keypair)
        token = self._token(priv1, did,
                            kid='did:web:attacker.example#badge_1')
        with pytest.raises(OB3VerificationError, match='different DID'):
            OB3Verifier.for_issuer_did(
                did, download=_doc_download(doc)).verify(token)


def test_a_did_document_nested_past_the_parser_is_a_typed_failure():
    # 200 000 `[`: json.loads raises RecursionError, which is neither a
    # ValueError nor caught as one, and used to escape the fetch raw.
    from openbadgeslib.ob3.did import fetch_did_web_document
    with pytest.raises(OB3VerificationError, match='malformed DID document'):
        fetch_did_web_document('did:web:example.com',
                               download=lambda url: b'[' * 200000)


@pytest.mark.parametrize('depth', [65, 5000, 90000])
def test_a_did_document_nested_past_the_bound_is_refused(depth):
    # Balanced and valid JSON. Depends on the interpreter whether json.loads
    # takes it (3.14 parses ~100 000 levels, older ones stop near the recursion
    # limit); either way it must come out as a typed failure, never as the
    # RecursionError that repr() or json.dumps raise later on what it parsed.
    from openbadgeslib.ob3.did import fetch_did_web_document
    body = b'{"a":' * depth + b'1' + b'}' * depth
    with pytest.raises(OB3VerificationError, match='nested|malformed DID document'):
        fetch_did_web_document('did:web:example.com', download=lambda url: body)


def test_an_ordinary_did_document_is_far_below_the_depth_bound():
    from openbadgeslib.ob3.did import (MAX_DID_DOCUMENT_DEPTH,
                                       _nested_deeper_than)
    doc = {'id': 'did:web:example.com',
           'verificationMethod': [{'id': '#k', 'publicKeyJwk': {'kty': 'OKP'}}],
           'service': [{'serviceEndpoint': {'uris': ['https://a', ['b']]}}]}
    assert not _nested_deeper_than(doc, MAX_DID_DOCUMENT_DEPTH)
    assert _nested_deeper_than(doc, 3)
    assert not _nested_deeper_than([], 1) and not _nested_deeper_than('x', 0)


# ── #338: the did:web identifier is validated, not decoded; the document's ───
# ── id must be the DID it was resolved for ────────────────────────────────────

_ABSENT = object()


class _Recorder:
    """A download callable that records every URL and serves one document."""

    def __init__(self, doc=None):
        self.calls = []
        self._body = json.dumps(doc if doc is not None else {}).encode('utf-8')

    def __call__(self, url):
        self.calls.append(url)
        return self._body


def _key_doc(did, pub_pem):
    """A one-key DID document whose id is *did*."""
    from openbadgeslib.ob3.did import build_did_document
    return build_did_document(did, [('key-1', _jwk(pub_pem))])


#: The seven identifiers of #338, with the URL each one used to be turned into.
_HOSTILE_338 = [
    # a query, then a fragment, neutralises the mandatory /did.json suffix
    ('did:web:good.example:a%3Fq%3D1', 'https://good.example/a?q=1/did.json'),
    ('did:web:good.example:a%23frag', 'https://good.example/a#frag/did.json'),
    # an encoded separator, dot-segments and an empty segment walk the host
    ('did:web:good.example:a%2Fb', 'https://good.example/a/b/did.json'),
    ('did:web:good.example:..:..:etc',
     'https://good.example/../../etc/did.json'),
    ('did:web:good.example::x', 'https://good.example//x/did.json'),
    ('did:web:good.example%2F..%2F..%2Fx',
     'https://good.example/../../x/.well-known/did.json'),
    # userinfo: the real host is whatever follows the '@'
    ('did:web:good.example%40evil.example',
     'https://good.example@evil.example/.well-known/did.json'),
]

#: More of the same family, none of which may reach the downloader either.
_HOSTILE_MORE = [
    'did:web:good.example:%2E%2E:x',         # an encoded dot-segment
    'did:web:good.example:%2e',
    'did:web:good.example:.',
    'did:web:good.example:x:',               # trailing empty segment
    'did:web:good.example:a%5Cb',            # backslash
    'did:web:good.example:a%3Ab',            # a second ':' once decoded
    'did:web:good.example:a%40b',
    'did:web:good.example:a%00b',            # controls
    'did:web:good.example:a%0D%0Ab',
    'did:web:good.example:a%7Fb',
    'did:web:good.example:a%C2%85b',         # C1 control (NEL)
    'did:web:good.example:a b',              # not DID characters at all
    'did:web:good.example:a;b',
    'did:web:good.example:a?b',
    'did:web:good.example:a/b',
    'did:web:good.example:café',
    'did:web:good.example:a%zz',             # not a percent-encoding
    'did:web:good.example:a%2',
    'did:web:good.example\n',                # '$' would let this one through
    'did:web:good.example:a\n',
    'did:web:good.example/x',
    'did:web:good.example?x=1',
    'did:web:good.example.',
    'did:web:.good.example',
    'did:web:good..example',
    'did:web:-good.example',
    'did:web:good-.example',
    'did:web:good_host.example',
    'did:web:[::1]',
    'did:web:%5B::1%5D',
    'did:web:good.example%3A',               # port without digits
    'did:web:good.example%3A123456',
    'did:web:good.example%3A99999',          # not a TCP port
    'did:web:good.example%3A8443%3A1',
    'did:web:good.example%3Aabc',
    'did:web:%3A8443',
    'did:web::x',
]


class TestDidWebIdentifier:
    @pytest.mark.parametrize('did,old_url', _HOSTILE_338)
    def test_hostile_identifier_is_refused_before_any_fetch(self, did, old_url):
        from openbadgeslib.ob3 import resolve_verification_method
        from openbadgeslib.ob3.did import fetch_did_web_document
        for resolve in (
                lambda dl: resolve_did(did, download=dl),
                lambda dl: fetch_did_web_document(did, download=dl),
                lambda dl: resolve_verification_method(did + '#k', download=dl),
                lambda dl: OB3Verifier.for_issuer_did(did, download=dl)):
            fetch = _Recorder()
            with pytest.raises(OB3VerificationError,
                               match='invalid did:web identifier'):
                resolve(fetch)
            assert fetch.calls == [], (did, old_url)

    @pytest.mark.parametrize('did', _HOSTILE_MORE)
    def test_identifier_outside_the_method_syntax_is_refused(self, did):
        fetch = _Recorder()
        with pytest.raises(OB3VerificationError,
                           match='invalid did:web identifier'):
            resolve_did(did, download=fetch)
        assert fetch.calls == []

    def test_the_rejection_does_not_quote_the_identifier(self):
        with pytest.raises(OB3VerificationError) as err:
            resolve_did('did:web:good.example:s3cr3t%2Fpath',
                        download=_Recorder())
        assert 's3cr3t' not in str(err.value)

    def test_empty_identifier_is_refused(self):
        fetch = _Recorder()
        with pytest.raises(OB3VerificationError, match='empty did:web'):
            resolve_did('did:web:', download=fetch)
        assert fetch.calls == []

    @pytest.mark.parametrize('did', [
        'did:key:zabc', 'did:WEB:good.example', 'https://good.example/', '',
        None, b'did:web:good.example'])
    def test_the_public_fetch_takes_only_a_did_web(self, did):
        # 'did:key:' is as long as 'did:web:': the slice that drops the prefix
        # used to read 'zabc' as the host.
        from openbadgeslib.ob3.did import fetch_did_web_document
        fetch = _Recorder({'id': 'did:web:zabc'})
        with pytest.raises(OB3VerificationError, match='not a did:web'):
            fetch_did_web_document(did, download=fetch)
        assert fetch.calls == []

    def test_a_did_url_is_not_a_did(self):
        # resolve_verification_method only splits off the fragment: a path or
        # a query in front of it must not be read as part of the host.
        from openbadgeslib.ob3 import resolve_verification_method
        fetch = _Recorder()
        with pytest.raises(OB3VerificationError,
                           match='invalid did:web identifier'):
            resolve_verification_method('did:web:good.example/x?y#k',
                                        download=fetch)
        assert fetch.calls == []

    @pytest.mark.parametrize('did,url', [
        ('did:web:good.example', 'https://good.example/.well-known/did.json'),
        ('did:web:good.example%3A8443',
         'https://good.example:8443/.well-known/did.json'),
        ('did:web:good.example%3a8443',
         'https://good.example:8443/.well-known/did.json'),
        ('did:web:good.example%3A65535:a',
         'https://good.example:65535/a/did.json'),
        ('did:web:good.example:users:alice',
         'https://good.example/users/alice/did.json'),
        ('did:web:xn--caf-dma.example:a-b_c.d',
         'https://xn--caf-dma.example/a-b_c.d/did.json'),
        # A segment stays exactly as the DID spells it: the percent-encoding
        # is the path's own, not something to undo.
        ('did:web:good.example:a%20b', 'https://good.example/a%20b/did.json'),
        ('did:web:good.example:caf%C3%A9',
         'https://good.example/caf%C3%A9/did.json'),
        ('did:web:good.example:x%252Fy',
         'https://good.example/x%252Fy/did.json'),
        ('did:web:good.example:~alice', 'https://good.example/~alice/did.json'),
        ('did:web:good.example:...', 'https://good.example/.../did.json'),
    ])
    def test_legitimate_identifier_resolves_to_the_method_url(
            self, did, url, ed25519_pub_pem):
        fetch = _Recorder(_key_doc(did, ed25519_pub_pem))
        assert resolve_did(did, download=fetch) == ed25519_pub_pem
        assert fetch.calls == [url]

    @pytest.mark.parametrize('base,did,url', [
        ('https://issuer.example/badges/a b/',
         'did:web:issuer.example:badges:a%20b',
         'https://issuer.example/badges/a%20b/did.json'),
        ('https://Issuer.Example:8443/café/',
         'did:web:issuer.example%3A8443:caf%C3%A9',
         'https://issuer.example:8443/caf%C3%A9/did.json'),
    ])
    def test_round_trip_through_did_web_from_url(self, base, did, url,
                                                 ed25519_pub_pem):
        # publish side -> DID -> resolve side: the DID did_web_from_url derives
        # for a path that needs percent-encoding resolves under that path,
        # with the encoding the wire carries.
        from openbadgeslib.ob3.did import did_web_from_url
        assert did_web_from_url(base) == did
        fetch = _Recorder(_key_doc(did, ed25519_pub_pem))
        assert resolve_did(did, download=fetch) == ed25519_pub_pem
        assert fetch.calls == [url]


class TestDidWebDocumentId:
    """did-core / did:web: the resolved document's id is the DID. Without the
    check a host answers for any DID with any document it happens to serve."""

    DID = 'did:web:issuer.example'

    def _doc(self, pub_pem, doc_id):
        doc = _key_doc(self.DID, pub_pem)
        if doc_id is _ABSENT:
            del doc['id']
        else:
            doc['id'] = doc_id
        return doc

    @pytest.mark.parametrize('doc_id', [
        'did:web:somebody.else',
        'did:web:issuer.example:users:alice',
        'did:web:issuer.example#key-1',
        'did:web:issuer.example ',
        'DID:WEB:issuer.example',
        'did:key:z6MkTest',
        'https://issuer.example/.well-known/did.json',
        '',
    ])
    def test_a_different_id_is_refused(self, doc_id, ed25519_pub_pem):
        from openbadgeslib.ob3 import resolve_verification_method
        from openbadgeslib.ob3.did import fetch_did_web_document
        doc = self._doc(ed25519_pub_pem, doc_id)
        for resolve in (
                lambda dl: resolve_did(self.DID, download=dl),
                lambda dl: fetch_did_web_document(self.DID, download=dl),
                lambda dl: resolve_verification_method(
                    self.DID + '#key-1', download=dl),
                lambda dl: OB3Verifier.for_issuer_did(self.DID, download=dl)):
            fetch = _Recorder(doc)
            with pytest.raises(OB3VerificationError, match='is not the id'):
                resolve(fetch)
            assert fetch.calls == [
                'https://issuer.example/.well-known/did.json']

    @pytest.mark.parametrize('doc_id', [
        _ABSENT, None, 0, True, ['did:web:issuer.example'],
        {'id': 'did:web:issuer.example'}])
    def test_a_missing_or_non_string_id_is_refused(self, doc_id,
                                                   ed25519_pub_pem):
        from openbadgeslib.ob3 import resolve_verification_method
        from openbadgeslib.ob3.did import fetch_did_web_document
        doc = self._doc(ed25519_pub_pem, doc_id)
        for resolve in (
                lambda dl: resolve_did(self.DID, download=dl),
                lambda dl: fetch_did_web_document(self.DID, download=dl),
                lambda dl: resolve_verification_method(
                    self.DID + '#key-1', download=dl),
                lambda dl: OB3Verifier.for_issuer_did(self.DID, download=dl)):
            with pytest.raises(OB3VerificationError, match='is not the id'):
                resolve(_Recorder(doc))

    def test_case_folding_stays_inside_ascii(self, ed25519_pub_pem):
        # str.lower() turns the Kelvin sign into 'k': the host comparison must
        # not make two different strings the same DID.
        did = 'did:web:kelvin.example'
        fetch = _Recorder(_key_doc('did:web:Kelvin.example',
                                   ed25519_pub_pem))
        with pytest.raises(OB3VerificationError, match='is not the id'):
            resolve_did(did, download=fetch)

    def test_the_rejection_does_not_quote_the_served_id(self, ed25519_pub_pem):
        fetch = _Recorder(self._doc(ed25519_pub_pem, 'did:web:s3cr3t.example'))
        with pytest.raises(OB3VerificationError) as err:
            resolve_did(self.DID, download=fetch)
        assert 's3cr3t' not in str(err.value)

    @pytest.mark.parametrize('did,doc_id', [
        # A host name is case-insensitive, on either side.
        ('did:web:Issuer.Example', 'did:web:issuer.example'),
        ('did:web:issuer.example', 'did:web:ISSUER.example'),
        ('did:web:issuer.example%3A8443', 'did:web:Issuer.Example%3a8443'),
        ('did:web:Issuer.Example:Users:Alice',
         'did:web:issuer.example:Users:Alice'),
    ])
    def test_host_case_gives_no_false_rejection(self, did, doc_id,
                                                ed25519_pub_pem):
        fetch = _Recorder(_key_doc(doc_id, ed25519_pub_pem))
        assert resolve_did(did, download=fetch) == ed25519_pub_pem

    @pytest.mark.parametrize('did,doc_id', [
        # A path is case-sensitive, and so is its percent-encoding: the id is
        # compared as spelled, never decoded.
        ('did:web:issuer.example:Users:Alice',
         'did:web:issuer.example:users:alice'),
        ('did:web:issuer.example:caf%c3%a9',
         'did:web:issuer.example:caf%C3%A9'),
        ('did:web:issuer.example:a%20b', 'did:web:issuer.example:a b'),
    ])
    def test_path_is_compared_exactly(self, did, doc_id, ed25519_pub_pem):
        fetch = _Recorder(_key_doc(doc_id, ed25519_pub_pem))
        with pytest.raises(OB3VerificationError, match='is not the id'):
            resolve_did(did, download=fetch)

    def test_a_token_does_not_verify_against_another_dids_document(
            self, ed25519_priv_pem, ed25519_pub_pem):
        # The end of the chain in #338: a host that serves somebody else's
        # document (or one an attacker uploaded) for the issuer's DID. The
        # signature is good and the credential names the DID; only the
        # document's own id says it was never this DID's document.
        from openbadgeslib.ob3 import (OB3Signer, Achievement, Issuer,
                                       OpenBadgeCredential)
        credential = OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-000000000338',
            issuer=Issuer(id=self.DID, name='Issuer'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'))
        token = OB3Signer(privkey_pem=ed25519_priv_pem,
                          algorithm='EdDSA').sign(credential)
        good = _Recorder(_key_doc(self.DID, ed25519_pub_pem))
        assert OB3Verifier.for_issuer_did(
            self.DID, download=good).verify(token).issuer.id == self.DID
        other = _Recorder(_key_doc('did:web:somebody.else', ed25519_pub_pem))
        with pytest.raises(OB3VerificationError, match='is not the id'):
            OB3Verifier.for_issuer_did(self.DID, download=other)
