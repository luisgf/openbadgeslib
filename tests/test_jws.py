"""Tests for the openbadgeslib._jws module (sign, verify, utils, algos)."""
import json
import pytest

from openbadgeslib._jws import sign, verify_block
from openbadgeslib._jws import utils
from openbadgeslib._jws.exceptions import (
    SignatureError, RouteMissingError, MissingKey, MissingSigner, MissingVerifier,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def _build_jws(header, payload, raw_signature):
    """Assemble a complete JWS block from raw signature bytes."""
    return (
        utils.encode(header) + b'.'
        + utils.encode(payload) + b'.'
        + utils.to_base64(raw_signature)
    )


def _load_rsa_keys(rsa_priv_pem, rsa_pub_pem):
    from openbadgeslib.keys import KeyRSA
    k = KeyRSA()
    k.read_private_key(rsa_priv_pem)
    k.read_public_key(rsa_pub_pem)
    return k.get_priv_key(), k.get_pub_key()


def _load_ecc_keys(ecc_priv_pem, ecc_pub_pem):
    from openbadgeslib.keys import KeyECC
    k = KeyECC()
    k.read_private_key(ecc_priv_pem)
    k.read_public_key(ecc_pub_pem)
    return k.get_priv_key(), k.get_pub_key()


PAYLOAD = {'uid': 'test-123', 'recipient': {'identity': 'sha256$abc'}}


# ── sign + verify_block round-trips ───────────────────────────────────────────

class TestRSARoundTrip:
    def test_sign_returns_bytes(self, rsa_priv_pem, rsa_pub_pem):
        priv, _ = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        assert isinstance(sig, bytes)

    def test_verify_block_valid(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        assert verify_block(jws, key=pub) is True

    def test_wrong_public_key_raises(self, rsa_priv_pem, rsa_pub_pem, ecc_pub_pem):
        from openbadgeslib.keys import KeyECC
        priv, _ = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        k2 = KeyECC()
        k2.read_public_key(ecc_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        with pytest.raises(Exception):
            verify_block(jws, key=k2.get_pub_key())

    def test_tampered_payload_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        evil_payload = {'uid': 'EVIL', 'recipient': {'identity': 'sha256$abc'}}
        jws = _build_jws({'alg': 'RS256'}, evil_payload, raw_sig)
        with pytest.raises(SignatureError):
            verify_block(jws, key=pub)

    def test_truncated_signature_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)[:-10] + b'AAAAAAAAAA'
        with pytest.raises((SignatureError, Exception)):
            verify_block(jws, key=pub)

    def test_rsa_private_key_as_verify_key_raises_signature_error(self, rsa_priv_pem):
        # A malicious verify.url can serve an RSA *private* key PEM. It parses
        # as an RSA key, but PyJWT's RSAAlgorithm.verify() then calls .verify()
        # on an RSAPrivateKey (which lacks it), raising AttributeError. That
        # must surface as a SignatureError, never a raw crash.
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_private_key(rsa_priv_pem)
        priv = k.get_priv_key()
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        with pytest.raises(SignatureError):
            verify_block(jws, key=priv)


class TestECCRoundTrip:
    def test_sign_returns_bytes(self, ecc_priv_pem, ecc_pub_pem):
        priv, _ = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        assert isinstance(sig, bytes)

    def test_verify_block_valid(self, ecc_priv_pem, ecc_pub_pem):
        priv, pub = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        raw_sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'ES256'}, PAYLOAD, raw_sig)
        assert verify_block(jws, key=pub) is True

    def test_tampered_payload_raises(self, ecc_priv_pem, ecc_pub_pem):
        priv, pub = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        raw_sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        evil = {'uid': 'EVIL', 'recipient': {'identity': 'sha256$abc'}}
        jws = _build_jws({'alg': 'ES256'}, evil, raw_sig)
        with pytest.raises(SignatureError):
            verify_block(jws, key=pub)

    def test_wrong_key_raises(self, ecc_priv_pem, ecc_pub_pem, rsa_pub_pem):
        from openbadgeslib.keys import KeyRSA
        priv, _ = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        k2 = KeyRSA()
        k2.read_public_key(rsa_pub_pem)
        raw_sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'ES256'}, PAYLOAD, raw_sig)
        with pytest.raises(Exception):
            verify_block(jws, key=k2.get_pub_key())


class TestVerifyBlockEdgeCases:
    def test_malformed_block_no_dots(self):
        with pytest.raises(SignatureError):
            verify_block(b'notajwstoken', key=None)

    def test_malformed_block_one_dot(self):
        with pytest.raises(SignatureError):
            verify_block(b'header.payload', key=None)

    def test_missing_key_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        with pytest.raises(MissingKey):
            verify_block(jws, key=None)

    def test_non_json_header_raises_signature_error(self, rsa_pub_pem):
        """A base64url-valid but non-JSON header must not leak json.JSONDecodeError."""
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        bad_header = utils.to_base64(b'not-json-at-all')
        jws = bad_header + b'.' + utils.encode(PAYLOAD) + b'.' + utils.to_base64(b'sig')
        with pytest.raises(SignatureError):
            verify_block(jws, key=k.get_pub_key())

    def test_non_dict_header_raises_signature_error(self, rsa_pub_pem):
        """A header that decodes to valid JSON that isn't an object must be rejected cleanly."""
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        list_header = utils.encode(['not', 'a', 'dict'])
        jws = list_header + b'.' + utils.encode(PAYLOAD) + b'.' + utils.to_base64(b'sig')
        with pytest.raises(SignatureError):
            verify_block(jws, key=k.get_pub_key())

    def test_malformed_signature_segment_raises_signature_error(self, rsa_pub_pem):
        """An invalid-length base64url signature segment must not leak binascii.Error."""
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        jws = utils.encode({'alg': 'RS256'}) + b'.' + utils.encode(PAYLOAD) + b'.A'
        with pytest.raises(SignatureError):
            verify_block(jws, key=k.get_pub_key())

    def test_unclassifiable_key_fails_closed(self, rsa_priv_pem, rsa_pub_pem):
        """A verification key whose type cannot be classified must be refused,
        not have its algorithm pinning silently skipped (issue #20)."""
        priv, _pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        with pytest.raises(SignatureError, match='pinned'):
            verify_block(jws, key=b'not a real pem key')

    def test_empty_allowed_algs_fails_closed(self, rsa_priv_pem, rsa_pub_pem,
                                             monkeypatch):
        """Even with an otherwise-valid signature, an empty allowed-algorithm
        set (an unclassifiable or future key type) must fail closed: the
        algorithm cannot be pinned, so verification is refused rather than
        falling through to the header-chosen algorithm."""
        import openbadgeslib._jws as jws_mod
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        monkeypatch.setattr(jws_mod, '_allowed_algs_for_key', lambda key: set())
        with pytest.raises(SignatureError, match='pinned'):
            verify_block(jws, key=pub)

    @pytest.mark.parametrize('bad_alg', [['ES256'], {'a': 1}, 123, True])
    def test_non_string_alg_header_raises_jws_exception(self, rsa_pub_pem, bad_alg):
        """A non-string 'alg' (esp. an unhashable list/dict) must be rejected as
        a clean JWSException, not leak a raw TypeError from the membership test."""
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        jws = utils.encode({'alg': bad_alg}) + b'.' + utils.encode(PAYLOAD) + b'.' + utils.to_base64(b'sig')
        with pytest.raises(MissingVerifier):
            verify_block(jws, key=k.get_pub_key())


class TestExceptionHierarchy:
    def test_all_jws_exceptions_are_libopenbadgesexception(self):
        from openbadgeslib.errors import LibOpenBadgesException
        for exc_cls in (MissingKey, MissingSigner, MissingVerifier, SignatureError, RouteMissingError):
            assert issubclass(exc_cls, LibOpenBadgesException)


class TestAlgorithmConfusion:
    """wiki/Security-Model.md claims OB2's _jws.verify_block pins alg to the
    key type, blocking none/HMAC downgrades and cross-type confusion. The
    control already works (verified live); this locks it with a regression
    test mirroring test_ob3_verifier.py's alg-confusion coverage, so a future
    refactor of _allowed_algs_for_key/verify_block can't silently reintroduce
    the vulnerability without a test failing."""

    def test_alg_none_rejected_by_key_pinning(self, rsa_pub_pem):
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        jws = _build_jws({'alg': 'none'}, PAYLOAD, b'')
        with pytest.raises(SignatureError):
            verify_block(jws, key=k.get_pub_key())

    def test_hs256_confusion_rejected_by_key_pinning(self, rsa_pub_pem):
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        jws = _build_jws({'alg': 'HS256'}, PAYLOAD, b'forged-hmac-signature')
        with pytest.raises(SignatureError):
            verify_block(jws, key=k.get_pub_key())


class TestCritHeader:
    """#292: RFC 7515 §4.1.11 — reject a JWS whose 'crit' header names
    extensions this verifier does not understand. openbadgeslib understands
    none, so any present 'crit' must fail closed."""

    def test_crit_extension_rejected(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        header = {'alg': 'RS256', 'crit': ['bork'], 'bork': True}
        raw_sig = sign(header, PAYLOAD, key=priv)
        jws = _build_jws(header, PAYLOAD, raw_sig)
        with pytest.raises(SignatureError, match='crit'):
            verify_block(jws, key=pub)

    def test_empty_crit_list_rejected(self, rsa_priv_pem, rsa_pub_pem):
        # An empty crit array is non-conformant but still means the issuer
        # marked something critical; fail closed rather than accept.
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        header = {'alg': 'RS256', 'crit': []}
        raw_sig = sign(header, PAYLOAD, key=priv)
        jws = _build_jws(header, PAYLOAD, raw_sig)
        with pytest.raises(SignatureError, match='crit'):
            verify_block(jws, key=pub)

    def test_no_crit_still_accepts(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        assert verify_block(jws, key=pub) is True


class TestEcCurveBinding:
    """#284: ES* algorithms must bind the NIST curve RFC 7518 §3.4 pairs with
    each alg (ES256→P-256, ES384→P-384, ES512→P-521). Without that pin,
    verify_block accepted a P-384 key for ES256 — a combination jwt.decode
    rejects and that no conformant verifier should accept."""

    def test_es256_with_p384_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from jwt.algorithms import ECAlgorithm

        priv = ec.generate_private_key(ec.SECP384R1())
        pub = priv.public_key()
        # Sign with an unbound ES256 algorithm (no expected_curve) so the
        # token is well-formed but wrong-curve; the library's curve-bound
        # verify must then reject it.
        unbound = ECAlgorithm(ECAlgorithm.SHA256)
        header = {'alg': 'ES256'}
        signing_input = utils.encode(header) + b'.' + utils.encode(PAYLOAD)
        raw_sig = unbound.sign(signing_input, unbound.prepare_key(priv))
        jws = signing_input + b'.' + utils.to_base64(raw_sig)
        with pytest.raises(SignatureError):
            verify_block(jws, key=pub)

    def test_es256_with_p256_key_still_accepts(self, ecc_priv_pem, ecc_pub_pem):
        # Regression: the curve pin must not break the legitimate ES256+P-256
        # path the library has always used for ECC badges.
        priv, pub = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        raw_sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'ES256'}, PAYLOAD, raw_sig)
        assert verify_block(jws, key=pub) is True

    def test_sign_es256_with_p384_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        priv = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(SignatureError):
            sign({'alg': 'ES256'}, PAYLOAD, key=priv)


# ── utils ──────────────────────────────────────────────────────────────────────

class TestUtils:
    def test_encode_decode_roundtrip(self):
        data = {'hello': 'world', 'n': 42}
        assert utils.decode(utils.encode(data)) == data

    def test_to_base64_from_base64_roundtrip(self):
        raw = b'\x00\x01\x02\xff\xfe'
        assert utils.from_base64(utils.to_base64(raw)) == raw

    def test_base64_no_padding(self):
        encoded = utils.to_base64(b'test')
        assert b'=' not in encoded

    def test_from_json_bytes(self):
        assert utils.from_json(b'"hello"') == 'hello'
        assert utils.from_json(b'{"k": 1}') == {'k': 1}

    def test_from_json_str(self):
        assert utils.from_json('{"k": 1}') == {'k': 1}

    def test_to_json_produces_bytes(self):
        result = utils.to_json({'a': 1})
        assert isinstance(result, bytes)
        assert json.loads(result) == {'a': 1}


# ── sign edge cases ────────────────────────────────────────────────────────────

class TestSignEdgeCases:
    def test_missing_key_raises(self, rsa_pub_pem):
        with pytest.raises(MissingKey):
            sign({'alg': 'RS256'}, PAYLOAD, key=None)

    def test_missing_alg_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, _ = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        with pytest.raises(MissingSigner):
            sign({}, PAYLOAD, key=priv)

    def test_unknown_algorithm_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, _ = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        with pytest.raises(RouteMissingError):
            sign({'alg': 'XX999'}, PAYLOAD, key=priv)

    def test_wrong_key_type_for_algorithm_raises(self, rsa_priv_pem, ecc_pub_pem):
        from openbadgeslib.keys import KeyECC
        k = KeyECC()
        k.read_public_key(ecc_pub_pem)
        with pytest.raises((SignatureError, Exception)):
            sign({'alg': 'RS256'}, PAYLOAD, key=k.get_pub_key())

    def test_live_wrong_family_key_raises_signature_error(self, ecc_priv_pem,
                                                          rsa_pub_pem):
        # #288: a live cryptography EC key with alg RS256 used to raise a raw
        # TypeError from prepare_key; it must be SignatureError (mirrors
        # verify_block). The OB1 signer path hands in live key objects.
        from openbadgeslib.keys import KeyECC
        k = KeyECC()
        k.read_private_key(ecc_priv_pem)
        with pytest.raises(SignatureError):
            sign({'alg': 'RS256'}, PAYLOAD, key=k.get_priv_key())


# ── key-object reuse (#215) ────────────────────────────────────────────────────

class TestKeyObjectReuse:
    """#215: an already-loaded cryptography key object is handed straight to
    PyJWT's prepare_key instead of being re-serialised to PEM and re-parsed on
    every sign. The OB1 path passes ``Badge.priv_key`` (loaded once at Badge
    construction), so the old ``prepare_key(key_to_pem(key))`` round-trip paid a
    ``load_pem_private_key`` per badge for nothing."""

    def test_prepare_key_arg_passes_objects_and_pems_through(self, rsa_priv_pem, rsa_pub_pem):
        from openbadgeslib._jws import _prepare_key_arg
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        assert _prepare_key_arg(priv) is priv              # object reused as-is
        assert _prepare_key_arg(pub) is pub
        assert _prepare_key_arg(rsa_priv_pem) is rsa_priv_pem   # PEM bytes untouched

    def test_sign_with_key_object_does_not_re_serialise(self, rsa_priv_pem, rsa_pub_pem, monkeypatch):
        import openbadgeslib._jws as jws_mod
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        calls = {'n': 0}
        orig = jws_mod.key_to_pem

        def counting(key):
            calls['n'] += 1
            return orig(key)

        monkeypatch.setattr(jws_mod, 'key_to_pem', counting)
        raw = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        assert calls['n'] == 0                             # no PEM round-trip for an object
        # …and the resulting signature is still valid.
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw)
        assert verify_block(jws, key=pub) is True

    def test_repeated_signing_with_object_stays_valid(self, ecc_priv_pem, ecc_pub_pem):
        # Sign several times with the same key object (ES256 → distinct tokens);
        # every signature must verify.
        priv, pub = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        for _ in range(4):
            raw = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
            jws = _build_jws({'alg': 'ES256'}, PAYLOAD, raw)
            assert verify_block(jws, key=pub) is True
