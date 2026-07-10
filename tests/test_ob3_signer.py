"""Tests for the OpenBadges 3.0 signer."""
import pytest
from xml.dom.minidom import parseString

from openbadgeslib.ob3 import OB3Signer
from openbadgeslib.errors import ErrorSigningFile


# ── OB3Signer construction ─────────────────────────────────────────────────────

class TestOB3SignerConstruction:
    def test_rsa_signer_created(self, rsa_priv_pem):
        s = OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')
        assert s.algorithm == 'RS256'

    def test_ecc_signer_created(self, ecc_priv_pem):
        s = OB3Signer(privkey_pem=ecc_priv_pem, algorithm='ES256')
        assert s.algorithm == 'ES256'

    def test_unsupported_algorithm_raises(self, rsa_priv_pem):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            OB3Signer(privkey_pem=rsa_priv_pem, algorithm='HS256')

    def test_accepts_key_object_rsa(self, rsa_priv_pem):
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_private_key(rsa_priv_pem)
        s = OB3Signer(privkey_pem=k.get_priv_key())
        assert s.algorithm == 'RS256'

    def test_accepts_key_object_ecc(self, ecc_priv_pem):
        from openbadgeslib.keys import KeyECC
        k = KeyECC()
        k.read_private_key(ecc_priv_pem)
        s = OB3Signer(privkey_pem=k.get_priv_key(), algorithm='ES256')
        assert s.algorithm == 'ES256'


# ── sign() ─────────────────────────────────────────────────────────────────────

class TestOB3SignerSign:
    def test_sign_returns_string(self, ob3_rsa_signer, ob3_credential):
        token = ob3_rsa_signer.sign(ob3_credential)
        assert isinstance(token, str)

    def test_sign_produces_three_part_jwt(self, ob3_rsa_signer, ob3_credential):
        token = ob3_rsa_signer.sign(ob3_credential)
        parts = token.split('.')
        assert len(parts) == 3
        assert all(p for p in parts)

    def test_sign_rsa_different_from_ecc(self, ob3_rsa_signer, ob3_ecc_signer, ob3_credential):
        rsa_token = ob3_rsa_signer.sign(ob3_credential)
        ecc_token = ob3_ecc_signer.sign(ob3_credential)
        # Different algorithms → different header (and signature)
        assert rsa_token != ecc_token

    def test_sign_rsa_deterministic(self, ob3_rsa_signer, ob3_credential):
        # RS256 with PKCS1v1.5 is deterministic for the same input
        t1 = ob3_rsa_signer.sign(ob3_credential)
        t2 = ob3_rsa_signer.sign(ob3_credential)
        assert t1 == t2

    def test_sign_ecc_verifiable(self, ob3_ecc_signer, ob3_ecc_verifier, ob3_credential):
        # ES256 uses a random nonce — verify instead of comparing tokens
        token = ob3_ecc_signer.sign(ob3_credential)
        restored = ob3_ecc_verifier.verify(token)
        assert restored.recipient_id == ob3_credential.recipient_id

    def test_jwt_header_contains_alg(self, ob3_rsa_signer, ob3_credential):
        import jwt
        token = ob3_rsa_signer.sign(ob3_credential)
        header = jwt.get_unverified_header(token)
        assert header['alg'] == 'RS256'

    def test_jwt_payload_is_native_credential(self, ob3_rsa_signer, ob3_credential):
        import jwt
        token = ob3_rsa_signer.sign(ob3_credential)
        # Decode without verification to inspect payload. OB3 native VC-JWT:
        # the credential is at the payload top level, not under a 'vc' claim.
        payload = jwt.decode(token, options={"verify_signature": False})
        assert 'vc' not in payload
        assert payload['type'] == ['VerifiableCredential', 'OpenBadgeCredential']
        assert payload['iss'] == ob3_credential.issuer.id
        assert payload['sub'] == ob3_credential.recipient_id
        assert 'nbf' in payload and 'iat' not in payload

    def test_jose_header_carries_public_jwk(self, ob3_rsa_signer, ob3_credential):
        import jwt
        token = ob3_rsa_signer.sign(ob3_credential)
        header = jwt.get_unverified_header(token)
        # OB3 §8.2.3: the header conveys the key via jwk; only public params.
        assert 'jwk' in header
        assert header['jwk'].get('kty') == 'RSA'
        assert 'd' not in header['jwk']

    def test_sign_rsa_key_with_ecc_algorithm_raises_clean_error(self, rsa_priv_pem, ob3_credential):
        # A supported-but-mismatched algorithm/key-type pair must not leak a
        # raw jwt.exceptions.InvalidKeyError out of sign().
        signer = OB3Signer(privkey_pem=rsa_priv_pem, algorithm='ES256')
        with pytest.raises(ErrorSigningFile):
            signer.sign(ob3_credential)

    def test_sign_ecc_key_with_rsa_algorithm_raises_clean_error(self, ecc_priv_pem, ob3_credential):
        signer = OB3Signer(privkey_pem=ecc_priv_pem, algorithm='RS256')
        with pytest.raises(ErrorSigningFile):
            signer.sign(ob3_credential)


# ── private-key caching (#215) ─────────────────────────────────────────────────

class TestOB3SignerKeyCaching:
    """#215: a signer parses its private-key PEM once and reuses the loaded
    object. The old path re-parsed it twice per credential — once in
    _public_jwk() and once inside jwt.encode() — which dominated batch signing
    (~86 ms/badge for RSA)."""

    def _count_pem_loads(self, monkeypatch):
        import cryptography.hazmat.primitives.serialization as ser
        calls = {'n': 0}
        orig = ser.load_pem_private_key

        def counting(*args, **kwargs):
            calls['n'] += 1
            return orig(*args, **kwargs)

        monkeypatch.setattr(ser, 'load_pem_private_key', counting)
        return calls

    def test_rsa_key_parsed_once_across_many_signs(self, rsa_priv_pem, ob3_credential, monkeypatch):
        calls = self._count_pem_loads(monkeypatch)
        signer = OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')  # PEM bytes: no load yet
        tokens = [signer.sign(ob3_credential) for _ in range(4)]
        assert calls['n'] == 1                             # loaded once, not 8 times
        assert all(len(t.split('.')) == 3 for t in tokens)

    def test_ed25519_key_parsed_once_across_many_signs(self, ed25519_priv_pem, ob3_credential, monkeypatch):
        calls = self._count_pem_loads(monkeypatch)
        signer = OB3Signer(privkey_pem=ed25519_priv_pem, algorithm='EdDSA')
        for _ in range(3):
            signer.sign(ob3_credential)
        assert calls['n'] == 1

    def test_batch_of_rsa_signatures_all_verify(self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential):
        # RS256 is deterministic, but the point is that reusing the cached key
        # yields signatures that still verify against the matching public key.
        tokens = [ob3_rsa_signer.sign(ob3_credential) for _ in range(5)]
        for token in tokens:
            assert ob3_rsa_verifier.verify(token).recipient_id == ob3_credential.recipient_id

    def test_batch_of_ecc_signatures_all_verify(self, ob3_ecc_signer, ob3_ecc_verifier, ob3_credential):
        # ES256 uses a random nonce, so each token differs; every one must still
        # verify with the memoised key.
        tokens = [ob3_ecc_signer.sign(ob3_credential) for _ in range(5)]
        assert len(set(tokens)) == 5
        for token in tokens:
            assert ob3_ecc_verifier.verify(token).recipient_id == ob3_credential.recipient_id

    def test_public_jwk_unchanged_by_caching(self, ob3_rsa_signer, ob3_credential):
        # The cached public JWK must be the same object/content across signs and
        # still carry only public parameters.
        import jwt
        h1 = jwt.get_unverified_header(ob3_rsa_signer.sign(ob3_credential))
        h2 = jwt.get_unverified_header(ob3_rsa_signer.sign(ob3_credential))
        assert h1['jwk'] == h2['jwk']
        assert h1['jwk']['kty'] == 'RSA' and 'd' not in h1['jwk']


# ── sign_into_svg() ────────────────────────────────────────────────────────────

class TestSignIntoSVG:
    def test_returns_bytes(self, ob3_rsa_signer, ob3_credential, svg_image):
        result = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        assert isinstance(result, bytes)

    def test_result_is_valid_xml(self, ob3_rsa_signer, ob3_credential, svg_image):
        result = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        doc = parseString(result)   # raises if invalid XML
        doc.unlink()

    def test_assertion_element_embedded(self, ob3_rsa_signer, ob3_credential, svg_image):
        result = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        doc = parseString(result)
        nodes = doc.getElementsByTagName('openbadges:credential')
        assert nodes.length == 1
        doc.unlink()

    def test_assertion_verify_attribute_is_jwt(self, ob3_rsa_signer, ob3_credential, svg_image):
        result = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        doc = parseString(result)
        token = doc.getElementsByTagName('openbadges:credential')[0].attributes['verify'].nodeValue
        doc.unlink()
        assert len(token.split('.')) == 3

    def test_ecc_sign_into_svg(self, ob3_ecc_signer, ob3_credential, svg_image):
        result = ob3_ecc_signer.sign_into_svg(ob3_credential, svg_image)
        doc = parseString(result)
        assert doc.getElementsByTagName('openbadges:credential').length == 1
        doc.unlink()

    def test_ob3_svg_uses_ob3_element_and_namespace(self, ob3_rsa_signer, ob3_credential, svg_image):
        # OB 3.0 baking identifiers, not the OB 2.0 ones.
        result = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        assert b'openbadges:credential' in result
        assert b'https://purl.imsglobal.org/ob/v3p0' in result
        assert b'openbadges:assertion' not in result

    def test_malformed_svg_raises_error_signing_file(self, ob3_rsa_signer, ob3_credential):
        from openbadgeslib.errors import ErrorSigningFile
        with pytest.raises(ErrorSigningFile):
            ob3_rsa_signer.sign_into_svg(ob3_credential, b'not even xml <<<')


# ── sign_into_png() ────────────────────────────────────────────────────────────

class TestSignIntoPNG:
    def test_returns_bytes(self, ob3_rsa_signer, ob3_credential, png_image):
        result = ob3_rsa_signer.sign_into_png(ob3_credential, png_image)
        assert isinstance(result, bytes)

    def test_result_starts_with_png_signature(self, ob3_rsa_signer, ob3_credential, png_image):
        from png import signature as _png_sig
        result = ob3_rsa_signer.sign_into_png(ob3_credential, png_image)
        assert result[:8] == _png_sig

    def test_itxt_chunk_present(self, ob3_rsa_signer, ob3_credential, png_image):
        from png import Reader
        result = ob3_rsa_signer.sign_into_png(ob3_credential, png_image)
        found = any(
            (tag.decode('ascii') if isinstance(tag, bytes) else tag) == 'iTXt'
            and data.startswith(b'openbadgecredential')
            for tag, data in Reader(bytes=result).chunks()
        )
        assert found

    def test_ecc_sign_into_png(self, ob3_ecc_signer, ob3_credential, png_image):
        from png import Reader
        result = ob3_ecc_signer.sign_into_png(ob3_credential, png_image)
        found = any(
            (tag.decode('ascii') if isinstance(tag, bytes) else tag) == 'iTXt'
            and data.startswith(b'openbadgecredential')
            for tag, data in Reader(bytes=result).chunks()
        )
        assert found

    def test_malformed_png_raises_error_signing_file(self, ob3_rsa_signer, ob3_credential):
        from openbadgeslib.errors import ErrorSigningFile
        with pytest.raises(ErrorSigningFile):
            ob3_rsa_signer.sign_into_png(ob3_credential, b'not a png at all')
