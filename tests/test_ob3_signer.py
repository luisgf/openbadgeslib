"""Tests for the OpenBadges 3.0 signer."""
import pytest
from xml.dom.minidom import parseString

from openbadgeslib.ob3 import OB3Signer, OB3Verifier


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

    def test_jwt_payload_contains_vc_claim(self, ob3_rsa_signer, ob3_credential):
        import jwt
        token = ob3_rsa_signer.sign(ob3_credential)
        # Decode without verification to inspect payload
        payload = jwt.decode(token, options={"verify_signature": False})
        assert 'vc' in payload
        assert payload['iss'] == ob3_credential.issuer.id
        assert payload['sub'] == ob3_credential.recipient_id


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
        nodes = doc.getElementsByTagName('openbadges:assertion')
        assert nodes.length == 1
        doc.unlink()

    def test_assertion_verify_attribute_is_jwt(self, ob3_rsa_signer, ob3_credential, svg_image):
        result = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        doc = parseString(result)
        token = doc.getElementsByTagName('openbadges:assertion')[0].attributes['verify'].nodeValue
        doc.unlink()
        assert len(token.split('.')) == 3

    def test_ecc_sign_into_svg(self, ob3_ecc_signer, ob3_credential, svg_image):
        result = ob3_ecc_signer.sign_into_svg(ob3_credential, svg_image)
        doc = parseString(result)
        assert doc.getElementsByTagName('openbadges:assertion').length == 1
        doc.unlink()


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
            and data.startswith(b'openbadges')
            for tag, data in Reader(bytes=result).chunks()
        )
        assert found

    def test_ecc_sign_into_png(self, ob3_ecc_signer, ob3_credential, png_image):
        from png import Reader
        result = ob3_ecc_signer.sign_into_png(ob3_credential, png_image)
        found = any(
            (tag.decode('ascii') if isinstance(tag, bytes) else tag) == 'iTXt'
            and data.startswith(b'openbadges')
            for tag, data in Reader(bytes=result).chunks()
        )
        assert found
