"""Tests for the OpenBadges 3.0 verifier."""
import pytest
from datetime import datetime, timezone, timedelta

from openbadgeslib.ob3 import (
    OB3Signer, OB3Verifier, OB3VerificationError, OpenBadgeCredential,
    Achievement, Issuer,
)


def _expired_credential(base_credential):
    """Return a copy of base_credential with an expiration date in the past."""
    from dataclasses import replace
    return replace(
        base_credential,
        expiration_date=datetime(2000, 1, 1, tzinfo=timezone.utc),
    )


# ── verify() ───────────────────────────────────────────────────────────────────

class TestOB3VerifierVerify:
    def test_valid_rsa_token_returns_credential(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        token = ob3_rsa_signer.sign(ob3_credential)
        restored = ob3_rsa_verifier.verify(token)
        assert isinstance(restored, OpenBadgeCredential)

    def test_valid_ecc_token_returns_credential(
        self, ob3_ecc_signer, ob3_ecc_verifier, ob3_credential
    ):
        token = ob3_ecc_signer.sign(ob3_credential)
        restored = ob3_ecc_verifier.verify(token)
        assert isinstance(restored, OpenBadgeCredential)

    def test_verified_credential_matches_original(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        token = ob3_rsa_signer.sign(ob3_credential)
        restored = ob3_rsa_verifier.verify(token)
        assert restored.recipient_id == ob3_credential.recipient_id
        assert restored.issuer.id == ob3_credential.issuer.id
        assert restored.achievement.name == ob3_credential.achievement.name
        assert restored.id == ob3_credential.id

    def test_tampered_signature_raises(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        token = ob3_rsa_signer.sign(ob3_credential)
        header, payload, sig = token.split('.')
        # Flip last character of signature
        tampered_sig = sig[:-1] + ('A' if sig[-1] != 'A' else 'B')
        tampered = f"{header}.{payload}.{tampered_sig}"
        with pytest.raises(OB3VerificationError):
            ob3_rsa_verifier.verify(tampered)

    def test_tampered_payload_raises(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        import base64, json
        token = ob3_rsa_signer.sign(ob3_credential)
        header, payload_b64, sig = token.split('.')
        # Decode → modify → re-encode
        pad = '=' * (-len(payload_b64) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
        decoded['sub'] = 'mailto:attacker@evil.com'
        tampered_payload = base64.urlsafe_b64encode(
            json.dumps(decoded).encode()
        ).rstrip(b'=').decode()
        tampered = f"{header}.{tampered_payload}.{sig}"
        with pytest.raises(OB3VerificationError):
            ob3_rsa_verifier.verify(tampered)

    def test_wrong_key_raises(self, ob3_rsa_signer, ob3_ecc_verifier, ob3_credential):
        token = ob3_rsa_signer.sign(ob3_credential)
        with pytest.raises(OB3VerificationError):
            ob3_ecc_verifier.verify(token)

    def test_wrong_rsa_key_raises(
        self, ob3_rsa_signer, ob3_credential, rsa_pub_pem
    ):
        # Sign with one key, verify with a freshly-generated different key
        from openbadgeslib.keys import KeyRSA
        other = KeyRSA()
        _, other_pub_pem = other.generate_keypair()
        token = ob3_rsa_signer.sign(ob3_credential)
        verifier = OB3Verifier(pubkey_pem=other_pub_pem)
        with pytest.raises(OB3VerificationError):
            verifier.verify(token)

    def test_expired_token_raises(self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential):
        expired = _expired_credential(ob3_credential)
        token = ob3_rsa_signer.sign(expired)
        with pytest.raises(OB3VerificationError, match="expired"):
            ob3_rsa_verifier.verify(token)

    def test_not_a_jwt_vc_raises(self, ob3_rsa_verifier, signed_svg_rsa):
        # OB 2.0 assertion embedded in SVG — extract the raw JWS string and
        # pass it to the OB 3.0 verifier, which should reject it.
        from xml.dom.minidom import parseString
        doc = parseString(signed_svg_rsa.signed)
        jws = doc.getElementsByTagName('openbadges:assertion')[0] \
                  .attributes['verify'].nodeValue
        doc.unlink()
        with pytest.raises(OB3VerificationError):
            ob3_rsa_verifier.verify(jws)

    def test_garbage_input_raises(self, ob3_rsa_verifier):
        with pytest.raises(OB3VerificationError):
            ob3_rsa_verifier.verify("not.a.jwt")

    def test_unsupported_algorithm_in_header_raises(
        self, ob3_rsa_verifier, ob3_credential
    ):
        import jwt as _jwt
        # Craft a token with HS256 in the header (not in _SUPPORTED_ALGORITHMS)
        payload = ob3_credential.to_jwt_payload()
        token = _jwt.encode(payload, 'secret', algorithm='HS256')
        with pytest.raises(OB3VerificationError, match="Unsupported algorithm"):
            ob3_rsa_verifier.verify(token)


# ── extract_token_from_svg() ───────────────────────────────────────────────────

class TestExtractFromSVG:
    def test_extracts_jwt_from_signed_svg(
        self, ob3_rsa_signer, ob3_credential, svg_image
    ):
        signed_svg = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        token = OB3Verifier.extract_token_from_svg(signed_svg)
        assert len(token.split('.')) == 3

    def test_extracted_token_matches_original(
        self, ob3_rsa_signer, ob3_credential, svg_image
    ):
        original_token = ob3_rsa_signer.sign(ob3_credential)
        signed_svg = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        extracted_token = OB3Verifier.extract_token_from_svg(signed_svg)
        assert extracted_token == original_token

    def test_missing_assertion_raises(self, svg_image):
        with pytest.raises(OB3VerificationError, match="No openbadges"):
            OB3Verifier.extract_token_from_svg(svg_image)

    def test_invalid_xml_raises(self):
        from openbadgeslib.errors import ErrorParsingFile
        with pytest.raises(ErrorParsingFile):
            OB3Verifier.extract_token_from_svg(b'not xml at all')


# ── extract_token_from_png() ───────────────────────────────────────────────────

class TestExtractFromPNG:
    def test_extracts_jwt_from_signed_png(
        self, ob3_rsa_signer, ob3_credential, png_image
    ):
        signed_png = ob3_rsa_signer.sign_into_png(ob3_credential, png_image)
        token = OB3Verifier.extract_token_from_png(signed_png)
        assert len(token.split('.')) == 3

    def test_extracted_token_matches_original(
        self, ob3_rsa_signer, ob3_credential, png_image
    ):
        original_token = ob3_rsa_signer.sign(ob3_credential)
        signed_png = ob3_rsa_signer.sign_into_png(ob3_credential, png_image)
        extracted_token = OB3Verifier.extract_token_from_png(signed_png)
        assert extracted_token == original_token

    def test_unsigned_png_raises(self, png_image):
        with pytest.raises(OB3VerificationError, match="No openbadges"):
            OB3Verifier.extract_token_from_png(png_image)


# ── end-to-end roundtrips ──────────────────────────────────────────────────────

class TestEndToEndRoundtrip:
    def test_svg_rsa_roundtrip(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential, svg_image
    ):
        signed_svg = ob3_rsa_signer.sign_into_svg(ob3_credential, svg_image)
        token = OB3Verifier.extract_token_from_svg(signed_svg)
        restored = ob3_rsa_verifier.verify(token)
        assert restored.recipient_id == ob3_credential.recipient_id
        assert restored.achievement.name == ob3_credential.achievement.name

    def test_png_rsa_roundtrip(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential, png_image
    ):
        signed_png = ob3_rsa_signer.sign_into_png(ob3_credential, png_image)
        token = OB3Verifier.extract_token_from_png(signed_png)
        restored = ob3_rsa_verifier.verify(token)
        assert restored.recipient_id == ob3_credential.recipient_id

    def test_svg_ecc_roundtrip(
        self, ob3_ecc_signer, ob3_ecc_verifier, ob3_credential, svg_image
    ):
        signed_svg = ob3_ecc_signer.sign_into_svg(ob3_credential, svg_image)
        token = OB3Verifier.extract_token_from_svg(signed_svg)
        restored = ob3_ecc_verifier.verify(token)
        assert restored.recipient_id == ob3_credential.recipient_id

    def test_png_ecc_roundtrip(
        self, ob3_ecc_signer, ob3_ecc_verifier, ob3_credential, png_image
    ):
        signed_png = ob3_ecc_signer.sign_into_png(ob3_credential, png_image)
        token = OB3Verifier.extract_token_from_png(signed_png)
        restored = ob3_ecc_verifier.verify(token)
        assert restored.recipient_id == ob3_credential.recipient_id

    def test_evidence_survives_roundtrip(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential, svg_image
    ):
        from dataclasses import replace
        cred_with_evidence = replace(
            ob3_credential,
            evidence_url='https://example.com/proof/123',
        )
        signed_svg = ob3_rsa_signer.sign_into_svg(cred_with_evidence, svg_image)
        token = OB3Verifier.extract_token_from_svg(signed_svg)
        restored = ob3_rsa_verifier.verify(token)
        assert restored.evidence_url == 'https://example.com/proof/123'
