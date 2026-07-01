"""Tests for the OpenBadges 3.0 verifier."""
import pytest
from datetime import datetime, timezone

from openbadgeslib.ob3 import (
    OB3Verifier, OB3VerificationError, OpenBadgeCredential,
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
        import base64
        import json
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

    def test_expired_vc_validuntil_rejected_independent_of_exp_claim(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        # The base credential has no expiration_date, so to_jwt_payload()
        # never sets the top-level 'exp' claim: PyJWT's own expiry check
        # cannot fire. vc.validUntil is the untrusted claim downstream
        # consumers actually read, and it must be re-checked independently.
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p['vc'].__setitem__('validUntil', '2000-01-01T00:00:00Z'))
        with pytest.raises(OB3VerificationError, match="expired"):
            ob3_rsa_verifier.verify(token)

    def test_future_vc_validfrom_rejected_as_not_yet_valid(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p['vc'].__setitem__('validFrom', '2099-01-01T00:00:00Z'))
        with pytest.raises(OB3VerificationError, match="not yet valid"):
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
        # Craft a token with HS256 in the header. The verifier pins the allowed
        # algorithms to its (RSA) key type, so HS256 is rejected up front.
        payload = ob3_credential.to_jwt_payload()
        token = _jwt.encode(payload, 'secret', algorithm='HS256')
        with pytest.raises(OB3VerificationError, match="not allowed for this key"):
            ob3_rsa_verifier.verify(token)

    def test_alg_none_token_rejected(self, ob3_rsa_verifier, ob3_credential):
        # Classic unsecured-JWT attack: an unsigned token with {"alg":"none"}.
        # Key pinning must reject it before any signature check is skipped.
        import jwt as _jwt
        payload = ob3_credential.to_jwt_payload()
        token = _jwt.encode(payload, key=None, algorithm='none')
        with pytest.raises(OB3VerificationError, match="not allowed for this key"):
            ob3_rsa_verifier.verify(token)

    def test_iss_claim_must_match_credential_issuer(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        # A validly-signed token whose registered 'iss' disagrees with the vc
        # issuer must be rejected (SEC-6).
        import jwt as _jwt
        payload = ob3_credential.to_jwt_payload()
        payload['iss'] = 'https://attacker.example/issuer'
        token = _jwt.encode(payload, rsa_priv_pem, algorithm='RS256')
        with pytest.raises(OB3VerificationError, match="iss"):
            ob3_rsa_verifier.verify(token)

    def test_sub_claim_must_match_subject_id(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        import jwt as _jwt
        payload = ob3_credential.to_jwt_payload()
        payload['sub'] = 'mailto:attacker@evil.com'
        token = _jwt.encode(payload, rsa_priv_pem, algorithm='RS256')
        with pytest.raises(OB3VerificationError, match="sub"):
            ob3_rsa_verifier.verify(token)

    def test_verification_error_is_a_library_exception(self):
        # OB3VerificationError must be catchable as the shared library base so a
        # single except covers both OB2 and OB3 (ARCH-9).
        from openbadgeslib.errors import LibOpenBadgesException
        assert issubclass(OB3VerificationError, LibOpenBadgesException)

    # ── malformed (but validly-signed) vc payloads are rejected with a clear
    #    message, not a raw KeyError/TypeError ───────────────────────────────
    def _signed_with_vc(self, rsa_priv_pem, ob3_credential, mutate):
        import jwt as _jwt
        payload = ob3_credential.to_jwt_payload()
        mutate(payload)
        return _jwt.encode(payload, rsa_priv_pem, algorithm='RS256')

    def test_missing_issuer_id_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p['vc']['issuer'].pop('id'))
        with pytest.raises(OB3VerificationError, match="vc.issuer.id"):
            ob3_rsa_verifier.verify(token)

    def test_missing_achievement_name_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        def mutate(p):
            p['vc']['credentialSubject']['achievement'].pop('name')
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        with pytest.raises(OB3VerificationError, match="achievement.name"):
            ob3_rsa_verifier.verify(token)

    def test_issuer_not_an_object_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p['vc'].__setitem__('issuer', 'https://e/issuer'))
        with pytest.raises(OB3VerificationError, match="must be a JSON object"):
            ob3_rsa_verifier.verify(token)

    def test_malformed_date_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p['vc'].__setitem__('validFrom', 'not-a-date'))
        with pytest.raises(OB3VerificationError, match="ISO 8601"):
            ob3_rsa_verifier.verify(token)

    def test_non_string_date_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        # A non-string validFrom must not leak a raw AttributeError out of
        # verify() (_parse_iso calls str.replace() on it directly).
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p['vc'].__setitem__('validFrom', 12345))
        with pytest.raises(OB3VerificationError, match="ISO 8601"):
            ob3_rsa_verifier.verify(token)

    # ── a non-object 'vc' claim, or a non-str/non-list 'vc.type', must not leak
    #    a raw AttributeError/TypeError out of verify() ────────────────────────
    @pytest.mark.parametrize('bad_vc', ['just-a-string', 12345, None, [], True])
    def test_non_object_vc_claim_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential, bad_vc):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.__setitem__('vc', bad_vc))
        with pytest.raises(OB3VerificationError, match="object"):
            ob3_rsa_verifier.verify(token)

    @pytest.mark.parametrize('bad_type', [None, 12345, {'not': 'a list'}])
    def test_non_list_vc_type_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential, bad_type):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p['vc'].__setitem__('type', bad_type))
        with pytest.raises(OB3VerificationError, match="OpenBadgeCredential"):
            ob3_rsa_verifier.verify(token)

    # ── array credentialSubject: the sub cross-check must normalise the list to
    #    its first element, not call .get() on the list (which raised a raw
    #    AttributeError that escaped verify()) ─────────────────────────────────
    def test_array_credential_subject_with_matching_sub_verifies(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        def mutate(p):
            # credentialSubject as a non-empty array; 'sub' still matches its id.
            p['vc']['credentialSubject'] = [p['vc']['credentialSubject']]
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        restored = ob3_rsa_verifier.verify(token)
        assert isinstance(restored, OpenBadgeCredential)
        assert restored.recipient_id == ob3_credential.recipient_id

    def test_array_credential_subject_with_mismatched_sub_raises(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        def mutate(p):
            p['vc']['credentialSubject'] = [p['vc']['credentialSubject']]
            p['sub'] = 'mailto:attacker@evil.com'
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        # Must be a clean OB3VerificationError, not a raw AttributeError.
        with pytest.raises(OB3VerificationError, match="sub"):
            ob3_rsa_verifier.verify(token)


class TestOB3VerifierRecipientBinding:
    def test_matching_expected_recipient_ok(self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential):
        token = ob3_rsa_signer.sign(ob3_credential)
        restored = ob3_rsa_verifier.verify(token, expected_recipient='recipient@example.com')
        assert restored.recipient_id == 'mailto:recipient@example.com'

    def test_matching_expected_recipient_with_mailto_ok(self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential):
        token = ob3_rsa_signer.sign(ob3_credential)
        restored = ob3_rsa_verifier.verify(token, expected_recipient='mailto:recipient@example.com')
        assert restored is not None

    def test_mismatched_expected_recipient_raises(self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential):
        token = ob3_rsa_signer.sign(ob3_credential)
        with pytest.raises(OB3VerificationError, match="mismatch"):
            ob3_rsa_verifier.verify(token, expected_recipient='attacker@evil.com')

    def test_did_recipient_passthrough(self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential):
        # A DID recipient must not be mangled into 'mailto:did:...': signer and
        # verifier both pass it through unchanged (DRY-5).
        from dataclasses import replace
        did = 'did:example:abc123'
        cred = replace(ob3_credential, recipient_id=did)
        token = ob3_rsa_signer.sign(cred)
        restored = ob3_rsa_verifier.verify(token, expected_recipient=did)
        assert restored.recipient_id == did

    def test_mixed_case_mailto_recipient_still_matches(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        # The email was baked in with one casing at sign time; verifying with
        # a differently-cased spelling of the same address must still match.
        from dataclasses import replace
        cred = replace(ob3_credential, recipient_id='mailto:John@Example.com')
        token = ob3_rsa_signer.sign(cred)
        restored = ob3_rsa_verifier.verify(token, expected_recipient='john@example.com')
        assert restored.recipient_id == 'mailto:John@Example.com'

    def test_case_sensitive_did_mismatch_still_raises(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        # Unlike mailto: URIs, DIDs are compared exactly — a differently-cased
        # DID must still be rejected as a mismatch.
        from dataclasses import replace
        cred = replace(ob3_credential, recipient_id='did:example:ABC123')
        token = ob3_rsa_signer.sign(cred)
        with pytest.raises(OB3VerificationError, match="mismatch"):
            ob3_rsa_verifier.verify(token, expected_recipient='did:example:abc123')

    def test_non_openbadge_credential_type_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        import jwt as _jwt
        payload = ob3_credential.to_jwt_payload()
        payload['vc']['type'] = ['VerifiableCredential']  # drop OpenBadgeCredential
        token = _jwt.encode(payload, rsa_priv_pem, algorithm='RS256')
        with pytest.raises(OB3VerificationError, match="OpenBadgeCredential"):
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

    def test_entity_expansion_svg_is_rejected(self):
        # Billion-laughs: defusedxml must refuse entity-expansion before it can
        # exhaust memory (SEC-3). It surfaces as a parse error, not a hang.
        from openbadgeslib.errors import ErrorParsingFile
        billion = (
            b'<?xml version="1.0"?>\n'
            b'<!DOCTYPE lolz [<!ENTITY lol "lol">'
            b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>\n'
            b'<svg>&lol2;</svg>'
        )
        with pytest.raises(ErrorParsingFile):
            OB3Verifier.extract_token_from_svg(billion)


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

    @staticmethod
    def _bake_compressed_itxt(png_image, text_bytes):
        """Insert an openbadges iTXt chunk with the compression flag set,
        mirroring the writer layout but with zlib-compressed text."""
        import zlib
        from struct import pack
        from zlib import crc32
        from png import Reader, signature as _png_signature
        # keyword \0 comp_flag=1 comp_method=0 lang \0 trans \0 <compressed text>
        itxt_data = b'openbadges' + pack('BBBBB', 0, 1, 0, 0, 0) + zlib.compress(text_bytes)
        chunks = list(Reader(bytes=png_image).chunks())
        chunks.insert(len(chunks) - 1, ('iTXt', itxt_data))
        out = _png_signature
        for tag, data in chunks:
            out += pack('!I', len(data))
            if isinstance(tag, str):
                tag = tag.encode('iso8859-1')
            out += tag + data
            checksum = crc32(tag)
            checksum = crc32(data, checksum) & 0xFFFFFFFF
            out += pack('!I', checksum)
        return out

    def test_compressed_itxt_token_is_extracted(self, png_image):
        # A conformant compressed iTXt token must be inflated and recovered.
        png = self._bake_compressed_itxt(png_image, b'header.payload.signature')
        assert OB3Verifier.extract_token_from_png(png) == 'header.payload.signature'

    def test_decompression_bomb_is_rejected(self, png_image):
        # A small chunk that inflates past the cap must be refused, not expanded
        # into memory (SEC-4).
        png = self._bake_compressed_itxt(png_image, b'A' * (5 * 1024 * 1024))
        with pytest.raises(OB3VerificationError, match="limit"):
            OB3Verifier.extract_token_from_png(png)


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
