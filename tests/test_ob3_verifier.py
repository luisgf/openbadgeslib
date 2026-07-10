"""Tests for the OpenBadges 3.0 verifier."""
import pytest
from datetime import datetime, timezone

from openbadgeslib.ob3 import (
    OB3Verifier, OB3VerificationError, OpenBadgeCredential,
)
from openbadgeslib.errors import ErrorParsingFile


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
            lambda p: p.__setitem__('validUntil', '2000-01-01T00:00:00Z'))
        with pytest.raises(OB3VerificationError, match="expired"):
            ob3_rsa_verifier.verify(token)

    def test_future_vc_validfrom_rejected_as_not_yet_valid(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p.__setitem__('validFrom', '2099-01-01T00:00:00Z'))
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
                                     lambda p: p['issuer'].pop('id'))
        with pytest.raises(OB3VerificationError, match="vc.issuer.id"):
            ob3_rsa_verifier.verify(token)

    def test_missing_achievement_name_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        def mutate(p):
            p['credentialSubject']['achievement'].pop('name')
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        with pytest.raises(OB3VerificationError, match="achievement.name"):
            ob3_rsa_verifier.verify(token)

    def test_issuer_neither_object_nor_string_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        # issuer must be a Profile object or a string IRI; a number is neither.
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.__setitem__('issuer', 12345))
        with pytest.raises(OB3VerificationError, match="must be a JSON object"):
            ob3_rsa_verifier.verify(token)

    def test_malformed_date_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.__setitem__('validFrom', 'not-a-date'))
        with pytest.raises(OB3VerificationError, match="ISO 8601"):
            ob3_rsa_verifier.verify(token)

    def test_non_string_date_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        # A non-string validFrom must not leak a raw AttributeError out of
        # verify() (_parse_iso calls str.replace() on it directly).
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.__setitem__('validFrom', 12345))
        with pytest.raises(OB3VerificationError, match="ISO 8601"):
            ob3_rsa_verifier.verify(token)

    @pytest.mark.parametrize('field', ['validFrom', 'validUntil'])
    def test_timezone_naive_date_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential, field):
        # A syntactically-valid ISO 8601 string with no UTC/offset suffix
        # parses to a naive datetime, which must not leak a raw TypeError out
        # of verify() when compared against the tz-aware "now".
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.__setitem__(field, '2026-01-01T00:00:00'))
        with pytest.raises(OB3VerificationError, match="ISO 8601"):
            ob3_rsa_verifier.verify(token)

    # ── a payload with no OB3 type, or a non-str/non-list type, must not leak
    #    a raw AttributeError/TypeError out of verify() ────────────────────────
    def test_missing_type_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        # OB3 native: the payload IS the credential; one carrying no
        # OpenBadgeCredential type token must be rejected cleanly.
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.pop('type'))
        with pytest.raises(OB3VerificationError, match="OpenBadgeCredential"):
            ob3_rsa_verifier.verify(token)

    @pytest.mark.parametrize('bad_type', [None, 12345, {'not': 'a list'}])
    def test_non_list_vc_type_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential, bad_type):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.__setitem__('type', bad_type))
        with pytest.raises(OB3VerificationError, match="OpenBadgeCredential"):
            ob3_rsa_verifier.verify(token)

    # ── accept spec-valid shapes the verifier used to reject (#113) ────────────
    def test_achievementcredential_alias_accepted(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p.__setitem__('type', ['VerifiableCredential', 'AchievementCredential']))
        assert ob3_rsa_verifier.verify(token) is not None

    def test_missing_verifiablecredential_type_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p.__setitem__('type', ['OpenBadgeCredential']))
        with pytest.raises(OB3VerificationError, match="VerifiableCredential"):
            ob3_rsa_verifier.verify(token)

    def test_string_iri_issuer_accepted(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        # issuer as a bare IRI string (not a Profile object) is schema-valid.
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential, lambda p: p.__setitem__('issuer', p['iss']))
        restored = ob3_rsa_verifier.verify(token)
        assert restored.issuer.id == ob3_credential.issuer.id

    def test_subject_id_absent_with_identifier_accepted(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        def mutate(p):
            p['credentialSubject'].pop('id')
            p['credentialSubject']['identifier'] = [
                {'type': 'IdentityObject', 'hashed': True,
                 'identityHash': 'sha256$abc', 'identityType': 'emailAddress'}]
            p.pop('sub', None)   # sub mirrors credentialSubject.id
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        restored = ob3_rsa_verifier.verify(token)
        assert restored.recipient_id is None

    def test_subject_without_id_or_identifier_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        def mutate(p):
            p['credentialSubject'].pop('id')
            p.pop('sub', None)
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        with pytest.raises(OB3VerificationError, match="identifier"):
            ob3_rsa_verifier.verify(token)

    # ── enforce @context and required registered claims (#114) ─────────────────
    @pytest.mark.parametrize('ctx', [
        None,
        ['https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'],   # VC 2.0 missing
        ['https://www.w3.org/ns/credentials/v2'],                          # OB context missing
        ['https://example.com/ctx', 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'],
        'not-an-array',
    ])
    def test_bad_context_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential, ctx):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.__setitem__('@context', ctx))
        with pytest.raises(OB3VerificationError, match="@context"):
            ob3_rsa_verifier.verify(token)

    def test_missing_iss_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.pop('iss'))
        with pytest.raises(OB3VerificationError, match="iss"):
            ob3_rsa_verifier.verify(token)

    def test_missing_nbf_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.pop('nbf'))
        with pytest.raises(OB3VerificationError, match="nbf"):
            ob3_rsa_verifier.verify(token)

    def test_future_nbf_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        # A registered nbf claim well in the future makes PyJWT raise
        # ImmatureSignatureError (an InvalidTokenError) — it must surface as an
        # OB3VerificationError, not leak. One hour ahead is beyond any leeway.
        import time
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p.__setitem__('nbf', int(time.time()) + 3600))
        with pytest.raises(OB3VerificationError):
            ob3_rsa_verifier.verify(token)

    def test_missing_sub_when_subject_has_id_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential,
                                     lambda p: p.pop('sub'))
        with pytest.raises(OB3VerificationError, match="sub"):
            ob3_rsa_verifier.verify(token)

    def test_validfrom_within_clock_skew_accepted(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        # #217: a validFrom a few seconds ahead (issuer clock slightly fast)
        # must not false-reject a freshly issued credential — CLOCK_SKEW_LEEWAY
        # absorbs it. nbf is kept in the past so PyJWT's own (leeway-0) nbf
        # check does not trip first.
        from datetime import timedelta

        def mutate(p):
            now = datetime.now(timezone.utc)
            p['validFrom'] = (now + timedelta(seconds=20)).isoformat().replace('+00:00', 'Z')
            p['nbf'] = int((now - timedelta(seconds=1)).timestamp())
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        assert ob3_rsa_verifier.verify(token) is not None

    def test_validfrom_beyond_clock_skew_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        # #217: a validFrom an hour ahead is genuinely not-yet-valid — the
        # leeway must not swallow a real future-dating.
        from datetime import timedelta

        def mutate(p):
            now = datetime.now(timezone.utc)
            p['validFrom'] = (now + timedelta(hours=1)).isoformat().replace('+00:00', 'Z')
            p['nbf'] = int((now - timedelta(seconds=1)).timestamp())
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        with pytest.raises(OB3VerificationError, match='not yet valid'):
            ob3_rsa_verifier.verify(token)

    # ── a non-string id/name field (consumed downstream as a string, e.g.
    #    recipient binding calls .lower()) must not leak a raw AttributeError ───
    @pytest.mark.parametrize('bad_id', [12345, True, ['a'], {'x': 1}])
    def test_non_string_credential_subject_id_rejected(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential, bad_id
    ):
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p['credentialSubject'].__setitem__('id', bad_id))
        # Rejected even without expected_recipient (at credential-build time).
        with pytest.raises(OB3VerificationError, match="must be a string"):
            ob3_rsa_verifier.verify(token)

    def test_non_string_credential_subject_id_with_expected_recipient_rejected(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        # The documented recipient-binding path (-r/--receptor) must surface a
        # clean OB3VerificationError, not a raw AttributeError from .lower().
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p['credentialSubject'].__setitem__('id', 12345))
        with pytest.raises(OB3VerificationError):
            ob3_rsa_verifier.verify(token, expected_recipient='someone@example.com')

    def test_non_string_issuer_id_rejected(self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential):
        token = self._signed_with_vc(
            rsa_priv_pem, ob3_credential,
            lambda p: p['issuer'].__setitem__('id', 12345))
        with pytest.raises(OB3VerificationError, match="must be a string"):
            ob3_rsa_verifier.verify(token)

    # ── array credentialSubject: the sub cross-check must normalise the list to
    #    its first element, not call .get() on the list (which raised a raw
    #    AttributeError that escaped verify()) ─────────────────────────────────
    def test_array_credential_subject_with_matching_sub_verifies(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        def mutate(p):
            # credentialSubject as a non-empty array; 'sub' still matches its id.
            p['credentialSubject'] = [p['credentialSubject']]
        token = self._signed_with_vc(rsa_priv_pem, ob3_credential, mutate)
        restored = ob3_rsa_verifier.verify(token)
        assert isinstance(restored, OpenBadgeCredential)
        assert restored.recipient_id == ob3_credential.recipient_id

    def test_array_credential_subject_with_mismatched_sub_raises(
        self, rsa_priv_pem, ob3_rsa_verifier, ob3_credential
    ):
        def mutate(p):
            p['credentialSubject'] = [p['credentialSubject']]
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
        payload['type'] = ['VerifiableCredential']  # drop OpenBadgeCredential
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
        with pytest.raises(OB3VerificationError, match="No openbadgecredential"):
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
        itxt_data = b'openbadgecredential' + pack('BBBBB', 0, 1, 0, 0, 0) + zlib.compress(text_bytes)
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

    @staticmethod
    def _bake_raw_itxt(png_image, raw_text_bytes):
        """Insert an openbadges iTXt chunk with the compression flag unset and
        arbitrary (possibly non-UTF-8) raw text bytes."""
        from struct import pack
        from zlib import crc32
        from png import Reader, signature as _png_signature
        itxt_data = b'openbadgecredential' + pack('BBBBB', 0, 0, 0, 0, 0) + raw_text_bytes
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

    def test_malformed_utf8_itxt_text_raises_clean_error(self, png_image):
        # Invalid UTF-8 text bytes must not leak a raw UnicodeDecodeError out
        # of extract_token_from_png().
        png = self._bake_raw_itxt(png_image, b'\xff\xfe\xfd')
        with pytest.raises((OB3VerificationError, ErrorParsingFile)):
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


class TestJtiBinding:
    # The jti claim binds the token to the credential id (OB3 §8.2). A validly
    # signed token whose jti disagrees with (or omits) the credential id must be
    # rejected — sign_payload lets us forge exactly that.
    def test_mismatched_jti_raises(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        payload = ob3_credential.to_jwt_payload()
        payload['jti'] = 'urn:uuid:00000000-0000-0000-0000-000000000000'
        token = ob3_rsa_signer.sign_payload(payload)
        with pytest.raises(OB3VerificationError, match="jti"):
            ob3_rsa_verifier.verify(token)

    def test_missing_jti_raises(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        payload = ob3_credential.to_jwt_payload()
        del payload['jti']
        token = ob3_rsa_signer.sign_payload(payload)
        with pytest.raises(OB3VerificationError, match="jti"):
            ob3_rsa_verifier.verify(token)


class TestRawPassthrough:
    # The verified credential exposes the raw validated document so a caller can
    # read spec fields the model does not map, without re-parsing the token.
    def test_verify_exposes_raw_document(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        token = ob3_rsa_signer.sign(ob3_credential)
        credential = ob3_rsa_verifier.verify(token)
        assert credential.raw is not None
        assert credential.raw['id'] == credential.id
        # credentialSchema is emitted but not mapped onto the model — raw is the
        # only way to read it back.
        assert credential.raw['credentialSchema'][0]['type'] \
            == '1EdTechJsonSchemaValidator2019'

    def test_raw_passes_through_unmapped_fields(
        self, ob3_rsa_signer, ob3_rsa_verifier, ob3_credential
    ):
        payload = ob3_credential.to_jwt_payload()
        # alignment is a real OB3 achievement field the model does not map.
        payload['credentialSubject']['achievement']['alignment'] = [
            {'type': ['Alignment'], 'targetName': 'Competency X',
             'targetUrl': 'https://framework.example/x'}]
        token = ob3_rsa_signer.sign_payload(payload)
        credential = ob3_rsa_verifier.verify(token)
        alignment = credential.raw['credentialSubject']['achievement']['alignment']
        assert alignment[0]['targetName'] == 'Competency X'

    def test_raw_excluded_from_equality(self, ob3_credential):
        from dataclasses import replace
        a = replace(ob3_credential)
        b = replace(ob3_credential)
        a.raw = {'x': 1}
        assert a == b   # raw is compare=False, so it never affects ==
