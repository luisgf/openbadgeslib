"""Tests for the EUDI SD-JWT VC track (openbadgeslib.ob3.eudi), which issues and
verifies Open Badges as SD-JWT VC by consuming the openvc-core library.

The crypto tests need the [eudi] extra (openvc-core) and skip without it; the
"extra absent" test runs always (it simulates the missing dependency).
"""
import sys

import pytest

from openbadgeslib.ob3.eudi import (
    DEFAULT_DISCLOSABLE,
    OB3_SD_JWT_VCT,
    EudiError,
    badge_to_sd_jwt_claims,
    issue_badge_sd_jwt,
    verify_badge_sd_jwt,
)


class TestSdJwtBadge:
    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip("openvc")

    # ── issue + verify round-trip ────────────────────────────────────────────

    def test_roundtrip_ed25519(self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        result = verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)
        assert result.issuer == ob3_credential.issuer.id
        assert result.vct == OB3_SD_JWT_VCT
        assert result.claims["achievement"]["name"] == ob3_credential.achievement.name
        assert result.claims["credentialSubject"]["id"] == ob3_credential.recipient_id

    def test_roundtrip_es256(self, ob3_credential, ecc_priv_pem, ecc_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ecc_priv_pem)
        result = verify_badge_sd_jwt(token, pubkey_pem=ecc_pub_pem)
        assert result.issuer == ob3_credential.issuer.id
        assert result.claims["achievement"]["name"] == ob3_credential.achievement.name

    def test_claims_shape(self, ob3_credential):
        claims = badge_to_sd_jwt_claims(ob3_credential)
        assert claims["iss"] == ob3_credential.issuer.id
        assert claims["achievement"]["name"] == ob3_credential.achievement.name
        assert claims["credentialSubject"]["id"] == ob3_credential.recipient_id
        assert "credentialSubject" in DEFAULT_DISCLOSABLE   # recipient is disclosable

    # ── selective disclosure ─────────────────────────────────────────────────

    def test_holder_can_withhold_recipient(self, ob3_credential,
                                           ed25519_priv_pem, ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        # A holder presentation that drops the disclosures keeps the achievement
        # but withholds the (selectively-disclosable) recipient identity.
        issuer_jwt = token.split("~", 1)[0] + "~"
        result = verify_badge_sd_jwt(issuer_jwt, pubkey_pem=ed25519_pub_pem)
        assert result.claims["achievement"]["name"] == ob3_credential.achievement.name
        assert "credentialSubject" not in result.claims

    # ── key binding (the EUDI wallet flow) ───────────────────────────────────

    def test_key_binding_presentation(self, ob3_credential,
                                      ed25519_priv_pem, ed25519_pub_pem):
        from openvc.keys import P256SigningKey
        from openvc.proof.sd_jwt import SdJwtVcProofSuite

        holder = P256SigningKey.generate(kid="did:example:holder#0")
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   holder_jwk=holder.public_jwk())
        presentation = SdJwtVcProofSuite().create_presentation(
            token, holder_key=holder, audience="https://verifier.example",
            nonce="n-123")
        result = verify_badge_sd_jwt(
            presentation, pubkey_pem=ed25519_pub_pem,
            audience="https://verifier.example", nonce="n-123",
            require_key_binding=True)
        assert result.key_bound is True

    # ── failure modes ────────────────────────────────────────────────────────

    def test_wrong_key_fails(self, ob3_credential, ed25519_priv_pem, rsa_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(token, pubkey_pem=rsa_pub_pem)

    def test_tampered_token_fails(self, ob3_credential, ed25519_priv_pem,
                                  ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        head, sep, rest = token.partition("~")
        tampered = head[:-3] + ("aaa" if head[-3:] != "aaa" else "bbb") + sep + rest
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(tampered, pubkey_pem=ed25519_pub_pem)

    def test_expected_vct_mismatch_fails(self, ob3_credential, ed25519_priv_pem,
                                         ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                expected_vct="https://example.com/other-type")

    def test_rsa_key_rejected(self, ob3_credential, rsa_priv_pem):
        # SD-JWT's algorithm set is {ES256, EdDSA}; RSA is not allowed.
        with pytest.raises(EudiError, match="Ed25519|P-256|RSA"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=rsa_priv_pem)


# ── behaviour without the [eudi] extra (runs with or without openvc) ─────────

class TestExtraAbsent:
    def test_missing_openvc_yields_actionable_error(self, monkeypatch,
                                                    ob3_credential, ed25519_priv_pem):
        # Null the submodules too — nulling only the top package is ignored when
        # the submodules are already cached in sys.modules.
        for name in ("openvc", "openvc.keys", "openvc.proof.sd_jwt"):
            monkeypatch.setitem(sys.modules, name, None)
        with pytest.raises(EudiError, match=r"openbadgeslib\[eudi\]"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
