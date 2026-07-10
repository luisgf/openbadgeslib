"""Tests for the programmatic verification facade — openbadgeslib.verify.

verify_badge is the library counterpart of issue_from_conf: it runs the whole
verification (token extraction, JWT-VC/LDP auto-detection, DID resolution, trust
classification, signature/status) and returns a VerifyResult, doing no I/O. The
openbadges-verifier CLI is now a thin presenter over it (see the CLI tests for
the human/JSON output); these cover the facade contract directly.
"""
import pytest

from openbadgeslib.verify import (VerifyResult, verify_badge,
                                  issuer_did_from_token)


# ── OB3 ──────────────────────────────────────────────────────────────────────

class TestVerifyBadgeOB3:
    def test_pinned_key_valid_and_trusted(self, ob3_ed25519_signer,
                                          ed25519_pub_pem, ob3_credential,
                                          svg_image):
        baked = ob3_ed25519_signer.sign_into_svg(ob3_credential, svg_image)
        res = verify_badge(baked, '3', pubkey_pem=ed25519_pub_pem)
        assert isinstance(res, VerifyResult)
        assert res.valid and res.trusted
        assert res.proof_format == 'vc-jwt'
        assert res.reason is None
        assert res.credential.achievement.name == 'Test Achievement'

    def test_png_format_auto_detected(self, ob3_ed25519_signer, ed25519_pub_pem,
                                      ob3_credential, png_image):
        baked = ob3_ed25519_signer.sign_into_png(ob3_credential, png_image)
        # No image_format hint: the PNG signature is detected from the bytes.
        res = verify_badge(baked, '3', pubkey_pem=ed25519_pub_pem)
        assert res.valid and res.trusted

    def test_recipient_binding(self, ob3_ed25519_signer, ed25519_pub_pem,
                               ob3_credential, svg_image):
        baked = ob3_ed25519_signer.sign_into_svg(ob3_credential, svg_image)
        ok = verify_badge(baked, '3', pubkey_pem=ed25519_pub_pem,
                          expected_recipient='recipient@example.com')
        assert ok.valid
        bad = verify_badge(baked, '3', pubkey_pem=ed25519_pub_pem,
                           expected_recipient='someone-else@example.com')
        assert not bad.valid
        assert 'mismatch' in bad.reason.lower()

    def test_wrong_key_is_invalid(self, ob3_ed25519_signer, rsa_pub_pem,
                                  ob3_credential, svg_image):
        baked = ob3_ed25519_signer.sign_into_svg(ob3_credential, svg_image)
        res = verify_badge(baked, '3', pubkey_pem=rsa_pub_pem)
        assert not res.valid and not res.trusted
        assert res.reason.startswith('OB3 verification failed')

    def test_no_anchor_is_invalid(self, ob3_ed25519_signer, ob3_credential,
                                  svg_image):
        baked = ob3_ed25519_signer.sign_into_svg(ob3_credential, svg_image)
        res = verify_badge(baked, '3')          # no pubkey, no resolve_did
        assert not res.valid
        assert 'trusted key' in res.reason and 'resolve_did' in res.reason

    def test_unsupported_format_is_invalid(self, ed25519_pub_pem):
        res = verify_badge(b'this is not an image', '3',
                           pubkey_pem=ed25519_pub_pem)
        assert not res.valid
        assert 'Unsupported file format' in res.reason

    def test_resolve_did_key_is_valid_but_untrusted(self, ed25519_keypair,
                                                    svg_image):
        # A did:key issuer is self-asserted: resolving it proves the signature
        # matches the key, not who issued the badge -> valid but not trusted.
        from openbadgeslib.ob3 import (Achievement, Issuer, OB3Signer,
                                       OpenBadgeCredential)
        from openbadgeslib.ob3.did import did_key_from_pem
        priv, pub = ed25519_keypair
        did = did_key_from_pem(pub)
        cred = OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-0000000000c2',
            issuer=Issuer(id=did, name='Self'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'))
        baked = OB3Signer(privkey_pem=priv, algorithm='EdDSA').sign_into_svg(
            cred, svg_image)
        res = verify_badge(baked, '3', resolve_did=True)
        assert res.valid and not res.trusted
        assert res.issuer_did == did
        assert res.reason and 'self-asserted' in res.reason


# OB2 note: verify_badge('2', …) runs OB2Verifier.verify(check_revocation=True),
# which fetches the BadgeClass / CryptographicKey, so a hermetic OB2 test needs
# a mocked downloader. That full OB2 path (SignedBadge trusted/untrusted, Hosted,
# scope, revocation) is exercised through the CLI, which now calls verify_badge —
# see tests/test_ob2_cli.py and tests/test_ob2_verifier.py.


# ── misuse ───────────────────────────────────────────────────────────────────

def test_ob1_version_raises():
    with pytest.raises(ValueError, match='verified through the CLI only'):
        verify_badge(b'<svg/>', '1')


def test_unknown_version_raises():
    with pytest.raises(ValueError):
        verify_badge(b'<svg/>', '9')


def test_issuer_did_from_token_reexported():
    # The unverified-anchor helper is public API on verify (used by resolve_did).
    from openbadgeslib.ob3 import OB3VerificationError
    with pytest.raises(OB3VerificationError):
        issuer_did_from_token('not-a-jwt')
