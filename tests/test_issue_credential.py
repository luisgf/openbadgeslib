"""Tests for issue_credential_from_conf — issuing a credential as a token.

The counterpart of test_issue.py's SignResult path: same orchestration, but the
deliverable is the credential itself rather than a badge image, and the subject
may be bound to a wallet key instead of an email.
"""
import base64
import json
from pathlib import Path

import jwt
import pytest

from openbadgeslib.issue import (CredentialResult, IssuanceError,
                                 issue_credential_from_conf)
from openbadgeslib.oid4vci import FORMAT_JWT_VC_JSON, FORMAT_SD_JWT_VC

TESTS_DIR = Path(__file__).parent

# A wallet holder key, as it would arrive in an OID4VCI key proof header.
HOLDER_JWK = {'kty': 'EC', 'crv': 'P-256',
              'x': 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
              'y': 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0'}


def _write_conf(tmp_path, *, key_type='RSA', priv='test_sign_rsa.pem',
                pub='test_verify_rsa.pem', status=False, sd_jwt_vct=None,
                proof_format=None):
    logdir = tmp_path / 'log'
    logdir.mkdir(exist_ok=True)
    lines = [
        "[paths]",
        "base = %s" % tmp_path,
        "base_log = %s" % logdir,
        "base_image = %s" % (TESTS_DIR / 'images'),
        "",
        "[logs]", "general = general.log", "signer = signer.log", "",
        "[issuer]",
        "name = Test Issuer",
        "url = https://example.com",
        "publish_url = https://issuer.example/issuer/",
    ]
    if sd_jwt_vct:
        lines.append("sd_jwt_vct = %s" % sd_jwt_vct)
    lines += [
        "",
        "[badge_1]",
        "name = Test Badge",
        "description = Test",
        "local_image = sample1.svg",
        "image = https://example.com/badge.svg",
        "criteria = https://example.com/criteria.html",
        "verify_key = https://example.com/verify.pem",
        "badge = https://example.com/badge.json",
        "crypto_key = https://example.com/key.json",
        "private_key = %s/%s" % (TESTS_DIR, priv),
        "public_key = %s/%s" % (TESTS_DIR, pub),
        "key_type = %s" % key_type,
    ]
    if status:
        lines.append("status_lists = revocation")
    if proof_format:
        lines.append("proof_format = %s" % proof_format)
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text("\n".join(lines) + "\n")
    from openbadgeslib.confparser import read_config_or_exit
    return read_config_or_exit(str(cfg))


def _claims(token):
    """The JWT-VC payload, without verifying (the signature has its own tests)."""
    return jwt.decode(token, options={'verify_signature': False})


class TestJwtVcIssuance:
    def test_returns_a_token_and_no_image(self, tmp_path):
        conf = _write_conf(tmp_path)
        result = issue_credential_from_conf(conf, 'badge_1', 'r@example.com')
        assert isinstance(result, CredentialResult)
        assert result.credential_format == FORMAT_JWT_VC_JSON
        # A compact JWS, not a baked SVG.
        assert result.token.count('.') == 2
        assert not result.token.startswith('<')
        assert result.jti and result.jti.startswith('urn:uuid:')
        assert result.credential is not None
        assert result.status_index is None
        assert result.holder_did is None

    def test_token_verifies_against_the_badge_key(self, tmp_path):
        from openbadgeslib.ob3 import OB3Verifier
        conf = _write_conf(tmp_path)
        result = issue_credential_from_conf(conf, 'badge_1', 'r@example.com')
        pubkey = (TESTS_DIR / 'test_verify_rsa.pem').read_bytes()
        credential = OB3Verifier(pubkey_pem=pubkey).verify(result.token)
        assert credential.achievement.name == 'Test Badge'

    def test_subject_is_the_recipient_without_a_holder_key(self, tmp_path):
        conf = _write_conf(tmp_path)
        result = issue_credential_from_conf(conf, 'badge_1', 'r@example.com')
        assert result.credential.recipient_id == 'mailto:r@example.com'
        assert _claims(result.token)['sub'] == 'mailto:r@example.com'

    def test_ldp_badge_section_does_not_divert_this_path(self, tmp_path):
        # proof_format governs the baked-image path only; a token is a token.
        # The badge here is RSA, which the ldp path rejects outright ("requires
        # an Ed25519 key") — so this passing proves the section's setting was
        # not consulted rather than merely that the output looks right.
        conf = _write_conf(tmp_path, proof_format='ldp')
        result = issue_credential_from_conf(conf, 'badge_1', 'r@example.com')
        assert result.token.count('.') == 2

    def test_evidence_and_expiry_flow_through(self, tmp_path):
        conf = _write_conf(tmp_path)
        result = issue_credential_from_conf(
            conf, 'badge_1', 'r@example.com',
            evidence='https://example.com/evidence', expires=30)
        assert result.credential.evidence_url == 'https://example.com/evidence'
        assert 'exp' in _claims(result.token)

    def test_unknown_format_is_refused(self, tmp_path):
        conf = _write_conf(tmp_path)
        with pytest.raises(IssuanceError, match='credential_format must be'):
            issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                       credential_format='ldp_vc')

    def test_missing_config_key_is_an_issuance_error(self, tmp_path):
        conf = _write_conf(tmp_path)
        with pytest.raises(IssuanceError):
            issue_credential_from_conf(conf, 'badge_nope', 'r@example.com')


class TestHolderBinding:
    def test_subject_becomes_the_holder_did_jwk(self, tmp_path):
        from openbadgeslib.ob3.did import did_jwk_from_jwk
        conf = _write_conf(tmp_path)
        result = issue_credential_from_conf(
            conf, 'badge_1', 'r@example.com', holder_jwk=HOLDER_JWK)
        expected = did_jwk_from_jwk(HOLDER_JWK)
        assert result.holder_did == expected
        assert result.credential.recipient_id == expected
        assert _claims(result.token)['sub'] == expected

    def test_recipient_survives_as_a_salted_hash(self, tmp_path):
        # The whole point of the identifier: the credential stays attributable
        # to a person even though the subject id is now an opaque wallet key.
        from openbadgeslib.ob2.models import hash_identity
        conf = _write_conf(tmp_path)
        result = issue_credential_from_conf(
            conf, 'badge_1', 'r@example.com', holder_jwk=HOLDER_JWK)
        identifiers = result.credential.identifiers
        assert len(identifiers) == 1
        ident = identifiers[0]
        assert ident.hashed is True
        assert ident.identity_type == 'emailAddress'
        assert ident.salt
        assert ident.identity_hash == hash_identity('r@example.com', ident.salt)
        # The plaintext address must not survive anywhere in the token.
        payload = _claims(result.token)
        assert 'r@example.com' not in json.dumps(payload)

    def test_salt_is_fresh_per_credential(self, tmp_path):
        # Two badges for the same person must not carry the same hash, or they
        # correlate the holder across credentials.
        conf = _write_conf(tmp_path)
        a = issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                       holder_jwk=HOLDER_JWK)
        b = issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                       holder_jwk=HOLDER_JWK)
        assert a.credential.identifiers[0].salt != b.credential.identifiers[0].salt
        assert (a.credential.identifiers[0].identity_hash
                != b.credential.identifiers[0].identity_hash)

    def test_a_leaked_private_key_is_refused(self, tmp_path):
        conf = _write_conf(tmp_path)
        with pytest.raises(IssuanceError, match='invalid holder key'):
            issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                       holder_jwk=dict(HOLDER_JWK, d='SECRET'))

    def test_a_malformed_holder_key_is_refused(self, tmp_path):
        conf = _write_conf(tmp_path)
        with pytest.raises(IssuanceError, match='invalid holder key'):
            issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                       holder_jwk={'no': 'kty'})

    def test_bound_credential_round_trips_through_the_verifier(self, tmp_path):
        from openbadgeslib.ob3 import OB3Verifier
        conf = _write_conf(tmp_path)
        result = issue_credential_from_conf(
            conf, 'badge_1', 'r@example.com', holder_jwk=HOLDER_JWK)
        pubkey = (TESTS_DIR / 'test_verify_rsa.pem').read_bytes()
        credential = OB3Verifier(pubkey_pem=pubkey).verify(result.token)
        assert credential.recipient_id == result.holder_did
        assert credential.identifiers[0].hashed is True


class TestStatus:
    def test_index_is_allocated_and_stamped(self, tmp_path):
        conf = _write_conf(tmp_path, status=True)
        result = issue_credential_from_conf(conf, 'badge_1', 'r@example.com')
        assert result.status_index is not None
        entries = result.credential.credential_status
        assert len(entries) == 1
        assert entries[0]['statusPurpose'] == 'revocation'
        assert entries[0]['statusListIndex'] == str(result.status_index)

    def test_registry_records_the_credential(self, tmp_path):
        from openbadgeslib.ob3.status_registry import StatusRegistry
        conf = _write_conf(tmp_path, status=True)
        result = issue_credential_from_conf(conf, 'badge_1', 'r@example.com')
        registry_path = tmp_path / 'status' / 'badge_1.json'
        registry = StatusRegistry.load(str(registry_path))
        assert registry.find(result.jti) is not None

    def test_a_reserved_index_is_used_instead_of_allocating(self, tmp_path):
        # The OID4VCI shape: the index was decided when the offer was made, so
        # the claim path stamps it without touching the registry.
        conf = _write_conf(tmp_path, status=True)
        result = issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                            status_index=4242)
        assert result.status_index == 4242
        assert result.credential.credential_status[0]['statusListIndex'] == '4242'
        registry_path = tmp_path / 'status' / 'badge_1.json'
        assert not registry_path.exists()

    def test_a_reserved_index_without_status_lists_is_refused(self, tmp_path):
        conf = _write_conf(tmp_path, status=False)
        with pytest.raises(IssuanceError, match='no status_lists'):
            issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                       status_index=7)

    def test_sd_jwt_with_status_lists_is_refused_early(self, tmp_path):
        # SD-JWT VC cannot carry status (#226), so a revocable badge issued in
        # that format would be silently irrevocable. Refuse before allocating.
        conf = _write_conf(tmp_path, key_type='ECC', priv='test_sign_ecc.pem',
                           pub='test_verify_ecc.pem', status=True)
        with pytest.raises(IssuanceError, match='irrevocable'):
            issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                       credential_format=FORMAT_SD_JWT_VC)
        # Nothing was allocated: the refusal happens before the registry write.
        assert not (tmp_path / 'status' / 'badge_1.json').exists()


class TestSdJwtIssuance:
    def test_issues_an_sd_jwt_bound_to_the_holder(self, tmp_path):
        pytest.importorskip('openvc')
        from openbadgeslib.ob3.eudi import verify_badge_sd_jwt
        conf = _write_conf(tmp_path, key_type='ECC', priv='test_sign_ecc.pem',
                           pub='test_verify_ecc.pem')
        result = issue_credential_from_conf(
            conf, 'badge_1', 'r@example.com',
            credential_format=FORMAT_SD_JWT_VC, holder_jwk=HOLDER_JWK)
        assert result.credential_format == FORMAT_SD_JWT_VC
        assert '~' in result.token
        pubkey = (TESTS_DIR / 'test_verify_ecc.pem').read_bytes()
        verified = verify_badge_sd_jwt(result.token, pubkey_pem=pubkey)
        # The cnf must be the key the wallet proved possession of.
        assert verified.confirmation['jwk']['x'] == HOLDER_JWK['x']

    def test_uses_the_issuer_vct_when_configured(self, tmp_path):
        pytest.importorskip('openvc')
        vct = 'https://issuer.example/issuer/vct/openbadge'
        conf = _write_conf(tmp_path, key_type='ECC', priv='test_sign_ecc.pem',
                           pub='test_verify_ecc.pem', sd_jwt_vct=vct)
        result = issue_credential_from_conf(
            conf, 'badge_1', 'r@example.com',
            credential_format=FORMAT_SD_JWT_VC)
        # An SD-JWT is <issuer-jwt>~<disclosure>~…; the vct lives in the
        # issuer JWT's payload and is always disclosed.
        issuer_jwt = result.token.split('~')[0]
        payload = issuer_jwt.split('.')[1]
        claims = json.loads(
            base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        assert claims['vct'] == vct

    def test_missing_extra_is_an_issuance_error(self, tmp_path, monkeypatch):
        # Without [eudi] installed the caller gets the documented error type,
        # not an ImportError leaking out of the issuance facade.
        import openbadgeslib.ob3.eudi as eudi
        from openbadgeslib.errors import LibOpenBadgesException
        conf = _write_conf(tmp_path, key_type='ECC', priv='test_sign_ecc.pem',
                           pub='test_verify_ecc.pem')

        def _boom(*a, **kw):
            raise eudi.EudiError('SD-JWT VC support needs the [eudi] extra')
        monkeypatch.setattr(eudi, 'issue_badge_sd_jwt', _boom)
        with pytest.raises(LibOpenBadgesException, match='eudi'):
            issue_credential_from_conf(conf, 'badge_1', 'r@example.com',
                                       credential_format=FORMAT_SD_JWT_VC)
