"""Unit tests for the reusable issuance API (openbadgeslib.issue).

Exercised directly — no CLI, no argv, no sys.exit — which is the point of
#160: the credential-construction, the status-registry→sign transactional
order and the Data Integrity verificationMethod policy are now callable and
assertable as a library, not only reachable by driving openbadges-signer.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from openbadgeslib.errors import ErrorSigningFile
from openbadgeslib.issue import (BatchResult, IssuanceError, SignResult,
                                 issue_batch_from_conf, issue_from_conf,
                                 output_basename)
from openbadgeslib.ob1.badge import BadgeImgType

TESTS_DIR = Path(__file__).parent


def _write_conf(tmp_path, *, priv='test_sign_rsa.pem', pub='test_verify_rsa.pem',
                key_type='RSA', base_key=None, status=False, hosted=False,
                crypto=True, did=None, proof_format=None):
    """A config parsed exactly as the CLI parses it (ExtendedInterpolation),
    for the RSA test keys committed under tests/ unless overridden."""
    base_key = str(base_key) if base_key is not None else str(TESTS_DIR)
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
    if did:
        lines.append("did = %s" % did)
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
        "private_key = %s/%s" % (base_key, priv),
        "public_key = %s/%s" % (base_key, pub),
        "key_type = %s" % key_type,
    ]
    if crypto:
        lines.append("crypto_key = https://example.com/key.json")
    if hosted:
        lines.append("hosted_assertions_base = https://example.com/assertions/")
    if status:
        lines.append("status_lists = revocation")
    if proof_format:
        lines.append("proof_format = %s" % proof_format)
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text("\n".join(lines) + "\n")
    from openbadgeslib.confparser import read_config_or_exit
    return read_config_or_exit(str(cfg))


class TestOutputBasename:
    def test_svg_and_png(self):
        assert output_basename('badge_1', 'a@e.com',
                               BadgeImgType.SVG) == 'badge_1_a@e.com.svg'
        assert output_basename('badge_1', 'a@e.com',
                               BadgeImgType.PNG) == 'badge_1_a@e.com.png'

    def test_rejects_path_separator(self):
        with pytest.raises(ValueError):
            output_basename('../evil', 'a@e.com', BadgeImgType.SVG)


class TestIssueOb3:
    def test_returns_signresult_and_writes_no_badge(self, tmp_path):
        conf = _write_conf(tmp_path)
        result = issue_from_conf(conf, 'badge_1', 'r@example.com', '3')
        assert isinstance(result, SignResult)
        assert result.ob_version == '3'
        assert result.proof_format == 'vc-jwt'
        assert result.badge_bytes and b'<svg' in result.badge_bytes
        assert result.jti and result.jti.startswith('urn:uuid:')
        assert result.credential is not None
        assert result.status_index is None
        assert result.badge_filename == 'badge_1_r@example.com.svg'
        # No user-facing I/O: writing the badge is the caller's job.
        assert not (tmp_path / result.badge_filename).exists()

    def test_status_registry_persisted_before_signing(self, tmp_path):
        # The registry→sign order is testable off the CLI: issue_from_conf
        # allocates and persists the index (an orchestration side effect) even
        # though it writes no badge, and the credential carries the matching
        # credentialStatus. A signing failure would thus leave only a harmless
        # orphan index, never a delivered-but-unrevocable badge.
        conf = _write_conf(tmp_path, status=True)
        result = issue_from_conf(conf, 'badge_1', 'r@example.com', '3')
        # The index is randomised (privacy — it must not leak issuance order or
        # count), so assert it is allocated and consistently stamped, not == 0.
        assert result.status_index is not None
        registry = tmp_path / 'status' / 'badge_1.json'
        assert registry.is_file()
        assert result.jti in registry.read_text()
        assert result.credential.credential_status
        assert result.credential.credential_status[0]['statusListIndex'] == \
            str(result.status_index)
        assert not (tmp_path / result.badge_filename).exists()

    def test_invalid_proof_format_raises_issuance_error(self, tmp_path):
        conf = _write_conf(tmp_path, proof_format='jwt')   # not vc-jwt/ldp
        with pytest.raises(IssuanceError, match='proof_format'):
            issue_from_conf(conf, 'badge_1', 'r@example.com', '3')

    def test_missing_issuer_section_raises_issuance_error(self, tmp_path):
        # A config problem (missing [issuer]) must surface as IssuanceError, not
        # a raw KeyError escaping the documented contract (#208).
        conf = _write_conf(tmp_path)
        conf.remove_section('issuer')
        with pytest.raises(IssuanceError):
            issue_from_conf(conf, 'badge_1', 'r@example.com', '3')


class TestIssueOb2:
    def test_signed_returns_bytes_and_assertion(self, tmp_path):
        conf = _write_conf(tmp_path)
        result = issue_from_conf(conf, 'badge_1', 'r@example.com', '2')
        assert result.ob_version == '2'
        assert result.assertion is not None
        assert result.assertion_id is None       # signed, not hosted
        assert result.hosted_json is None
        assert result.badge_bytes

    def test_signed_requires_crypto_key(self, tmp_path):
        conf = _write_conf(tmp_path, crypto=False)
        with pytest.raises(IssuanceError, match='crypto_key'):
            issue_from_conf(conf, 'badge_1', 'r@example.com', '2')

    def test_hosted_returns_assertion_json(self, tmp_path):
        conf = _write_conf(tmp_path, hosted=True)
        result = issue_from_conf(conf, 'badge_1', 'r@example.com', '2',
                                 hosted=True)
        assert result.hosted_json is not None
        assert result.assertion_id and result.assertion_id.endswith('.json')
        json.loads(result.hosted_json)           # valid JSON

    def test_hosted_requires_base(self, tmp_path):
        conf = _write_conf(tmp_path, hosted=False)
        with pytest.raises(IssuanceError, match='hosted_assertions_base'):
            issue_from_conf(conf, 'badge_1', 'r@example.com', '2', hosted=True)


class TestUnsupportedVersion:
    def test_ob1_is_cli_only(self, tmp_path):
        conf = _write_conf(tmp_path)
        with pytest.raises(IssuanceError, match='OpenBadges 1.0'):
            issue_from_conf(conf, 'badge_1', 'r@example.com', '1')


class TestVerificationMethodPolicy:
    """did:web-trusted vs did:key-self-asserted, decided in the API and now
    assertable without the CLI (#160)."""

    @pytest.fixture()
    def ed25519_dir(self, tmp_path, ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        (tmp_path / 'sign_ed25519.pem').write_bytes(priv_pem)
        (tmp_path / 'verify_ed25519.pem').write_bytes(pub_pem)
        return tmp_path

    def test_did_web_issuer_names_published_vm(self, ed25519_dir, tmp_path):
        pytest.importorskip('pyld')
        conf = _write_conf(tmp_path, base_key=ed25519_dir,
                           priv='sign_ed25519.pem', pub='verify_ed25519.pem',
                           key_type='ED25519', did='auto')
        result = issue_from_conf(conf, 'badge_1', 'r@example.com', '3',
                                 proof_format='ldp')
        from openbadgeslib.ob3 import OB3Verifier
        doc = json.loads(OB3Verifier.extract_token_from_svg(result.badge_bytes))
        assert doc['issuer']['id'] == 'did:web:issuer.example:issuer'
        assert doc['proof']['verificationMethod'] == \
            'did:web:issuer.example:issuer#badge_1'
        assert not result.notices        # trusted did:web → no self-asserted hint

    def test_non_did_issuer_warns_self_asserted(self, ed25519_dir, tmp_path):
        pytest.importorskip('pyld')
        conf = _write_conf(tmp_path, base_key=ed25519_dir,
                           priv='sign_ed25519.pem', pub='verify_ed25519.pem',
                           key_type='ED25519')   # plain URL issuer, no did
        result = issue_from_conf(conf, 'badge_1', 'r@example.com', '3',
                                 proof_format='ldp')
        assert any('self-asserted' in n for n in result.notices)

    def test_non_ed25519_key_with_ldp_raises(self, tmp_path):
        conf = _write_conf(tmp_path, proof_format='ldp')   # RSA key + ldp
        with pytest.raises(IssuanceError, match='Ed25519'):
            issue_from_conf(conf, 'badge_1', 'r@example.com', '3')


class TestIssueBatch:
    """Batch issuance (#165): several recipients, one registry transaction,
    per-recipient results, failures isolated."""

    def test_ob3_batch_is_a_single_registry_transaction(self, tmp_path):
        # The core win: N recipients get N indices allocated and stamped in ONE
        # registry file — load once, save once — not N separate load/save cycles.
        conf = _write_conf(tmp_path, status=True)
        recipients = ['a@e.com', 'b@e.com', 'c@e.com']
        results = issue_batch_from_conf(conf, 'badge_1', recipients, '3')
        assert [r.recipient for r in results] == recipients
        assert all(isinstance(r, BatchResult) and r.result is not None
                   and r.error is None for r in results)
        indices = [r.result.status_index for r in results]
        assert len(set(indices)) == 3                 # distinct indices
        registries = list((tmp_path / 'status').glob('*.json'))
        assert len(registries) == 1                   # one file for the batch
        registry_text = registries[0].read_text()
        assert all(r.result.jti in registry_text for r in results)

    def test_ob3_batch_without_status_has_no_indices(self, tmp_path):
        conf = _write_conf(tmp_path)                  # no status_lists
        results = issue_batch_from_conf(conf, 'badge_1',
                                        ['a@e.com', 'b@e.com'], '3')
        assert len(results) == 2
        assert all(r.result.status_index is None for r in results)
        assert not (tmp_path / 'status').exists()

    def test_ob2_batch_returns_one_result_per_recipient(self, tmp_path):
        conf = _write_conf(tmp_path)
        results = issue_batch_from_conf(conf, 'badge_1',
                                        ['a@e.com', 'b@e.com'], '2')
        assert [r.recipient for r in results] == ['a@e.com', 'b@e.com']
        assert all(r.result is not None and r.result.ob_version == '2'
                   for r in results)

    def test_ob2_batch_isolates_per_recipient_failures(self, tmp_path):
        # A config that makes every OB2 signing fail (no crypto_key) surfaces as
        # per-recipient errors, never a raised exception aborting the batch.
        conf = _write_conf(tmp_path, crypto=False)
        results = issue_batch_from_conf(conf, 'badge_1',
                                        ['a@e.com', 'b@e.com'], '2')
        assert len(results) == 2
        assert all(r.result is None and 'crypto_key' in (r.error or '')
                   for r in results)

    def test_empty_recipients_returns_empty(self, tmp_path):
        conf = _write_conf(tmp_path, status=True)
        assert issue_batch_from_conf(conf, 'badge_1', [], '3') == []

    def test_ob1_batch_rejected(self, tmp_path):
        conf = _write_conf(tmp_path)
        with pytest.raises(IssuanceError, match='single-recipient'):
            issue_batch_from_conf(conf, 'badge_1', ['a@e.com', 'b@e.com'], '1')


class TestSigningErrorIsWrapped:
    """#190 -- a baking/signing failure raises ErrorSigningFile, which is not an
    IssuanceError. The vc-jwt (OB3 default) and OB2 paths must surface it as an
    IssuanceError (like the LDP path) so the batch loop / CLI handle it instead
    of leaking a raw traceback; a status index was already allocated."""

    def test_ob3_vcjwt_single_wraps_it(self, tmp_path):
        conf = _write_conf(tmp_path)
        with patch('openbadgeslib.ob3.signer.OB3Signer.sign_into_svg',
                   side_effect=ErrorSigningFile('bad carrier image')):
            with pytest.raises(IssuanceError, match='bad carrier image'):
                issue_from_conf(conf, 'badge_1', 'r@example.com', '3')

    def test_ob2_single_wraps_it(self, tmp_path):
        conf = _write_conf(tmp_path)
        with patch('openbadgeslib.ob2.signer.OB2Signer.sign_into_svg',
                   side_effect=ErrorSigningFile('bad carrier image')):
            with pytest.raises(IssuanceError, match='bad carrier image'):
                issue_from_conf(conf, 'badge_1', 'r@example.com', '2')

    def test_ob3_batch_isolates_it_per_recipient(self, tmp_path):
        conf = _write_conf(tmp_path)
        with patch('openbadgeslib.ob3.signer.OB3Signer.sign_into_svg',
                   side_effect=ErrorSigningFile('bad carrier image')):
            results = issue_batch_from_conf(conf, 'badge_1',
                                            ['a@e.com', 'b@e.com'], '3')
        assert len(results) == 2
        assert all(r.result is None and 'bad carrier image' in (r.error or '')
                   for r in results)
