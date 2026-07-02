"""End-to-end CLI tests for the OB3 issuer lifecycle:
openbadges-signer -V 3 with credentialStatus, and openbadges-publish -V 3
(status list + did.json generation, revocation management)."""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from openbadgeslib import openbadges_signer

TESTS_DIR = Path(__file__).parent
RECIPIENT = 'recipient@example.com'


def _write_config(tmp_path, key='rsa', status_lists=None, did=None,
                  status_base=None):
    (tmp_path / 'log').mkdir(exist_ok=True)
    lines = [
        "[paths]",
        "base = %s" % tmp_path,
        "base_key = %s" % TESTS_DIR,
        "base_log = ${base}/log",
        "base_image = %s" % (TESTS_DIR / 'images'),
        "base_status = ${base}/status",
        "",
        "[logs]", "general = general.log", "signer = signer.log", "",
        "[issuer]",
        "name = Test Issuer",
        "url = https://example.com",
        "email = issuer@example.com",
        "publish_url = https://example.com/issuer/",
        "revocationList = revoked.json",
    ]
    if did is not None:
        lines.append("did = %s" % did)
    lines += [
        "",
        "[badge_1]",
        "name = Test Badge",
        "description = Test",
        "local_image = sample1.svg",
        "image = https://example.com/badge.svg",
        "criteria = https://example.com/criteria.html",
        "criteria_narrative = Pass the test",
        "verify_key = https://example.com/verify.pem",
        "badge = https://example.com/badge.json",
        "private_key = ${paths:base_key}/test_sign_%s.pem" % key,
        "public_key = ${paths:base_key}/test_verify_%s.pem" % key,
        "key_type = %s" % key.upper(),
    ]
    if status_lists is not None:
        lines.append("status_lists = %s" % status_lists)
    if status_base is not None:
        lines.append("status_base = %s" % status_base)
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


def _sign(tmp_path, cfg, extra=()):
    out = tmp_path / 'out'
    out.mkdir(exist_ok=True)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
            '-o', str(out), '-E', '-V', '3'] + list(extra)
    with patch.object(sys, 'argv', argv):
        openbadges_signer.main()
    return out / ('badge_1_%s.svg' % RECIPIENT)


def _credential_from(badge_file, pub_pem):
    from openbadgeslib.ob3 import OB3Verifier
    token = OB3Verifier.extract_token_from_svg(badge_file.read_bytes())
    return OB3Verifier(pubkey_pem=pub_pem).verify(token,
                                                  expected_recipient=RECIPIENT)


# ── openbadges-signer -V 3 with status lists ─────────────────────────────────

class TestSignerStatus:
    def test_credential_carries_both_entries(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation, suspension')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)

        entries = credential.credential_status
        assert [e['statusPurpose'] for e in entries] == \
            ['revocation', 'suspension']
        assert [e['statusListCredential'] for e in entries] == [
            'https://example.com/issuer/badge_1/revocation.jwt',
            'https://example.com/issuer/badge_1/suspension.jwt',
        ]
        # One shared index across both purposes.
        assert len({e['statusListIndex'] for e in entries}) == 1
        assert all(e['type'] == 'BitstringStatusListEntry' for e in entries)

    def test_registry_records_the_issuance(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)

        registry = json.loads((tmp_path / 'status' / 'badge_1.json').read_text())
        entry = registry['entries'][credential.id]
        assert entry['index'] == int(
            credential.credential_status[0]['statusListIndex'])
        assert entry['recipient'] == 'mailto:' + RECIPIENT

    def test_signer_log_names_jti_and_index(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        log = (tmp_path / 'log' / 'signer.log').read_text()
        assert 'OB3 SIGNED for %s' % RECIPIENT in log
        assert 'JTI %s' % credential.id in log
        assert 'STATUS %s' % credential.credential_status[0]['statusListIndex'] \
            in log

    def test_custom_status_base(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation',
                            status_base='https://cdn.example.com/status')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.credential_status[0]['statusListCredential'] == \
            'https://cdn.example.com/status/revocation.jwt'

    def test_unknown_purpose_exits(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation, message')
        with pytest.raises(SystemExit):
            _sign(tmp_path, cfg)
        assert 'unknown purpose' in capsys.readouterr().out

    def test_without_status_lists_behaviour_unchanged(self, tmp_path,
                                                      rsa_pub_pem):
        cfg = _write_config(tmp_path)   # no status_lists: pre-3.1 behaviour
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.credential_status == []
        assert not (tmp_path / 'status').exists()
        log = (tmp_path / 'log' / 'signer.log').read_text()
        assert 'JTI' in log and 'STATUS' not in log


# ── [issuer] did handling ────────────────────────────────────────────────────

class TestIssuerDid:
    def test_did_auto_derives_from_publish_url(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, did='auto')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.issuer.id == 'did:web:example.com:issuer'

    def test_explicit_did_used_verbatim(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, did='did:web:issuer.example')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.issuer.id == 'did:web:issuer.example'

    def test_unset_keeps_publish_url(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path)
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.issuer.id == 'https://example.com/issuer/'

    def test_invalid_did_exits(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, did='not-a-did')
        with pytest.raises(SystemExit):
            _sign(tmp_path, cfg)
        assert "[issuer] did" in capsys.readouterr().out
