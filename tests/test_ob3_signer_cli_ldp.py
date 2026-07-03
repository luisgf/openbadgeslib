"""End-to-end CLI tests for OB3 Data Integrity issuance —
openbadges-signer --proof-format ldp / [badge_N] proof_format = ldp.

Signing needs pyld (the [ldp] extra); the extra-absent test runs always.
"""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

TESTS_DIR = Path(__file__).parent
RECIPIENT = 'recipient@example.com'


@pytest.fixture()
def ed25519_key_files(tmp_path, ed25519_keypair):
    priv_pem, pub_pem = ed25519_keypair
    priv = tmp_path / 'sign_ed25519.pem'
    pub = tmp_path / 'verify_ed25519.pem'
    priv.write_bytes(priv_pem)
    pub.write_bytes(pub_pem)
    return priv, pub


def _write_config(tmp_path, *, key_type='ED25519',
                  priv='sign_ed25519.pem', pub='verify_ed25519.pem',
                  proof_format=None, did=None):
    logdir = tmp_path / 'log'
    logdir.mkdir(exist_ok=True)
    lines = [
        "[paths]",
        "base = %s" % tmp_path,
        "base_key = %s" % tmp_path,
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
        "private_key = ${paths:base_key}/%s" % priv,
        "public_key = ${paths:base_key}/%s" % pub,
        "key_type = %s" % key_type,
    ]
    if proof_format:
        lines.append("proof_format = %s" % proof_format)
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


def _sign(argv):
    from openbadgeslib import openbadges_signer
    with patch.object(sys, 'argv', argv):
        openbadges_signer.main()


def _verify_json(argv, capsys):
    from openbadgeslib import openbadges_verifier
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_verifier.main()
    return exc.value.code, json.loads(capsys.readouterr().out)


class TestSignerLdpCli:
    @pytest.fixture(autouse=True)
    def _needs_pyld(self):
        pytest.importorskip('pyld')

    def test_flag_signs_ldp_and_verifies(self, tmp_path, ed25519_key_files,
                                         capsys):
        cfg = _write_config(tmp_path)
        _sign(['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
               '-o', str(tmp_path), '-V', '3', '-E', '--proof-format', 'ldp'])
        out = capsys.readouterr().out
        assert 'OB3 SIGNED' in out and 'PROOF ldp' in out
        badge = tmp_path / ('badge_1_%s.svg' % RECIPIENT)
        assert badge.is_file()

        code, result = _verify_json(
            ['openbadges-verifier', '-i', str(badge), '-r', RECIPIENT,
             '-V', '3', '-k', str(ed25519_key_files[1]), '--json'], capsys)
        assert code == 0
        assert result['valid'] is True and result['proof_format'] == 'ldp'

    def test_ini_proof_format_needs_no_flag(self, tmp_path, ed25519_key_files,
                                            capsys):
        cfg = _write_config(tmp_path, proof_format='ldp')
        _sign(['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
               '-o', str(tmp_path), '-V', '3', '-E'])
        assert 'PROOF ldp' in capsys.readouterr().out
        badge = tmp_path / ('badge_1_%s.svg' % RECIPIENT)
        code, result = _verify_json(
            ['openbadges-verifier', '-i', str(badge), '-r', RECIPIENT,
             '-V', '3', '-k', str(ed25519_key_files[1]), '--json'], capsys)
        assert code == 0 and result['proof_format'] == 'ldp'

    def test_flag_overrides_ini(self, tmp_path, ed25519_key_files, capsys):
        cfg = _write_config(tmp_path, proof_format='ldp')
        _sign(['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
               '-o', str(tmp_path), '-V', '3', '-E',
               '--proof-format', 'vc-jwt'])
        assert 'PROOF ldp' not in capsys.readouterr().out
        badge = tmp_path / ('badge_1_%s.svg' % RECIPIENT)
        code, result = _verify_json(
            ['openbadges-verifier', '-i', str(badge), '-r', RECIPIENT,
             '-V', '3', '-k', str(ed25519_key_files[1]), '--json'], capsys)
        assert code == 0 and result['proof_format'] == 'vc-jwt'

    def test_did_web_issuer_uses_published_vm(self, tmp_path,
                                              ed25519_key_files, capsys):
        # did = auto → did:web from publish_url; the proof must name the
        # method id openbadges-publish publishes: did:web:…#badge_1.
        cfg = _write_config(tmp_path, did='auto')
        _sign(['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
               '-o', str(tmp_path), '-V', '3', '-E', '--proof-format', 'ldp'])
        capsys.readouterr()
        badge = tmp_path / ('badge_1_%s.svg' % RECIPIENT)

        from openbadgeslib.ob3 import OB3Verifier
        doc = json.loads(OB3Verifier.extract_token_from_svg(
            badge.read_bytes()))
        assert doc['issuer']['id'] == 'did:web:issuer.example:issuer'
        assert doc['proof']['verificationMethod'] == \
            'did:web:issuer.example:issuer#badge_1'

    def test_audit_log_carries_proof_token(self, tmp_path, ed25519_key_files,
                                           capsys):
        cfg = _write_config(tmp_path, proof_format='ldp')
        _sign(['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
               '-o', str(tmp_path), '-V', '3', '-E'])
        capsys.readouterr()
        log = (tmp_path / 'log' / 'signer.log').read_text()
        assert 'OB3 SIGNED' in log and 'PROOF ldp' in log

    def test_url_issuer_warns_self_asserted(self, tmp_path, ed25519_key_files,
                                            capsys):
        cfg = _write_config(tmp_path)   # no [issuer] did → plain URL issuer
        _sign(['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
               '-o', str(tmp_path), '-V', '3', '-E', '--proof-format', 'ldp'])
        out = capsys.readouterr().out
        assert '[i]' in out and 'did = auto' in out

    def test_non_ed25519_key_exits_with_hint(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, key_type='RSA',
                            priv='test_sign_rsa.pem',
                            pub='test_verify_rsa.pem')
        # RSA test keys live in TESTS_DIR, not tmp_path.
        text = (tmp_path / 'cfg.ini').read_text().replace(
            'base_key = %s' % tmp_path, 'base_key = %s' % TESTS_DIR)
        (tmp_path / 'cfg.ini').write_text(text)
        with pytest.raises(SystemExit):
            _sign(['openbadges-signer', '-c', str(cfg), '-b', '1',
                   '-r', RECIPIENT, '-o', str(tmp_path), '-V', '3', '-E',
                   '--proof-format', 'ldp'])
        out = capsys.readouterr().out
        assert 'Ed25519' in out and 'openbadges-keygenerator' in out

    def test_bad_ini_proof_format_exits_cleanly(self, tmp_path,
                                                ed25519_key_files, capsys):
        cfg = _write_config(tmp_path, proof_format='jwt')
        with pytest.raises(SystemExit):
            _sign(['openbadges-signer', '-c', str(cfg), '-b', '1',
                   '-r', RECIPIENT, '-o', str(tmp_path), '-V', '3', '-E'])
        assert 'proof_format' in capsys.readouterr().out

    def test_proof_format_rejected_for_ob2(self, tmp_path, ed25519_key_files):
        cfg = _write_config(tmp_path)
        with pytest.raises(SystemExit, match='OpenBadges 3.0 only'):
            _sign(['openbadges-signer', '-c', str(cfg), '-b', '1',
                   '-r', RECIPIENT, '-o', str(tmp_path), '-V', '2', '-E',
                   '--proof-format', 'ldp'])


class TestEd25519CliSupport:
    # Badge.create_from_conf rejected key_type = ED25519 outright, so the
    # CLI could never sign with the keys openbadges-keygenerator -t ED25519
    # produces — a prerequisite for LDP issuance, fixed alongside it.

    def test_vc_jwt_with_ed25519_key_roundtrips(self, tmp_path,
                                                ed25519_key_files, capsys):
        cfg = _write_config(tmp_path)   # default proof format: vc-jwt
        _sign(['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
               '-o', str(tmp_path), '-V', '3', '-E'])
        assert 'OB3 SIGNED' in capsys.readouterr().out
        badge = tmp_path / ('badge_1_%s.svg' % RECIPIENT)
        code, result = _verify_json(
            ['openbadges-verifier', '-i', str(badge), '-r', RECIPIENT,
             '-V', '3', '-k', str(ed25519_key_files[1]), '--json'], capsys)
        assert code == 0 and result['proof_format'] == 'vc-jwt'

    def test_ob1_with_ed25519_key_exits_cleanly(self, tmp_path,
                                                ed25519_key_files):
        # The legacy JWS path has no Ed25519 support; it must refuse with a
        # clean message, not crash deep in jws_sign.
        cfg = _write_config(tmp_path)
        with pytest.raises(SystemExit, match='RSA and ECC'):
            _sign(['openbadges-signer', '-c', str(cfg), '-b', '1',
                   '-r', RECIPIENT, '-o', str(tmp_path), '-V', '1', '-E'])


class TestSignerLdpCliExtraAbsent:
    def test_missing_pyld_reports_install_hint(self, tmp_path,
                                               ed25519_key_files,
                                               monkeypatch, capsys):
        monkeypatch.setitem(sys.modules, 'pyld', None)
        cfg = _write_config(tmp_path, proof_format='ldp')
        with pytest.raises(SystemExit):
            _sign(['openbadges-signer', '-c', str(cfg), '-b', '1',
                   '-r', RECIPIENT, '-o', str(tmp_path), '-V', '3', '-E'])
        out = capsys.readouterr().out
        assert 'pip install openbadgeslib[ldp]' in out
        # No badge file may be left behind by a failed signing.
        assert not (tmp_path / ('badge_1_%s.svg' % RECIPIENT)).exists()
