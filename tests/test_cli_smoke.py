"""Smoke / integration tests for the CLI entrypoints and previously-untested
code paths (publish, keygenerator key_type, urls_has_problems, mail errors)."""
import sys
from unittest.mock import patch


# ── openbadges-init ─────────────────────────────────────────────────────────────

def test_init_creates_directory_layout(tmp_path):
    from openbadgeslib import openbadges_init
    target = tmp_path / 'config'
    with patch.object(sys, 'argv', ['openbadges-init', str(target)]):
        openbadges_init.main()
    assert (target / 'config.ini').is_file()
    for sub in ('keys', 'images', 'log'):
        assert (target / sub).is_dir()


# ── openbadges-keygenerator honours key_type from the badge profile ─────────────

def _write_keygen_config(tmp_path, key_type):
    keys = tmp_path / 'keys'
    keys.mkdir()
    (tmp_path / 'log').mkdir()
    cfg = tmp_path / 'config.ini'
    cfg.write_text(
        "[paths]\n"
        f"base = {tmp_path}\n"
        f"base_key = {keys}\n"
        f"base_log = {tmp_path}/log\n"
        f"base_image = {tmp_path}/images\n\n"
        "[logs]\ngeneral = general.log\nsigner = signer.log\n\n"
        "[issuer]\nname = Test Issuer\n\n"
        "[badge_1]\nname = Badge 1\n"
        f"private_key = {keys}/sign.pem\n"
        f"public_key = {keys}/verify.pem\n"
        f"key_type = {key_type}\n"
    )
    return cfg


def test_keygenerator_generates_ecc_when_profile_says_ecc(tmp_path):
    from openbadgeslib import openbadges_keygenerator
    from openbadgeslib.keys import detect_key_type, KeyType
    cfg = _write_keygen_config(tmp_path, 'ECC')
    with patch.object(sys, 'argv',
                      ['openbadges-keygenerator', '-c', str(cfg), '-g', '1']):
        openbadges_keygenerator.main()
    pub = (tmp_path / 'keys' / 'verify.pem').read_bytes()
    assert detect_key_type(pub) is KeyType.ECC


def test_keygenerator_generates_rsa_by_default(tmp_path):
    from openbadgeslib import openbadges_keygenerator
    from openbadgeslib.keys import detect_key_type, KeyType
    cfg = _write_keygen_config(tmp_path, 'RSA')
    with patch.object(sys, 'argv',
                      ['openbadges-keygenerator', '-c', str(cfg), '-g', '1']):
        openbadges_keygenerator.main()
    pub = (tmp_path / 'keys' / 'verify.pem').read_bytes()
    assert detect_key_type(pub) is KeyType.RSA


# ── openbadges-verifier OB3 end-to-end ──────────────────────────────────────────

def test_verifier_ob3_end_to_end(tmp_path, rsa_priv_pem, rsa_pub_pem, svg_image, capsys):
    from openbadgeslib import openbadges_verifier
    from openbadgeslib.ob3 import OB3Signer, Issuer, Achievement, OpenBadgeCredential

    signer = OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')
    cred = OpenBadgeCredential(
        issuer=Issuer(id='https://example.com/issuer', name='Issuer'),
        recipient_id='mailto:recipient@example.com',
        achievement=Achievement(id='https://example.com/a', name='A',
                                description='d', criteria_narrative='c'),
    )
    badge_file = tmp_path / 'badge.svg'
    badge_file.write_bytes(signer.sign_into_svg(cred, svg_image))
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)

    argv = ['openbadges-verifier', '-i', str(badge_file),
            '-r', 'recipient@example.com', '-V', '3', '-k', str(pub)]
    with patch.object(sys, 'argv', argv):
        openbadges_verifier.main()
    assert 'valid' in capsys.readouterr().out.lower()


# ── openbadges-verifier OB2 end-to-end ──────────────────────────────────────────

def _make_signed_ob2_svg(tmp_path, badge, identity='recipient@example.com'):
    """Sign an OB2 SVG badge to a file and return its path."""
    from openbadgeslib.signer import Signer
    from openbadgeslib.badge import BadgeType
    signed = Signer(identity=identity, badge_type=BadgeType.SIGNED,
                    deterministic=True).sign_badge(badge)
    badge_file = tmp_path / 'badge.svg'
    badge_file.write_bytes(signed.signed)
    return badge_file


def _fake_revocation_download(url, *a, **k):
    """Stand in for the badge.json -> issuer.json -> revocationList chain,
    reporting the badge as not revoked."""
    import json as _json
    if url.endswith('badge.json'):
        return _json.dumps({'issuer': 'https://example.com/issuer.json'}).encode()
    return _json.dumps({}).encode()   # issuer JSON: no revocationList


def test_verifier_ob2_end_to_end_trusted_key(tmp_path, svg_rsa_badge, rsa_pub_pem, capsys):
    from openbadgeslib import openbadges_verifier
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)

    argv = ['openbadges-verifier', '-i', str(badge_file),
            '-r', 'recipient@example.com', '-V', '2', '-k', str(pub)]
    with patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem), \
         patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_revocation_download), \
         patch.object(sys, 'argv', argv):
        openbadges_verifier.main()
    assert 'Signature is correct' in capsys.readouterr().out


def test_verifier_ob2_without_trusted_key_warns(tmp_path, svg_rsa_badge, rsa_pub_pem, capsys):
    # No --local/--pubkey: the embedded key is used and the result must be
    # reported as internally-consistent-only, not '[+] correct' (SEC-2).
    from openbadgeslib import openbadges_verifier
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)

    argv = ['openbadges-verifier', '-i', str(badge_file),
            '-r', 'recipient@example.com', '-V', '2']
    with patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem), \
         patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_revocation_download), \
         patch.object(sys, 'argv', argv):
        openbadges_verifier.main()
    out = capsys.readouterr().out
    assert 'Signature is correct' not in out
    assert 'does NOT prove issuer identity' in out


def test_verifier_ob2_wrong_receptor_reports_mismatch(tmp_path, svg_rsa_badge, rsa_pub_pem, capsys):
    from openbadgeslib import openbadges_verifier
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)

    argv = ['openbadges-verifier', '-i', str(badge_file),
            '-r', 'someone-else@example.com', '-V', '2', '-k', str(pub)]
    with patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem), \
         patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_revocation_download), \
         patch.object(sys, 'argv', argv):
        openbadges_verifier.main()
    assert '[-]' in capsys.readouterr().out


def test_verifier_missing_file_exits(tmp_path):
    import pytest
    from openbadgeslib import openbadges_verifier
    argv = ['openbadges-verifier', '-i', str(tmp_path / 'nope.svg'),
            '-r', 'recipient@example.com', '-V', '2']
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit):
            openbadges_verifier.main()


# ── openbadges-signer → openbadges-verifier (OB3 CLI roundtrip) ─────────────────

def test_signer_ob3_then_verify_roundtrip(tmp_path, capsys):
    from openbadgeslib import openbadges_signer, openbadges_verifier

    sign_argv = ['openbadges-signer', '-c', './config1.ini', '-b', 'test_1',
                 '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '3', '-E']
    with patch.object(sys, 'argv', sign_argv):
        openbadges_signer.main()

    signed = tmp_path / 'badge_test_1_recipient@example.com.svg'
    assert signed.is_file()

    verify_argv = ['openbadges-verifier', '-i', str(signed),
                   '-r', 'recipient@example.com', '-V', '3',
                   '-k', 'test_verify_rsa.pem']
    with patch.object(sys, 'argv', verify_argv):
        openbadges_verifier.main()
    assert 'valid' in capsys.readouterr().out.lower()


# ── openbadges-publish ──────────────────────────────────────────────────────────

def test_publish_ob3_prints_info(tmp_path, capsys):
    from openbadgeslib import openbadges_publish
    argv = ['openbadges-publish', '-o', str(tmp_path / 'out'), '-V', '3']
    with patch.object(sys, 'argv', argv):
        openbadges_publish.main()
    out = capsys.readouterr().out
    assert 'JWT-VC' in out or 'self-contained' in out


def test_publish_ob2_creates_full_tree(tmp_path):
    """Every badge section must get a badge.json AND a verify.pem (the bug that
    silently published nothing is fixed)."""
    from openbadgeslib import openbadges_publish
    out = tmp_path / 'published'
    argv = ['openbadges-publish', '-c', './config1.ini', '-o', str(out)]
    with patch.object(sys, 'argv', argv):
        openbadges_publish.main()

    assert (out / 'organization.json').is_file()
    assert (out / 'revoked.json').is_file()
    for name in ('badge_test_1', 'badge_test_2', 'badge_test_3', 'badge_test_4'):
        assert (out / name / 'badge.json').is_file()
        assert (out / name / 'verify.pem').is_file()


# ── Badge.urls_has_problems ─────────────────────────────────────────────────────

def test_urls_has_problems_all_ok(svg_rsa_badge):
    with patch('openbadgeslib.ob2.badge.download_file', return_value=b'data'):
        assert svg_rsa_badge.urls_has_problems() is False


def test_urls_has_problems_detects_later_failure(svg_rsa_badge):
    # A later URL failing must be reported even though earlier ones succeed —
    # the stale-`data` masking bug is fixed.
    calls = {'n': 0}

    def fake_download(url, *a, **k):
        calls['n'] += 1
        if calls['n'] >= 3:
            raise ValueError('unreachable')
        return b'data'

    with patch('openbadgeslib.ob2.badge.download_file', side_effect=fake_download):
        assert svg_rsa_badge.urls_has_problems() is True


# ── BadgeMail error handling ────────────────────────────────────────────────────

def test_badgemail_send_handles_connection_error(svg_rsa_badge, capsys):
    from openbadgeslib.mail import BadgeMail
    from openbadgeslib.signer import Signer
    from openbadgeslib.badge import BadgeType

    signed = Signer(identity='user@example.com', badge_type=BadgeType.SIGNED,
                    deterministic=True).sign_badge(svg_rsa_badge)
    signed.file_out = 'badge.svg'

    mail = BadgeMail(smtp_server='localhost', smtp_port=2525, use_ssl=False,
                     mail_from='from@example.com')
    mail.set_subject('subject')
    mail.set_body('body')

    with patch('openbadgeslib.mail.SMTP', side_effect=ConnectionRefusedError('refused')):
        mail.send(signed)  # must not raise

    assert 'Error sending mail' in capsys.readouterr().out
