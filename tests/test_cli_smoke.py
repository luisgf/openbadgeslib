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


def test_init_creates_directories_with_restrictive_permissions(tmp_path):
    # The keys/ subdirectory will hold private key material; openbadges_init
    # applies a 0o077 umask around the mkdir calls so every created directory
    # (not just keys/) ends up owner-only (0700), not world/group readable.
    import os
    import stat
    from openbadgeslib import openbadges_init
    target = tmp_path / 'config'
    with patch.object(sys, 'argv', ['openbadges-init', str(target)]):
        openbadges_init.main()
    for path in (target, target / 'keys', target / 'images', target / 'log'):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o700, '%s has mode %o, expected 0700' % (path, mode)


def test_init_restores_umask_when_a_subdirectory_mkdir_fails(tmp_path):
    # If any mkdir after os.umask(0o077) raises, the original umask must
    # still be restored — otherwise it stays at 0o077 for the rest of the
    # process (test_cli_smoke.py runs entrypoints in-process).
    import os
    import pytest
    from openbadgeslib import openbadges_init

    original = os.umask(0)
    os.umask(original)  # just peeking; restore immediately

    target = tmp_path / 'config'
    real_mkdir = os.mkdir

    def flaky_mkdir(path, *a, **k):
        if str(path).endswith('images'):
            raise OSError('simulated mkdir failure')
        return real_mkdir(path, *a, **k)

    with patch.object(sys, 'argv', ['openbadges-init', str(target)]):
        with patch('openbadgeslib.openbadges_init.os.mkdir', side_effect=flaky_mkdir):
            with pytest.raises(OSError):
                openbadges_init.main()

    after = os.umask(0)
    os.umask(after)
    assert after == original


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


def test_verifier_local_missing_pubkey_file_exits_cleanly(tmp_path):
    # The --local branch of _resolve_trusted_pubkey must guard a missing
    # public_key path the same way the --pubkey branch already does, instead
    # of leaking a raw FileNotFoundError.
    import argparse
    import pytest
    from openbadgeslib import openbadges_verifier

    cfg = tmp_path / 'config.ini'
    cfg.write_text(
        '[paths]\nbase = .\n\n'
        '[badge_missing]\npublic_key = %s\n' % (tmp_path / 'nonexistent.pem'))
    args = argparse.Namespace(local='missing', pubkey=None, config=str(cfg))
    with pytest.raises(SystemExit):
        openbadges_verifier._resolve_trusted_pubkey(args)


def test_verifier_garbage_pubkey_file_exits_cleanly(tmp_path, svg_rsa_badge, capsys):
    # A non-PEM --pubkey file must be reported via the CLI's '[-] ...' error
    # path (VerifierExceptions), not a raw traceback from detect_key_type().
    import pytest
    from openbadgeslib import openbadges_verifier
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    garbage = tmp_path / 'garbage.pem'
    garbage.write_bytes(b'this is not a pem key at all, just garbage text')

    argv = ['openbadges-verifier', '-i', str(badge_file),
            '-r', 'recipient@example.com', '-V', '2', '-k', str(garbage)]
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit):
            openbadges_verifier.main()
    assert '[-]' in capsys.readouterr().out


def test_verifier_local_and_pubkey_are_mutually_exclusive():
    # wiki/CLI-Reference.md documents -l/-k as mutually exclusive; enforce
    # that in argparse itself instead of silently letting -l win.
    import pytest
    from openbadgeslib import openbadges_verifier
    parser = openbadges_verifier.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(['-i', 'badge.svg', '-r', 'r@example.com',
                           '-l', '1', '-k', 'key.pem'])


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


def test_publish_restores_umask_when_a_badge_mkdir_fails(tmp_path):
    # If any step after os.umask(0o077) raises (a badge section's mkdir, a
    # missing public_key file, ...), the original umask must still be
    # restored rather than staying at 0o077 for the rest of the process.
    import os
    import pytest
    from openbadgeslib import openbadges_publish

    original = os.umask(0)
    os.umask(original)  # just peeking; restore immediately

    out = tmp_path / 'published'
    argv = ['openbadges-publish', '-c', './config1.ini', '-o', str(out)]
    real_mkdir = os.mkdir

    def flaky_mkdir(path, *a, **k):
        if 'badge_test_1' in str(path):
            raise OSError('simulated mkdir failure')
        return real_mkdir(path, *a, **k)

    with patch.object(sys, 'argv', argv):
        with patch('openbadgeslib.openbadges_publish.os.mkdir', side_effect=flaky_mkdir):
            with pytest.raises(OSError):
                openbadges_publish.main()

    after = os.umask(0)
    os.umask(after)
    assert after == original


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


def _signed_for_mail(badge, suffix, identity='user@example.com'):
    from openbadgeslib.signer import Signer
    from openbadgeslib.badge import BadgeType
    signed = Signer(identity=identity, badge_type=BadgeType.SIGNED,
                    deterministic=True).sign_badge(badge)
    signed.file_out = 'badge.' + suffix
    return signed


def test_badgemail_send_success_invokes_smtp(svg_rsa_badge):
    from unittest.mock import MagicMock
    from openbadgeslib.mail import BadgeMail
    signed = _signed_for_mail(svg_rsa_badge, 'svg')
    mail = BadgeMail('localhost', 465, True, 'from@example.com',
                     username='u', password='p')
    mail.set_subject('s')
    mail.set_body('b')
    smtp = MagicMock()
    with patch('openbadgeslib.mail.SMTP_SSL', return_value=smtp):
        mail.send(signed)
    smtp.login.assert_called_once_with('u', 'p')
    smtp.sendmail.assert_called_once()
    smtp.quit.assert_called_once()


def test_badgemail_send_handles_crlf_injection_value_error(svg_rsa_badge, capsys):
    # smtplib itself raises a bare ValueError as its CRLF header-injection
    # guard for a malformed from/to address; that must not crash send().
    from openbadgeslib.mail import BadgeMail
    from unittest.mock import MagicMock

    signed = _signed_for_mail(svg_rsa_badge, 'svg')
    mail = BadgeMail(smtp_server='localhost', smtp_port=25, use_ssl=False,
                     mail_from='from@example.com')
    mail.set_subject('subject')
    mail.set_body('body')

    smtp = MagicMock()
    smtp.sendmail.side_effect = ValueError('An address is only allowed to have <>')
    with patch('openbadgeslib.mail.SMTP', return_value=smtp):
        mail.send(signed)  # must not raise

    assert 'Error sending mail' in capsys.readouterr().out


def test_badgemail_auth_requires_ssl():
    import pytest
    from openbadgeslib.mail import BadgeMail

    with pytest.raises(ValueError, match='SMTP authentication requires'):
        BadgeMail('localhost', 25, False, 'from@example.com',
                  username='u', password='p')


def test_badgemail_send_uses_ssl_and_png_mime(png_rsa_badge):
    from unittest.mock import MagicMock
    from openbadgeslib.mail import BadgeMail
    signed = _signed_for_mail(png_rsa_badge, 'png')
    mail = BadgeMail('localhost', 465, True, 'from@example.com')
    mail.set_subject('s')
    mail.set_body('b')
    smtp = MagicMock()
    with patch('openbadgeslib.mail.SMTP_SSL', return_value=smtp) as ssl_ctor:
        mail.send(signed)
    ssl_ctor.assert_called_once()
    smtp.sendmail.assert_called_once()


def test_badgemail_auth_error_exits(svg_rsa_badge):
    import pytest
    from unittest.mock import MagicMock
    from smtplib import SMTPAuthenticationError
    from openbadgeslib.mail import BadgeMail
    signed = _signed_for_mail(svg_rsa_badge, 'svg')
    mail = BadgeMail('localhost', 465, True, 'from@example.com',
                     username='u', password='bad')
    mail.set_subject('s')
    mail.set_body('b')
    smtp = MagicMock()
    smtp.login.side_effect = SMTPAuthenticationError(535, b'bad creds')
    with patch('openbadgeslib.mail.SMTP_SSL', return_value=smtp):
        with pytest.raises(SystemExit):
            mail.send(signed)


def test_get_mail_content_empty_file_returns_none(tmp_path):
    from openbadgeslib.mail import BadgeMail
    empty = tmp_path / 'empty.txt'
    empty.write_text('')
    mail = BadgeMail('localhost', 25, False, 'from@example.com')
    assert mail.get_mail_content(str(empty)) == (None, None)


def test_get_mail_content_parses_subject_and_body(tmp_path):
    from openbadgeslib.mail import BadgeMail
    f = tmp_path / 'mail.txt'
    f.write_text('Subject line\nbody line 1\nbody line 2\n')
    mail = BadgeMail('localhost', 25, False, 'from@example.com')
    subject, body = mail.get_mail_content(str(f))
    assert subject == 'Subject line'
    assert 'body line 1' in body


# ── openbadges-signer OB2 end-to-end ────────────────────────────────────────────

def _write_ob2_sign_config(tmp_path, key='rsa', img='svg'):
    from pathlib import Path
    tests_dir = Path(__file__).parent
    logdir = tmp_path / 'log'
    logdir.mkdir()
    maildir = tmp_path / 'badgemail.txt'
    maildir.write_text('Your badge\nCongratulations!\n')
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text(
        "[paths]\n"
        f"base = {tmp_path}\n"
        f"base_key = {tests_dir}\n"
        f"base_log = {logdir}\n"
        f"base_image = {tests_dir / 'images'}\n\n"
        "[logs]\ngeneral = general.log\nsigner = signer.log\n\n"
        "[smtp]\nsmtp_server = localhost\nsmtp_port = 25\nuse_ssl = False\n"
        "mail_from = no-reply@example.com\n\n"
        "[issuer]\nname = Test Issuer\nurl = https://example.com\n"
        "publish_url = https://example.com/issuer/\nrevocationList = revocation.json\n\n"
        "[badge_1]\nname = Test Badge\ndescription = Test\n"
        f"local_image = sample1.{img}\n"
        f"image = https://example.com/badge.{img}\n"
        "criteria = https://example.com/criteria.html\n"
        "verify_key = https://example.com/verify.pem\n"
        "badge = https://example.com/badge.json\n"
        f"private_key = ${{paths:base_key}}/test_sign_{key}.pem\n"
        f"public_key = ${{paths:base_key}}/test_verify_{key}.pem\n"
        f"key_type = {key.upper()}\n"
        f"mail = {maildir}\n"
    )
    return cfg


def test_signer_ob2_writes_file_and_log(tmp_path, capsys):
    from openbadgeslib import openbadges_signer
    cfg = _write_ob2_sign_config(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-E']
    with patch('openbadgeslib.ob2.badge.download_file', return_value=b'data'), \
            patch.object(sys, 'argv', argv):
        openbadges_signer.main()
    out = capsys.readouterr().out
    assert 'SIGNED' in out
    assert (tmp_path / 'badge_1_recipient@example.com.svg').is_file()
    assert (tmp_path / 'log' / 'signer.log').read_text().strip() != ''


def test_signer_ob2_mail_badge_sends(tmp_path):
    from unittest.mock import MagicMock
    from openbadgeslib import openbadges_signer
    cfg = _write_ob2_sign_config(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-E', '-M']
    smtp = MagicMock()
    with patch('openbadgeslib.ob2.badge.download_file', return_value=b'data'), \
            patch('openbadgeslib.mail.SMTP', return_value=smtp), \
            patch.object(sys, 'argv', argv):
        openbadges_signer.main()
    smtp.sendmail.assert_called_once()


def test_signer_ob2_mail_badge_auth_without_ssl_reports_clean_error(tmp_path, capsys):
    # BadgeMail.__init__ raises a bare ValueError when username is set but
    # use_ssl is not True. The CLI must report it cleanly (the badge is
    # already signed and saved) instead of crashing with a raw traceback.
    from openbadgeslib import openbadges_signer
    cfg = _write_ob2_sign_config(tmp_path)
    cfg.write_text(cfg.read_text().replace(
        'mail_from = no-reply@example.com\n',
        'mail_from = no-reply@example.com\nusername = user\npassword = pass\n'))
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-E', '-M']
    with patch('openbadgeslib.ob2.badge.download_file', return_value=b'data'), \
            patch.object(sys, 'argv', argv):
        openbadges_signer.main()   # must not raise
    out = capsys.readouterr().out
    assert '[!] Could not send mail' in out
    signed = list(tmp_path.glob('badge_1_recipient@example.com.*'))
    assert signed, "badge must still be saved even though mailing failed"


def test_signer_ob2_mail_badge_missing_template_reports_clean_error(tmp_path, capsys):
    # A missing/unreadable mail template file makes get_mail_content() raise
    # OSError. The CLI must report it cleanly (the badge is already signed and
    # saved) instead of crashing with a raw traceback.
    from openbadgeslib import openbadges_signer
    cfg = _write_ob2_sign_config(tmp_path)
    cfg.write_text(cfg.read_text().replace(
        'mail = %s\n' % (tmp_path / 'badgemail.txt'),
        'mail = %s\n' % (tmp_path / 'nonexistent-mail.txt')))
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-E', '-M']
    with patch('openbadgeslib.ob2.badge.download_file', return_value=b'data'), \
            patch.object(sys, 'argv', argv):
        openbadges_signer.main()   # must not raise
    out = capsys.readouterr().out
    assert '[!] Could not send mail' in out
    signed = list(tmp_path.glob('badge_1_recipient@example.com.*'))
    assert signed, "badge must still be saved even though mailing failed"


def test_signer_requires_evidence_choice(tmp_path):
    import pytest
    from openbadgeslib import openbadges_signer
    cfg = _write_ob2_sign_config(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'r@example.com', '-o', str(tmp_path), '-V', '2']  # neither -e nor -E
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit):
            openbadges_signer.main()


# ── --debug flag wiring ─────────────────────────────────────────────────────────

def test_enable_debug_logging_sets_level():
    import logging
    from openbadgeslib.logs import enable_debug_logging
    enable_debug_logging(True)
    assert logging.getLogger().level == logging.DEBUG
    enable_debug_logging(False)
    assert logging.getLogger().level == logging.INFO


def test_all_cli_tools_expose_debug_flag():
    import importlib
    for name in ('openbadges_signer', 'openbadges_verifier', 'openbadges_keygenerator'):
        mod = importlib.import_module(f'openbadgeslib.{name}')
        opts = {o for a in mod.build_parser()._actions for o in a.option_strings}
        assert '--debug' in opts, f'{name} is missing --debug'


def test_verifier_debug_flag_emits_debug_records(tmp_path, svg_rsa_badge, rsa_pub_pem, caplog):
    import logging
    from openbadgeslib import openbadges_verifier
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)

    argv = ['openbadges-verifier', '-i', str(badge_file),
            '-r', 'recipient@example.com', '-V', '2', '-k', str(pub), '-d']
    with caplog.at_level(logging.DEBUG, logger='openbadgeslib.openbadges_verifier'):
        with patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem), \
                patch('openbadgeslib.ob2.verifier.download_file',
                      side_effect=_fake_revocation_download), \
                patch.object(sys, 'argv', argv):
            openbadges_verifier.main()
    assert any(r.levelno == logging.DEBUG for r in caplog.records)
