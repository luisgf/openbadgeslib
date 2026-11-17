"""CLI batch-issuance tests for openbadges-signer (#165).

Multiple -r / --recipients-file drive a single-transaction batch: N badges from
one registry load/save, a per-recipient JSON summary, --force/skip semantics for
existing files, and failures isolated so one bad recipient never aborts the run.
"""
import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from openbadgeslib import openbadges_signer

TESTS_DIR = Path(__file__).parent


def _write_config(tmp_path, *, status=False, hosted=False):
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
        "",
        "[badge_1]",
        "name = Test Badge",
        "description = Test",
        "local_image = sample1.svg",
        "image = https://example.com/badge.svg",
        "criteria = https://example.com/criteria.html",
        "verify_key = https://example.com/verify.pem",
        "badge = https://example.com/badge.json",
        "private_key = %s/test_sign_rsa.pem" % TESTS_DIR,
        "public_key = %s/test_verify_rsa.pem" % TESTS_DIR,
        "key_type = RSA",
        "crypto_key = https://example.com/key.json",     # OB2 SignedBadge
    ]
    if status:
        lines.append("status_lists = revocation")
    if hosted:
        lines.append("hosted_assertions_base = https://example.com/assertions/")
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


def _out_dir(tmp_path):
    out = tmp_path / 'out'
    out.mkdir(exist_ok=True)
    return out


def _run_json(argv, capsys):
    """Run main() in --json mode, returning (exit_code, parsed_summary)."""
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_signer.main()
    return exc.value.code, json.loads(capsys.readouterr().out)


def test_missing_output_dir_is_created_before_issue(tmp_path, capsys):
    # #282: -o pointing at a missing directory used to allocate an OB3 status
    # index and then raise FileNotFoundError on write. The signer now creates
    # the directory up front so issuance only runs when the badge can land.
    cfg = _write_config(tmp_path, status=True)
    out = tmp_path / 'new' / 'nested' / 'out'     # does not exist yet
    assert not out.exists()
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '3', '-E', '--json', '-r', 'a@e.com']
    code, result = _run_json(argv, capsys)
    assert code == 0
    assert out.is_dir()
    # Single-recipient path returns the historical one-badge payload (not the
    # batch {signed:[…]} shape).
    assert Path(result['badge_file']).is_file()
    assert result['status_index'] is not None


def test_output_path_that_is_a_file_exits_cleanly(tmp_path, capsys):
    # #282: -o must be a directory; a regular file is a clean CLI error, not a
    # traceback mid-issue after a status index has been burned.
    cfg = _write_config(tmp_path, status=True)
    not_a_dir = tmp_path / 'not_a_dir'
    not_a_dir.write_text('nope')
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(not_a_dir),
            '-V', '3', '-E', '--json', '-r', 'a@e.com']
    code, result = _run_json(argv, capsys)
    assert code == 1
    assert 'error' in result
    assert 'not a directory' in result['error']
    # No status registry should have been written (issuance never started).
    status_dir = tmp_path / 'status'
    if status_dir.exists():
        assert list(status_dir.rglob('*.json')) == []


def test_batch_multiple_recipients_one_registry_transaction(tmp_path, capsys):
    cfg = _write_config(tmp_path, status=True)
    out = _out_dir(tmp_path)
    recipients = ['a@e.com', 'b@e.com', 'c@e.com']
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '3', '-E', '--json']
    for r in recipients:
        argv += ['-r', r]
    code, result = _run_json(argv, capsys)
    assert code == 0
    assert [s['recipient'] for s in result['signed']] == recipients
    assert result['skipped'] == [] and result['failed'] == []
    for r in recipients:
        assert (out / ('badge_1_%s.svg' % r)).is_file()
    # Single transaction: one registry file carries all three allocations.
    registries = list((tmp_path / 'status').glob('*.json'))
    assert len(registries) == 1
    indices = [s['status_index'] for s in result['signed']]
    assert len(set(indices)) == 3


def test_batch_skips_existing_then_force_overwrites(tmp_path, capsys):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    base = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '3', '-E', '--json', '-r', 'a@e.com', '-r', 'b@e.com']
    code, result = _run_json(base, capsys)
    assert code == 0 and len(result['signed']) == 2

    # Re-run: both output files exist → all skipped, exit 2, nothing re-signed.
    code, result = _run_json(base, capsys)
    assert code == 2
    assert len(result['skipped']) == 2 and len(result['signed']) == 0
    assert all(s['reason'] == 'exists' for s in result['skipped'])

    # --force overwrites them.
    code, result = _run_json(base + ['--force'], capsys)
    assert code == 0 and len(result['signed']) == 2 and result['skipped'] == []


def test_recipients_file_and_dedup(tmp_path, capsys):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    rfile = tmp_path / 'recipients.txt'
    # comments, blank lines, comma-separated cells, and a -r duplicate.
    rfile.write_text("# team\na@e.com\nb@e.com\n\nc@e.com, d@e.com\n")
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '3', '-E', '--json', '-r', 'a@e.com',
            '--recipients-file', str(rfile)]
    code, result = _run_json(argv, capsys)
    assert code == 0
    assert {s['recipient'] for s in result['signed']} == \
        {'a@e.com', 'b@e.com', 'c@e.com', 'd@e.com'}       # a@e.com not doubled


def test_recipients_file_skips_a_bom(tmp_path):
    # A Windows editor's BOM must not stick to the first recipient.
    import argparse
    rfile = tmp_path / 'recipients.txt'
    rfile.write_bytes(b'\xef\xbb\xbf' + 'begoña@e.com\nb@e.com\n'.encode('utf-8'))
    args = argparse.Namespace(receptor=None, recipients_file=str(rfile))
    assert openbadges_signer._gather_recipients(args) == ['begoña@e.com', 'b@e.com']


def test_recipients_file_not_utf8_exits_cleanly(tmp_path):
    import argparse
    rfile = tmp_path / 'recipients.txt'
    rfile.write_bytes('josé@e.com\n'.encode('cp1252'))
    args = argparse.Namespace(receptor=None, recipients_file=str(rfile))
    with pytest.raises(SystemExit, match='is not valid UTF-8'):
        openbadges_signer._gather_recipients(args)


def test_batch_isolates_unsafe_recipient(tmp_path, capsys):
    # An unsafe recipient (path separator) is skipped with a reason; the good
    # one still issues — one bad recipient does not abort the batch.
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '3', '-E', '--json',
            '-r', 'good@e.com', '-r', 'a/../etc/passwd']
    code, result = _run_json(argv, capsys)
    assert code == 2
    assert [s['recipient'] for s in result['signed']] == ['good@e.com']
    assert [s['recipient'] for s in result['skipped']] == ['a/../etc/passwd']


def test_batch_human_summary(tmp_path, capsys):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '3', '-E', '-r', 'a@e.com', '-r', 'b@e.com']
    with patch.object(sys, 'argv', argv):
        openbadges_signer.main()   # full success -> no SystemExit (exit 0)
    text = capsys.readouterr().out
    assert text.count('OB3 SIGNED') == 2
    assert '2 signed, 0 skipped, 0 failed' in text


def test_batch_partial_exits_nonzero_in_human_mode(tmp_path, capsys):
    # #191 -- a partial batch (a recipient skipped/failed) must exit non-zero in
    # human mode too, not silently exit 0; only --json used to surface exit 2.
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '3', '-E', '-r', 'a@e.com', '-r', 'b@e.com']
    with patch.object(sys, 'argv', argv):
        openbadges_signer.main()               # first run signs both
    capsys.readouterr()
    with patch.object(sys, 'argv', argv):      # re-run: both files exist -> all
        with pytest.raises(SystemExit) as exc:  # skipped -> _exit=2 -> non-zero
            openbadges_signer.main()
    assert exc.value.code not in (0, None)


def test_ob2_batch(tmp_path, capsys):
    # OB2 batch: no status registry, per-recipient SignedBadge, one summary.
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '2', '-E', '--json', '-r', 'a@e.com', '-r', 'b@e.com']
    code, result = _run_json(argv, capsys)
    assert code == 0
    assert [s['recipient'] for s in result['signed']] == ['a@e.com', 'b@e.com']
    assert result['ob_version'] == '2'
    for r in ('a@e.com', 'b@e.com'):
        assert (out / ('badge_1_%s.svg' % r)).is_file()
    assert not (tmp_path / 'status').exists()      # OB2 has no registry


def test_ob1_batch_rejected(tmp_path):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-V', '1', '-E', '-r', 'a@e.com', '-r', 'b@e.com']
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_signer.main()
    assert exc.value.code not in (0, None)


def test_no_recipient_errors(tmp_path):
    cfg = _write_config(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o',
            str(_out_dir(tmp_path)), '-V', '3', '-E']
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_signer.main()
    assert exc.value.code not in (0, None)


# ── #342: the output paths are never written through a planted symlink ────────
#
# The output names are predictable (<out>/badge_<n>_<recipient>.<ext> and
# ....assertion.json), so a local user who can write to the -o directory can
# plant a symlink there before the operator signs.

def _plant_symlink(link, target):
    """Create *link* -> *target*, or skip where symlinks cannot be made (a
    Windows account without the privilege, or a platform without them)."""
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip('cannot create a symlink here: %s' % exc)


def _no_temp_left(out):
    return [p.name for p in out.iterdir() if p.name.endswith('.tmp')] == []


def _signer_argv(cfg, out, *extra):
    return ['openbadges-signer', '-c', str(cfg), '-b', '1', '-o', str(out),
            '-E', *extra]


@pytest.mark.parametrize('version', ['3', '2', '1'])
def test_single_dangling_symlink_is_not_followed(tmp_path, capsys, version):
    cfg = _write_config(tmp_path, status=True)
    out = _out_dir(tmp_path)
    target = tmp_path / 'victim' / 'created.txt'
    target.parent.mkdir()
    link = out / 'badge_1_mallory@e.com.svg'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', version, '--json', '-r', 'mallory@e.com')
    code, result = _run_json(argv, capsys)
    assert code == 1
    assert 'has already signed for mallory@e.com' in result['error']
    assert not target.exists()                 # nothing written through it
    assert link.is_symlink()                   # and the link is left alone
    # Refused before issuing: no status-list index was allocated for it.
    assert not (tmp_path / 'status').exists()


def test_single_dangling_symlink_human_mode_exits_cleanly(tmp_path, capsys):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    target = tmp_path / 'created.txt'
    _plant_symlink(out / 'badge_1_mallory@e.com.svg', target)
    argv = _signer_argv(cfg, out, '-V', '3', '-r', 'mallory@e.com')
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_signer.main()
    assert exc.value.code == 1
    assert 'has already signed for mallory@e.com' in capsys.readouterr().out
    assert not target.exists()


def test_single_symlink_to_existing_file_without_force(tmp_path, capsys):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    target = tmp_path / 'precious.txt'
    target.write_text('precious')
    link = out / 'badge_1_trent@e.com.svg'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', '3', '--json', '-r', 'trent@e.com')
    code, result = _run_json(argv, capsys)
    assert code == 1 and 'has already signed' in result['error']
    assert target.read_text() == 'precious'
    assert link.is_symlink()


@pytest.mark.parametrize('version', ['3', '2', '1'])
def test_single_force_replaces_the_symlink_not_its_target(tmp_path, capsys,
                                                          version):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    target = tmp_path / 'precious.txt'
    target.write_text('precious')
    link = out / 'badge_1_trent@e.com.svg'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', version, '--json', '-r', 'trent@e.com',
                        '--force')
    # -V 1 checks that the badge URLs are reachable before signing.
    with patch('openbadgeslib.badge_model.download_file', return_value=b'data'):
        code, result = _run_json(argv, capsys)
    assert code == 0
    assert result['badge_file'] == str(link)
    assert target.read_text() == 'precious'    # the target is untouched
    assert not link.is_symlink()               # the link became the badge
    assert link.read_bytes().startswith(b'<?xml')
    assert _no_temp_left(out)


def test_single_force_replaces_dangling_symlink(tmp_path, capsys):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    target = tmp_path / 'created.txt'
    link = out / 'badge_1_mallory@e.com.svg'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', '3', '--json', '-r', 'mallory@e.com',
                        '--force')
    code, _ = _run_json(argv, capsys)
    assert code == 0
    assert not target.exists()
    assert link.is_file() and not link.is_symlink()


def test_force_over_regular_file_keeps_new_badge_mode(tmp_path, capsys):
    # --force keeps overwriting a regular badge file, and the file it leaves
    # has the mode a newly signed badge gets (umask-derived, as open() gives).
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    badge = out / 'badge_1_a@e.com.svg'
    argv = _signer_argv(cfg, out, '-V', '3', '--json', '-r', 'a@e.com')
    old = os.umask(0o027)
    try:
        code, _ = _run_json(argv, capsys)
        assert code == 0
        first = badge.read_bytes()
        new_mode = stat.S_IMODE(badge.stat().st_mode)
        plain = tmp_path / 'plain'
        with open(plain, 'wb'):
            pass
        assert new_mode == stat.S_IMODE(plain.stat().st_mode)

        code, _ = _run_json(argv + ['--force'], capsys)
        assert code == 0
        assert badge.read_bytes() != first             # re-signed (new jti)
        assert badge.read_bytes().startswith(b'<?xml')
        assert stat.S_IMODE(badge.stat().st_mode) == new_mode
    finally:
        os.umask(old)
    if os.name != 'nt':
        assert new_mode == 0o640
    assert _no_temp_left(out)


def test_hosted_assertion_dangling_symlink_is_not_followed(tmp_path, capsys):
    cfg = _write_config(tmp_path, hosted=True)
    out = _out_dir(tmp_path)
    target = tmp_path / 'hosted.json'
    link = out / 'badge_1_oscar@e.com.assertion.json'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', '2', '-H', '--json', '-r', 'oscar@e.com')
    code, result = _run_json(argv, capsys)
    assert code == 1
    assert 'has already signed for oscar@e.com' in result['error']
    assert str(link) in result['error']
    assert not target.exists()
    assert link.is_symlink()
    # Refused before issuing, so no badge without its assertion is left behind.
    assert not (out / 'badge_1_oscar@e.com.svg').exists()


def test_hosted_assertion_force_replaces_the_symlink(tmp_path, capsys):
    cfg = _write_config(tmp_path, hosted=True)
    out = _out_dir(tmp_path)
    target = tmp_path / 'precious.json'
    target.write_text('precious')
    link = out / 'badge_1_oscar@e.com.assertion.json'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', '2', '-H', '--json', '-r', 'oscar@e.com',
                        '--force')
    code, result = _run_json(argv, capsys)
    assert code == 0
    assert target.read_text() == 'precious'
    assert not link.is_symlink()
    assertion = json.loads(link.read_bytes().decode('ascii'))
    assert assertion['id'] == result['assertion_id']
    # Same bytes as before the fix: the JSON text, ASCII, no trailing newline.
    assert link.read_bytes() == json.dumps(
        assertion, sort_keys=True, ensure_ascii=True).encode('ascii')
    assert _no_temp_left(out)


def test_without_hosted_the_assertion_path_is_not_checked(tmp_path, capsys):
    # Without -H there is no assertion file to write, so a file at that name
    # is neither a reason to refuse nor touched.
    cfg = _write_config(tmp_path, hosted=True)
    out = _out_dir(tmp_path)
    other = out / 'badge_1_a@e.com.assertion.json'
    other.write_text('mine')
    argv = _signer_argv(cfg, out, '-V', '2', '--json', '-r', 'a@e.com')
    code, _ = _run_json(argv, capsys)
    assert code == 0
    assert other.read_text() == 'mine'


def test_batch_skips_planted_symlink_and_signs_the_rest(tmp_path, capsys):
    cfg = _write_config(tmp_path, status=True)
    out = _out_dir(tmp_path)
    target = tmp_path / 'created.txt'
    link = out / 'badge_1_b@e.com.svg'
    _plant_symlink(link, target)
    rfile = tmp_path / 'recipients.txt'
    rfile.write_text('a@e.com\nb@e.com\n')
    argv = _signer_argv(cfg, out, '-V', '3', '--json',
                        '--recipients-file', str(rfile))
    code, result = _run_json(argv, capsys)
    assert code == 2
    assert [s['recipient'] for s in result['signed']] == ['a@e.com']
    assert result['skipped'] == [{'recipient': 'b@e.com', 'reason': 'exists',
                                  'badge_file': str(link)}]
    assert result['failed'] == []
    assert not target.exists()
    assert link.is_symlink()


def test_batch_force_replaces_planted_symlinks(tmp_path, capsys):
    cfg = _write_config(tmp_path, hosted=True)
    out = _out_dir(tmp_path)
    badge_target = tmp_path / 'precious.txt'
    badge_target.write_text('precious')
    json_target = tmp_path / 'precious.json'
    json_target.write_text('precious')
    badge_link = out / 'badge_1_a@e.com.svg'
    json_link = out / 'badge_1_b@e.com.assertion.json'
    _plant_symlink(badge_link, badge_target)
    _plant_symlink(json_link, json_target)
    argv = _signer_argv(cfg, out, '-V', '2', '-H', '--json', '--force',
                        '-r', 'a@e.com', '-r', 'b@e.com')
    code, result = _run_json(argv, capsys)
    assert code == 0 and len(result['signed']) == 2
    assert badge_target.read_text() == 'precious'
    assert json_target.read_text() == 'precious'
    for link in (badge_link, json_link):
        assert link.is_file() and not link.is_symlink()
    assert _no_temp_left(out)


def test_batch_skips_planted_hosted_assertion_symlink(tmp_path, capsys):
    cfg = _write_config(tmp_path, hosted=True)
    out = _out_dir(tmp_path)
    target = tmp_path / 'hosted.json'
    link = out / 'badge_1_b@e.com.assertion.json'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', '2', '-H', '-r', 'a@e.com',
                        '-r', 'b@e.com')
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_signer.main()
    assert exc.value.code == 2
    text = capsys.readouterr().out
    assert '[i] skipped b@e.com (%s)' % link in text
    assert '1 signed, 1 skipped, 0 failed' in text
    assert not target.exists()
    assert not (out / 'badge_1_b@e.com.svg').exists()
    assert (out / 'badge_1_a@e.com.assertion.json').is_file()


# The checks above run before issuing. The write itself must hold too, for a
# link planted between the check and the write. Refusing a symlink at that
# point is the exclusive create's job, which POSIX guarantees (O_EXCL, with
# O_NOFOLLOW on top). Windows has no O_NOFOLLOW and the signer documents the
# check as the protection there, so the three link-after-the-check tests do
# not run on it.
posix_exclusive_create = pytest.mark.skipif(
    not hasattr(os, 'O_NOFOLLOW'),
    reason='no O_NOFOLLOW: the already-signed check is the protection here')


def test_write_new_file_refuses_an_existing_path(tmp_path):
    path = tmp_path / 'badge.svg'
    path.write_bytes(b'old')
    with pytest.raises(FileExistsError):
        openbadges_signer._write_new_file(str(path), b'new', False)
    assert path.read_bytes() == b'old'


@posix_exclusive_create
def test_write_new_file_refuses_a_symlink(tmp_path):
    target = tmp_path / 'created.txt'
    link = tmp_path / 'badge.svg'
    _plant_symlink(link, target)
    with pytest.raises(OSError):
        openbadges_signer._write_new_file(str(link), b'new', False)
    assert not target.exists()


@posix_exclusive_create
@pytest.mark.parametrize('version', ['3', '2', '1'])
def test_badge_write_race_exits_cleanly(tmp_path, capsys, version):
    # A link that appears after the already-signed check: the exclusive create
    # fails and the CLI reports it like any other badge-write failure.
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    target = tmp_path / 'created.txt'
    link = out / 'badge_1_a@e.com.svg'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', version, '--json', '-r', 'a@e.com')
    with patch.object(openbadges_signer, '_existing_output', return_value=None), \
            patch('openbadgeslib.badge_model.download_file', return_value=b'data'):
        code, result = _run_json(argv, capsys)
    assert code == 1
    assert result['error'].startswith('[!] Could not write badge to %s' % link)
    assert not target.exists()


@posix_exclusive_create
def test_hosted_write_race_exits_cleanly(tmp_path, capsys):
    cfg = _write_config(tmp_path, hosted=True)
    out = _out_dir(tmp_path)
    target = tmp_path / 'created.json'
    link = out / 'badge_1_a@e.com.assertion.json'
    _plant_symlink(link, target)
    argv = _signer_argv(cfg, out, '-V', '2', '-H', '--json', '-r', 'a@e.com')
    with patch.object(openbadges_signer, '_existing_output', return_value=None):
        code, result = _run_json(argv, capsys)
    assert code == 1
    assert result['error'].startswith(
        '[!] Could not write hosted assertion to %s' % link)
    assert not target.exists()


def test_force_write_failure_removes_the_temp_file(tmp_path, capsys):
    cfg = _write_config(tmp_path)
    out = _out_dir(tmp_path)
    badge = out / 'badge_1_a@e.com.svg'
    badge.write_bytes(b'old badge')
    argv = _signer_argv(cfg, out, '-V', '3', '--json', '-r', 'a@e.com',
                        '--force')
    with patch.object(openbadges_signer.os, 'replace',
                      side_effect=PermissionError(13, 'denied')):
        code, result = _run_json(argv, capsys)
    assert code == 1
    assert result['error'].startswith('[!] Could not write badge to %s' % badge)
    assert badge.read_bytes() == b'old badge'      # never truncated
    assert [p.name for p in out.iterdir()] == [badge.name]


def test_force_write_failure_reports_the_write_error_not_the_cleanup(tmp_path):
    # If the temp file cannot be removed either, the error that reaches the
    # caller is still the one that made the write fail.
    path = tmp_path / 'badge.svg'
    with patch.object(openbadges_signer.os, 'replace',
                      side_effect=PermissionError(13, 'replace denied')), \
            patch.object(openbadges_signer.os, 'unlink',
                         side_effect=OSError(5, 'unlink failed')):
        with pytest.raises(PermissionError, match='replace denied'):
            openbadges_signer._write_new_file(str(path), b'new', True)
    assert not path.exists()
