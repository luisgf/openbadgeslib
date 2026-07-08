"""CLI batch-issuance tests for openbadges-signer (#165).

Multiple -r / --recipients-file drive a single-transaction batch: N badges from
one registry load/save, a per-recipient JSON summary, --force/skip semantics for
existing files, and failures isolated so one bad recipient never aborts the run.
"""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from openbadgeslib import openbadges_signer

TESTS_DIR = Path(__file__).parent


def _write_config(tmp_path, *, status=False):
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
        openbadges_signer.main()
    text = capsys.readouterr().out
    assert text.count('OB3 SIGNED') == 2
    assert '2 signed, 0 skipped, 0 failed' in text


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
