"""Tests for openbadges-verifier --json machine-readable output."""
import json
import sys
from unittest.mock import patch

import pytest

from openbadgeslib import openbadges_verifier


def _fake_revocation_download(url, *a, **k):
    if url.endswith('badge.json'):
        return json.dumps({'issuer': 'https://example.com/issuer.json'}).encode()
    return json.dumps({}).encode()


def _run(argv, capsys, extra_patches=()):
    """Run main() with the given argv, returning (exit_code, parsed_json)."""
    with patch.object(sys, 'argv', argv):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in extra_patches:
                stack.enter_context(p)
            with pytest.raises(SystemExit) as exc:
                openbadges_verifier.main()
    out = capsys.readouterr().out
    # --json must emit exactly one JSON object and no human [+]/[-]/[~] lines.
    assert '[+]' not in out and '[-]' not in out and '[~]' not in out
    return exc.value.code, json.loads(out)


# ── OB3 ──────────────────────────────────────────────────────────────────────

def _ob3_badge(tmp_path, priv_pem, svg_image, recipient='mailto:recipient@example.com'):
    from openbadgeslib.ob3 import OB3Signer, Issuer, Achievement, OpenBadgeCredential
    signer = OB3Signer(privkey_pem=priv_pem, algorithm='RS256')
    cred = OpenBadgeCredential(
        issuer=Issuer(id='https://example.com/issuer', name='Issuer'),
        recipient_id=recipient,
        achievement=Achievement(id='https://example.com/a', name='A',
                                description='d', criteria_narrative='c'),
    )
    badge_file = tmp_path / 'badge.svg'
    badge_file.write_bytes(signer.sign_into_svg(cred, svg_image))
    return badge_file


def test_ob3_valid_json(tmp_path, rsa_priv_pem, rsa_pub_pem, svg_image, capsys):
    badge = _ob3_badge(tmp_path, rsa_priv_pem, svg_image)
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)
    argv = ['openbadges-verifier', '-i', str(badge), '-r', 'recipient@example.com',
            '-V', '3', '-k', str(pub), '--json']
    code, result = _run(argv, capsys)
    assert code == 0
    assert result['valid'] is True
    assert result['ob_version'] == '3'
    assert result['issuer'] == 'Issuer'
    assert result['achievement'] == 'A'
    assert result['reason'] is None


def test_ob3_wrong_receptor_json(tmp_path, rsa_priv_pem, rsa_pub_pem, svg_image, capsys):
    badge = _ob3_badge(tmp_path, rsa_priv_pem, svg_image)
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)
    argv = ['openbadges-verifier', '-i', str(badge), '-r', 'someone-else@example.com',
            '-V', '3', '-k', str(pub), '--json']
    code, result = _run(argv, capsys)
    assert code != 0
    assert result['valid'] is False
    assert 'reason' in result and result['reason']


def test_ob3_no_key_json(tmp_path, rsa_priv_pem, svg_image, capsys):
    badge = _ob3_badge(tmp_path, rsa_priv_pem, svg_image)
    argv = ['openbadges-verifier', '-i', str(badge), '-r', 'recipient@example.com',
            '-V', '3', '--json']
    code, result = _run(argv, capsys)
    assert code != 0
    assert result['valid'] is False
    assert 'requires' in result['reason']


# ── OB2 ──────────────────────────────────────────────────────────────────────

def _make_signed_ob2_svg(tmp_path, badge, identity='recipient@example.com'):
    from openbadgeslib.signer import Signer
    from openbadgeslib.badge import BadgeType
    signed = Signer(identity=identity, badge_type=BadgeType.SIGNED,
                    deterministic=True).sign_badge(badge)
    badge_file = tmp_path / 'badge.svg'
    badge_file.write_bytes(signed.signed)
    return badge_file


def test_ob2_valid_trusted_json(tmp_path, svg_rsa_badge, rsa_pub_pem, capsys):
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)
    argv = ['openbadges-verifier', '-i', str(badge_file), '-r', 'recipient@example.com',
            '-V', '2', '-k', str(pub), '--json']
    code, result = _run(argv, capsys, extra_patches=(
        patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem),
        patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_revocation_download),
    ))
    assert code == 0
    assert result['valid'] is True
    assert result['trusted'] is True
    assert result['status'] == 'VALID'
    assert result['ob_version'] == '2'


def test_ob2_untrusted_is_valid_but_not_trusted_json(tmp_path, svg_rsa_badge, rsa_pub_pem, capsys):
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    argv = ['openbadges-verifier', '-i', str(badge_file), '-r', 'recipient@example.com',
            '-V', '2', '--json']
    code, result = _run(argv, capsys, extra_patches=(
        patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem),
        patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_revocation_download),
    ))
    assert code == 0
    assert result['valid'] is True
    assert result['trusted'] is False


def test_ob2_wrong_receptor_json_exits_nonzero(tmp_path, svg_rsa_badge, rsa_pub_pem, capsys):
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)
    argv = ['openbadges-verifier', '-i', str(badge_file), '-r', 'someone-else@example.com',
            '-V', '2', '-k', str(pub), '--json']
    code, result = _run(argv, capsys, extra_patches=(
        patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem),
        patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_revocation_download),
    ))
    assert code != 0
    assert result['valid'] is False


# ── shared ───────────────────────────────────────────────────────────────────

def test_missing_file_json(tmp_path, capsys):
    argv = ['openbadges-verifier', '-i', str(tmp_path / 'nope.svg'),
            '-r', 'recipient@example.com', '-V', '2', '--json']
    code, result = _run(argv, capsys)
    assert code != 0
    assert result['valid'] is False
    assert 'does not exist' in result['reason']
