"""End-to-end CLI tests for strict OpenBadges 2.0 (openbadges-signer/verifier/publish -V 2)."""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from openbadgeslib._jws import utils as jws_utils

TESTS_DIR = Path(__file__).parent


def _write_config(tmp_path, key='rsa', img='svg', with_crypto=True, with_hosted=True,
                  with_publish_url=True, with_revocation=True):
    logdir = tmp_path / 'log'
    logdir.mkdir()
    issuer = ["[issuer]", "name = Test Issuer", "url = https://example.com"]
    if with_publish_url:
        issuer.append("publish_url = https://example.com/issuer/")
    if with_revocation:
        issuer.append("revocationList = revocation.json")
    lines = [
        "[paths]",
        "base = %s" % tmp_path,
        "base_key = %s" % TESTS_DIR,
        "base_log = %s" % logdir,
        "base_image = %s" % (TESTS_DIR / 'images'),
        "",
        "[logs]", "general = general.log", "signer = signer.log", "",
        *issuer,
        "",
        "[badge_1]",
        "name = Test Badge",
        "description = Test",
        "local_image = sample1.%s" % img,
        "image = https://example.com/badge.%s" % img,
        "criteria = https://example.com/criteria.html",
        "verify_key = https://example.com/verify.pem",
        "badge = https://example.com/badge.json",
        "private_key = ${paths:base_key}/test_sign_%s.pem" % key,
        "public_key = ${paths:base_key}/test_verify_%s.pem" % key,
        "key_type = %s" % key.upper(),
    ]
    if with_crypto:
        lines.append("crypto_key = https://example.com/key.json")
    if with_hosted:
        lines.append("hosted_assertions_base = https://example.com/assertions/")
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


def _fake_revocation_download(url, *a, **k):
    """badge.json -> issuer.json chain reporting no revocation list."""
    if url.endswith('badge.json'):
        return json.dumps({'issuer': 'https://example.com/issuer.json'}).encode()
    return json.dumps({}).encode()   # issuer JSON: no revocationList


# ── openbadges-signer -V 2 ──────────────────────────────────────────────────────

def test_sign_v2_signed_writes_strict_payload(tmp_path, capsys):
    from openbadgeslib import openbadges_signer
    from openbadgeslib.ob2 import OB2Verifier
    cfg = _write_config(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-E']
    with patch.object(sys, 'argv', argv):
        openbadges_signer.main()
    out = capsys.readouterr().out
    assert 'OB2 SIGNED' in out
    signed = tmp_path / 'badge_1_recipient@example.com.svg'
    assert signed.is_file()

    token = OB2Verifier.extract_token_from_svg(signed.read_bytes())
    body = jws_utils.decode(token.split('.')[1].encode())
    assert body['@context'] == 'https://w3id.org/openbadges/v2'
    assert body['type'] == 'Assertion'
    assert body['id'].startswith('urn:uuid:')
    assert body['recipient']['hashed'] is True
    assert body['verification'] == {'type': 'SignedBadge',
                                    'creator': 'https://example.com/key.json'}
    assert 'uid' not in body and 'verify' not in body


def test_sign_v2_signed_requires_crypto_key(tmp_path):
    from openbadgeslib import openbadges_signer
    cfg = _write_config(tmp_path, with_crypto=False)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-E']
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit):
            openbadges_signer.main()


def test_sign_v2_hosted_writes_assertion_json(tmp_path, capsys):
    from openbadgeslib import openbadges_signer
    cfg = _write_config(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-H', '-E']
    with patch.object(sys, 'argv', argv):
        openbadges_signer.main()
    out = capsys.readouterr().out
    assert 'OB2 SIGNED' in out
    assert 'Publish the hosted assertion' in out
    assert (tmp_path / 'badge_1_recipient@example.com.svg').is_file()
    assert (tmp_path / 'badge_1_recipient@example.com.assertion.json').is_file()


def test_sign_hosted_with_v3_is_rejected(tmp_path):
    # -H is only consumed on the OB2 path; with -V 3 (or the default) it must be
    # a clean error, not a silently ignored flag (#206).
    from openbadgeslib import openbadges_signer
    cfg = _write_config(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '3',
            '-H', '-E']
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_signer.main()
    assert '-H/--hosted applies to OpenBadges 2.0' in str(exc.value)


def test_sign_v2_hosted_requires_base(tmp_path):
    from openbadgeslib import openbadges_signer
    cfg = _write_config(tmp_path, with_hosted=False)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-H', '-E']
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit):
            openbadges_signer.main()


# ── openbadges-signer -V 2 → openbadges-verifier -V 2 roundtrip ─────────────────

def _sign_v2(tmp_path):
    from openbadgeslib import openbadges_signer
    cfg = _write_config(tmp_path)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1',
            '-r', 'recipient@example.com', '-o', str(tmp_path), '-V', '2', '-E']
    with patch.object(sys, 'argv', argv):
        openbadges_signer.main()
    return tmp_path / 'badge_1_recipient@example.com.svg'


def test_verify_v2_trusted_end_to_end(tmp_path, capsys):
    from openbadgeslib import openbadges_verifier
    signed = _sign_v2(tmp_path)
    pub = TESTS_DIR / 'test_verify_rsa.pem'
    argv = ['openbadges-verifier', '-i', str(signed),
            '-r', 'recipient@example.com', '-V', '2', '-k', str(pub)]
    with patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_revocation_download), \
            patch.object(sys, 'argv', argv):
        openbadges_verifier.main()
    assert 'Signature is correct' in capsys.readouterr().out


def test_verify_v2_untrusted_warns(tmp_path, capsys):
    # No -k: the signed path resolves verification.creator (badge-declared key)
    # and must report it as untrusted, not '[+] correct'.
    from openbadgeslib import openbadges_verifier
    signed = _sign_v2(tmp_path)
    pub_str = (TESTS_DIR / 'test_verify_rsa.pem').read_bytes().decode('ascii')

    def fake(url, *a, **k):
        if url == 'https://example.com/key.json':
            return json.dumps({'@context': 'https://w3id.org/openbadges/v2',
                               'type': 'CryptographicKey', 'id': 'https://example.com/key.json',
                               'owner': 'https://example.com/issuer.json',
                               'publicKeyPem': pub_str}).encode()
        if url.endswith('badge.json'):
            return json.dumps({'issuer': 'https://example.com/issuer.json'}).encode()
        return json.dumps({'id': 'https://example.com/issuer.json',
                           'publicKey': ['https://example.com/key.json']}).encode()

    argv = ['openbadges-verifier', '-i', str(signed),
            '-r', 'recipient@example.com', '-V', '2']
    with patch('openbadgeslib.ob2.verifier.download_file', side_effect=fake), \
            patch.object(sys, 'argv', argv):
        openbadges_verifier.main()
    out = capsys.readouterr().out
    assert 'Signature is correct' not in out
    assert 'does NOT prove issuer identity' in out


def test_verify_v2_json_valid(tmp_path, capsys):
    from openbadgeslib import openbadges_verifier
    signed = _sign_v2(tmp_path)
    capsys.readouterr()   # discard the signer's stdout so only the JSON remains
    pub = TESTS_DIR / 'test_verify_rsa.pem'
    argv = ['openbadges-verifier', '-i', str(signed),
            '-r', 'recipient@example.com', '-V', '2', '-k', str(pub), '--json']
    with patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_revocation_download), \
            patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_verifier.main()
    assert exc.value.code == 0
    result = json.loads(capsys.readouterr().out)
    assert result['valid'] is True
    assert result['trusted'] is True
    assert result['ob_version'] == '2'
    assert result['status'] == 'VALID'


# ── openbadges-publish -V 2 ─────────────────────────────────────────────────────

def test_publish_v2_creates_key_json_and_public_key(tmp_path):
    from openbadgeslib import openbadges_publish
    out = tmp_path / 'published'
    argv = ['openbadges-publish', '-c', './config1.ini', '-o', str(out), '-V', '2']
    with patch.object(sys, 'argv', argv):
        openbadges_publish.main()

    assert (out / 'organization.json').is_file()
    assert (out / 'revocation.json').is_file()
    for name in ('badge_test_1', 'badge_test_2', 'badge_test_3', 'badge_test_4'):
        assert (out / name / 'badge.json').is_file()
        assert (out / name / 'key.json').is_file()
        assert (out / name / 'verify.pem').is_file()

    issuer = json.loads((out / 'organization.json').read_text())
    assert issuer['@context'] == 'https://w3id.org/openbadges/v2'
    assert issuer['type'] == 'Issuer'
    assert issuer['id'].endswith('/organization.json')
    assert len(issuer['publicKey']) == 4

    key = json.loads((out / 'badge_test_1' / 'key.json').read_text())
    assert key['type'] == 'CryptographicKey'
    assert key['owner'] == issuer['id']
    assert 'BEGIN PUBLIC KEY' in key['publicKeyPem']


# ── hosted-publish config guards (#156) ─────────────────────────────────────────
# The OB1/OB2 publish paths dereference [issuer].publish_url / .revocationList
# directly. A misconfigured [issuer] must exit with a clean message before any
# output directory is created, not raise a raw KeyError mid-publish.

def test_publish_v2_missing_publish_url_exits_cleanly(tmp_path):
    from openbadgeslib import openbadges_publish
    cfg = _write_config(tmp_path, with_publish_url=False)
    out = tmp_path / 'published'
    argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out), '-V', '2']
    with patch.object(sys, 'argv', argv), pytest.raises(SystemExit) as exc:
        openbadges_publish.main()
    assert 'publish_url' in str(exc.value)
    assert not out.exists()


def test_publish_v2_missing_revocation_list_exits_cleanly(tmp_path):
    from openbadgeslib import openbadges_publish
    cfg = _write_config(tmp_path, with_revocation=False)
    out = tmp_path / 'published'
    argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out), '-V', '2']
    with patch.object(sys, 'argv', argv), pytest.raises(SystemExit) as exc:
        openbadges_publish.main()
    assert 'revocationList' in str(exc.value)
    assert not out.exists()


def test_publish_v1_missing_publish_url_exits_cleanly(tmp_path, capsys):
    from openbadgeslib import openbadges_publish
    cfg = _write_config(tmp_path, with_publish_url=False)
    out = tmp_path / 'published'
    argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out), '-V', '1']
    with patch.object(sys, 'argv', argv), pytest.raises(SystemExit) as exc:
        openbadges_publish.main()
    assert 'publish_url' in str(exc.value)
    assert not out.exists()
