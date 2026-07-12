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


def test_ob3_json_surfaces_broadened_model_fields(tmp_path, rsa_priv_pem,
                                                  rsa_pub_pem, svg_image, capsys):
    # #162: the broadened OB 3.0 model fields appear in --json output.
    from openbadgeslib.ob3 import (OB3Signer, Issuer, Achievement,
                                   OpenBadgeCredential, Alignment, Result,
                                   ResultDescription)
    signer = OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')
    cred = OpenBadgeCredential(
        issuer=Issuer(id='https://example.com/issuer', name='Issuer'),
        recipient_id='mailto:recipient@example.com',
        achievement=Achievement(
            id='https://example.com/a', name='A', description='d',
            criteria_narrative='c', achievement_type='Competency',
            credits_available=3.0,
            alignments=[Alignment(target_name='Skill', target_url='https://f/x')],
            result_descriptions=[ResultDescription(
                id='urn:uuid:rd-1', name='G', result_type='LetterGrade')]),
        credits_earned=2.0,
        results=[Result(value='A', result_description='urn:uuid:rd-1')])
    badge = tmp_path / 'badge.svg'
    badge.write_bytes(signer.sign_into_svg(cred, svg_image))
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)
    argv = ['openbadges-verifier', '-i', str(badge), '-r', 'recipient@example.com',
            '-V', '3', '-k', str(pub), '--json']
    code, result = _run(argv, capsys)
    assert code == 0
    assert result['achievement_type'] == 'Competency'
    assert result['credits_available'] == 3.0
    assert result['credits_earned'] == 2.0
    assert result['alignments'] == 1
    assert result['results'] == 1
    assert result['identifiers'] == 0


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


# ── OB3 --resolve-did trust semantics ─────────────────────────────────────────

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    out = ''
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b'\x00'))
    return '1' * pad + out


def _did_key_ed25519(pub) -> str:
    from cryptography.hazmat.primitives import serialization as ser
    raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return 'did:key:z' + _b58encode(b'\xed\x01' + raw)


def _ob3_did_badge(tmp_path, ed25519_priv_pem, svg_image, issuer_did):
    from openbadgeslib.ob3 import OB3Signer, Issuer, Achievement, OpenBadgeCredential
    signer = OB3Signer(privkey_pem=ed25519_priv_pem, algorithm='EdDSA')
    cred = OpenBadgeCredential(
        issuer=Issuer(id=issuer_did, name='Self Issuer'),
        recipient_id='mailto:recipient@example.com',
        achievement=Achievement(id='https://example.com/a', name='A',
                                description='d', criteria_narrative='c'),
    )
    badge_file = tmp_path / 'badge.svg'
    badge_file.write_bytes(signer.sign_into_svg(cred, svg_image))
    return badge_file


def test_ob3_resolve_did_key_is_untrusted_json(
    tmp_path, ed25519_priv_pem, ed25519_pub_pem, svg_image, capsys
):
    # --resolve-did on a did:key reads the verification key from the token
    # itself: the signature is valid but self-asserted (the presenter chose the
    # key), so it must report trusted:false and exit 2 — never an exit-0
    # "verified", mirroring the OB2 badge-embedded-key case.
    from cryptography.hazmat.primitives import serialization as ser
    did = _did_key_ed25519(ser.load_pem_public_key(ed25519_pub_pem))
    badge = _ob3_did_badge(tmp_path, ed25519_priv_pem, svg_image, did)
    argv = ['openbadges-verifier', '-i', str(badge), '-r', 'recipient@example.com',
            '-V', '3', '--resolve-did', '--json']
    code, result = _run(argv, capsys)
    assert code == 2
    assert result['valid'] is True
    assert result['trusted'] is False
    assert result['issuer_did'] == did


def test_ob3_resolve_did_web_is_trusted_json(
    tmp_path, ed25519_priv_pem, ed25519_pub_pem, svg_image, capsys
):
    # A did:web issuer is anchored on DNS + TLS, so a resolved-and-verified
    # credential is trusted:true and exits 0.
    import base64
    from cryptography.hazmat.primitives import serialization as ser
    pub = ser.load_pem_public_key(ed25519_pub_pem)
    raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    did = 'did:web:issuer.example'
    doc = {"id": did, "verificationMethod": [
        {"id": did + "#k", "type": "JsonWebKey2020", "controller": did,
         "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}]}
    badge = _ob3_did_badge(tmp_path, ed25519_priv_pem, svg_image, did)
    argv = ['openbadges-verifier', '-i', str(badge), '-r', 'recipient@example.com',
            '-V', '3', '--resolve-did', '--json']
    code, result = _run(argv, capsys, extra_patches=(
        patch('openbadgeslib.ob3.did.download_file',
              return_value=json.dumps(doc).encode('utf-8')),
    ))
    assert code == 0
    assert result['valid'] is True
    assert result['trusted'] is True


# ── OB2 ──────────────────────────────────────────────────────────────────────

def _make_signed_ob2_svg(tmp_path, badge, identity='recipient@example.com'):
    from openbadgeslib.ob1.signer import Signer
    from openbadgeslib.ob1.badge import BadgeType
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
            '-V', '1', '-k', str(pub), '--json']
    code, result = _run(argv, capsys, extra_patches=(
        patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem),
        patch('openbadgeslib.ob1.verifier.download_file', side_effect=_fake_revocation_download),
    ))
    assert code == 0
    assert result['valid'] is True
    assert result['trusted'] is True
    assert result['status'] == 'VALID'
    assert result['ob_version'] == '1'


def test_ob2_untrusted_is_valid_but_not_trusted_json(tmp_path, svg_rsa_badge, rsa_pub_pem, capsys):
    # Verified against the badge-embedded key (no --local/--pubkey): the
    # signature is internally consistent but the issuer is not anchored, so the
    # process must NOT exit 0 (which automation reads as "verified"). Exit 2
    # signals "valid signature, untrusted issuer"; the JSON still reports the
    # detail. Exit 0 here would let a self-signed forgery pass a CI gate.
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    argv = ['openbadges-verifier', '-i', str(badge_file), '-r', 'recipient@example.com',
            '-V', '1', '--json']
    code, result = _run(argv, capsys, extra_patches=(
        patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem),
        patch('openbadgeslib.ob1.verifier.download_file', side_effect=_fake_revocation_download),
    ))
    assert code == 2
    assert result['valid'] is True
    assert result['trusted'] is False


def test_ob2_wrong_receptor_json_exits_nonzero(tmp_path, svg_rsa_badge, rsa_pub_pem, capsys):
    badge_file = _make_signed_ob2_svg(tmp_path, svg_rsa_badge)
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)
    argv = ['openbadges-verifier', '-i', str(badge_file), '-r', 'someone-else@example.com',
            '-V', '1', '-k', str(pub), '--json']
    code, result = _run(argv, capsys, extra_patches=(
        patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem),
        patch('openbadgeslib.ob1.verifier.download_file', side_effect=_fake_revocation_download),
    ))
    assert code != 0
    assert result['valid'] is False


# ── shared ───────────────────────────────────────────────────────────────────

def test_missing_file_json(tmp_path, capsys):
    argv = ['openbadges-verifier', '-i', str(tmp_path / 'nope.svg'),
            '-r', 'recipient@example.com', '-V', '1', '--json']
    code, result = _run(argv, capsys)
    assert code != 0
    assert result['valid'] is False
    assert 'does not exist' in result['reason']
