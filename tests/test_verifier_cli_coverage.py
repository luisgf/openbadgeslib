"""#169 — targeted coverage for openbadges_verifier.py: the error and display
branches an adopter hits first when something fails (was the worst-covered
module at 74%)."""
import sys
from unittest.mock import patch

import jwt
import pytest

from openbadgeslib import openbadges_verifier
from openbadgeslib.openbadges_verifier import (_issuer_did_from_document,
                                               _issuer_did_from_token)
from openbadgeslib.ob3 import (Achievement, Evidence, Issuer,
                               OB3VerificationError, OB3Signer,
                               OpenBadgeCredential)


def _run(argv):
    with patch.object(sys, 'argv', argv):
        try:
            openbadges_verifier.main()
        except SystemExit:
            pass


# ── issuer-DID extraction helpers (unverified anchor read for --resolve-did) ─

class TestIssuerDidHelpers:
    def test_token_malformed_jwt(self):
        with pytest.raises(OB3VerificationError, match='could not read'):
            _issuer_did_from_token('not-a-jwt')

    def test_token_iss_not_a_did(self):
        token = jwt.encode({'iss': 'https://issuer.example'}, 'x' * 32,
                           algorithm='HS256')
        with pytest.raises(OB3VerificationError, match='not a DID'):
            _issuer_did_from_token(token)

    def test_token_falls_back_to_vc_issuer(self):
        token = jwt.encode({'vc': {'issuer': {'id': 'did:web:x.example'}}}, 'x' * 32,
                           algorithm='HS256')
        assert _issuer_did_from_token(token) == 'did:web:x.example'

    def test_document_malformed_json(self):
        with pytest.raises(OB3VerificationError, match='could not read'):
            _issuer_did_from_document('{not json')

    def test_document_issuer_not_a_did(self):
        with pytest.raises(OB3VerificationError, match='not a DID'):
            _issuer_did_from_document('{"issuer": "https://issuer.example"}')

    def test_document_issuer_object(self):
        assert _issuer_did_from_document(
            '{"issuer": {"id": "did:key:zabc"}}') == 'did:key:zabc'


# ── OB3 verify CLI: error and display branches ───────────────────────────────

def _ob3_svg(tmp_path, priv_pem, svg_image, **cred_kw):
    cred = OpenBadgeCredential(
        issuer=Issuer(id='https://issuer.example', name='Issuer'),
        recipient_id='mailto:r@example.com',
        achievement=Achievement(id='https://a.example/1', name='A',
                                description='d', criteria_narrative='c'),
        **cred_kw)
    badge = tmp_path / 'badge.svg'
    badge.write_bytes(OB3Signer(privkey_pem=priv_pem, algorithm='RS256')
                      .sign_into_svg(cred, svg_image))
    return badge


class TestOb3CliBranches:
    def test_no_key_and_no_resolve_did_errors(self, tmp_path, rsa_priv_pem,
                                              svg_image, capsys):
        badge = _ob3_svg(tmp_path, rsa_priv_pem, svg_image)
        _run(['openbadges-verifier', '-i', str(badge), '-r', 'r@example.com',
              '-V', '3'])                    # no -k / --local / --resolve-did
        assert 'requires --local' in capsys.readouterr().out

    def test_unsupported_extension_errors(self, tmp_path, rsa_pub_pem, capsys):
        f = tmp_path / 'badge.txt'
        f.write_text('nope')
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run(['openbadges-verifier', '-i', str(f), '-r', 'r@example.com',
              '-V', '3', '-k', str(pub)])
        assert 'Unsupported file format' in capsys.readouterr().out

    def test_corrupt_token_errors(self, tmp_path, rsa_pub_pem, capsys):
        f = tmp_path / 'badge.svg'
        f.write_bytes(b'<svg>no credential here</svg>')
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run(['openbadges-verifier', '-i', str(f), '-r', 'r@example.com',
              '-V', '3', '-k', str(pub)])
        assert 'Could not extract OB3 token' in capsys.readouterr().out

    def test_show_prints_details(self, tmp_path, rsa_priv_pem, rsa_pub_pem,
                                 svg_image, capsys):
        badge = _ob3_svg(tmp_path, rsa_priv_pem, svg_image,
                         evidence=[Evidence(id='https://ev/1',
                                            narrative='did it')],
                         expiration_date=None)
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run(['openbadges-verifier', '-i', str(badge), '-r', 'r@example.com',
              '-V', '3', '-k', str(pub), '--show'])
        out = capsys.readouterr().out
        assert 'Credential issuer' in out and 'Achievement' in out
        assert 'Evidence' in out

    def test_pubkey_file_missing_exits(self, tmp_path, capsys):
        f = tmp_path / 'badge.svg'
        f.write_bytes(b'<svg/>')
        _run(['openbadges-verifier', '-i', str(f), '-r', 'r@example.com',
              '-V', '3', '-k', str(tmp_path / 'nope.pem')])
        assert 'NOT exists' in capsys.readouterr().out


class TestOb2CliBranches:
    def test_unsupported_extension_errors(self, tmp_path, rsa_pub_pem, capsys):
        f = tmp_path / 'badge.txt'
        f.write_text('nope')
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run(['openbadges-verifier', '-i', str(f), '-r', 'r@example.com',
              '-V', '2', '-k', str(pub)])
        assert 'Unsupported file format for OB2' in capsys.readouterr().out

    def test_corrupt_token_errors(self, tmp_path, rsa_pub_pem, capsys):
        f = tmp_path / 'badge.svg'
        f.write_bytes(b'<svg>no OB2 assertion here</svg>')
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run(['openbadges-verifier', '-i', str(f), '-r', 'r@example.com',
              '-V', '2', '-k', str(pub)])
        assert 'Could not extract OB2 token' in capsys.readouterr().out


# ── --local resolves the key from the config (exercises _resolve_trusted…) ───

def test_local_reads_key_from_config(tmp_path, rsa_priv_pem, rsa_pub_pem,
                                     svg_image, capsys):
    badge = _ob3_svg(tmp_path, rsa_priv_pem, svg_image)
    (tmp_path / 'log').mkdir()
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text('\n'.join([
        '[paths]', 'base = %s' % tmp_path,
        '[issuer]', 'name = I',
        '[badge_1]', 'name = B', 'description = d',
        'public_key = %s' % pub,
    ]) + '\n')
    _run(['openbadges-verifier', '-i', str(badge), '-r', 'r@example.com',
          '-V', '3', '-c', str(cfg), '--local', '1'])
    # A key came from the config and verification ran (valid or trust notice).
    out = capsys.readouterr().out
    assert 'signature' in out.lower()
