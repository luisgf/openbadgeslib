"""#169 — targeted coverage for openbadges_verifier.py: the error and display
branches an adopter hits first when something fails (was the worst-covered
module at 74%)."""
import json
import sys
from unittest.mock import patch

import jwt
import pytest

from openbadgeslib import openbadges_verifier
from openbadgeslib.verify import (issuer_did_from_document,
                                  issuer_did_from_token)
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
            issuer_did_from_token('not-a-jwt')

    def test_token_iss_not_a_did(self):
        token = jwt.encode({'iss': 'https://issuer.example'}, 'x' * 32,
                           algorithm='HS256')
        with pytest.raises(OB3VerificationError, match='not a DID'):
            issuer_did_from_token(token)

    def test_token_falls_back_to_vc_issuer(self):
        token = jwt.encode({'vc': {'issuer': {'id': 'did:web:x.example'}}}, 'x' * 32,
                           algorithm='HS256')
        assert issuer_did_from_token(token) == 'did:web:x.example'

    def test_document_malformed_json(self):
        with pytest.raises(OB3VerificationError, match='could not read'):
            issuer_did_from_document('{not json')

    def test_document_issuer_not_a_did(self):
        with pytest.raises(OB3VerificationError, match='not a DID'):
            issuer_did_from_document('{"issuer": "https://issuer.example"}')

    def test_document_issuer_object(self):
        assert issuer_did_from_document(
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

    def test_wrong_key_fails(self, tmp_path, rsa_priv_pem, ecc_pub_pem,
                             svg_image, capsys):
        badge = _ob3_svg(tmp_path, rsa_priv_pem, svg_image)
        pub = tmp_path / 'k.pem'
        pub.write_bytes(ecc_pub_pem)                   # wrong key family
        _run(['openbadges-verifier', '-i', str(badge), '-r', 'r@example.com',
              '-V', '3', '-k', str(pub)])
        assert 'OB3 verification failed' in capsys.readouterr().out

    def test_show_broadened_model_fields(self, tmp_path, rsa_priv_pem,
                                         rsa_pub_pem, svg_image, capsys):
        from openbadgeslib.ob3 import Alignment, Result
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://issuer.example', name='Issuer'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(
                id='https://a.example/1', name='A', description='d',
                criteria_narrative='c', achievement_type='Competency',
                credits_available=3.0,
                alignments=[Alignment(target_name='Skill',
                                      target_url='https://f/x')]),
            credits_earned=2.0,
            results=[Result(value='A', status='Completed')])
        badge = tmp_path / 'badge.svg'
        badge.write_bytes(OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')
                          .sign_into_svg(cred, svg_image))
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run(['openbadges-verifier', '-i', str(badge), '-r', 'r@example.com',
              '-V', '3', '-k', str(pub), '--show'])
        out = capsys.readouterr().out
        assert 'Achievement type' in out
        assert 'Credits available' in out and 'Credits earned' in out
        assert 'Alignments' in out and 'Results' in out


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

def _ob2_signed(tmp_path, priv_pem, image, recipient='r@example.com', png=False):
    from openbadgeslib.ob2 import (OB2Signer, Assertion, IdentityObject,
                                   Verification)
    assertion = Assertion(
        recipient=IdentityObject.create(recipient, salt='abcd'),
        badge='https://example.com/badge.json',
        verification=Verification(type='SignedBadge',
                                  creator='https://example.com/key.json'),
        image='https://example.com/badge.svg')
    signer = OB2Signer(privkey_pem=priv_pem, algorithm='RS256')
    ext = 'png' if png else 'svg'
    out = signer.sign_into_png(assertion, image) if png \
        else signer.sign_into_svg(assertion, image)
    badge = tmp_path / ('badge.%s' % ext)
    badge.write_bytes(out)
    return badge


def _fake_dl(url, *a, **k):
    """Stand in for ob2.verifier.download_file: BadgeClass -> issuer chain, no
    revocation list — so OB2 SignedBadge verification runs fully offline."""
    if url.endswith('badge.json'):
        return json.dumps({'issuer': 'https://example.com/issuer.json'}).encode()
    return json.dumps({}).encode()


def _run_ob2(argv):
    with patch('openbadgeslib.ob2.verifier.download_file', side_effect=_fake_dl):
        _run(argv)


class TestOb2VerifyBranches:
    def test_signed_trusted_with_key_and_show(self, tmp_path, rsa_priv_pem,
                                              rsa_pub_pem, svg_image, capsys):
        badge = _ob2_signed(tmp_path, rsa_priv_pem, svg_image)
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run_ob2(['openbadges-verifier', '-i', str(badge), '-r', 'r@example.com',
                  '-V', '2', '-k', str(pub), '--show'])
        out = capsys.readouterr().out
        assert 'Assertion:' in out                    # --show branch
        assert 'Signature is correct' in out          # trusted SignedBadge

    def test_png_extraction(self, tmp_path, rsa_priv_pem, rsa_pub_pem,
                            png_image, capsys):
        badge = _ob2_signed(tmp_path, rsa_priv_pem, png_image, png=True)
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run_ob2(['openbadges-verifier', '-i', str(badge), '-r', 'r@example.com',
                  '-V', '2', '-k', str(pub)])
        assert 'Signature is correct' in capsys.readouterr().out

    def test_wrong_recipient_fails(self, tmp_path, rsa_priv_pem, rsa_pub_pem,
                                   svg_image, capsys):
        badge = _ob2_signed(tmp_path, rsa_priv_pem, svg_image)
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        _run_ob2(['openbadges-verifier', '-i', str(badge),
                  '-r', 'other@example.com', '-V', '2', '-k', str(pub)])
        assert 'Recipient mismatch' in capsys.readouterr().out   # verify fails


class TestOb1VerifyBranches:
    def test_corrupt_badge_reports_clean_error(self, tmp_path, capsys):
        # A file that is not a readable OB1 badge surfaces as a clean CLI error
        # (LibOpenBadgesException handler), not an uncaught traceback — after the
        # -V 1 legacy notice. Offline: it fails before any URL fetch.
        badge = tmp_path / 'badge.svg'
        badge.write_bytes(b'<svg>not an ob1 assertion</svg>')
        _run(['openbadges-verifier', '-i', str(badge), '-r', 'test@example.com',
              '-V', '1'])
        out = capsys.readouterr().out
        assert 'legacy' in out                         # -V 1 notice
        assert '[-]' in out                            # clean error line


class TestVerifierMiscBranches:
    def test_missing_badge_file(self, tmp_path, capsys):
        _run(['openbadges-verifier', '-i', str(tmp_path / 'nope.svg'),
              '-r', 'r@example.com', '-V', '3'])
        assert 'NOT exists' in capsys.readouterr().out

    def test_issuer_did_token_vc_not_a_dict(self):
        # iss absent and vc not an object → the vc={} fallback, then no DID.
        token = jwt.encode({'vc': 'not-an-object'}, 'x' * 32, algorithm='HS256')
        with pytest.raises(OB3VerificationError, match='not a DID'):
            issuer_did_from_token(token)


class TestHumanModeExitCodes:
    """#189 — in human (non-``--json``) mode the process exit code must reflect
    the verdict for OB1/OB2 too: an invalid badge exits non-zero (it used to
    exit 0, so `verifier … && grant` passed on a forged/expired/revoked badge),
    a valid badge exits 0. Mirrors OB3 and the ``--json`` path."""

    @staticmethod
    def _code(argv):
        with patch.object(sys, 'argv', argv):
            try:
                openbadges_verifier.main()
            except SystemExit as exc:
                c = exc.code
                return c if isinstance(c, int) else (0 if c is None else 1)
            return 0

    def test_ob2_invalid_exits_nonzero(self, tmp_path, rsa_priv_pem, rsa_pub_pem,
                                       svg_image):
        badge = _ob2_signed(tmp_path, rsa_priv_pem, svg_image)
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        with patch('openbadgeslib.ob2.verifier.download_file',
                   side_effect=_fake_dl):
            code = self._code(['openbadges-verifier', '-i', str(badge),
                               '-r', 'other@example.com',   # recipient mismatch
                               '-V', '2', '-k', str(pub)])
        assert code != 0

    def test_ob2_valid_exits_zero(self, tmp_path, rsa_priv_pem, rsa_pub_pem,
                                  svg_image):
        badge = _ob2_signed(tmp_path, rsa_priv_pem, svg_image)
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        with patch('openbadgeslib.ob2.verifier.download_file',
                   side_effect=_fake_dl):
            code = self._code(['openbadges-verifier', '-i', str(badge),
                               '-r', 'r@example.com', '-V', '2', '-k', str(pub)])
        assert code == 0

    def test_ob1_invalid_exits_nonzero(self, tmp_path, signed_svg_rsa,
                                       rsa_pub_pem):
        # A well-formed OB1 badge for test@example.com, verified for a different
        # recipient -> INVALID verdict (the else branch), which must exit
        # non-zero. read_from_file resolves the key via download_file (mocked).
        badge = tmp_path / 'badge.svg'
        badge.write_bytes(signed_svg_rsa.signed)
        pub = tmp_path / 'k.pem'
        pub.write_bytes(rsa_pub_pem)
        with patch('openbadgeslib.ob1.badge.download_file',
                   return_value=rsa_pub_pem):
            code = self._code(['openbadges-verifier', '-i', str(badge),
                               '-r', 'wrong@example.com', '-V', '1',
                               '-k', str(pub)])
        assert code != 0


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
