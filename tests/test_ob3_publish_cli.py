"""End-to-end CLI tests for the OB3 issuer lifecycle:
openbadges-signer -V 3 with credentialStatus, and openbadges-publish -V 3
(status list + did.json generation, revocation management)."""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from openbadgeslib import openbadges_publish, openbadges_signer

TESTS_DIR = Path(__file__).parent
RECIPIENT = 'recipient@example.com'


def _write_config(tmp_path, key='rsa', status_lists=None, did=None,
                  status_base=None):
    (tmp_path / 'log').mkdir(exist_ok=True)
    lines = [
        "[paths]",
        "base = %s" % tmp_path,
        "base_key = %s" % TESTS_DIR,
        "base_log = ${base}/log",
        "base_image = %s" % (TESTS_DIR / 'images'),
        "base_status = ${base}/status",
        "",
        "[logs]", "general = general.log", "signer = signer.log", "",
        "[issuer]",
        "name = Test Issuer",
        "url = https://example.com",
        "email = issuer@example.com",
        "publish_url = https://example.com/issuer/",
        "revocationList = revoked.json",
    ]
    if did is not None:
        lines.append("did = %s" % did)
    lines += [
        "",
        "[badge_1]",
        "name = Test Badge",
        "description = Test",
        "local_image = sample1.svg",
        "image = https://example.com/badge.svg",
        "criteria = https://example.com/criteria.html",
        "criteria_narrative = Pass the test",
        "verify_key = https://example.com/verify.pem",
        "badge = https://example.com/badge.json",
        "private_key = ${paths:base_key}/test_sign_%s.pem" % key,
        "public_key = ${paths:base_key}/test_verify_%s.pem" % key,
        "key_type = %s" % key.upper(),
    ]
    if status_lists is not None:
        lines.append("status_lists = %s" % status_lists)
    if status_base is not None:
        lines.append("status_base = %s" % status_base)
    cfg = tmp_path / 'cfg.ini'
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


def _sign(tmp_path, cfg, extra=()):
    out = tmp_path / 'out'
    out.mkdir(exist_ok=True)
    argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
            '-o', str(out), '-E', '-V', '3'] + list(extra)
    with patch.object(sys, 'argv', argv):
        openbadges_signer.main()
    return out / ('badge_1_%s.svg' % RECIPIENT)


def _credential_from(badge_file, pub_pem):
    from openbadgeslib.ob3 import OB3Verifier
    token = OB3Verifier.extract_token_from_svg(badge_file.read_bytes())
    return OB3Verifier(pubkey_pem=pub_pem).verify(token,
                                                  expected_recipient=RECIPIENT)


# ── openbadges-signer -V 3 with status lists ─────────────────────────────────

class TestSignerStatus:
    def test_credential_carries_both_entries(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation, suspension')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)

        entries = credential.credential_status
        assert [e['statusPurpose'] for e in entries] == \
            ['revocation', 'suspension']
        assert [e['statusListCredential'] for e in entries] == [
            'https://example.com/issuer/badge_1/revocation.jwt',
            'https://example.com/issuer/badge_1/suspension.jwt',
        ]
        # One shared index across both purposes.
        assert len({e['statusListIndex'] for e in entries}) == 1
        assert all(e['type'] == 'BitstringStatusListEntry' for e in entries)

    def test_registry_records_the_issuance(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)

        registry = json.loads((tmp_path / 'status' / 'badge_1.json').read_text())
        entry = registry['entries'][credential.id]
        assert entry['index'] == int(
            credential.credential_status[0]['statusListIndex'])
        assert entry['recipient'] == 'mailto:' + RECIPIENT

    def test_signer_log_names_jti_and_index(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        log = (tmp_path / 'log' / 'signer.log').read_text()
        assert 'OB3 SIGNED for %s' % RECIPIENT in log
        assert 'JTI %s' % credential.id in log
        assert 'STATUS %s' % credential.credential_status[0]['statusListIndex'] \
            in log

    def test_custom_status_base(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation',
                            status_base='https://cdn.example.com/status')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.credential_status[0]['statusListCredential'] == \
            'https://cdn.example.com/status/revocation.jwt'

    def test_unknown_purpose_exits(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation, message')
        with pytest.raises(SystemExit):
            _sign(tmp_path, cfg)
        assert 'unknown purpose' in capsys.readouterr().out

    def test_without_status_lists_behaviour_unchanged(self, tmp_path,
                                                      rsa_pub_pem):
        cfg = _write_config(tmp_path)   # no status_lists: pre-3.1 behaviour
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.credential_status == []
        assert not (tmp_path / 'status').exists()
        log = (tmp_path / 'log' / 'signer.log').read_text()
        assert 'JTI' in log and 'STATUS' not in log


# ── [issuer] did handling ────────────────────────────────────────────────────

class TestIssuerDid:
    def test_did_auto_derives_from_publish_url(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, did='auto')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.issuer.id == 'did:web:example.com:issuer'

    def test_explicit_did_used_verbatim(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, did='did:web:issuer.example')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.issuer.id == 'did:web:issuer.example'

    def test_unset_keeps_publish_url(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path)
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        assert credential.issuer.id == 'https://example.com/issuer/'

    def test_invalid_did_exits(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, did='not-a-did')
        with pytest.raises(SystemExit):
            _sign(tmp_path, cfg)
        assert "[issuer] did" in capsys.readouterr().out


# ── openbadges-publish -V 3 ──────────────────────────────────────────────────

def _publish(tmp_path, cfg, extra=()):
    out = tmp_path / 'pub'
    argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out),
            '-V', '3'] + list(extra)
    with patch.object(sys, 'argv', argv):
        openbadges_publish.main()
    return out


def _served_from(pub_dir):
    """A download callable mapping the badge's status list URLs onto the
    files publish generated (the tests' stand-in for the web server)."""
    def download(url):
        assert url.startswith('https://example.com/issuer/badge_1/')
        name = url.rsplit('/', 1)[1]
        return (pub_dir / 'badge_1' / name).read_bytes()
    return download


def _check_status(badge_file, pub_pem, pub_dir):
    from openbadgeslib.ob3 import OB3Verifier, check_credential_status
    token = OB3Verifier.extract_token_from_svg(badge_file.read_bytes())
    credential = OB3Verifier(pubkey_pem=pub_pem).verify(
        token, expected_recipient=RECIPIENT)
    check_credential_status(credential, download=_served_from(pub_dir))


class TestPublishConfigErrors:
    def test_missing_publish_url_exits_cleanly(self, tmp_path, capsys):
        # [issuer] with url but no publish_url must fail with a clean [!]
        # message, not a raw KeyError('publish_url') traceback: ob3_issuer_id
        # falls back to url, so the omission slips past the pre-flight and
        # would otherwise surface deep in _publish_ob3 / ob3_status_config.
        cfg = tmp_path / 'cfg.ini'
        cfg.write_text('\n'.join([
            '[paths]', 'base = %s' % tmp_path,
            '[issuer]', 'name = I', 'url = https://example.com/issuer/',
            '[badge_1]', 'name = B', 'description = d',
            'public_key = %s' % (TESTS_DIR / 'test_verify_rsa.pem'),
            'private_key = %s' % (TESTS_DIR / 'test_sign_rsa.pem'),
            'status_lists = revocation',
        ]) + '\n')
        argv = ['openbadges-publish', '-c', str(cfg), '-o',
                str(tmp_path / 'pub'), '-V', '3']
        with patch.object(sys, 'argv', argv):
            with pytest.raises(SystemExit):
                openbadges_publish.main()
        assert 'publish_url' in capsys.readouterr().out


class TestPublishGeneration:
    def test_generates_lists_did_and_pem(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation, suspension')
        _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)

        assert (pub / 'badge_1' / 'revocation.jwt').is_file()
        assert (pub / 'badge_1' / 'suspension.jwt').is_file()
        assert (pub / 'badge_1' / 'verify.pem').read_bytes() == \
            (TESTS_DIR / 'test_verify_rsa.pem').read_bytes()
        doc = json.loads((pub / 'did.json').read_text())
        assert doc['id'] == 'did:web:example.com:issuer'
        assert doc['verificationMethod'][0]['id'] == \
            'did:web:example.com:issuer#badge_1'
        assert 'did:web:example.com:issuer' in capsys.readouterr().out

    def test_fresh_credential_passes_check_status(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation, suspension')
        badge_file = _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        _check_status(badge_file, rsa_pub_pem, pub)   # must not raise

    def test_no_status_lists_still_publishes_did(self, tmp_path, capsys):
        cfg = _write_config(tmp_path)
        pub = _publish(tmp_path, cfg)
        assert (pub / 'did.json').is_file()
        assert not (pub / 'badge_1').exists()
        assert 'no status_lists' in capsys.readouterr().out

    def test_badge_without_keys_is_skipped_in_did_json(self, tmp_path, capsys):
        # The scaffolded config ships badge sections whose keys may not have
        # been generated yet; they must not block publishing the others.
        cfg = _write_config(tmp_path, status_lists='revocation')
        with cfg.open('a') as f:
            f.write('\n[badge_2]\nname = B2\ndescription = d\n'
                    'public_key = %s\nprivate_key = %s\n'
                    % (tmp_path / 'missing_pub.pem', tmp_path / 'missing.pem'))
        _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        doc = json.loads((pub / 'did.json').read_text())
        assert [m['id'].rsplit('#')[1] for m in doc['verificationMethod']] == \
            ['badge_1']
        assert 'Skipping [badge_2]' in capsys.readouterr().out

    def test_republish_over_existing_directory(self, tmp_path):
        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        _publish(tmp_path, cfg)   # unlike -V 1/2 this must not exit
        assert (pub / 'badge_1' / 'revocation.jwt').is_file()

    @pytest.mark.parametrize('key,alg', [('rsa', 'RS256'), ('ecc', 'ES256')])
    def test_lists_are_signed_with_the_badge_key(self, tmp_path, key, alg):
        import jwt as pyjwt
        cfg = _write_config(tmp_path, key=key, status_lists='revocation')
        _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        token = (pub / 'badge_1' / 'revocation.jwt').read_text()
        pub_pem = (TESTS_DIR / ('test_verify_%s.pem' % key)).read_bytes()
        payload = pyjwt.decode(token, pub_pem, algorithms=[alg])
        assert payload['iss'] == 'https://example.com/issuer/'
        assert payload['credentialSubject']['statusPurpose'] == 'revocation'


class TestPublishManagement:
    def _issued(self, tmp_path, rsa_pub_pem, **kw):
        cfg = _write_config(tmp_path,
                            status_lists=kw.pop('status_lists',
                                                'revocation, suspension'))
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        return cfg, badge_file, credential

    def test_revoke_by_jti_then_verification_fails(self, tmp_path, rsa_pub_pem,
                                                   capsys):
        from openbadgeslib.ob3 import OB3VerificationError
        cfg, badge_file, credential = self._issued(tmp_path, rsa_pub_pem)
        pub = _publish(tmp_path, cfg, ['--revoke', credential.id,
                                       '--reason', 'cheating'])
        out = capsys.readouterr().out
        assert 'REVOKED' in out and credential.id in out
        assert 'Re-upload' in out
        with pytest.raises(OB3VerificationError, match='revocation'):
            _check_status(badge_file, rsa_pub_pem, pub)

    def test_revoke_by_email(self, tmp_path, rsa_pub_pem):
        from openbadgeslib.ob3 import OB3VerificationError
        cfg, badge_file, _credential = self._issued(tmp_path, rsa_pub_pem)
        pub = _publish(tmp_path, cfg, ['--revoke', RECIPIENT])
        with pytest.raises(OB3VerificationError, match='revocation'):
            _check_status(badge_file, rsa_pub_pem, pub)

    def test_revoke_scoped_to_badge(self, tmp_path, rsa_pub_pem):
        cfg, badge_file, _credential = self._issued(tmp_path, rsa_pub_pem)
        _publish(tmp_path, cfg, ['--revoke', RECIPIENT, '-b', '1'])

    def test_suspend_then_unsuspend(self, tmp_path, rsa_pub_pem):
        from openbadgeslib.ob3 import OB3VerificationError
        cfg, badge_file, credential = self._issued(tmp_path, rsa_pub_pem)
        pub = _publish(tmp_path, cfg, ['--suspend', credential.id])
        with pytest.raises(OB3VerificationError, match='suspension'):
            _check_status(badge_file, rsa_pub_pem, pub)
        pub = _publish(tmp_path, cfg, ['--unsuspend', credential.id])
        _check_status(badge_file, rsa_pub_pem, pub)   # suspension lifted

    def test_revoke_twice_fails(self, tmp_path, rsa_pub_pem, capsys):
        cfg, _badge_file, credential = self._issued(tmp_path, rsa_pub_pem)
        _publish(tmp_path, cfg, ['--revoke', credential.id])
        with pytest.raises(SystemExit):
            _publish(tmp_path, cfg, ['--revoke', credential.id])
        assert 'already revoked' in capsys.readouterr().out

    def test_unknown_credential_fails(self, tmp_path, rsa_pub_pem, capsys):
        cfg, _badge_file, _credential = self._issued(tmp_path, rsa_pub_pem)
        with pytest.raises(SystemExit):
            _publish(tmp_path, cfg, ['--revoke', 'urn:uuid:nope'])
        assert 'No credential' in capsys.readouterr().out

    def test_ambiguous_email_lists_jtis(self, tmp_path, rsa_pub_pem, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation')
        first = _sign(tmp_path, cfg)
        first.unlink()          # allow a second issuance to the same file
        _sign(tmp_path, cfg)
        capsys.readouterr()     # drop the signer output (it also prints JTIs)
        with pytest.raises(SystemExit):
            _publish(tmp_path, cfg, ['--revoke', RECIPIENT])
        out = capsys.readouterr().out
        assert 'several credentials' in out
        assert out.count('urn:uuid:') == 2

    def test_management_flags_require_v3(self, tmp_path):
        cfg = _write_config(tmp_path, status_lists='revocation')
        argv = ['openbadges-publish', '-c', str(cfg), '-o',
                str(tmp_path / 'pub2'), '-V', '2', '--revoke', 'x']
        with patch.object(sys, 'argv', argv):
            with pytest.raises(SystemExit, match='-V 3'):
                openbadges_publish.main()

    def test_reason_requires_operation(self, tmp_path):
        cfg = _write_config(tmp_path, status_lists='revocation')
        argv = ['openbadges-publish', '-c', str(cfg), '-o',
                str(tmp_path / 'pub'), '-V', '3', '--reason', 'x']
        with patch.object(sys, 'argv', argv):
            with pytest.raises(SystemExit, match='--reason'):
                openbadges_publish.main()
