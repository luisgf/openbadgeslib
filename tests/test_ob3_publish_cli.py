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
                  status_base=None, sd_jwt_vct=None, status_validity_days=None):
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
    if sd_jwt_vct is not None:
        lines.append("sd_jwt_vct = %s" % sd_jwt_vct)
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
    if status_validity_days is not None:
        lines.append("status_validity_days = %s" % status_validity_days)
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

    def test_status_loop_isolates_unclassifiable_key(self, tmp_path, capsys):
        # A per-badge key failure in the status-list regeneration loop
        # (detect_key_type -> UnknownKeyType, or a missing private_key/public_key
        # config key -> KeyError) must be isolated like the did.json skip:
        # record it and continue, not crash the whole publish with a raw
        # traceback after did.json (which could drop an urgent badge's
        # revocation regeneration).
        from openbadgeslib.errors import UnknownKeyType
        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)                     # create the registry + an entry
        out = tmp_path / 'pub'
        argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out), '-V', '3']
        with patch('openbadgeslib.keys.detect_key_type',
                   side_effect=UnknownKeyType('Unable to guess Key type')), \
                patch.object(sys, 'argv', argv):
            try:
                openbadges_publish.main()        # graceful non-zero exit is fine;
            except SystemExit:                   # a raw UnknownKeyType would fail
                pass
        text = capsys.readouterr().out
        assert 'Skipping [badge_1]' in text
        assert (out / 'did.json').is_file()      # publish proceeded past the loop
        assert not (out / 'badge_1' / 'revocation.jwt').is_file()

    def test_republish_over_existing_directory(self, tmp_path):
        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        _publish(tmp_path, cfg)   # unlike -V 1/2 this must not exit
        assert (pub / 'badge_1' / 'revocation.jwt').is_file()

    def test_cli_warns_when_no_validity_bound(self, tmp_path, capsys):
        # #227: publishing a revocable badge with no status_validity_days warns
        # loudly (no anti-replay freshness on the list).
        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        _publish(tmp_path, cfg)
        assert 'WITHOUT a validUntil bound' in capsys.readouterr().out

    def test_cli_no_warning_when_validity_days_set(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation',
                            status_validity_days=7)
        _sign(tmp_path, cfg)
        _publish(tmp_path, cfg)
        assert 'WITHOUT a validUntil bound' not in capsys.readouterr().out

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


# ── openbadges-publish -V 3 --list / --status (read-only audit) ───────────────

def _query(tmp_path, cfg, extra):
    """Run a query invocation — deliberately without -o, so these tests also
    prove the read-only paths need no output directory."""
    argv = ['openbadges-publish', '-c', str(cfg), '-V', '3'] + list(extra)
    with patch.object(sys, 'argv', argv):
        openbadges_publish.main()


class TestPublishQuery:
    def _issue(self, tmp_path, rsa_pub_pem, status_lists='revocation, suspension'):
        cfg = _write_config(tmp_path, status_lists=status_lists)
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        return cfg, credential

    def test_list_tabulates_issued_credentials(self, tmp_path, rsa_pub_pem,
                                               capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()                 # drop the signer output
        _query(tmp_path, cfg, ['--list'])
        out = capsys.readouterr().out
        assert 'badge_1' in out
        assert credential.id in out
        assert 'mailto:' + RECIPIENT in out
        assert 'active' in out
        assert '1 credential total' in out

    def test_list_needs_no_output_dir(self, tmp_path, rsa_pub_pem):
        # No -o is passed by _query: a read-only query must not require one.
        cfg, _credential = self._issue(tmp_path, rsa_pub_pem)
        _query(tmp_path, cfg, ['--list'])   # must not raise SystemExit

    def test_list_scoped_to_badge(self, tmp_path, rsa_pub_pem, capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        _query(tmp_path, cfg, ['--list', '-b', '1'])
        assert credential.id in capsys.readouterr().out

    def test_list_reflects_revocation(self, tmp_path, rsa_pub_pem, capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        _publish(tmp_path, cfg, ['--revoke', credential.id])
        capsys.readouterr()
        _query(tmp_path, cfg, ['--list'])
        assert 'REVOKED' in capsys.readouterr().out

    def test_status_by_jti_shows_full_detail(self, tmp_path, rsa_pub_pem,
                                             capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        _query(tmp_path, cfg, ['--status', credential.id])
        out = capsys.readouterr().out
        assert 'jti:' in out and credential.id in out
        assert 'recipient:' in out and 'mailto:' + RECIPIENT in out
        assert 'state:' in out and 'active' in out
        assert 'index:' in out

    def test_status_by_email(self, tmp_path, rsa_pub_pem, capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        _query(tmp_path, cfg, ['--status', RECIPIENT])
        assert credential.id in capsys.readouterr().out

    def test_status_shows_revocation_reason(self, tmp_path, rsa_pub_pem,
                                            capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        _publish(tmp_path, cfg, ['--revoke', credential.id,
                                 '--reason', 'cheating'])
        capsys.readouterr()
        _query(tmp_path, cfg, ['--status', credential.id])
        out = capsys.readouterr().out
        assert 'REVOKED' in out
        assert 'revoked:' in out and 'cheating' in out

    def test_status_unknown_exits_nonzero(self, tmp_path, rsa_pub_pem, capsys):
        cfg, _credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        with pytest.raises(SystemExit) as exc:
            _query(tmp_path, cfg, ['--status', 'urn:uuid:nope'])
        assert exc.value.code == 1
        assert 'No credential' in capsys.readouterr().out

    def test_list_without_status_lists_exits(self, tmp_path):
        cfg = _write_config(tmp_path)       # no status_lists configured
        with pytest.raises(SystemExit, match='No badge'):
            _query(tmp_path, cfg, ['--list'])

    def test_query_requires_v3(self, tmp_path):
        cfg = _write_config(tmp_path, status_lists='revocation')
        argv = ['openbadges-publish', '-c', str(cfg), '-V', '2', '--list']
        with patch.object(sys, 'argv', argv):
            with pytest.raises(SystemExit, match='-V 3'):
                openbadges_publish.main()

    def test_list_and_revoke_are_mutually_exclusive(self, tmp_path):
        cfg = _write_config(tmp_path, status_lists='revocation')
        argv = ['openbadges-publish', '-c', str(cfg), '-V', '3',
                '--list', '--revoke', 'x']
        with patch.object(sys, 'argv', argv):
            with pytest.raises(SystemExit):    # argparse: not allowed with
                openbadges_publish.main()


# ── #166: --json machine-readable output + exit-code contract ────────────────

def _run_json(main, argv):
    """Run a CLI main() in --json mode; return (exit_code, stdout)."""
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            main()
    return exc.value.code


class TestSignerJson:
    def test_sign_ob3_json_success(self, tmp_path, rsa_pub_pem, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation')
        out = tmp_path / 'out'
        out.mkdir(exist_ok=True)
        argv = ['openbadges-signer', '-c', str(cfg), '-b', '1', '-r', RECIPIENT,
                '-o', str(out), '-E', '-V', '3', '--json']
        code = _run_json(openbadges_signer.main, argv)
        result = json.loads(capsys.readouterr().out)
        assert code == 0
        assert result['ob_version'] == '3'
        assert result['jti'].startswith('urn:uuid:')
        assert result['status_index'] is not None
        assert result['proof_format'] == 'vc-jwt'
        assert result['badge_file'].endswith('.svg')

    def test_sign_json_error_is_json(self, tmp_path, capsys):
        cfg = _write_config(tmp_path)
        out = tmp_path / 'out'
        out.mkdir(exist_ok=True)
        argv = ['openbadges-signer', '-c', str(cfg), '-b', '99', '-r', RECIPIENT,
                '-o', str(out), '-E', '-V', '3', '--json']
        code = _run_json(openbadges_signer.main, argv)
        result = json.loads(capsys.readouterr().out)
        assert code == 1
        assert 'error' in result and 'badge' in result['error']


class TestPublishJson:
    def test_publish_ob3_json_success(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation, suspension')
        _sign(tmp_path, cfg)
        capsys.readouterr()
        argv = ['openbadges-publish', '-c', str(cfg), '-o', str(tmp_path / 'pub'),
                '-V', '3', '--json']
        code = _run_json(openbadges_publish.main, argv)
        result = json.loads(capsys.readouterr().out)
        assert code == 0
        assert result['did'] == 'did:web:example.com:issuer'
        assert 'did.json' in result['files_written']
        assert 'badge_1/revocation.jwt' in result['files_written']
        assert result['status_operation'] is None
        assert result['skipped'] == []

    def test_publish_revoke_json(self, tmp_path, rsa_pub_pem, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        capsys.readouterr()
        argv = ['openbadges-publish', '-c', str(cfg), '-o', str(tmp_path / 'pub'),
                '-V', '3', '--revoke', credential.id, '--reason', 'oops', '--json']
        code = _run_json(openbadges_publish.main, argv)
        result = json.loads(capsys.readouterr().out)
        assert code == 0
        assert result['status_operation']['operation'] == 'revoke'
        assert result['status_operation']['jti'] == credential.id
        assert result['status_operation']['reason'] == 'oops'

    def test_list_json(self, tmp_path, rsa_pub_pem, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        capsys.readouterr()
        argv = ['openbadges-publish', '-c', str(cfg), '-V', '3', '--list',
                '--json']
        code = _run_json(openbadges_publish.main, argv)
        result = json.loads(capsys.readouterr().out)
        assert code == 0
        assert result['total'] == 1
        cred = result['badges'][0]['credentials'][0]
        assert cred['jti'] == credential.id
        assert cred['state'] == 'active'

    def test_status_json(self, tmp_path, rsa_pub_pem, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        capsys.readouterr()
        argv = ['openbadges-publish', '-c', str(cfg), '-V', '3', '--status',
                credential.id, '--json']
        code = _run_json(openbadges_publish.main, argv)
        result = json.loads(capsys.readouterr().out)
        assert code == 0
        assert result['matches'][0]['jti'] == credential.id

    def test_status_json_not_found_exits_1(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        capsys.readouterr()
        argv = ['openbadges-publish', '-c', str(cfg), '-V', '3', '--status',
                'urn:uuid:nope', '--json']
        code = _run_json(openbadges_publish.main, argv)
        result = json.loads(capsys.readouterr().out)
        assert code == 1
        assert 'error' in result

    def test_json_rejected_for_v2(self, tmp_path):
        cfg = _write_config(tmp_path)
        argv = ['openbadges-publish', '-c', str(cfg), '-o', str(tmp_path / 'p'),
                '-V', '2', '--json']
        with patch.object(sys, 'argv', argv):
            with pytest.raises(SystemExit, match='-V 3'):
                openbadges_publish.main()


# ── #164: status list validUntil + opt-in proof verification ─────────────────

class TestPublishValidUntil:
    def test_validuntil_emitted_when_configured(self, tmp_path):
        import jwt as pyjwt
        cfg = _write_config(tmp_path, status_lists='revocation')
        with cfg.open('a') as f:
            f.write('status_validity_days = 7\n')
        _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        token = (pub / 'badge_1' / 'revocation.jwt').read_text()
        payload = pyjwt.decode(token, options={'verify_signature': False})
        assert 'validUntil' in payload and 'validFrom' in payload

    def test_no_validuntil_by_default(self, tmp_path):
        import jwt as pyjwt
        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        token = (pub / 'badge_1' / 'revocation.jwt').read_text()
        payload = pyjwt.decode(token, options={'verify_signature': False})
        assert 'validUntil' not in payload

    def test_invalid_validity_days_exits_cleanly(self, tmp_path, capsys):
        cfg = _write_config(tmp_path, status_lists='revocation')
        with cfg.open('a') as f:
            f.write('status_validity_days = soon\n')
        with pytest.raises(SystemExit):
            _publish(tmp_path, cfg)
        assert 'status_validity_days' in capsys.readouterr().out


class TestPublishVerifyList:
    def test_verify_list_proof_end_to_end(self, tmp_path, rsa_pub_pem):
        # The published list is signed with the badge key and its issuer is the
        # badge issuer, so verify_list=True (with that key) passes.
        from openbadgeslib.ob3 import check_credential_status
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        check_credential_status(credential, download=_served_from(pub),
                                verify_list=True, list_pubkey_pem=rsa_pub_pem)

    def test_verify_list_wrong_key_fails(self, tmp_path, rsa_pub_pem, ecc_pub_pem):
        from openbadgeslib.ob3 import check_credential_status, OB3VerificationError
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)
        pub = _publish(tmp_path, cfg)
        credential = _credential_from(badge_file, rsa_pub_pem)
        with pytest.raises(OB3VerificationError, match='proof is invalid'):
            check_credential_status(credential, download=_served_from(pub),
                                    verify_list=True, list_pubkey_pem=ecc_pub_pem)


# ── openbadges-publish -V 3 --check-live (#164) ──────────────────────────────

_BASE = 'https://example.com/issuer/'


class TestCheckLive:
    """--check-live fetches each written artifact from publish_url and
    byte-compares it against the local copy, so 're-upload' becomes verified."""

    def _publish_check_live(self, tmp_path, download, extra=()):
        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        out = tmp_path / 'pub'
        argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out),
                '-V', '3', '--check-live'] + list(extra)
        with patch.object(sys, 'argv', argv), \
                patch('openbadgeslib.util.download_file', side_effect=download):
            try:
                openbadges_publish.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return out, code

    def test_all_artifacts_current(self, tmp_path, capsys):
        out_holder = {}

        def live(url, *a, **k):
            return (out_holder['out'] / url[len(_BASE):]).read_bytes()

        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        out = tmp_path / 'pub'
        out_holder['out'] = out
        argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out),
                '-V', '3', '--check-live']
        with patch.object(sys, 'argv', argv), \
                patch('openbadgeslib.util.download_file', side_effect=live):
            openbadges_publish.main()          # exit 0: no SystemExit
        out_text = capsys.readouterr().out
        assert 'live and current' in out_text
        assert 'STALE' not in out_text

    def test_stale_artifact_flagged_json(self, tmp_path, capsys):
        out = tmp_path / 'pub'

        def live(url, *a, **k):
            if url.endswith('did.json'):
                return b'{"stale": true}'      # server serves an old copy
            return (out / url[len(_BASE):]).read_bytes()

        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        capsys.readouterr()                    # discard the signer's output
        argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out),
                '-V', '3', '--check-live', '--json']
        with patch.object(sys, 'argv', argv), \
                patch('openbadgeslib.util.download_file', side_effect=live), \
                pytest.raises(SystemExit) as exc:
            openbadges_publish.main()
        result = json.loads(capsys.readouterr().out)
        assert exc.value.code == 2             # partial success
        assert 'did.json' in result['live_check']['stale']

    def test_missing_artifact_exits_human(self, tmp_path, capsys):
        out = tmp_path / 'pub'

        def live(url, *a, **k):
            raise OSError('HTTP 404')

        cfg = _write_config(tmp_path, status_lists='revocation')
        _sign(tmp_path, cfg)
        argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out),
                '-V', '3', '--check-live']
        with patch.object(sys, 'argv', argv), \
                patch('openbadgeslib.util.download_file', side_effect=live), \
                pytest.raises(SystemExit) as exc:
            openbadges_publish.main()
        assert exc.value.code == 1             # human: stale/missing -> exit 1
        assert 'stale or missing' in capsys.readouterr().out


class TestPublishTypeMetadata:
    """`openbadges-publish -V 3` emits SD-JWT VC Type Metadata for a configured,
    issuer-hosted vct — servable at that URL and consumable by openvc-core (#176).
    """

    VCT = 'https://example.com/issuer/vct/openbadge'

    def test_emits_type_metadata_for_configured_vct(self, tmp_path):
        from openbadgeslib.ob3.eudi import (badge_type_metadata,
                                            type_metadata_document_bytes)
        pub = _publish(tmp_path, _write_config(tmp_path, sd_jwt_vct=self.VCT))
        served = (pub / 'vct' / 'openbadge').read_bytes()
        assert served == type_metadata_document_bytes(
            badge_type_metadata(self.VCT))

    def test_unset_vct_emits_nothing(self, tmp_path):
        pub = _publish(tmp_path, _write_config(tmp_path))
        assert (pub / 'did.json').is_file()          # normal publish still ran
        assert not (pub / 'vct').exists()

    def test_vct_not_under_publish_url_is_skipped_with_notice(
            self, tmp_path, capsys):
        pub = _publish(tmp_path, _write_config(
            tmp_path, sd_jwt_vct='https://elsewhere.example/vct/x'))
        assert 'not under publish_url' in capsys.readouterr().out
        assert not (pub / 'vct').exists()

    def test_published_metadata_validates_a_pinned_badge(
            self, tmp_path, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        pytest.importorskip('openvc')
        from openvc.type_metadata import validate_type_metadata

        from openbadgeslib.ob3.eudi import (badge_type_metadata,
                                            issue_badge_sd_jwt,
                                            type_metadata_integrity,
                                            verify_badge_sd_jwt)
        pub = _publish(tmp_path, _write_config(tmp_path, sd_jwt_vct=self.VCT))
        served = (pub / 'vct' / 'openbadge').read_bytes()
        integrity = type_metadata_integrity(badge_type_metadata(self.VCT))
        token = issue_badge_sd_jwt(
            ob3_credential, privkey_pem=ed25519_priv_pem, vct=self.VCT,
            vct_integrity=integrity)
        payload = verify_badge_sd_jwt(
            token, pubkey_pem=ed25519_pub_pem, expected_vct=self.VCT).claims

        def resolve(url):
            if url == self.VCT:
                return served
            raise LookupError(url)

        result = validate_type_metadata(
            payload, vct=self.VCT, vct_integrity=payload['vct#integrity'],
            resolve=resolve)
        assert result.vct == self.VCT


# ── programmatic publish facade (#222) ───────────────────────────────────────

class TestPublishFacade:
    """Direct tests of publish_ob3 — the CLI (tested above) is a thin presenter
    over it. The facade writes artefacts (its purpose) but does no printing and
    raises PublishError instead of sys.exit."""

    def _conf(self, cfg):
        from openbadgeslib.confparser import read_config_or_exit
        return read_config_or_exit(str(cfg))

    def test_full_publish_writes_artifacts(self, tmp_path):
        from openbadgeslib.ob3.publish import PublishResult, publish_ob3
        cfg = _write_config(tmp_path, status_lists='revocation')
        out = tmp_path / 'pub'
        res = publish_ob3(self._conf(cfg), str(out))
        assert isinstance(res, PublishResult)
        assert res.did.startswith('did:web:')
        assert res.status_operation is None
        assert 'did.json' in res.files_written
        assert (out / 'did.json').is_file()
        assert (out / 'badge_1' / 'revocation.jwt').is_file()
        assert (out / 'badge_1' / 'verify.pem').is_file()

    def test_revoke_returns_operation(self, tmp_path, rsa_pub_pem):
        from openbadgeslib.ob3.publish import publish_ob3
        cfg = _write_config(tmp_path, status_lists='revocation')
        badge_file = _sign(tmp_path, cfg)          # issues + allocates an index
        cred = _credential_from(badge_file, rsa_pub_pem)
        res = publish_ob3(self._conf(cfg), str(tmp_path / 'pub'), revoke=cred.id)
        assert res.status_operation is not None
        assert res.status_operation.operation == 'revoke'
        assert res.status_operation.verb == 'REVOKED'
        assert res.status_operation.jti == cred.id

    def test_credential_not_found_raises(self, tmp_path):
        from openbadgeslib.ob3.publish import CredentialNotFound, publish_ob3
        cfg = _write_config(tmp_path, status_lists='revocation')
        with pytest.raises(CredentialNotFound):
            publish_ob3(self._conf(cfg), str(tmp_path / 'pub'),
                        revoke='urn:uuid:does-not-exist')

    def test_no_validity_bound_flagged_when_days_unset(self, tmp_path):
        # #227: a revocable badge published without status_validity_days has no
        # validUntil, hence no anti-replay freshness — the facade flags it.
        from openbadgeslib.ob3.publish import publish_ob3
        cfg = _write_config(tmp_path, status_lists='revocation')
        res = publish_ob3(self._conf(cfg), str(tmp_path / 'pub'))
        assert res.no_validity_bound == ['badge_1']

    def test_validity_days_stamps_validuntil_and_clears_flag(self, tmp_path):
        # #227: with status_validity_days set, the published list carries a
        # validUntil and the badge is not flagged.
        import jwt as pyjwt
        from openbadgeslib.ob3.publish import publish_ob3
        cfg = _write_config(tmp_path, status_lists='revocation',
                            status_validity_days=7)
        out = tmp_path / 'pub'
        res = publish_ob3(self._conf(cfg), str(out))
        assert res.no_validity_bound == []
        token = (out / 'badge_1' / 'revocation.jwt').read_text()
        payload = pyjwt.decode(token, options={'verify_signature': False})
        assert 'validUntil' in payload

    def test_reason_without_revoke_raises(self, tmp_path):
        from openbadgeslib.ob3.publish import PublishError, publish_ob3
        cfg = _write_config(tmp_path, status_lists='revocation')
        with pytest.raises(PublishError, match='--reason needs'):
            publish_ob3(self._conf(cfg), str(tmp_path / 'pub'), reason='oops')

    def test_missing_issuer_section_raises(self, tmp_path):
        import configparser

        from openbadgeslib.ob3.publish import PublishError, publish_ob3
        conf = configparser.ConfigParser()
        conf.read_string('[badge_1]\nname = X\n')
        with pytest.raises(PublishError, match='issuer'):
            publish_ob3(conf, str(tmp_path / 'pub'))
