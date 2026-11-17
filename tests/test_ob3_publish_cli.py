"""End-to-end CLI tests for the OB3 issuer lifecycle:
openbadges-signer -V 3 with credentialStatus, and openbadges-publish -V 3
(status list + did.json generation, revocation management)."""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from openbadgeslib import openbadges_cli, openbadges_publish, openbadges_signer

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
        # verify.pem is the validated public key, re-serialised (#337), not a
        # byte copy of the configured file (which has no trailing newline).
        assert (pub / 'badge_1' / 'verify.pem').read_bytes() == \
            _spki((TESTS_DIR / 'test_verify_rsa.pem').read_bytes())
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
        assert exc.value.code == 2             # stale/missing -> exit 2 (#233)
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

    def test_vct_dotdot_is_refused(self, tmp_path):
        from openbadgeslib.ob3.publish import PublishError, _sd_jwt_vct_relpath
        with pytest.raises(PublishError, match='escapes'):
            _sd_jwt_vct_relpath(
                'https://example.com/issuer/../../../tmp/pwned',
                'https://example.com/issuer/')
        cfg = _write_config(
            tmp_path,
            sd_jwt_vct='https://example.com/issuer/../../../tmp/pwned')
        with pytest.raises(SystemExit):
            _publish(tmp_path, cfg)
        assert not (tmp_path / 'tmp' / 'pwned').exists()

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


# ── openbadges status (the read-only query as a first-class command) ──────────

def _status(cfg, extra=()):
    """Run `openbadges status ...` through the unified front-end, so these
    tests cover the dispatch too, not just the command's own parser."""
    argv = ['openbadges', 'status', '-c', str(cfg)] + list(extra)
    with patch.object(sys, 'argv', argv):
        openbadges_cli.main()


class TestStatusCommand:
    """`openbadges status` shares query_ob3 with `publish --list/--status`, so
    these assert the wiring (dispatch, argument mapping, exit status) rather
    than re-testing the table/detail rendering TestPublishQuery covers."""

    def _issue(self, tmp_path, rsa_pub_pem):
        cfg = _write_config(tmp_path, status_lists='revocation, suspension')
        badge_file = _sign(tmp_path, cfg)
        return cfg, _credential_from(badge_file, rsa_pub_pem)

    def test_no_id_tabulates_every_credential(self, tmp_path, rsa_pub_pem,
                                              capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()                 # drop the signer output
        _status(cfg)
        out = capsys.readouterr().out
        assert credential.id in out
        assert 'active' in out
        assert '1 credential total' in out

    def test_id_shows_the_full_record(self, tmp_path, rsa_pub_pem, capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        _status(cfg, [credential.id])
        out = capsys.readouterr().out
        assert 'jti:' in out and credential.id in out
        assert 'state:' in out and 'active' in out

    def test_id_accepts_a_recipient_email(self, tmp_path, rsa_pub_pem, capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        _status(cfg, [RECIPIENT])
        assert credential.id in capsys.readouterr().out

    def test_reflects_a_revocation_and_its_reason(self, tmp_path, rsa_pub_pem,
                                                  capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        _publish(tmp_path, cfg, ['--revoke', credential.id,
                                 '--reason', 'cheating'])
        capsys.readouterr()
        _status(cfg, [credential.id])
        out = capsys.readouterr().out
        assert 'REVOKED' in out
        assert 'revoked:' in out and 'cheating' in out

    def test_scoped_to_one_badge(self, tmp_path, rsa_pub_pem, capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        _status(cfg, ['-b', '1'])
        assert credential.id in capsys.readouterr().out

    def test_json_emits_the_same_records(self, tmp_path, rsa_pub_pem, capsys):
        cfg, credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        # --json always exits explicitly under the machine-output contract:
        # 0 here, since a successful query is a success (#233).
        with pytest.raises(SystemExit) as exc:
            _status(cfg, ['--json'])
        assert exc.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        jtis = [c['jti'] for b in payload['badges'] for c in b['credentials']]
        assert credential.id in jtis

    def test_unknown_id_exits_1(self, tmp_path, rsa_pub_pem, capsys):
        cfg, _credential = self._issue(tmp_path, rsa_pub_pem)
        capsys.readouterr()
        with pytest.raises(SystemExit) as exc:
            _status(cfg, ['urn:uuid:nope'])
        assert exc.value.code == 1
        assert 'No credential' in capsys.readouterr().out

    def test_needs_no_output_directory(self, tmp_path, rsa_pub_pem):
        # The command has no -o at all: a read must never require the publish
        # tree. (It would raise SystemExit(2) on an unrecognised flag.)
        cfg, _credential = self._issue(tmp_path, rsa_pub_pem)
        _status(cfg)

    def test_without_status_lists_exits(self, tmp_path):
        cfg = _write_config(tmp_path)       # no status_lists configured
        with pytest.raises(SystemExit, match='No badge'):
            _status(cfg)


# ── the published key is a validated public key, never a file copy (#337) ────

def _spki(pem):
    """The SubjectPublicKeyInfo PEM publish writes for the public key *pem*."""
    from openbadgeslib.keys import _load_public_pem, _public_pem
    return _public_pem(_load_public_pem(pem))


def _leaks(root):
    """Published files that hold private key material (there must be none)."""
    if not root.exists():
        return []
    return sorted(str(p.relative_to(root)) for p in root.rglob('*')
                  if p.is_file() and b'PRIVATE KEY' in p.read_bytes())


def _keys_config(tmp_path, badges):
    """A config every -V can publish. *badges* is a list of dicts: ``public``
    (path), and optionally ``private`` (path), ``status_lists``, ``key_type``;
    they become [badge_1], [badge_2], ..."""
    lines = [
        "[paths]", "base = %s" % tmp_path, "base_status = ${base}/status", "",
        "[issuer]", "name = Test Issuer", "url = https://example.com",
        "email = issuer@example.com", "image = issuer.png",
        "publish_url = https://example.com/issuer/",
        "revocationList = revoked.json",
    ]
    for number, badge in enumerate(badges, 1):
        lines += ["", "[badge_%d]" % number, "name = Badge %d" % number,
                  "description = Test", "image = badge.svg",
                  "criteria = https://example.com/criteria.html",
                  "public_key = %s" % badge['public']]
        for option, key in (('private_key', 'private'),
                            ('status_lists', 'status_lists'),
                            ('key_type', 'key_type')):
            if badge.get(key) is not None:
                lines.append("%s = %s" % (option, badge[key]))
    cfg = tmp_path / 'keys.ini'
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


def _publish_exit(cfg, out, version, extra=()):
    """Run openbadges-publish; return its exit status (0 when it returns)."""
    argv = ['openbadges-publish', '-c', str(cfg), '-o', str(out),
            '-V', version] + list(extra)
    with patch.object(sys, 'argv', argv):
        try:
            openbadges_publish.main()
        except SystemExit as exc:
            return exc.code
    return 0


RSA_PAIR = {'public': TESTS_DIR / 'test_verify_rsa.pem',
            'private': TESTS_DIR / 'test_sign_rsa.pem'}
ECC_PAIR = {'public': TESTS_DIR / 'test_verify_ecc.pem',
            'private': TESTS_DIR / 'test_sign_ecc.pem'}
# public_key pointing at the private key: the one-line config slip of #337.
CROSSED = {'public': TESTS_DIR / 'test_sign_rsa.pem',
           'private': TESTS_DIR / 'test_sign_rsa.pem'}


def _unrelated_p256_public(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from openbadgeslib.keys import _public_pem
    path = tmp_path / 'unrelated_p256.pem'
    path.write_bytes(_public_pem(
        ec.generate_private_key(ec.SECP256R1()).public_key()))
    return path


class TestPublishValidatesPublicKey:
    # ── OB3 ──────────────────────────────────────────────────────────────────
    def test_v3_crossed_path_skips_the_badge(self, tmp_path, capsys):
        cfg = _keys_config(tmp_path, [
            dict(CROSSED, status_lists='revocation, suspension'),
            dict(ECC_PAIR, status_lists='revocation')])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, '3', ['--json'])
        result = json.loads(capsys.readouterr().out)

        assert _leaks(out) == []
        assert code == 2
        assert result['skipped'] == ['badge_1']
        # Nothing at all is written for the refused badge...
        assert not (out / 'badge_1').exists()
        assert not any(f.startswith('badge_1/')
                       for f in result['files_written'])
        # ...it is not advertised in did.json, and the other badge publishes.
        doc = json.loads((out / 'did.json').read_text())
        assert [m['id'].rsplit('#')[1] for m in doc['verificationMethod']] == \
            ['badge_2']
        assert (out / 'badge_2' / 'verify.pem').read_bytes() == \
            _spki(ECC_PAIR['public'].read_bytes())

    def test_v3_crossed_path_exits_2_and_says_why(self, tmp_path, capsys):
        cfg = _keys_config(tmp_path, [
            dict(CROSSED, status_lists='revocation'),
            dict(ECC_PAIR, status_lists='revocation')])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, '3')
        text = capsys.readouterr().out

        assert _leaks(out) == []
        assert code == 2
        assert 'Skipping [badge_1]' in text
        assert 'private key' in text
        assert 'BEGIN' not in text              # the message carries no key

    def test_v3_only_badge_crossed_writes_nothing(self, tmp_path, capsys):
        # With no publishable key left there is no did.json to write: the
        # publish fails as a whole, and says which key it refused and why.
        cfg = _keys_config(tmp_path, [dict(CROSSED, status_lists='revocation')])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, '3', ['--json'])
        result = json.loads(capsys.readouterr().out)

        assert _leaks(out) == []
        assert code == 1
        assert 'badge_1' in result['error']
        assert 'private key' in result['error']
        assert not out.exists()

    def test_v3_no_key_generated_yet_keeps_its_message(self, tmp_path, capsys):
        # No key file at all is the "run the keygenerator" case, not a refusal.
        cfg = _keys_config(tmp_path, [dict(public=tmp_path / 'missing.pem')])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, '3', ['--json'])
        result = json.loads(capsys.readouterr().out)

        assert code == 1
        assert 'No badge public key could be read' in result['error']
        assert not out.exists()

    def test_v3_refused_badge_without_status_lists_exits_2(self, tmp_path,
                                                           capsys):
        # A refusal is reported even when the badge has no status list to
        # skip: a crossed config must not publish with exit 0.
        cfg = _keys_config(tmp_path, [CROSSED, ECC_PAIR])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, '3', ['--json'])
        result = json.loads(capsys.readouterr().out)

        assert _leaks(out) == []
        assert code == 2
        assert result['skipped'] == ['badge_1']
        assert sorted(p.name for p in out.iterdir()) == ['did.json']

    @pytest.mark.parametrize('same_algorithm', [True, False])
    def test_v3_unrelated_pair_refused(self, tmp_path, capsys, same_algorithm):
        # public_key is a real public key, but not the badge's: publishing it
        # would advertise a key the badge's credentials do not verify under.
        public = _unrelated_p256_public(tmp_path) if same_algorithm \
            else TESTS_DIR / 'test_verify_rsa.pem'
        cfg = _keys_config(tmp_path, [
            dict(public=public, private=ECC_PAIR['private'],
                 status_lists='revocation'),
            dict(RSA_PAIR, status_lists='revocation')])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, '3', ['--json'])
        result = json.loads(capsys.readouterr().out)

        assert code == 2
        assert result['skipped'] == ['badge_1']
        assert not (out / 'badge_1').exists()
        doc = json.loads((out / 'did.json').read_text())
        assert [m['id'].rsplit('#')[1] for m in doc['verificationMethod']] == \
            ['badge_2']

    def test_v3_unreadable_public_key_still_regenerates_lists(self, tmp_path,
                                                              capsys):
        # A public key file that cannot be read is not a refusal: as before
        # the fix, the badge's lists are regenerated (a revocation must get
        # out) and the badge is reported as skipped for its missing verify.pem.
        cfg = _keys_config(tmp_path, [
            dict(RSA_PAIR, status_lists='revocation'),
            dict(public=tmp_path / 'missing.pem', private=ECC_PAIR['private'],
                 status_lists='revocation')])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, '3', ['--json'])
        result = json.loads(capsys.readouterr().out)

        assert code == 2
        assert result['skipped'] == ['badge_2']
        assert (out / 'badge_2' / 'revocation.jwt').is_file()
        assert not (out / 'badge_2' / 'verify.pem').exists()
        assert 'badge_2/verify.pem' not in result['files_written']
        assert (out / 'badge_1' / 'verify.pem').is_file()

    def test_v3_facade_reports_the_refusal(self, tmp_path):
        from openbadgeslib.confparser import read_config_or_exit
        from openbadgeslib.ob3.publish import publish_ob3
        cfg = _keys_config(tmp_path, [
            dict(CROSSED, status_lists='revocation'), ECC_PAIR])
        result = publish_ob3(read_config_or_exit(str(cfg)),
                             str(tmp_path / 'pub'))
        assert [name for name, _ in result.did_skipped] == ['badge_1']
        assert [name for name, _ in result.status_skipped] == ['badge_1']
        assert 'private key' in result.status_skipped[0][1]
        assert result.partial
        assert result.files_written == ['did.json']

    # ── OB2 / OB1 ────────────────────────────────────────────────────────────
    @pytest.mark.parametrize('version', ['2', '1'])
    def test_hosted_crossed_path_publishes_nothing(self, tmp_path, version):
        # The refused badge is the second one: the first must not have been
        # written either (the keys are all checked before the first mkdir).
        cfg = _keys_config(tmp_path, [RSA_PAIR, CROSSED])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, version)

        assert _leaks(out) == []
        assert isinstance(code, str) and code.startswith('[!] [badge_2]')
        assert 'private key' in code
        assert 'BEGIN' not in code
        assert not out.exists()

    @pytest.mark.parametrize('version', ['2', '1'])
    def test_hosted_unrelated_pair_publishes_nothing(self, tmp_path, version):
        cfg = _keys_config(tmp_path, [
            dict(public=_unrelated_p256_public(tmp_path),
                 private=ECC_PAIR['private'])])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, version)

        assert isinstance(code, str) and '[badge_1]' in code
        assert 'does not match' in code
        assert not out.exists()

    @pytest.mark.parametrize('version', ['2', '1'])
    def test_hosted_missing_key_file_exits_cleanly(self, tmp_path, version):
        # Used to be a FileNotFoundError traceback over a half-written tree.
        cfg = _keys_config(tmp_path, [
            RSA_PAIR, dict(public=tmp_path / 'missing.pem')])
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, version)

        assert isinstance(code, str) and code.startswith('[!] [badge_2]')
        assert not out.exists()

    @pytest.mark.parametrize('version', ['2', '1'])
    def test_hosted_missing_public_key_option(self, tmp_path, version):
        cfg = _keys_config(tmp_path, [RSA_PAIR])
        cfg.write_text(cfg.read_text().replace('public_key = ', 'pubkey = '))
        out = tmp_path / 'pub'
        code = _publish_exit(cfg, out, version)

        assert 'missing required config key' in code
        assert 'public_key' in code
        assert not out.exists()

    # ── what the file may hold ───────────────────────────────────────────────
    def test_public_block_followed_by_private_block_is_refused(self, tmp_path):
        # The file parses as a public key (the first block), so only the
        # marker check stands between it and a publish.
        from openbadgeslib.ob3.publish import (PublicKeyRefused,
                                               load_publishable_public_key)
        both = tmp_path / 'both.pem'
        both.write_bytes(RSA_PAIR['public'].read_bytes() + b'\n'
                         + RSA_PAIR['private'].read_bytes())
        with pytest.raises(PublicKeyRefused, match='private key'):
            load_publishable_public_key(str(both))

        out = tmp_path / 'pub'
        code = _publish_exit(_keys_config(tmp_path, [dict(public=both)]),
                             out, '2')
        assert 'private key' in code
        assert not out.exists()

    @pytest.mark.parametrize('kind', ['garbage', 'certificate', 'x25519',
                                      'der-private', 'empty'])
    def test_not_a_supported_public_key_is_refused(self, tmp_path, kind):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from openbadgeslib.keys import _public_pem
        from openbadgeslib.ob3.publish import (PublicKeyRefused,
                                               load_publishable_public_key)
        if kind == 'garbage':
            data = b'not a key at all\n'
        elif kind == 'certificate':
            data = (b'-----BEGIN CERTIFICATE-----\nMIIB\n'
                    b'-----END CERTIFICATE-----\n')
        elif kind == 'x25519':          # a public key, but not one we sign with
            data = _public_pem(x25519.X25519PrivateKey.generate().public_key())
        elif kind == 'der-private':     # private material without a PEM marker
            data = ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
        else:
            data = b''
        path = tmp_path / 'key.pem'
        path.write_bytes(data)
        with pytest.raises(PublicKeyRefused) as exc:
            load_publishable_public_key(str(path))
        assert str(path) in str(exc.value)

    def test_missing_file_is_an_oserror_not_a_refusal(self, tmp_path):
        # "Not generated yet" stays distinguishable from "refused": the OB3
        # publish skips the first in did.json only, as it always did.
        from openbadgeslib.ob3.publish import load_publishable_public_key
        with pytest.raises(OSError):
            load_publishable_public_key(str(tmp_path / 'missing.pem'))

    # ── happy paths ──────────────────────────────────────────────────────────
    @pytest.mark.parametrize('version', ['3', '2', '1'])
    def test_verify_pem_is_the_reserialised_key(self, tmp_path, version):
        # tests/test_verify_rsa.pem has no trailing newline: a byte copy of it
        # and the re-serialised key differ, and the second is what is written
        # (LF line ends on every platform, the same bytes under every -V).
        cfg = _keys_config(tmp_path, [dict(RSA_PAIR, status_lists='revocation')])
        out = tmp_path / 'pub'
        assert _publish_exit(cfg, out, version) == 0
        source = RSA_PAIR['public'].read_bytes()
        written = (out / 'badge_1' / 'verify.pem').read_bytes()
        assert written == _spki(source)
        assert written != source
        assert written.endswith(b'-----END PUBLIC KEY-----\n')
        assert b'\r' not in written
        assert written.split() == source.split()    # same key, same base64

    @pytest.mark.parametrize('version', ['3', '2', '1'])
    def test_pkcs1_rsa_public_key_still_publishes(self, tmp_path, version):
        # "BEGIN RSA PUBLIC KEY" (PKCS#1) is a valid public key in another PEM
        # flavour; it is published as SubjectPublicKeyInfo.
        from cryptography.hazmat.primitives import serialization
        from openbadgeslib.keys import _load_public_pem
        spki = RSA_PAIR['public'].read_bytes()
        pkcs1 = tmp_path / 'pkcs1.pem'
        pkcs1.write_bytes(_load_public_pem(spki).public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.PKCS1))
        assert pkcs1.read_bytes().startswith(b'-----BEGIN RSA PUBLIC KEY-----')

        cfg = _keys_config(tmp_path, [dict(
            public=pkcs1, private=RSA_PAIR['private'],
            status_lists='revocation')])
        out = tmp_path / 'pub'
        assert _publish_exit(cfg, out, version) == 0
        assert (out / 'badge_1' / 'verify.pem').read_bytes() == _spki(spki)
        if version == '2':
            key = json.loads((out / 'badge_1' / 'key.json').read_text())
            assert key['publicKeyPem'] == _spki(spki).decode('ascii')

    @pytest.mark.parametrize('key_type', ['RSA', 'ECC', 'ED25519'])
    @pytest.mark.parametrize('version', ['3', '2', '1'])
    def test_keygenerator_keys_publish(self, tmp_path, version, key_type):
        # Whatever openbadges-keygenerator writes must publish, byte for byte.
        from openbadgeslib import openbadges_keygenerator
        from openbadgeslib.keys import KeyType, detect_key_type
        public, private = tmp_path / 'verify.pem', tmp_path / 'sign.pem'
        cfg = _keys_config(tmp_path, [dict(
            public=public, private=private, key_type=key_type,
            status_lists='revocation')])
        with patch.object(sys, 'argv', ['openbadges-keygenerator', '-c',
                                        str(cfg), '-g', '1']):
            openbadges_keygenerator.main()
        generated = public.read_bytes()
        assert detect_key_type(generated) is KeyType[key_type]

        out = tmp_path / 'pub'
        assert _publish_exit(cfg, out, version) == 0
        assert (out / 'badge_1' / 'verify.pem').read_bytes() == generated
        assert _leaks(out) == []
        if version == '3':
            doc = json.loads((out / 'did.json').read_text())
            assert len(doc['verificationMethod']) == 1
            assert (out / 'badge_1' / 'revocation.jwt').is_file()
        if version == '2':
            key = json.loads((out / 'badge_1' / 'key.json').read_text())
            assert key['publicKeyPem'] == generated.decode('ascii')

    @pytest.mark.parametrize('private', ['unset', 'missing', 'unparsable'])
    @pytest.mark.parametrize('version', ['3', '2', '1'])
    def test_publishes_without_a_usable_private_key(self, tmp_path, version,
                                                    private):
        # Publishing hosted metadata or did.json never needed the private key
        # (it may live on another machine): with none to compare against, a
        # valid public key is published as before.
        badge = dict(public=RSA_PAIR['public'])
        if private == 'missing':
            badge['private'] = tmp_path / 'not_here.pem'
        elif private == 'unparsable':
            badge['private'] = tmp_path / 'broken.pem'
            badge['private'].write_bytes(b'not a key\n')
        cfg = _keys_config(tmp_path, [badge])
        out = tmp_path / 'pub'
        assert _publish_exit(cfg, out, version) == 0
        if version == '3':
            doc = json.loads((out / 'did.json').read_text())
            assert len(doc['verificationMethod']) == 1
        else:
            assert (out / 'badge_1' / 'verify.pem').read_bytes() == \
                _spki(RSA_PAIR['public'].read_bytes())
