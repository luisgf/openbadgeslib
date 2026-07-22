"""Tests for openbadgeslib.confparser edge cases not covered elsewhere."""
import pytest

from openbadgeslib.confparser import ConfParser


def _write(tmp_path, text):
    p = tmp_path / 'config.ini'
    p.write_text(text)
    return str(p)


class TestReadConfBaseValidation:
    def test_missing_paths_section_raises_value_error(self, tmp_path):
        path = _write(tmp_path, '[logs]\ngeneral = general.log\n')
        with pytest.raises(ValueError):
            ConfParser(path).read_conf()

    def test_missing_base_key_raises_value_error(self, tmp_path):
        path = _write(tmp_path, '[paths]\nbase_log = ./log\n')
        with pytest.raises(ValueError):
            ConfParser(path).read_conf()

    def test_empty_base_value_raises_value_error(self, tmp_path):
        path = _write(tmp_path, '[paths]\nbase = \n')
        with pytest.raises(ValueError):
            ConfParser(path).read_conf()

    def test_relative_base_is_resolved_to_absolute(self, tmp_path):
        path = _write(tmp_path, '[paths]\nbase = .\n')
        conf = ConfParser(path).read_conf()
        assert conf['paths']['base'] == str(tmp_path)

    def test_relative_base_with_suffix_keeps_suffix(self, tmp_path):
        # './data' must resolve to <config_dir>/data, not be truncated to
        # <config_dir> (which would silently misplace keys/logs/images).
        import os
        path = _write(tmp_path, '[paths]\nbase = ./data\n')
        conf = ConfParser(path).read_conf()
        assert conf['paths']['base'] == os.path.join(str(tmp_path), 'data')

    def test_parent_relative_base_is_resolved(self, tmp_path):
        import os
        path = _write(tmp_path, '[paths]\nbase = ../shared\n')
        conf = ConfParser(path).read_conf()
        assert conf['paths']['base'] == os.path.abspath(
            os.path.join(str(tmp_path), '..', 'shared'))

    def test_plain_relative_base_anchored_to_config_dir(self, tmp_path):
        # A relative base with no leading dot is anchored to the config-file
        # directory, not left relative to the process CWD.
        import os
        path = _write(tmp_path, '[paths]\nbase = badgedata\n')
        conf = ConfParser(path).read_conf()
        assert conf['paths']['base'] == os.path.join(str(tmp_path), 'badgedata')

    def test_hidden_dir_base_is_not_truncated(self, tmp_path):
        # A directory literally named '.hidden' must be kept, not dropped by the
        # old base[0] == '.' shortcut.
        import os
        path = _write(tmp_path, '[paths]\nbase = .hidden\n')
        conf = ConfParser(path).read_conf()
        assert conf['paths']['base'] == os.path.join(str(tmp_path), '.hidden')

    def test_absolute_base_is_left_unchanged(self, tmp_path):
        abs_base = str(tmp_path / 'keys')
        path = _write(tmp_path, '[paths]\nbase = %s\n' % abs_base)
        conf = ConfParser(path).read_conf()
        assert conf['paths']['base'] == abs_base

    def test_config_dir_with_dollar_sign_round_trips(self, tmp_path):
        # A config directory whose path contains a literal '$' must not raise
        # (ExtendedInterpolation escaping) and must resolve back to the original
        # path, including through a ${base} reference.
        import os
        d = tmp_path / 'a$b'
        d.mkdir()
        p = d / 'config.ini'
        p.write_text('[paths]\nbase = data\nbase_key = ${base}/keys\n')
        conf = ConfParser(str(p)).read_conf()
        assert conf['paths']['base'] == os.path.join(str(d), 'data')
        # base_key is ${base} + the INI's literal '/keys'; the separator after
        # base stays '/' on every platform (os.path.join would use '\' on
        # Windows and spuriously mismatch), so compare against base + '/keys'.
        assert conf['paths']['base_key'] == conf['paths']['base'] + '/keys'

    def test_nonexistent_file_returns_none(self, tmp_path):
        assert ConfParser(str(tmp_path / 'missing.ini')).read_conf() is None


#: A password distinctive enough that its absence from an error message is
#: meaningful (no substring of the config, the paths or the boilerplate).
_PW = 'hunter2-zzz'


class TestUrlUserinfoRejected:
    """A publish_url (or any other [issuer]/[badge_*] URL) carrying
    ``user:password@`` is refused at load time: that URL is printed by the
    CLIs, joined into the ids written to organization.json / badge.json /
    key.json, turned into the issuer's did:web and embedded in the
    credentialStatus of signed OB3 credentials — so accepting it would leak the
    credential into user-visible output, public files and issued badges alike.
    No message may echo the password."""

    def test_publish_url_with_userinfo_rejected(self, tmp_path):
        from openbadgeslib.errors import ConfigError
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\n'
            'publish_url = https://user:%s@issuer.example/issuer/\n' % _PW)
        with pytest.raises(ConfigError) as exc:
            ConfParser(path).read_conf()
        assert '[issuer] publish_url' in str(exc.value)
        assert _PW not in str(exc.value)

    def test_password_absent_from_repr_too(self, tmp_path):
        # repr() is what a traceback shows; neither it nor str() may carry it.
        from openbadgeslib.errors import ConfigError
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\n'
            'publish_url = https://user:%s@issuer.example/\n' % _PW)
        with pytest.raises(ConfigError) as exc:
            ConfParser(path).read_conf()
        assert _PW not in repr(exc.value)

    @pytest.mark.parametrize('url', [
        'https://user:%s@issuer.example/' % _PW,   # user:password@
        'https://user@issuer.example/',            # bare user@
        'https://@issuer.example/',                # empty userinfo
        'http://user:%s@issuer.example/' % _PW,    # any scheme, not just https
    ])
    def test_every_userinfo_shape_rejected(self, tmp_path, url):
        from openbadgeslib.errors import ConfigError
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\npublish_url = %s\n' % url)
        with pytest.raises(ConfigError):
            ConfParser(path).read_conf()

    @pytest.mark.parametrize('key', ['url', 'image'])
    def test_other_issuer_url_keys_rejected(self, tmp_path, key):
        # publish_url is the documented leak, but [issuer] url is the OB3
        # issuer-id fallback and image is urljoin'd into published metadata:
        # every identifier in the section is public.
        from openbadgeslib.errors import ConfigError
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\n%s = '
            'https://user:%s@issuer.example/x\n' % (key, _PW))
        with pytest.raises(ConfigError) as exc:
            ConfParser(path).read_conf()
        assert '[issuer] %s' % key in str(exc.value)
        assert _PW not in str(exc.value)

    @pytest.mark.parametrize('key', ['image', 'criteria', 'status_base',
                                     'hosted_assertions_base'])
    def test_badge_section_url_keys_rejected(self, tmp_path, key):
        from openbadgeslib.errors import ConfigError
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[badge_1]\n%s = '
            'https://user:%s@issuer.example/badge_1/\n' % (key, _PW))
        with pytest.raises(ConfigError) as exc:
            ConfParser(path).read_conf()
        assert '[badge_1] %s' % key in str(exc.value)
        assert _PW not in str(exc.value)

    @pytest.mark.parametrize('url', [
        'https://user:12345/x@host/',        # numeric "port": encoded into the DID
        'https://user:%s/x@host/' % _PW,     # '/' in the password moves the '@'
        'https://user:%s?q@host/' % _PW,     # ... and so do '?' and '#'
        'https://user:%s#f@host/' % _PW,
        'https://user%%40host/badges/',      # '@' written as %40 ('%%' = literal %)
        'https://host/x?u=a@b',              # '@' in the query
    ])
    def test_at_sign_outside_the_authority_rejected(self, tmp_path, url):
        # urlsplit only reports userinfo when the '@' sits inside the
        # authority, so checking netloc alone left a bypass: these all loaded
        # cleanly and then leaked — 'https://user:12345/x@host/' became the
        # issuer id 'did:web:user%3A12345:x%40host', carried by every signed
        # credential, and the non-numeric ones surfaced the password through
        # urllib's own "Port could not be cast..." message.
        from openbadgeslib.errors import ConfigError
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\npublish_url = %s\n' % url)
        with pytest.raises(ConfigError) as exc:
            ConfParser(path).read_conf()
        assert _PW not in str(exc.value)
        assert '12345' not in str(exc.value)

    def test_at_sign_in_path_rejected_even_when_innocent(self, tmp_path):
        # Deliberate false positive, documented on reject_url_userinfo: once
        # parsed, 'https://host/@name/' is the same shape as one hiding a
        # credential, so the blunt rule wins over the rare legitimate use.
        from openbadgeslib.errors import ConfigError
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\n'
            'publish_url = https://issuer.example/@name/\n')
        with pytest.raises(ConfigError):
            ConfParser(path).read_conf()

    def test_email_and_paths_with_at_sign_still_accepted(self, tmp_path):
        # A value with no authority is not a dereferenceable URL: an address or
        # a local path may hold an '@' and must keep loading.
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\n'
            'email = issuer_mail@issuer.badge\n\n'
            '[badge_1]\nmail = ${paths:base}/@inbox/badge_1.txt\n')
        conf = ConfParser(path).read_conf()
        assert conf['issuer']['email'] == 'issuer_mail@issuer.badge'
        assert conf['badge_1']['mail'].endswith('/@inbox/badge_1.txt')

    def test_interpolated_userinfo_rejected(self, tmp_path):
        # The check runs after ${...} resolution, so a credential cannot be
        # smuggled in through a reference to an unchecked section.
        from openbadgeslib.errors import ConfigError
        path = _write(
            tmp_path,
            '[paths]\nbase = .\nhost = user:%s@issuer.example\n\n'
            '[issuer]\nname = x\n'
            'publish_url = https://${paths:host}/issuer/\n' % _PW)
        with pytest.raises(ConfigError) as exc:
            ConfParser(path).read_conf()
        assert _PW not in str(exc.value)

    def test_clean_urls_accepted(self, tmp_path):
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\n'
            'url = https://www.issuer.example\n'
            'email = issuer_mail@issuer.example\n'
            'publish_url = https://issuer.example:8443/issuer/\n'
            'revocationList = revoked.json\n\n'
            '[badge_1]\nimage = https://issuer.example/b/badge1.svg\n'
            'private_key = ${paths:base}/keys/sign.pem\n'
            'mail = ${paths:base}/badge_1_mail.txt\n')
        conf = ConfParser(path).read_conf()
        # A bare mail address is not userinfo, and neither are paths or ports.
        assert conf['issuer']['email'] == 'issuer_mail@issuer.example'
        assert conf['issuer']['publish_url'] == 'https://issuer.example:8443/issuer/'

    def test_smtp_credentials_are_not_touched(self, tmp_path):
        # [smtp] username/password are legitimate secrets that stay on the
        # issuer's machine — they are never published, so they are not checked.
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[smtp]\nsmtp_server = localhost\n'
            'username = postmaster\npassword = %s\n' % _PW)
        conf = ConfParser(path).read_conf()
        assert conf['smtp']['password'] == _PW

    def test_cli_wrapper_exits_without_echoing_the_password(self, tmp_path, capsys):
        from openbadgeslib.confparser import read_config_or_exit
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = x\n'
            'publish_url = https://user:%s@issuer.example/issuer/\n' % _PW)
        with pytest.raises(SystemExit):
            read_config_or_exit(path)
        out = capsys.readouterr()
        assert out.out.startswith('[!]')
        assert _PW not in out.out and _PW not in out.err

    def test_bad_interpolation_reference_raises_clean_value_error(self, tmp_path):
        # ExtendedInterpolation resolves ${...} lazily; a bad reference in a
        # section other than [paths] must surface here, at load time, as a
        # clean ValueError — not as a raw configparser.Error deep inside a
        # CLI tool the first time that key happens to be read.
        path = _write(tmp_path, '[paths]\nbase = .\n\n[badge_1]\nimage = ${missing}/x.svg\n')
        with pytest.raises(ValueError):
            ConfParser(path).read_conf()

    def test_valid_interpolation_reference_resolves(self, tmp_path):
        path = _write(
            tmp_path,
            '[paths]\nbase = .\nbase_image = ${base}/images\n\n'
            '[badge_1]\nimage = ${paths:base_image}/x.svg\n',
        )
        conf = ConfParser(path).read_conf()
        assert conf['badge_1']['image'] == '%s/images/x.svg' % conf['paths']['base']

    def test_duplicate_section_raises_value_error(self, tmp_path):
        # DuplicateSectionError raises directly from parser.read(), before
        # [paths]/base is ever touched.
        path = _write(tmp_path, '[paths]\nbase = .\n\n[paths]\nbase = .\n')
        with pytest.raises(ValueError):
            ConfParser(path).read_conf()

    def test_duplicate_option_raises_value_error(self, tmp_path):
        path = _write(tmp_path, '[paths]\nbase = .\nbase = ./other\n')
        with pytest.raises(ValueError):
            ConfParser(path).read_conf()

    def test_missing_section_header_raises_value_error(self, tmp_path):
        path = _write(tmp_path, 'base = .\n\n[paths]\nbase = .\n')
        with pytest.raises(ValueError):
            ConfParser(path).read_conf()


class TestReadConfigOrExit:
    """read_config_or_exit() is the shared CLI wrapper; a malformed config must
    exit cleanly (SystemExit + '[!] ...'), not leak read_conf()'s ValueError."""

    def test_unresolvable_interpolation_exits_cleanly(self, tmp_path, capsys):
        from openbadgeslib.confparser import read_config_or_exit
        path = _write(
            tmp_path,
            '[paths]\nbase = .\n\n[issuer]\nname = ${nonexistent:key}\n')
        with pytest.raises(SystemExit):
            read_config_or_exit(path)
        assert capsys.readouterr().out.startswith('[!]')

    def test_invalid_ini_syntax_exits_cleanly(self, tmp_path, capsys):
        from openbadgeslib.confparser import read_config_or_exit
        path = _write(tmp_path, '[paths]\nbase = .\nbase = ./other\n')  # duplicate option
        with pytest.raises(SystemExit):
            read_config_or_exit(path)
        assert capsys.readouterr().out.startswith('[!]')

    def test_missing_file_exits_cleanly(self, tmp_path, capsys):
        from openbadgeslib.confparser import read_config_or_exit
        with pytest.raises(SystemExit):
            read_config_or_exit(str(tmp_path / 'missing.ini'))
        assert 'does not exist or is empty' in capsys.readouterr().out


class TestOb3ProofFormat:
    def _conf(self, value=None):
        from configparser import ConfigParser
        conf = ConfigParser()
        conf['badge_1'] = {} if value is None else {'proof_format': value}
        return conf

    def test_defaults_to_vc_jwt(self):
        from openbadgeslib.confparser import ob3_proof_format
        assert ob3_proof_format(self._conf(), 'badge_1') == 'vc-jwt'

    def test_ldp_accepted(self):
        from openbadgeslib.confparser import ob3_proof_format
        assert ob3_proof_format(self._conf('ldp'), 'badge_1') == 'ldp'

    def test_whitespace_stripped(self):
        from openbadgeslib.confparser import ob3_proof_format
        assert ob3_proof_format(self._conf(' vc-jwt '), 'badge_1') == 'vc-jwt'

    def test_unknown_value_rejected(self):
        from openbadgeslib.confparser import ob3_proof_format
        with pytest.raises(ValueError, match=r'\[badge_1\] proof_format'):
            ob3_proof_format(self._conf('jwt'), 'badge_1')


class TestOb3StatusConfigSizeBits:
    def _conf(self, size_bits):
        from configparser import ConfigParser
        conf = ConfigParser()
        conf['paths'] = {'base': '/tmp/x', 'base_status': '/tmp/x/status'}
        conf['issuer'] = {'publish_url': 'https://issuer.example/'}
        conf['badge_1'] = {'status_lists': 'revocation',
                           'status_size_bits': str(size_bits)}
        return conf

    def test_multiple_of_8_accepted(self):
        from openbadgeslib.confparser import ob3_status_config
        assert ob3_status_config(self._conf(131072), 'badge_1').size_bits == 131072

    def test_non_multiple_of_8_rejected(self):
        # A latent bad size would otherwise crash publish's encode_bitstring with
        # a raw ValueError (#204); reject it as a clean config error here.
        from openbadgeslib.confparser import ob3_status_config
        with pytest.raises(ValueError, match='positive multiple of 8'):
            ob3_status_config(self._conf(131070), 'badge_1')

    def test_zero_rejected(self):
        from openbadgeslib.confparser import ob3_status_config
        with pytest.raises(ValueError, match='positive multiple of 8'):
            ob3_status_config(self._conf(0), 'badge_1')


class TestLoadConfig:
    """load_config is the library entry point (raises ConfigError);
    read_config_or_exit is the thin CLI wrapper over it (prints + exits)."""

    def test_returns_configparser_for_valid_file(self, tmp_path):
        from openbadgeslib.confparser import load_config
        conf = load_config(_write(tmp_path, '[paths]\nbase = .\n'))
        assert conf['paths']['base'] == str(tmp_path)

    def test_missing_file_raises_config_error(self, tmp_path):
        from openbadgeslib.confparser import load_config
        from openbadgeslib.errors import ConfigError
        with pytest.raises(ConfigError, match='does not exist or is empty'):
            load_config(str(tmp_path / 'missing.ini'))

    def test_malformed_raises_config_error(self, tmp_path):
        from openbadgeslib.confparser import load_config
        from openbadgeslib.errors import ConfigError
        path = _write(tmp_path, '[logs]\ngeneral = general.log\n')  # no [paths]
        with pytest.raises(ConfigError):
            load_config(path)

    def test_config_error_is_still_a_value_error(self, tmp_path):
        # Backward compat: an integrator catching ValueError keeps working.
        from openbadgeslib.confparser import load_config
        with pytest.raises(ValueError):
            load_config(str(tmp_path / 'missing.ini'))


class TestResolveKeyType:
    def test_defaults_to_rsa(self):
        from openbadgeslib.confparser import resolve_key_type
        from openbadgeslib.keys import KeyType
        assert resolve_key_type(None) is KeyType.RSA
        assert resolve_key_type('') is KeyType.RSA

    def test_maps_names_case_insensitively(self):
        from openbadgeslib.confparser import resolve_key_type
        from openbadgeslib.keys import KeyType
        assert resolve_key_type('ecc') is KeyType.ECC
        assert resolve_key_type(' ED25519 ') is KeyType.ED25519
        assert resolve_key_type('eddsa') is KeyType.ED25519   # alias

    def test_unknown_name_raises_config_error(self):
        from openbadgeslib.confparser import resolve_key_type
        from openbadgeslib.errors import ConfigError
        with pytest.raises(ConfigError, match='Unknown key_type'):
            resolve_key_type('dsa')


class TestIssuerConfig:
    def _conf(self, **issuer):
        from configparser import ConfigParser
        conf = ConfigParser()
        if issuer:
            conf['issuer'] = {k: v for k, v in issuer.items() if v is not None}
        return conf

    def test_resolves_fields_and_id(self):
        from openbadgeslib.confparser import issuer_config
        cfg = issuer_config(self._conf(
            name='Acme', url='https://acme.example',
            publish_url='https://acme.example/', email='a@acme.example'))
        assert cfg.name == 'Acme'
        assert cfg.id == 'https://acme.example/'   # publish_url is the OB3 id
        assert cfg.url == 'https://acme.example'
        assert cfg.email == 'a@acme.example'

    def test_missing_section_raises_config_error(self):
        from openbadgeslib.confparser import issuer_config
        from openbadgeslib.errors import ConfigError
        with pytest.raises(ConfigError, match=r'\[issuer\] section'):
            issuer_config(self._conf())

    def test_missing_name_raises_config_error(self):
        from openbadgeslib.confparser import issuer_config
        from openbadgeslib.errors import ConfigError
        with pytest.raises(ConfigError, match="required 'name'"):
            issuer_config(self._conf(url='https://acme.example'))


class TestBadgeSectionConfig:
    def _conf(self, **badge):
        from configparser import ConfigParser
        conf = ConfigParser()
        conf['badge_1'] = {k: v for k, v in badge.items() if v is not None}
        return conf

    def test_criteria_narrative_used_when_present(self):
        from openbadgeslib.confparser import badge_section_config
        bsc = badge_section_config(
            self._conf(criteria_narrative='Do the thing',
                       criteria='https://x/c.html'), 'badge_1')
        assert bsc.criteria_narrative == 'Do the thing'

    def test_falls_back_to_ob1_criteria(self):
        from openbadgeslib.confparser import badge_section_config
        bsc = badge_section_config(
            self._conf(criteria='https://x/c.html'), 'badge_1')
        assert bsc.criteria_narrative == 'https://x/c.html'

    def test_empty_when_neither_present(self):
        from openbadgeslib.confparser import badge_section_config
        assert badge_section_config(self._conf(), 'badge_1').criteria_narrative == ''

    def test_hosted_assertions_base(self):
        from openbadgeslib.confparser import badge_section_config
        bsc = badge_section_config(
            self._conf(hosted_assertions_base='https://x/a/'), 'badge_1')
        assert bsc.hosted_assertions_base == 'https://x/a/'
