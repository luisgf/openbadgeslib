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
        assert conf['paths']['base_key'] == os.path.join(str(d), 'data', 'keys')

    def test_nonexistent_file_returns_none(self, tmp_path):
        assert ConfParser(str(tmp_path / 'missing.ini')).read_conf() is None

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
