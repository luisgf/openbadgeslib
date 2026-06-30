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

    def test_nonexistent_file_returns_none(self, tmp_path):
        assert ConfParser(str(tmp_path / 'missing.ini')).read_conf() is None
