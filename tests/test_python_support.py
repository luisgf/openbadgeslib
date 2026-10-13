"""Supported Python versions — the runtime deprecation of Python 3.10 (#242).

openbadgeslib 4.x supports CPython 3.10–3.15. Python 3.10 is deprecated since
4.6.0 and dropped in 5.0 (CONTRIBUTING.md "Supported Python versions"), so
importing the package on 3.10 emits one DeprecationWarning, attributed to the
code that imported openbadgeslib (PEP 565: shown by default for a script or an
installed console script, hidden when another module pulls us in — including
`python -m openbadgeslib.<tool>` and importlib-based loaders, whose importer is
runpy/importlib). 3.11+ stays silent.
"""
import os
import subprocess
import sys
import warnings

import pytest

from openbadgeslib import _python_support

# The canonical text (Changelog, README and the wiki paraphrase it): spelled
# out here so a change to the user-facing message is a deliberate one.
MESSAGE = ('Python 3.10 is deprecated in openbadgeslib (CPython end of life: '
           '2026-10-31); openbadgeslib 5.0 will require Python 3.11 or newer.')
MARKER = 'Python 3.10 is deprecated in openbadgeslib'
ON_PY310 = sys.version_info < (3, 11)


def _package_init(version_info):
    # Stands in for openbadgeslib/__init__.py, the helper's only real caller.
    _python_support.warn_if_deprecated(version_info)


class TestHelper:
    @pytest.mark.parametrize('version_info', [
        (3, 10, 0), (3, 10, 22), (3, 10, 20, 'final', 0),
    ])
    def test_python_310_warns_once(self, version_info):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            _package_init(version_info)
        assert len(caught) == 1
        assert caught[0].category is DeprecationWarning
        assert str(caught[0].message) == MESSAGE

    @pytest.mark.parametrize('version_info', [
        (3, 11, 0), (3, 14, 8), (3, 15, 0), (3, 15, 0, 'candidate', 3),
        (3, 15, 0, 'final', 0), (4, 0, 0),
    ])
    def test_supported_python_is_silent(self, version_info):
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            _package_init(version_info)

    def test_attributed_to_the_importer(self):
        # stacklevel=3 skips the helper and the package __init__ (here
        # _package_init), so the warning points at the line that imported us.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            _package_init((3, 10, 20))
            line = sys._getframe().f_lineno - 1
        assert (caught[0].filename, caught[0].lineno) == (__file__, line)

    def test_helper_is_not_public(self):
        import openbadgeslib
        ns = {}
        exec('from openbadgeslib import *', ns)
        for name in ('_python_support', 'warn_if_deprecated'):
            assert name not in openbadgeslib.__all__
            assert name not in ns


def _run_python(*args, cwd=None):
    # A clean child: no inherited warning filters or dev mode, so the
    # interpreter's default filters (PEP 565) are the ones under test, and no
    # PYTHONSAFEPATH, so `-c` code can import a module from its cwd. Its
    # stderr is UTF-8 and decoded as such, whatever the platform.
    env = {k: v for k, v in os.environ.items()
           if k not in ('PYTHONWARNINGS', 'PYTHONDEVMODE', 'PYTHONSAFEPATH')}
    env['PYTHONIOENCODING'] = 'utf-8'
    result = subprocess.run([sys.executable, *args], cwd=cwd,
                            capture_output=True, encoding='utf-8', env=env)
    assert result.returncode == 0, result.stderr
    return result.stderr


class TestRealInterpreter:
    @pytest.mark.parametrize('code', [
        'import openbadgeslib',
        'import openbadgeslib.util',
        'from openbadgeslib.ob3 import OB3Verifier',
        # Several import paths in one process still warn exactly once.
        'import openbadgeslib; import openbadgeslib.ob1; '
        'from openbadgeslib.ob3 import OB3Verifier; import openbadgeslib.util',
    ])
    def test_first_import_warns_only_on_310(self, code):
        # However the package is first imported, the warning fires once and
        # names the importing line (here `-c` code: "<string>:1").
        stderr = _run_python('-W', 'always::DeprecationWarning', '-c', code)
        if ON_PY310:
            assert stderr.count(MARKER) == 1, stderr
            assert '<string>:1: DeprecationWarning: ' + MARKER in stderr
        else:
            assert MARKER not in stderr

    def test_default_filters_show_it_to_scripts_only(self):
        # PEP 565: shown by default when __main__ imports openbadgeslib ...
        script = _run_python('-c', 'import openbadgeslib')
        # ... hidden when library code (here importlib) is the importer.
        library = _run_python(
            '-c', 'import importlib; importlib.import_module("openbadgeslib")')
        assert (MARKER in script) is ON_PY310
        assert MARKER not in library

    def test_a_library_module_importing_us_is_named(self, tmp_path):
        # The real third-party case: a module that does `import openbadgeslib`,
        # imported by a script. Hidden by default (the importer is not
        # __main__); when shown, it names that module's import line.
        (tmp_path / 'mylib.py').write_text('import openbadgeslib\n',
                                           encoding='utf-8')
        hidden = _run_python('-c', 'import mylib', cwd=str(tmp_path))
        shown = _run_python('-W', 'always::DeprecationWarning',
                            '-c', 'import mylib', cwd=str(tmp_path))
        assert MARKER not in hidden
        if ON_PY310:
            assert 'mylib.py:1: DeprecationWarning: ' + MARKER in shown
        else:
            assert MARKER not in shown
