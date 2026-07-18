"""The unified ``openbadges <command>`` front-end (#234).

The shell must recognise each command, hand the rest of the argv to that tool's
own main() unchanged, and otherwise behave like a normal argparse program
(top-level --help/--version, exit 2 on no/unknown command).
"""
import pathlib
import sys

import pytest
from unittest.mock import patch

from openbadgeslib import openbadges_cli


def _run(argv):
    """Run the front-end with argv (excluding prog); return the SystemExit code
    (None if main() returned without exiting)."""
    with patch.object(sys, 'argv', ['openbadges', *argv]):
        try:
            openbadges_cli.main()
        except SystemExit as exc:
            return exc.code
        return None


def test_top_level_help_lists_every_command(capsys):
    assert _run(['--help']) == 0
    out = capsys.readouterr().out
    for command in ('init', 'keygen', 'sign', 'verify', 'publish', 'status'):
        assert command in out


def test_top_level_version(capsys):
    from openbadgeslib.util import __version__
    assert _run(['--version']) == 0
    assert capsys.readouterr().out.strip() == __version__


def test_no_command_exits_2(capsys):
    assert _run([]) == 2
    assert 'COMMAND' in capsys.readouterr().err


def test_unknown_command_exits_2(capsys):
    assert _run(['frobnicate']) == 2
    assert 'frobnicate' in capsys.readouterr().err


@pytest.mark.parametrize('command, needle', [
    ('init', 'DIRECTORY'),
    ('keygen', '--genkey'),
    ('sign', '--badge'),
    ('verify', '--filein'),
    ('publish', '--check-live'),
    ('status', 'ID'),
])
def test_command_help_is_the_tools_own(command, needle, capsys):
    # `openbadges CMD --help` shows that tool's own parser (a command-specific
    # flag proves the dispatch reached it). The prog re-labels to
    # "openbadges CMD" in real use; that is not asserted here because argparse's
    # default prog reads the runner's argv under pytest regardless of sys.argv.
    assert _run([command, '--help']) == 0
    assert needle in capsys.readouterr().out


def test_command_version_is_delegated(capsys):
    # A flag after the command belongs to the tool: `openbadges sign --version`
    # prints the library version via the signer's own parser.
    from openbadgeslib.util import __version__
    assert _run(['sign', '--version']) == 0
    assert capsys.readouterr().out.strip() == __version__


def test_dispatch_actually_invokes_the_tool(tmp_path):
    # End-to-end: `openbadges init DIR` must run openbadges_init.main() and build
    # the directory layout, proving the shell dispatches rather than just parses.
    target = tmp_path / 'ob'
    assert _run(['init', str(target)]) is None
    assert (target / 'config.ini').is_file()
    for sub in ('keys', 'images', 'log', 'status'):
        assert (target / sub).is_dir()


def test_missing_required_flag_reaches_tool_parser(capsys):
    # `openbadges sign` with no -b hits the signer's own required-arg check
    # (exit 2), not a shell-level error.
    assert _run(['sign']) == 2
    assert 'required' in capsys.readouterr().err.lower()


def test_status_is_dispatchable_but_has_no_alias_script():
    # status is reachable through the front-end like any other command...
    assert 'status' in openbadges_cli.COMMANDS
    # ...but unlike the other five it is deliberately NOT installed as its own
    # openbadges-status script (the aliases exist only because they predate the
    # front-end). The top-level --help promises exactly this, so guard the
    # console_scripts table against growing one by accident.
    pyproject = (pathlib.Path(__file__).parent.parent / 'pyproject.toml')
    scripts = pyproject.read_text(encoding='utf-8').split('[project.scripts]')[1]
    scripts = scripts.split('\n[', 1)[0]
    assert 'openbadges-publish' in scripts          # the section was found
    assert 'openbadges-status' not in scripts
