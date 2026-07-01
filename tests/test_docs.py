"""Documentation-alignment gates.

These tests fail when the docs drift from the code, so CI catches it:
- every CLI flag the argparse parsers define is documented in the wiki,
- every wiki [[cross-link]] resolves to a real page,
- no wiki content page starts with an H1 (GitHub renders the title),
- the version is single-sourced (pyproject reads it dynamically).
"""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WIKI = REPO / 'wiki'

CLI_TOOLS = [
    'openbadges_keygenerator',
    'openbadges_signer',
    'openbadges_verifier',
    'openbadges_publish',
]


def _long_options():
    """Every --long option string defined by the CLI parsers (minus --help)."""
    import importlib
    opts = set()
    for name in CLI_TOOLS:
        mod = importlib.import_module(f'openbadgeslib.{name}')
        for action in mod.build_parser()._actions:
            for opt in action.option_strings:
                if opt.startswith('--') and opt != '--help':
                    opts.add(opt)
    return opts


def _wiki_md_files():
    return sorted(WIKI.glob('*.md'))


def test_cli_flags_are_documented():
    """Every argparse --flag must appear in the CLI Reference page."""
    doc = (WIKI / 'CLI-Reference.md').read_text(encoding='utf-8')
    missing = sorted(opt for opt in _long_options() if opt not in doc)
    assert not missing, f"CLI flags not documented in CLI-Reference.md: {missing}"


def test_wiki_cross_links_resolve():
    """Every [[wiki link]] must point to an existing page (or an intra-page #anchor)."""
    pages = {p.name for p in _wiki_md_files()}
    broken = []
    for p in _wiki_md_files():
        for raw in re.findall(r'\[\[([^\]]+)\]\]', p.read_text(encoding='utf-8')):
            target = raw.split('|')[-1].strip()
            if target.startswith('#'):
                continue
            if (target.replace(' ', '-') + '.md') not in pages:
                broken.append(f"{p.name}: [[{raw}]]")
    assert not broken, f"Broken wiki links: {broken}"


def test_wiki_content_pages_have_no_h1():
    """GitHub renders the page title from the filename; pages must not add an H1."""
    offenders = []
    for p in _wiki_md_files():
        if p.name.startswith('_'):  # _Sidebar / _Footer are navigation
            continue
        first = next((ln for ln in p.read_text(encoding='utf-8').splitlines() if ln.strip()), '')
        if first.startswith('# '):
            offenders.append(p.name)
    assert not offenders, f"Wiki pages starting with an H1: {offenders}"


def test_version_is_single_sourced():
    """pyproject must read the version dynamically from util.__version__,
    not hardcode it (which would drift)."""
    pyproject = (REPO / 'pyproject.toml').read_text(encoding='utf-8')
    assert 'dynamic = ["version"]' in pyproject
    assert 'attr = "openbadgeslib.util.__version__"' in pyproject
    # No static version = "..." line under [project].
    assert not re.search(r'(?m)^version\s*=\s*"', pyproject)


def test_cli_reference_does_not_claim_fileexistserror():
    """openbadges-init/publish exit cleanly with a '[!] ... already exists'
    message on a pre-existing target; the wiki must not still claim they raise
    a raw FileExistsError."""
    doc = (WIKI / 'CLI-Reference.md').read_text(encoding='utf-8')
    assert 'FileExistsError' not in doc, \
        "CLI-Reference.md still claims a FileExistsError; init/publish exit cleanly instead"


@pytest.mark.parametrize('name', CLI_TOOLS)
def test_build_parser_is_exposed(name):
    """Each CLI tool exposes build_parser() so the parser is testable/documentable."""
    import importlib
    mod = importlib.import_module(f'openbadgeslib.{name}')
    assert mod.build_parser() is not None
