"""Documentation-alignment gates.

These tests fail when the docs drift from the code, so CI catches it:
- every CLI flag the argparse parsers define is documented in the wiki,
- every wiki [[cross-link]] resolves to a real page,
- no wiki content page starts with an H1 (GitHub renders the title),
- the version is single-sourced (pyproject reads it dynamically),
- environment.yml's runtime block mirrors the pyproject dependencies,
- CI derives the openvc-core floor instead of restating it.
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


def _pyproject_runtime_dependencies():
    """Package names from [project] dependencies in pyproject.toml.

    Parsed with a regex rather than tomllib: the CI matrix still includes
    Python 3.10, where tomllib does not exist.
    """
    text = (REPO / 'pyproject.toml').read_text(encoding='utf-8')
    block = re.search(r'(?ms)^dependencies\s*=\s*\[(.*?)^\]', text)
    assert block, 'could not locate [project] dependencies in pyproject.toml'
    names = set()
    for spec in re.findall(r'"([^"]+)"', block.group(1)):
        names.add(re.split(r"[\[<>=!~;\s]", spec, maxsplit=1)[0].strip().lower())
    return names


def test_conda_environment_mirrors_the_runtime_dependencies():
    """environment.yml's Runtime block must list exactly the pyproject runtime
    dependencies.

    It drifted: the #167 port dropped pycryptodome and python-ecdsa (the latter
    carrying a permanent pip-audit flag, CVE-2024-23342), but the documented
    conda setup kept installing both — reinstating a flagged package the audit
    job believes is gone (#265). Names only; the floors are commented in place."""
    env = (REPO / 'environment.yml').read_text(encoding='utf-8')
    runtime = env.split('# Runtime', 1)[1].split('# Development', 1)[0]
    conda = {re.split(r"[<>=!\s]", line.strip().lstrip("- "), maxsplit=1)[0].lower()
             for line in runtime.splitlines()
             if line.strip().startswith('- ')}
    conda.discard('python')                      # the interpreter, not a dep
    assert conda == _pyproject_runtime_dependencies(), (
        'environment.yml Runtime block and pyproject dependencies disagree: '
        'only in conda=%s, only in pyproject=%s'
        % (sorted(conda - _pyproject_runtime_dependencies()),
           sorted(_pyproject_runtime_dependencies() - conda)))


def test_ci_does_not_restate_the_openvc_floor():
    """The eudi job's authoritative 'floor' leg must DERIVE the openvc-core
    floor from pyproject.toml, not restate it.

    Same single-sourcing rule as the version above: the hardcoded pin drifted
    once already — 677f4ed raised the [eudi] floor to >=1.21 and touched only
    pyproject.toml, leaving CI installing 1.18, below the package's own
    constraint, so the shipped floor went untested (#264)."""
    ci = (REPO / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
    # The derived pin is `openvc-core==${floor}.*`; a literal one starts with a
    # digit, which is what must never come back.
    literal = re.findall(r'openvc-core==\d[^"\'\s]*', ci)
    assert not literal, \
        f"ci.yml pins openvc-core literally ({literal}); derive it from pyproject.toml"


def test_cli_reference_does_not_claim_fileexistserror():
    """openbadges-init/publish exit cleanly with a '[!] ... already exists'
    message on a pre-existing target; the wiki must not still claim they raise
    a raw FileExistsError."""
    doc = (WIKI / 'CLI-Reference.md').read_text(encoding='utf-8')
    assert 'FileExistsError' not in doc, \
        "CLI-Reference.md still claims a FileExistsError; init/publish exit cleanly instead"


def test_docs_cryptography_floor_matches_pyproject():
    """README and Installation must not restate a stale cryptography floor (#304)."""
    pyproject = (REPO / 'pyproject.toml').read_text(encoding='utf-8')
    match = re.search(r'"cryptography>=(\d+)"', pyproject)
    assert match, 'could not find cryptography floor in pyproject.toml'
    floor = match.group(1)
    for path in (REPO / 'README.md', WIKI / 'Installation.md'):
        compact = path.read_text(encoding='utf-8').replace(' ', '')
        assert ('>=%s' % floor) in compact, \
            '%s does not document cryptography>=%s' % (path.name, floor)


@pytest.mark.parametrize('name', CLI_TOOLS)
def test_build_parser_is_exposed(name):
    """Each CLI tool exposes build_parser() so the parser is testable/documentable."""
    import importlib
    mod = importlib.import_module(f'openbadgeslib.{name}')
    assert mod.build_parser() is not None
