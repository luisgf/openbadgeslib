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
    # The derived pins are `openvc-core==${OPENVC_FLOOR}` and, for the [ldp-sd]
    # suite, `openvc-core[data-integrity]==${OPENVC_FLOOR}`; a literal one
    # starts with a digit, with or without the extras bracket, and must never
    # come back.
    literal = re.findall(r'openvc-core(?:\[[^\]]*\])?==\d[^"\'\s]*', ci)
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
    for path in (REPO / 'README.md', WIKI / 'Installation.md',
                 REPO / 'environment.yml'):
        compact = path.read_text(encoding='utf-8').replace(' ', '')
        assert ('>=%s' % floor) in compact, \
            '%s does not document cryptography>=%s' % (path.name, floor)


def test_pyld_range_is_the_one_the_canonicalization_guard_meters():
    """Both extras that pull pyld carry one range, and its ceiling is the
    guard's supported major version plus one: pip checks a dependency range
    only when it resolves (an upgrade of pyld alone installs 4.x without a
    word), so a ceiling dropped from one extra would leave only the run-time
    refusal of ob3/_canon_guard.py -- and the documented range stale."""
    from openbadgeslib.ob3 import _canon_guard
    pyproject = (REPO / 'pyproject.toml').read_text(encoding='utf-8')
    ranges = re.findall(r'"(pyld>=[^"]*)"', pyproject)
    assert len(ranges) == 2 and len(set(ranges)) == 1, \
        'the [ldp] and [ldp-sd] extras must both carry the same pyld range: %s' % ranges
    match = re.fullmatch(r'pyld>=(\d+)\.(\d+)\.(\d+),<(\d+)', ranges[0])
    assert match, 'pyld range %r is not >=X.Y.Z,<N' % ranges[0]
    major = _canon_guard._SUPPORTED_PYLD_MAJOR
    assert int(match.group(1)) == major and int(match.group(4)) == major + 1
    installation = (WIKI / 'Installation.md').read_text(encoding='utf-8')
    floor = '.'.join(match.group(i) for i in (1, 2, 3))
    assert '(>= %s, < %s)' % (floor, match.group(4)) in installation


def _audit_floors_script():
    """The python heredoc the audit workflow's 'Read the declared floors' step
    runs, with the workflow's indentation stripped."""
    audit = (REPO / '.github' / 'workflows' / 'audit.yml').read_text(encoding='utf-8')
    step = re.search(r"(?ms)^( *)python - > \"\$RUNNER_TEMP/floors\.txt\" <<'PY'\n"
                     r"(.*?)^\1PY$", audit)
    assert step, "audit.yml has no 'Read the declared floors' step"
    indent = len(step.group(1))
    return '\n'.join(line[indent:] for line in step.group(2).splitlines()) + '\n'


def test_audit_floors_job_derives_the_floors():
    """The weekly floors audit installs the exact floors pyproject.toml
    declares, so it must read them from there and run: a floor it cannot parse
    (a `~=` spec, a marker, two extras that disagree) would otherwise break the
    job on a Monday, not in the pull request that introduced it.

    cryptography>=45 sat in pyproject.toml while 45.0.0 was yanked and carried
    seven advisories, and the audit of the freshly resolved tree never saw it."""
    import subprocess
    import sys
    pytest.importorskip('tomllib')      # Python 3.11+, as on the audit runner
    audit = (REPO / '.github' / 'workflows' / 'audit.yml').read_text(encoding='utf-8')
    assert 'pip-audit (declared floors)' in audit
    literal = re.findall(r'\b[A-Za-z][\w.-]*(?:\[[^\]]*\])?==\d[^\s"\']*', audit)
    assert not literal, \
        'audit.yml pins %s literally; derive it from pyproject.toml' % literal
    run = subprocess.run([sys.executable, '-c', _audit_floors_script()],
                         cwd=REPO, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    pins = dict(line.split('==') for line in run.stdout.split())
    pyproject = (REPO / 'pyproject.toml').read_text(encoding='utf-8')
    cryptography = re.search(r'"cryptography>=(\d+(?:\.\d+)*)"', pyproject).group(1)
    assert pins['cryptography'] == cryptography
    assert set(pins) >= {'cryptography', 'pyjwt', 'pypng', 'defusedxml',
                         'pyld', 'openvc-core'}


def test_docs_pyjwt_floor_matches_pyproject():
    """README and Installation state the PyJWT[crypto] security floor exactly
    as pyproject.toml declares it: 4.6.1 raised it to 2.15.1 while both still
    said 2.13, and the cryptography check above only looks for a substring."""
    pyproject = (REPO / 'pyproject.toml').read_text(encoding='utf-8')
    match = re.search(r'"PyJWT\[crypto\]>=(\d+(?:\.\d+)*)"', pyproject)
    assert match, 'could not find the PyJWT[crypto] floor in pyproject.toml'
    floor = match.group(1)
    for path in (REPO / 'README.md', WIKI / 'Installation.md'):
        lines = [line.replace(' ', '').replace('`', '')
                 for line in path.read_text(encoding='utf-8').splitlines()
                 if 'PyJWT' in line and '>=' in line]
        assert lines, '%s does not document the PyJWT floor' % path.name
        for line in lines:
            stated = re.findall(r'>=(\d+(?:\.\d+)*)', line)
            assert stated and set(stated) == {floor}, \
                '%s states PyJWT >=%s, pyproject.toml >=%s' % (
                    path.name, ', '.join(stated), floor)


@pytest.mark.parametrize('name', CLI_TOOLS)
def test_build_parser_is_exposed(name):
    """Each CLI tool exposes build_parser() so the parser is testable/documentable."""
    import importlib
    mod = importlib.import_module(f'openbadgeslib.{name}')
    assert mod.build_parser() is not None
