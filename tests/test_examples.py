"""#168 — the committed examples/ scripts must run end to end.

Anti-drift guarantee, same philosophy as test_docs.py: if the public library
API changes shape, the narrative examples an adopter copies from break *here*,
in CI, instead of silently rotting in the docs. Each script is self-contained
(generates its own key, writes to a temp dir) and prints a result.
"""
import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).parent.parent / 'examples'
EXAMPLES = sorted(EXAMPLES_DIR.glob('*.py'))


def test_examples_dir_is_not_empty():
    assert EXAMPLES, 'no example scripts found under examples/'


@pytest.mark.parametrize('script', EXAMPLES, ids=lambda p: p.name)
def test_example_runs(script):
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, (
        'example %s exited %d:\n%s'
        % (script.name, result.returncode, result.stderr))
    assert result.stdout.strip(), (
        'example %s printed nothing — it should show its result' % script.name)
