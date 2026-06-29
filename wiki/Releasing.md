How to cut a new `openbadgeslib` release: bump the version in the source, update the changelog, tag, and let CI publish to PyPI. This is for maintainers; see [[Contributing]] for the day-to-day development workflow.

## Where the version lives

The version is **single-sourced** from `openbadgeslib/util.py` (`__version__`).
`pyproject.toml` reads it dynamically (`[tool.setuptools.dynamic]`) and
`docs/conf.py` parses the same file, so you only ever edit one place. The
`test_version_is_single_sourced` test fails CI if a static version is
reintroduced.

## Release steps

Replace `X.Y.Z` with the new version throughout.

1. **Bump the version** in `openbadgeslib/util.py` (`__version__`). That is the
   only place to edit.

   ```bash
   python -c "import openbadgeslib.util as u; print(u.__version__)"
   ```

2. **Add a `Changelog.txt` entry.** Entries are newest-first; follow the
   existing format (`* vX.Y.Z - YYYY-MM-DD` header, then `  - ` dash-prefixed
   bullets, with `SECURITY:` markers on security-relevant lines):

   ```text
   * vX.Y.Z - 2026-06-27

     - Short description of each change.
   ```

   `README.md` links to `Changelog.txt` rather than duplicating it, so there is
   nothing to mirror there.

3. **Run the checks locally** before tagging — CI runs the same `flake8` + `mypy` + `pytest` gate (see [[Contributing]]):

   ```bash
   pip install -e ".[dev]"
   flake8 openbadgeslib tests
   mypy
   pytest --cov=openbadgeslib --cov-report=term-missing
   ```

4. **Commit** the version bump and changelog:

   ```bash
   git add openbadgeslib/util.py Changelog.txt
   git commit -m "Release vX.Y.Z"
   git push origin master
   ```

5. **Tag the release** with an annotated tag and push it:

   ```bash
   git tag -a vX.Y.Z -m "openbadgeslib vX.Y.Z"
   git push origin vX.Y.Z
   ```

6. **Create the GitHub Release.** Draft a Release for the `vX.Y.Z` tag (Releases → Draft a new release, or `gh release create`) and **Publish** it. Publishing — not merely tagging — is what triggers the upload to PyPI.

   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" --notes-file -
   ```

## What CI does

The workflow is `.github/workflows/ci.yml`. It has two jobs:

- **test** runs on every `push` to `master` and every pull request, across the Python `3.10`, `3.11`, `3.12`, and `3.13` matrix (`fail-fast: false`). Each leg installs `".[dev]"`, runs `flake8 openbadgeslib tests`, then `mypy`, then `pytest --cov`.
- **publish** runs when a GitHub Release is *published* **or** the workflow is
  triggered manually (`workflow_dispatch`), and `needs: test`, so it runs
  **only if the whole test matrix passed**. It builds the sdist and wheel with
  `python -m build` and uploads them to PyPI via `pypa/gh-action-pypi-publish`.

```yaml
publish:
  needs: test
  if: github.event_name == 'release' || github.event_name == 'workflow_dispatch'
```

This means: tagging alone does nothing; a Release whose tests fail will **not**
publish; and you can publish the current `master` on demand from
**Actions → CI → Run workflow** (or `gh workflow run ci.yml`).

## The PyPI token

The publish job authenticates with `secrets.PYPI_API_TOKEN`:

```yaml
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    password: ${{ secrets.PYPI_API_TOKEN }}
```

This must exist as a repository (or environment) secret named `PYPI_API_TOKEN`, holding a PyPI API token scoped to the `openbadgeslib` project. If it is missing or expired the upload step fails even when every test passes. Rotate it in PyPI and update the GitHub secret when needed — the token never lives in the repo.

## Post-release checklist

- Confirm the **publish** job is green in the Actions tab.
- Confirm the new version appears on PyPI and installs cleanly: `pip install openbadgeslib==X.Y.Z`.
- Confirm `python -c "import openbadgeslib.util as u; print(u.__version__)"` reports `X.Y.Z` from the published wheel.
