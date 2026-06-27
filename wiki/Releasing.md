How to cut a new `openbadgeslib` release: bump the version in the source, update the changelog, tag, and let CI publish to PyPI. This is for maintainers; see [[Contributing]] for the day-to-day development workflow.

## Where the version lives

The version is declared in **three** places that must stay in sync. Bump all of them for every release:

- `pyproject.toml` — the `[project]` `version` field (currently `version = "1.1.1"`).
- `openbadgeslib/util.py` — the `__version__` string (currently `__version__ = '1.1.1'`).
- `docs/conf.py` — the Sphinx docs version.

There is no single source of truth, so a release where these disagree will ship a wheel whose metadata and `__version__` differ. Double-check all three.

## Release steps

Replace `X.Y.Z` with the new version throughout.

1. **Bump the version** in the three files above.

   ```bash
   # edit each, then sanity-check they all match
   grep -n 'version' pyproject.toml | head
   python -c "import openbadgeslib.util as u; print(u.__version__)"
   ```

2. **Add a `Changelog.txt` entry.** Entries are newest-first; follow the existing format (`* vX.Y.Z - YYYYMMDD` header, then dash-prefixed bullets, with `SECURITY:` markers on security-relevant lines):

   ```text
   * vX.Y.Z - 20260627

     - Short description of each change.
   ```

   Mirror the user-facing highlights in `README.txt` and `docs/intro.rst` so the landing page and the changelog don't drift.

3. **Run the checks locally** before tagging — CI runs the same `flake8` + `pytest` gate (see [[Contributing]]):

   ```bash
   pip install -e ".[dev]"
   flake8 openbadgeslib tests
   pytest --cov=openbadgeslib --cov-report=term-missing
   ```

4. **Commit** the version bump and changelog:

   ```bash
   git add pyproject.toml openbadgeslib/util.py docs/conf.py Changelog.txt README.txt docs/intro.rst
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

- **test** runs on every `push` to `master` and every pull request, across the Python `3.10`, `3.11`, `3.12`, and `3.13` matrix (`fail-fast: false`). Each leg installs `".[dev]"`, runs `flake8 openbadgeslib tests`, then `pytest --cov`.
- **publish** runs **only** when a GitHub Release is *published* (`if: github.event_name == 'release'`) and `needs: test`, so it runs **only if the whole test matrix passed**. It builds the sdist and wheel with `python -m build` and uploads them to PyPI via `pypa/gh-action-pypi-publish`.

```yaml
publish:
  needs: test
  if: github.event_name == 'release'
```

This means: tagging alone does nothing; pushing a tag without a published Release does nothing; and a Release whose tests fail will **not** publish.

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
