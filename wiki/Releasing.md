How to cut a new `openbadgeslib` release: bump the version in the source, update the changelog, tag, and let CI publish to PyPI. This is for maintainers; see [[Contributing]] for the day-to-day development workflow.

## Where the version lives

The version is **single-sourced** from `openbadgeslib/util.py` (`__version__`).
`pyproject.toml` reads it dynamically (`[tool.setuptools.dynamic]`), so you only
ever edit one place. The `test_version_is_single_sourced` test fails CI if a
static version is reintroduced.

## Release steps

Replace `X.Y.Z` with the new version throughout.

1. **Bump the version** in `openbadgeslib/util.py` (`__version__`). That is the
   only place to edit.

   ```bash
   python -c "import openbadgeslib.util as u; print(u.__version__)"
   ```

2. **Date the `Changelog.txt` entry.** Entries are written as changes land,
   newest-first, under a `* vX.Y.Z - unreleased` heading (`  - ` bullets, each
   prefixed with its commit type and optional scope —
   `feat`/`fix`/`security`/`perf`, e.g. `security(jws):` — see Commit messages
   in [[Contributing]]).
   Releasing means **dating** that heading — replace `unreleased` with today's
   date — not authoring it:

   ```text
   * vX.Y.Z - 2026-06-27

     - Short description of each change.
   ```

   `README.md` links to `Changelog.txt` rather than duplicating it, so there is
   nothing to mirror there.

   Before dating it, check that nothing is missing:
   `git log --pretty='%s%n%b' vPREV..HEAD` (`vPREV` = the previous release
   tag) lists the changelog-worthy commits (`feat`/`fix`/`security`/`perf`),
   and a `Changelog:` trailer on a commit carries wording to reuse. Then
   `python scripts/check_changelog_claims.py --strict` compares the budgets,
   caps and floors the entry quotes with the constants in the code and checks
   that the files, constants and classes it names exist.

3. **Run the checks locally** before tagging — CI runs the same `flake8` + `mypy` + `pytest` gate (see [[Contributing]]):

   ```bash
   pip install -e ".[dev,ldp,eudi,ldp-sd,oid4vci]"
   flake8 openbadgeslib tests
   mypy
   OPENBADGES_REQUIRE_LDP_SD=1 OPENBADGES_REQUIRE_OID4VCI=1 \
       pytest --cov=openbadgeslib --cov-report=term-missing
   ```

4. **Commit** the version bump and changelog:

   ```bash
   git add openbadgeslib/util.py Changelog.txt
   git commit -m "release: vX.Y.Z"
   git push origin master
   ```

5. **Tag the release** with an annotated tag and push it. **Pushing a `vX.Y.Z` tag is what triggers the build, test and PyPI upload** — no further step is required:

   ```bash
   git tag -a vX.Y.Z -m "openbadgeslib vX.Y.Z"
   git push origin vX.Y.Z
   ```

6. **Create the GitHub Release.** It is not needed to publish (the tag push in step 5 already does), but it is the release's announcement channel ([GOVERNANCE.md](https://github.com/luisgf/openbadgeslib/blob/master/GOVERNANCE.md)). Publishing it re-runs the workflow; `skip-existing` makes the duplicate upload a harmless no-op.

   ```bash
   gh release create vX.Y.Z --verify-tag --title "vX.Y.Z" --notes-file -
   ```

## What CI does

The workflow is `.github/workflows/ci.yml`. Two of its jobs decide a release:

- **test** runs on every trigger of the workflow (pushes to `master`, pull requests, `vX.Y.Z` tag pushes, published Releases and manual runs), across the Python `3.10`, `3.11`, `3.12`, `3.13`, `3.14` and `3.15` matrix (`fail-fast: false`). Each leg installs `".[dev,ldp,eudi,ldp-sd,oid4vci]"` (every optional extra, so no feature suite can pass by skipping itself), runs `flake8 openbadgeslib tests`, then `mypy`, then `pytest --cov=openbadgeslib --cov-report=term-missing` with `OPENBADGES_REQUIRE_LDP_SD=1` and `OPENBADGES_REQUIRE_OID4VCI=1`, so the ecdsa-sd-2023 and OID4VCI credential-endpoint suites fail rather than skip. The coverage floor (`fail_under` in `pyproject.toml`) applies to every leg.
- **publish** runs when a **`vX.Y.Z` tag is pushed**, when a GitHub Release is
  *published*, **or** the workflow is triggered manually (`workflow_dispatch`),
  and `needs: test`, so it runs **only if the whole test matrix passed**. It
  builds the sdist and wheel with `python -m build` and uploads them to PyPI via
  `pypa/gh-action-pypi-publish` (with `skip-existing: true`, so re-running or a
  tag+Release double trigger never fails).

```yaml
on:
  push:
    tags: ['v*']
publish:
  needs: test
  if: >-
    github.event_name == 'release'
    || github.event_name == 'workflow_dispatch'
    || startsWith(github.ref, 'refs/tags/v')
```

This means: **pushing the tag publishes** (the test matrix still gates it, so a
tag whose tests fail will **not** publish); a GitHub Release is not needed to
publish (it is the announcement, step 6); and you
can still publish the current `master` on demand from **Actions → CI → Run
workflow** (or `gh workflow run ci.yml`).

The workflow's other jobs — `windows` (the core extras on Python 3.12) and
`eudi` (the `[eudi]` extra in isolation, against the pinned openvc-core floor
and its latest release) — sit outside the publish gate: `publish` does not wait
for them.

## PyPI authentication (Trusted Publishing)

The publish job authenticates with **PyPI Trusted Publishing (OIDC)** (see
[GOVERNANCE.md](https://github.com/luisgf/openbadgeslib/blob/master/GOVERNANCE.md)).
The job is granted `id-token: write`, and the SHA-pinned publish action
exchanges GitHub's short-lived OIDC token for a PyPI upload credential:

```yaml
publish:
  permissions:
    contents: read
    id-token: write      # OIDC Trusted Publishing — no long-lived token
  steps:
    - name: Publish to PyPI
      uses: pypa/gh-action-pypi-publish@<commit-sha>  # SHA-pinned; Dependabot bumps it
      with:
        skip-existing: true   # no password: the id-token permission authenticates
```

This requires a **Trusted Publisher** configured on the `openbadgeslib` PyPI
project (GitHub Actions, repository `luisgf/openbadgeslib`, workflow `ci.yml`);
without it the upload step fails even when every test passes
([#149](https://github.com/luisgf/openbadgeslib/issues/149)). There is
nothing to rotate: no credential lives in the repo or in the GitHub secrets.

## Post-release checklist

- Confirm the **publish** job is green in the Actions tab.
- Confirm the new version appears on PyPI and installs cleanly: `pip install openbadgeslib==X.Y.Z`.
- Confirm `python -c "import openbadgeslib.util as u; print(u.__version__)"` reports `X.Y.Z` from the published wheel.
