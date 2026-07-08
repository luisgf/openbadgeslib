Developer guide for hacking on **openbadgeslib**. It covers setting up an editable dev environment, running the tests and linter, the repository layout, and how continuous integration validates every push and pull request. When you are ready to ship a new version, see [[Releasing]].

## Getting started

Clone the repository, create a virtual environment, and install the package in editable mode together with the dev extras (`pytest`, `pytest-cov`, `flake8`, `mypy`, `pdoc`, `gitlint`):

```sh
git clone https://github.com/luisgf/openbadgeslib
cd openbadgeslib

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -e ".[dev]"
```

This installs the runtime dependencies (`pypng`, `PyJWT[crypto]`, `cryptography`, `defusedxml`) plus the dev tooling. The five console scripts (`openbadges-init`, `openbadges-keygenerator`, `openbadges-signer`, `openbadges-verifier`, `openbadges-publish`) are placed on your `PATH` and point at your working tree, so edits take effect immediately. See [[CLI Reference]] for how to use them.

The minimum supported Python version is **3.10**.

## Running the tests

Tests use `pytest` and live in `tests/`. From the project root:

```sh
# Run all tests
pytest

# With coverage report
pytest --cov=openbadgeslib --cov-report=term-missing

# Stop at first failure
pytest -x
```

Shared fixtures (key material, badge objects, signed badges) live in `tests/conftest.py`. Session-scoped fixtures are used for performance; fixtures consumed by tests that mutate badge state are function-scoped to avoid cross-test contamination.

## Linting and type checking

Style follows PEP 8 and is enforced with `flake8`, which reads its configuration (including `max-line-length = 120`) from `setup.cfg`. CI lints both the package and the tests:

```sh
flake8 openbadgeslib tests
```

The package is type-annotated and ships a `py.typed` marker (PEP 561), so downstream type checkers pick up its types. Types are checked with `mypy` (config in `pyproject.toml`, `disallow_untyped_defs`), enforced in CI:

```sh
mypy
```

Make sure both `pytest` and `flake8` pass before opening a pull request.

## Commit messages

Commits follow a [Conventional Commits](https://www.conventionalcommits.org/)-style convention so the history is machine-readable and a changelog can be drafted from it. The format is:

```
type(optional-scope)!: short summary in the imperative mood
```

Use a scope like `ob2`/`ob3` when it helps (e.g. `fix(ob3): …`). The vocabulary is fixed:

| Type | Use for | In the changelog? |
| --- | --- | --- |
| `feat` | a user-facing feature or capability | **yes** → Added |
| `fix` | a user-facing bug fix | **yes** → Fixed |
| `security` | a security-relevant change | **yes** → Security |
| `perf` | a user-facing performance change | **yes** → Performance |
| `docs`, `test`, `refactor`, `chore`, `ci`, `build`, `style` | internal changes with no user-visible effect | no (dropped) |
| `release` | the version-bump/changelog commit | no |

A breaking change is marked with `!` after the type/scope (`feat!:`) or a `BREAKING CHANGE:` trailer in the body.

**Curated changelog line (optional but encouraged).** Changelog entries are still written by hand, but you can capture the polished wording *at commit time* with a `Changelog:` trailer in the body. A future generator (and the maintainer) prefer it over the terse subject:

```
fix: make -d/--debug actually enable debug logging

Changelog: The -d/--debug flag now enables DEBUG-level console logging
across all CLI tools (it was parsed but previously ignored).
```

This convention is enforced in CI by **gitlint** (config in `.gitlint`), which lints the commit messages of every push and pull request. Run it locally before pushing:

```sh
gitlint                       # lint the latest commit
gitlint --commits origin/master..HEAD   # lint a branch
```

You can wire it as a local `commit-msg` hook so it runs automatically:

```sh
gitlint install-hook
```

## Repository layout

```
openbadgeslib/
    __init__.py          unified public API (OB1 + OB2 + OB3 + shared keys/util)
    badge.py             backward-compat shim -> ob1.badge
    signer.py            backward-compat shim -> ob1.signer
    verifier.py          backward-compat shim -> ob1.verifier
    baking.py            shared SVG/PNG token baking + extraction (OB1/OB2/OB3)
    confparser.py        INI config file reader
    errors.py            custom exception hierarchy
    keys.py              KeyRSA, KeyECC, KeyFactory, detect_key_type
    logs.py              logging setup (file + console, debug toggle)
    mail.py              BadgeMail: email a signed badge over SMTP
    util.py              hash helpers, download_file, __version__
    py.typed             PEP 561 marker (the package is typed)
    _jws/                JWS engine (sign / verify_block) backed by PyJWT
    ob1/                 OB 1.0 (legacy): Badge, BadgeSigned, Assertion, Signer, Verifier
    ob2/                 OB 2.0 (strict): OB2Signer, OB2Verifier, Assertion, and the
                         model dataclasses (BadgeClass, Profile, CryptographicKey,
                         RevocationList)
    ob3/                 OB 3.0: Issuer, Achievement, OpenBadgeCredential,
                         OB3Signer, OB3Verifier (W3C VC / JWT-VC)
    openbadges_init.py          CLI: openbadges-init
    openbadges_keygenerator.py  CLI: openbadges-keygenerator
    openbadges_signer.py        CLI: openbadges-signer
    openbadges_verifier.py      CLI: openbadges-verifier
    openbadges_publish.py       CLI: openbadges-publish

tests/
    conftest.py          shared pytest fixtures (OB 2.0 + OB 3.0)
    test_*.py            unit + end-to-end tests
    fixtures/            schema + test-vector data files
```

Note: `baking.py` is a single shared top-level module (`openbadgeslib.baking`) that embeds/extracts the token in the SVG/PNG carrier; the OB1, OB2 and OB3 signers/verifiers all call it. The legacy OB 1.0 implementation lives in `ob1/` (the top-level `badge.py`, `signer.py`, and `verifier.py` are **deprecated** compatibility shims that re-export it so imports like `from openbadgeslib.badge import Badge` keep working, now with a `DeprecationWarning` — see [[Python API OB1]]); the strict OB 2.0 implementation lives in `ob2/` (`from openbadgeslib.ob2 import OB2Signer, OB2Verifier`). For how the generations differ see [[OB2 vs OB3]], and for the public interfaces see [[Python API OB1]], [[Python API OB2]] and [[Python API OB3]].

## Continuous integration

The workflow at `.github/workflows/ci.yml` runs on every **push to `master`**, every **pull request**, every **`vX.Y.Z` tag push**, and when a **release is published**. The `test` job uses a matrix across Python **3.10, 3.11, 3.12, and 3.13** (`fail-fast: false`, so all versions run even if one fails). For each version it:

1. Installs the package with `pip install -e ".[dev]"`.
2. Lints with `flake8 openbadgeslib tests`.
3. Type-checks with `mypy`.
4. Tests with `pytest --cov=openbadgeslib --cov-report=term-missing`.

A separate `publish` job builds the sdist and wheel and uploads to PyPI when a `vX.Y.Z` tag is pushed (or a GitHub Release is published, or via `workflow_dispatch`), and only after the full test matrix passes. That publish flow is documented in [[Releasing]].

A second workflow, `.github/workflows/commit-lint.yml`, runs **gitlint** on the new commits of every push and pull request to enforce the [commit-message convention](#commit-messages).

## Documentation

Documentation has three sources, all of which stay in sync with the code automatically:

- **Wiki** (this site) — narrative guides and references, edited in the `wiki/` folder of the repo and mirrored to the GitHub Wiki by `.github/workflows/wiki-sync.yml`.
- **API reference** — generated from the docstrings with [pdoc](https://pdoc.dev) and deployed to GitHub Pages by `.github/workflows/docs.yml`. Build it locally with:

  ```sh
  pdoc openbadgeslib -o site -d google
  ```

- **Drift gates** — `tests/test_docs.py` fails CI if a CLI flag is undocumented, a wiki link is broken, or the version is hardcoded, so docs can't silently fall behind the code.

## Issues and roadmap

Bug reports and planned work are tracked in
[GitHub Issues](https://github.com/luisgf/openbadgeslib/issues). There is no
in-repo TODO file; open an issue to propose or pick up work.

## Submitting changes

1. Fork the repository on GitHub.
2. Create a feature branch: `git checkout -b feature/my-change`
3. Write tests for your change.
4. Ensure `pytest` and `flake8` both pass with no regressions.
5. Write commit messages that follow the [convention above](#commit-messages) (`gitlint` will check them).
6. Open a pull request against `master`.
