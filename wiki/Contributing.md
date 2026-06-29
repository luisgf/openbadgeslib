Developer guide for hacking on **openbadgeslib**. It covers setting up an editable dev environment, running the tests and linter, the repository layout, and how continuous integration validates every push and pull request. When you are ready to ship a new version, see [[Releasing]].

## Getting started

Clone the repository, create a virtual environment, and install the package in editable mode together with the dev extras (`pytest`, `pytest-cov`, `flake8`, `mypy`, `pdoc`):

```sh
git clone https://github.com/luisgf/openbadgeslib
cd openbadgeslib

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -e ".[dev]"
```

This installs the runtime dependencies (`pycryptodome`, `ecdsa`, `pypng`, `PyJWT[crypto]`, `defusedxml`) plus the dev tooling. The five console scripts (`openbadges-init`, `openbadges-keygenerator`, `openbadges-signer`, `openbadges-verifier`, `openbadges-publish`) are placed on your `PATH` and point at your working tree, so edits take effect immediately. See [[CLI Reference]] for how to use them.

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

There is also a thin wrapper script that simply forwards its arguments to `pytest`:

```sh
sh tests/runtests.sh
sh tests/runtests.sh -x        # arguments are passed through
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

## Repository layout

```
openbadgeslib/
    __init__.py          unified public API (OB2 + OB3 + shared keys/util)
    badge.py             backward-compat shim -> ob2.badge
    signer.py            backward-compat shim -> ob2.signer
    verifier.py          backward-compat shim -> ob2.verifier
    baking.py            shared SVG/PNG token baking + extraction (OB2 + OB3)
    confparser.py        INI config file reader
    errors.py            custom exception hierarchy
    keys.py              KeyRSA, KeyECC, KeyFactory, detect_key_type
    logs.py              logging setup (file + console, debug toggle)
    mail.py              BadgeMail: email a signed badge over SMTP
    util.py              hash helpers, download_file, __version__
    py.typed             PEP 561 marker (the package is typed)
    _jws/                JWS engine (sign / verify_block) backed by PyJWT
    ob2/                 OB 2.0: Badge, BadgeSigned, Assertion, Signer, Verifier
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
    runtests.sh          wrapper that runs python3 -m pytest
```

Note: `baking.py` is a single shared top-level module (`openbadgeslib.baking`) that embeds/extracts the token in the SVG/PNG carrier; both the OB2 and OB3 signers/verifiers call it. The OB2 implementation lives in `ob2/`; the top-level `badge.py`, `signer.py`, and `verifier.py` are one-line re-export shims that keep imports like `from openbadgeslib.badge import Badge` working. New code should prefer `from openbadgeslib.ob2 import ...`. For the difference between the two formats see [[OB2 vs OB3]], and for the public interfaces see [[Python API OB2]] and [[Python API OB3]].

## Continuous integration

The workflow at `.github/workflows/ci.yml` runs on every **push to `master`**, every **pull request**, and when a **release is published**. The `test` job uses a matrix across Python **3.10, 3.11, 3.12, and 3.13** (`fail-fast: false`, so all versions run even if one fails). For each version it:

1. Installs the package with `pip install -e ".[dev]"`.
2. Lints with `flake8 openbadgeslib tests`.
3. Type-checks with `mypy`.
4. Tests with `pytest --cov=openbadgeslib --cov-report=term-missing`.

A separate `publish` job builds the sdist and wheel and uploads to PyPI, but only when a GitHub Release is published and only after the full test matrix passes. That publish flow is documented in [[Releasing]].

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
5. Open a pull request against `master`.
