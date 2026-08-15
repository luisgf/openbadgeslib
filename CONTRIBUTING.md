# Contributing to openbadgeslib

Thanks for your interest in improving **openbadgeslib** — a library and CLI for
issuing and verifying OpenBadges 2.0 and 3.0 credentials. This page is the quick
entry point; the full developer guide lives in the wiki
([Contributing](https://github.com/luisgf/openbadgeslib/wiki/Contributing),
[Releasing](https://github.com/luisgf/openbadgeslib/wiki/Releasing)).

## Reporting bugs and requesting capabilities

- **Bugs:** open a [Bug report](https://github.com/luisgf/openbadgeslib/issues/new/choose).
  Include the openbadgeslib version, your Python version, and a minimal
  reproduction.
- **Capabilities / features:** open a
  [Capability request](https://github.com/luisgf/openbadgeslib/issues/new/choose).
  This is also the **demand signal** the roadmap runs on — several planned items
  are deliberately *built when someone asks for them with a concrete use case*,
  so a well-described request genuinely moves them forward.
- **Security vulnerabilities:** do **not** open a public issue. Follow
  [SECURITY.md](SECURITY.md) (private GitHub advisory or email).

## Development setup

Requires a supported Python (see below). Everything runs from an editable
virtual environment:

```sh
git clone https://github.com/luisgf/openbadgeslib
cd openbadgeslib
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"          # add ,ldp and ,eudi to exercise those tracks
```

## The checks a pull request must pass

CI runs these on Python 3.10–3.14; run them locally before opening a PR (via
your `.venv`):

```sh
flake8 openbadgeslib tests       # style (max-line-length = 120, see setup.cfg)
mypy                             # types (config in pyproject.toml)
pytest                           # the suite; install [ldp]/[eudi] so their
                                 # tests actually run instead of skipping
```

The Data Integrity (LDP) tests need the `[ldp]` extra (pyld) and the EUDI
SD-JWT / X.509 tests need `[eudi]` — without them those tests silently
`importorskip`, so install the extras when touching those areas. Coverage is
enforced at a floor (currently 93%).

## Commit messages

Commits follow a [Conventional Commits](https://www.conventionalcommits.org/)
style so the history is machine-readable and the changelog can be drafted from
it — CI's `gitlint` check enforces the title format. The shape is
`type(optional-scope)!: imperative summary` (≤ 80 chars), with the vocabulary:

| Type | For | Changelog |
| --- | --- | --- |
| `feat` / `fix` / `security` / `perf` | user-facing change | **yes** |
| `docs` / `test` / `refactor` / `chore` / `ci` / `build` / `style` | internal, no user-visible effect | no |
| `release` | the version-bump/changelog commit | no |

A `!` (or a `BREAKING CHANGE:` body trailer) marks a breaking change. A
user-facing `feat`/`fix`/`security`/`perf` should add its `Changelog.txt` entry
in the same commit (newest-first, under a `* vX.Y.Z - unreleased` header). See
the wiki [Contributing](https://github.com/luisgf/openbadgeslib/wiki/Contributing)
page for the full convention.

## Supported Python versions

openbadgeslib supports **every CPython release that is not end-of-life**. The
policy is deliberately simple and predictable:

- A version is **dropped** — from `requires-python`, the classifiers, and the CI
  matrix — at the next **major** release after it reaches end-of-life. For
  example, Python **3.10 (EOL 2026-10)** stays supported through 4.x and is
  dropped at the next major after that EOL (5.0). Grouping drops into majors
  keeps breaking changes rare.
- A new CPython minor is **added** to the CI matrix once it has a stable
  (non-pre) release, so downstreams can adopt it early.
- The current matrix is **3.10–3.14**, and `requires-python = ">=3.10"`.

Security fixes always target the latest release only (see
[SECURITY.md](SECURITY.md)).

## Governance and licensing

Project governance, the release process, and the maintenance/continuity plan are
in [GOVERNANCE.md](GOVERNANCE.md). The library is licensed under the LGPLv3 and
the CLI entry points under BSD-2-Clause (see
[LICENSE.txt](LICENSE.txt)); by contributing you agree your contribution is
provided under those same terms.
