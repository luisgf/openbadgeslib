# Governance

How **openbadgeslib** is maintained, released, and kept available. It is a small
project with a clear, lightweight process — written down here because third
parties already depend on it to *verify* credentials, so continuity matters.

## Maintainership

openbadgeslib is actively maintained by **Luis González Fernández**
(`luisgf@luisgf.es`), the single active maintainer, who decides on scope,
roadmap, and releases. The project has a historical co-author, Jesús Cea Avión,
credited in the copyright headers and
[Authors, License and FAQ](https://github.com/luisgf/openbadgeslib/wiki/Authors-License-and-FAQ);
active maintenance today is solo.

Decision-making is lightweight: the roadmap is tracked as GitHub issues (label
`roadmap`, tracking issue
[#175](https://github.com/luisgf/openbadgeslib/issues/175)), and several items
are built on demand — a [capability request](CONTRIBUTING.md) with a concrete
use case is how they get prioritised.

## Releasing and publishing

Releases are **CI-driven and credential-less to publish**:

- The version is single-sourced in `openbadgeslib/util.py`; a pushed `vX.Y.Z`
  tag triggers the CI workflow, which runs the full test matrix (Python
  3.10–3.14) and then publishes to
  [PyPI](https://pypi.org/project/openbadgeslib/).
- Publishing uses **PyPI Trusted Publishing (OIDC)** — there is **no long-lived
  PyPI API token** stored anywhere. The publish job authenticates to PyPI from
  GitHub Actions via a short-lived OIDC token, so there is no release secret to
  leak, rotate, or lose.
- Each release is announced as a **GitHub Release** with curated notes drawn
  from `Changelog.txt`; the Release is the canonical announcement channel.
- The **human fallback** (a maintainer cutting a release by hand) is fully
  documented in the wiki
  [Releasing](https://github.com/luisgf/openbadgeslib/wiki/Releasing) runbook —
  it needs only repository write access plus the CI pipeline, no personal
  credentials.

## Bus factor and continuity

A single active maintainer is a real risk for a library others verify with. The
mitigations are deliberate:

1. **No secret is a single point of failure.** Trusted Publishing means losing
   access to a token cannot happen — there isn't one. Publishing is bound to the
   GitHub repository's identity, not a person's stored key.
2. **The whole release process is documented and automated** (the wiki Releasing
   runbook and the `release` skill), so anyone with repository access can ship a
   fix without tribal knowledge.
3. **Handover requirements are explicit.** Taking over maintenance needs two
   grants: **GitHub** repository admin, and **PyPI** owner/maintainer on the
   [`openbadgeslib` project](https://pypi.org/project/openbadgeslib/) plus the
   configured Trusted Publisher. A new maintainer with both can release
   immediately.

**Recommended hardening (maintainer action):** add a second **PyPI project
owner** and a backup **GitHub admin** so a bus event does not strand the
project. Until then, note that everything published stays available on PyPI
indefinitely, and the LGPLv3 permits anyone to fork and continue the work.

If the project were to become unmaintained, the last release remains installable
from PyPI, and this document plus the wiki are enough for a fork to pick it up.

## Reporting and contact

- Bugs and capability requests: GitHub issues (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- Security vulnerabilities: **privately**, per [SECURITY.md](SECURITY.md) — never
  a public issue.
- General contact: `luisgf@luisgf.es`.
