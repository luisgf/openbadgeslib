This page draws the line between the **stable public API** you can rely on across a major version and the **internals** that may change without notice. It is the "public contract" the library freezes for v4 — see [[Upgrading to 4.0]].

The rule of thumb: **if a name is in a package's `__all__`, it is public.** Everything else — any `_underscore` name, any module not listed, any attribute reached through a deep import path that `__all__` does not advertise — is internal and may change in a minor release.

## The stable surface

The top-level `openbadgeslib` package exports an explicit `__all__`. That list *is* the contract:

```python
import openbadgeslib

openbadgeslib.__all__
# __version__
# ob2, ob3, errors                      -> the subpackage entry points
# OB2Signer, OB2Verifier, OB2VerificationError
# OB3Signer, OB3Verifier, OB3VerificationError
# OpenBadgeCredential, Achievement, Issuer
# KeyFactory, KeyRSA, KeyECC, KeyEd25519
# issue_from_conf, verify_badge, IssuanceError, SignResult
```

Notes:

- **Keys.** `KeyEd25519` is a first-class export alongside `KeyRSA` / `KeyECC` — it is the recommended key type for OB 3.0 and the Data Integrity (LDP, `eddsa-rdfc-2022`) proof format.
- **Subpackages.** `openbadgeslib.ob2` and `openbadgeslib.ob3` each carry their own `__all__` (see [[Python API OB2]] / [[Python API OB3]]). `openbadgeslib.ob3.eudi` (the SD-JWT VC / EUDI track, `[eudi]` extra) is re-exported from `openbadgeslib.ob3`, so `openbadgeslib.ob3.eudi.issue_badge_sd_jwt(...)` needs no deep import. The OB 3.0 Data Integrity signer/verifier are `openbadgeslib.ob3.OB3LdpSigner` / `OB3LdpVerifier`.
- **Errors.** Every exception the library raises derives from `errors.LibOpenBadgesException`, so `except openbadgeslib.errors.LibOpenBadgesException` catches them all. See [[Keys and Errors]] for the full map.
- **Facades.** `issue_from_conf` and `verify_badge` are the programmatic "do what the CLI does, but return a result object instead of doing I/O" entry points. They are resolved lazily (a bare `import openbadgeslib` stays lightweight) but are fully part of the contract.

## What is internal

- **Underscore names.** Anything starting with `_` — `openbadgeslib.util._PinnedHTTPSConnection`, `openbadgeslib.confparser.ConfParser` internals, the `_jsonmodel` helpers, `issue._Ob3Context`, etc. These are implementation detail.
- **Modules not advertised in an `__all__`.** e.g. `openbadgeslib.signer` / `openbadgeslib.verifier` / `openbadgeslib.badge` at the top level are **legacy OpenBadges 1.0 compatibility shims**. They still work (OB 1.0 is supported, no removal planned) and emit a `DeprecationWarning` steering new work to `ob2` / `ob3`, but they are not the modern stable surface. Prefer `openbadgeslib.ob2` / `openbadgeslib.ob3`.
- **The `ob1` subpackage** is a legacy leaf; do not import from it directly.

## Versioning promise

The library follows [SemVer](https://semver.org/). Within a major version:

- names in a public `__all__` keep working (additions are allowed; removals/renames are not);
- a removal or a breaking signature change to a public name only happens on a major bump, and is called out in the [Changelog](https://github.com/luisgf/openbadgeslib/blob/master/Changelog.txt) and [[Upgrading to 4.0]].

Internals carry no such promise — pin your dependency and read the changelog if you reach past the public surface.

## The generated API reference

The canonical, always-current API reference is generated from the docstrings with [pdoc](https://pdoc.dev/) and published to GitHub Pages. Because the boundary types are declared (no bare `Any` on `SignResult.credential` / `.assertion`), the reference and your editor's autocompletion show the real types. See [[Guides]] for the link.
