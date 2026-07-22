openbadgeslib **4.0.0 is released** (2026-07-22, [on PyPI](https://pypi.org/project/openbadgeslib/4.0.0/)). It groups the breaking changes that would otherwise trickle out one major at a time, so upgrades stay rare and predictable. This page is what changed and how to move a 3.x deployment onto it.

```bash
pip install --upgrade openbadgeslib
```

## Timing

4.0.0 was originally timed to **Python 3.10's end of life (2026-10)**. It shipped early, in July, to get a set of security fixes into a release rather than leave them sitting unpublished on `master` — see the [Changelog](https://github.com/luisgf/openbadgeslib/blob/master/Changelog.txt).

One consequence matters for upgraders: **dropping Python 3.10 is deferred**, and is *not* part of this release. It will land in a later major, timed to 3.10's own EOL. See the Python support policy in [[Contributing]].

## Breaking changes

### One 0/1/2 CLI exit-code contract

Every CLI already emits this contract under `--json`; 4.0.0 makes **human mode** match it too, across `openbadges-verifier` / `-signer` / `-publish` / `-keygenerator` / `-init`:

| Code | Meaning |
|------|---------|
| `0` | success — a badge valid **and** trusted, or all work done |
| `1` | any error — bad input, I/O, an exception, an invalid badge, a bad command line |
| `2` | incomplete — a valid-but-**untrusted** verification, or a partial signer/publish batch |

Concretely, in human mode: errors that exited **255** now exit **1**; a **valid-but-untrusted** verification that exited **0** now exits **2** (it already did under `--json`); a **partial batch** that exited **1** now exits **2**; a **bad command line** now exits **1**, not argparse's **2**.

**Action:** a script that keys on the old `255`, or that read a human-mode exit `0` as "trusted", must adjust. To gate on "valid **and** trusted", require exit `0` (not merely non-error) — an untrusted signature now surfaces as `2` even without `--json`.

### The three top-level shim modules are removed

`openbadgeslib.badge`, `openbadgeslib.signer` and `openbadgeslib.verifier` no longer resolve. OpenBadges 1.0 itself stays fully supported: reach it through `openbadgeslib.ob1.*` (e.g. `from openbadgeslib.ob1 import Signer`) or the unprefixed `openbadgeslib.Signer` / `.Badge` / … re-exports, both of which still emit the steering `DeprecationWarning`.

**Action:** repoint `from openbadgeslib.badge import ...` (and `.signer` / `.verifier`) to `openbadgeslib.ob1.<module>`.

### The pycryptodome / python-ecdsa compat is removed

The 3.7 port already moved every key path onto [`cryptography`](https://cryptography.io/) and dropped both libraries as dependencies. 4.0.0 removes the last soft-import shim in `key_to_pem`, so a *live* pycryptodome/python-ecdsa key **object** is no longer accepted — pass a `cryptography` key object or PEM `bytes`/`str`. Key **files** are unaffected: they were already plain PEM and round-trip unchanged.

### Dependency floors raised

PyJWT rises to `>=2.13` and openvc-core (the `[eudi]` / `[ldp-sd]` extras) to `>=1.21`. The OB3 JWT-VC verifier decodes untrusted input with a signature-verifying `jwt.decode()`, so the PyJWT 2.12/2.13 advisory batch — RFC 7515 §4.1.11 `crit` validation (CVE-2026-32597) and the `b64=false` unencoded-payload DoS (CVE-2026-48525) — sits on a reachable path.

**Action:** only if you pinned below those floors alongside openbadgeslib.

### No `@` in a published URL

Every URL in `[issuer]` and `[badge_<name>]` is a public identifier: the tools print it, publish it inside `organization.json` / `badge.json` / `key.json`, derive the issuer's did:web from it, and embed it in signed credentials. A URL carrying `user:password@` leaked that credential into all of them, so such a config is now **rejected at load time**. The check refuses an `@` (or `%40`) *anywhere* in one of those URLs — a password containing a `/`, `?` or `#` moves the `@` out of the userinfo slot, where a parser stops calling it a credential but every consumer still publishes it.

**Action:** remove any credential from `publish_url` and friends, and protect a staging host with an IP allow-list or a token the library never sees. Note the deliberate false positive: an innocent `https://host/@name/` base is refused too. Values that are not URLs — `[issuer] email`, local paths — are unaffected, as are `[smtp] username` / `password`. See [[Configuration]].

## What is *not* changing

- **Python 3.10 is still supported.** `requires-python` stays `>=3.10`, and the CI matrix still covers it. The drop is deferred to 3.10's EOL.
- **OpenBadges 1.0 stays.** It is a supported legacy surface with no removal planned — see the "OpenBadges 1.0 lifecycle" note on [[Python API OB1]].
- **The `openbadges-<command>` scripts stay.** 4.0.0 also adds a unified `openbadges <command>` front-end, but every standalone script keeps working with the same options and output.

## Upgrade checklist

- [ ] Audit any script that inspects a CLI exit code — expect the `0/1/2` contract, and read `2` as "incomplete/untrusted", not a crash.
- [ ] Repoint imports of `openbadgeslib.badge` / `.signer` / `.verifier` to `openbadgeslib.ob1.<module>`.
- [ ] If you hand key material to the library as **objects**, use `cryptography` objects (PEM files are unaffected).
- [ ] Check your `config.ini` for an `@` in any `[issuer]` / `[badge_*]` URL — the config will not load until it is gone.
- [ ] Lift any pin below PyJWT `2.13` or openvc-core `1.21`.
