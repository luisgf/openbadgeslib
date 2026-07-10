openbadgeslib **4.0.0** is the next major release. It groups the breaking changes that would otherwise trickle out one major at a time, so upgrades stay rare and predictable. This page is the advance notice: nothing here has shipped in a 3.x release yet — it is what to expect and how to prepare.

## Timing

4.0.0 is timed to **Python 3.10's end of life (2026-10)**. Until then the 3.x line stays fully supported and keeps receiving fixes. Watch the [Changelog](https://github.com/luisgf/openbadgeslib/blob/master/Changelog.txt) for the cutover.

## Breaking changes

### Python 3.10 is dropped

`requires-python` rises to `>=3.11`; the classifiers and the CI matrix drop 3.10. Move to **Python 3.11+** before upgrading. See the Python support policy in [[Contributing]].

### One 0/1/2 CLI exit-code contract

Every CLI already emits this contract under `--json`; 4.0.0 makes **human mode** match it too, across `openbadges-verifier` / `-signer` / `-publish` / `-keygenerator` / `-init`:

| Code | Meaning |
|------|---------|
| `0` | success — a badge valid **and** trusted, or all work done |
| `1` | any error — bad input, I/O, an exception, an invalid badge, a bad command line |
| `2` | incomplete — a valid-but-**untrusted** verification, or a partial signer/publish batch |

Concretely, in human mode: errors that exited **255** now exit **1**; a **valid-but-untrusted** verification that exited **0** now exits **2** (it already did under `--json`); a **partial batch** that exited **1** now exits **2**; a **bad command line** now exits **1**, not argparse's **2**.

**Action:** a script that keys on the old `255`, or that read a human-mode exit `0` as "trusted", must adjust. To gate on "valid **and** trusted", require exit `0` (not merely non-error) — an untrusted signature now surfaces as `2` even without `--json`.

### The pycryptodome / python-ecdsa compat is removed

The 3.7 port already moved every key path onto [`cryptography`](https://cryptography.io/) and dropped both libraries as dependencies. 4.0.0 removes the last soft-import shim in `key_to_pem`, so a *live* pycryptodome/python-ecdsa key **object** is no longer accepted — pass a `cryptography` key object or PEM `bytes`/`str`. Key **files** are unaffected: they were already plain PEM and round-trip unchanged.

## What is *not* changing

- **OpenBadges 1.0 stays.** It is a supported legacy surface with no removal planned — see the "OpenBadges 1.0 lifecycle" note on [[Python API OB1]].
- **The `openbadges-<command>` scripts stay.** 4.0.0 also adds a unified `openbadges <command>` front-end, but every standalone script keeps working with the same options and output.

## Upgrade checklist

- [ ] Run on **Python 3.11+** (3.10 is dropped).
- [ ] Audit any script that inspects a CLI exit code — expect the `0/1/2` contract, and read `2` as "incomplete/untrusted", not a crash.
- [ ] If you hand key material to the library as **objects**, use `cryptography` objects (PEM files are unaffected).
