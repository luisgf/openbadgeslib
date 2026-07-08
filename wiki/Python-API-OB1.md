Programmatic guide to the **OpenBadges 1.0 (legacy)** API exposed by `openbadgeslib.ob1`. This is the frozen pre-2.0 wire format (a `uid`, a `verify: {type, url}` object, `hashed: "true"` as a string, and Unix-timestamp dates, with no `@context`/`type`). It is kept only for backward compatibility with badges already issued in this format — for new work use strict Open Badges 2.0 ([[Python API OB2]]) or 3.0 ([[Python API OB3]]). For how the generations differ see [[OB2 vs OB3]].

## Lifecycle policy

**OpenBadges 1.0 is a supported legacy surface — there is no removal planned.** It is a dead format in the wider ecosystem (the Mozilla Backpack that anchored it shut down in 2019) and is de-facto frozen here, but it stays **fully functional and supported**: existing OB 1.0 badges keep working and the code is maintained. It is simply *superseded* — for new work use strict Open Badges 2.0 ([[Python API OB2]]) or 3.0 ([[Python API OB3]]).

What "legacy" means in practice:

- **Library.** Reaching the OB1 API through its public surface emits a `DeprecationWarning` steering new work to OB2/OB3: the `openbadgeslib.ob1` package (e.g. `from openbadgeslib.ob1 import Signer`), the top-level `openbadgeslib.badge` / `openbadgeslib.signer` / `openbadgeslib.verifier` compatibility shims, and the unprefixed `openbadgeslib.Signer` / `openbadgeslib.Verifier` / `openbadgeslib.Badge` / … re-exports. It is a nudge, not a removal notice — `DeprecationWarning` is silent by default (`-W default::DeprecationWarning` to see it). A bare `import openbadgeslib`, the OB2/OB3 APIs, and the internal leaf import `openbadgeslib.ob1.badge` (the shared badge model) all stay silent.
- **CLI.** `openbadges-signer`, `openbadges-verifier` and `openbadges-publish` print a `[!] OpenBadges 1.0 (-V 1) is a legacy version, still supported …` notice on the `-V 1` paths. The verifier suppresses it under `--json` so machine output stays clean.

**OpenBadges 2.0 is _not_ legacy** and is unaffected: it is strict, recent and ecosystem-mainstream, fully supported. Only the pre-2.0 OB1 format carries the legacy label.

### Migrating off OB1 (when you choose to)

- Issue strict OB 2.0 (`-V 2`, [[Python API OB2]]) or OB 3.0 (`-V 3`, [[Python API OB3]]) instead of `-V 1` for new badges.
- Replace `openbadgeslib.signer.Signer` / `openbadgeslib.verifier.Verifier` with `openbadgeslib.ob2.OB2Signer`/`OB2Verifier` or `openbadgeslib.ob3.OB3Signer`/`OB3Verifier`.
- Existing OB1 badges stay verifiable with `-V 1` — there is no deadline.

### How OB1 is packaged (evaluated options)

- **Keep OB1 in-package as a supported legacy surface** — the current policy. It carries no unique dependencies (the `keys.py` port to `cryptography` in #167 dropped `pycryptodome`/`python-ecdsa`), so it adds no install weight; removing a working, dependency-free legacy surface was judged excessive. New work is *steered* to OB2/OB3 by the warnings, not forced.
- **A `[ob1]` / `[legacy]` install extra** (`pip install openbadgeslib[ob1]`): rejected. A Python extra gates *dependencies*, not code, and OB1 has none to gate — the extra would install exactly the same bytes, an empty container with install-time friction.
- **A separate PyPI package** for OB1: rejected as a large (L) effort — split packaging, CI, versioning and cross-package compatibility — whose only payoff, removing a few KB of dependency-free code from the default install, does not justify it.

> The full, always-up-to-date class/function reference is generated from the docstrings: **[API Reference](https://luisgf.github.io/openbadgeslib/)**.

The legacy names are re-exported both from `openbadgeslib.ob1` and, for backward compatibility, from the top-level `openbadgeslib.badge` / `openbadgeslib.signer` / `openbadgeslib.verifier` shims:

```python
from openbadgeslib.ob1 import (
    BadgeStatus, BadgeImgType, BadgeType,
    Assertion, Badge, BadgeSigned,
    extract_svg_assertion, extract_png_assertion,
    Signer, Verifier, VerifyInfo,
)
```

## Public classes and enums

### Enums

- `BadgeImgType` — image container of a badge: `SVG` or `PNG`.
- `BadgeType` — assertion verification model: `SIGNED` (JWS, default) or `HOSTED`.
- `BadgeStatus` — result of a verification: `VALID`, `SIGNATURE_ERROR`, `EXPIRED`, `REVOKED`, `IDENTITY_ERROR`, and `NONE` (an unset sentinel used as the `VerifyInfo` default; never returned by a real check).

### `Badge`

The unsigned source badge: its metadata, the raw image bytes, the issuer URLs and the key material. Constructed directly or via `Badge.create_from_conf(conf, badge_name)` which reads a section from a parsed `config.ini` (see [[Configuration]]).

Key constructor arguments: `ini_name`, `name`, `description`, `image_type` (a `BadgeImgType`), `image` (raw bytes of the image file), `image_url`, `criteria_url`, `json_url`, `verify_key_url`, `key_type` (a `KeyType` from `openbadgeslib.keys`), `privkey_pem` and `pubkey_pem` (PEM bytes). When `key_type` and the matching PEM are supplied, `Badge` eagerly imports them into `priv_key` / `pub_key` objects. An unsupported `key_type` raises `UnknownKeyType` (see [[Keys and Errors]]).

`badge.urls_has_problems()` downloads each configured URL and reports any that are unreachable.

### `Signer`

Builds and signs a legacy assertion, then bakes it into the image.

```python
Signer(identity=None, evidence=None, expiration=None,
       deterministic=False, badge_type=None)
```

- `identity` — the recipient email (stored hashed+salted in the assertion).
- `evidence`, `expiration` — optional assertion fields (`expiration` is a Unix timestamp).
- `badge_type` — pass `BadgeType.SIGNED` for a JWS assertion, or `BadgeType.HOSTED`. Anything other than `HOSTED` defaults to signed.
- `deterministic` — when `True`, uses a fixed salt (`s4lt3d`), `uid=0` and `issuedOn=0` so repeated signings produce an identical payload. Useful for tests; leave `False` in production.

`signer.sign_badge(badge)` returns a `BadgeSigned`, raising `ErrorSigningFile` if the image already contains an assertion.

### `BadgeSigned`

The signed result. The baked image bytes are in `.signed`; the JWS lives in `.assertion`. Useful accessors: `save_to_file(path)`, `get_assertion()`, `get_identity()` / `get_identity_hashed()` / `get_salt()` / `get_serial_num()`, `get_signkey_pem()`, and `BadgeSigned.read_from_file(path)` (loads a baked `.svg`/`.png` back into a `BadgeSigned`, downloading the issuer's verify key referenced by the assertion).

### `Assertion`

The decoded JWS triple (`header`, `body`, `signature`, all Base64URL). `Assertion.decode(data)` parses `header.body.signature` bytes; `decode_header()` / `decode_body()` return the JSON objects; `get_assertion()` re-joins the three parts.

### `Verifier` and `VerifyInfo`

```python
Verifier(verify_key=None, identity=None)
```

- `verify_key` — a **trusted** public key PEM. When supplied it is used for signature checks; only when it is omitted does the verifier fall back to the key the badge points to. Always pass a trusted key in production — see [[Security Model]].
- `identity` — the expected recipient email; omit it to do signature-only verification.

Methods return a `VerifyInfo(status, msg)` where `status` is a `BadgeStatus`: `check_jws_signature(badge)`, `get_badge_status(badge)` (the full pipeline: signature → revocation → expiration → identity), and `print_payload(badge)`.

### `extract_svg_assertion` / `extract_png_assertion`

Standalone helpers that pull the baked JWS out of raw image bytes and return an `Assertion`. They raise `ErrorParsingFile` / `AssertionFormatIncorrect` if no assertion is present.

## See also

- [[Python API OB2]] — the **strict** Open Badges 2.0 API (recommended over this legacy one).
- [[Python API OB3]] — the Open Badges 3.0 (JWT-VC) API.
- [[Keys and Errors]] — `KeyType`, key generation, and the exception types.
- [[Security Model]] — why you must pass a trusted `verify_key`.
- [[CLI Reference]] — the same operations from the command line (`-V 1`).
