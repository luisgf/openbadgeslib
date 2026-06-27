Programmatic guide to the Open Badges 2.0 API exposed by `openbadgeslib.ob2`. Everything here mirrors the JWS-signed-assertion model where the assertion is baked into an SVG or PNG image. For the W3C Verifiable Credentials / JWT-VC path see [[Python API OB3]]; for the differences between the two see [[OB2 vs OB3]].

> The full, always-up-to-date class/function reference is generated from the docstrings: **[API Reference](https://luisgf.github.io/openbadgeslib/)**.

All public OB2 names are re-exported from `openbadgeslib.ob2`, so you can import them from one place:

```python
from openbadgeslib.ob2 import (
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

Builds and signs an assertion, then bakes it into the image.

```python
Signer(identity=None, evidence=None, expiration=None,
       deterministic=False, badge_type=None)
```

- `identity` — the recipient email (stored hashed+salted in the assertion).
- `evidence`, `expiration` — optional assertion fields (`expiration` is a Unix timestamp).
- `badge_type` — pass `BadgeType.SIGNED` for a JWS assertion, or `BadgeType.HOSTED` for a hosted-verification badge. Anything other than `HOSTED` defaults to signed.
- `deterministic` — when `True`, uses a fixed salt (`s4lt3d`), `uid=0` and `issuedOn=0` so repeated signings produce an identical payload. Useful for tests; leave `False` in production.

`signer.sign_badge(badge)` returns a `BadgeSigned`, raising `ErrorSigningFile` if the image already contains an assertion. `signer.has_assertion(badge)` checks that condition without signing. `signer.generate_uid()` returns a fresh 40-char serial number.

### `BadgeSigned`

The signed result. The baked image bytes are in `.signed`; the JWS lives in `.assertion`. Useful accessors:

- `save_to_file(path)` — write `.signed` to disk.
- `get_assertion()` — the full `header.body.signature` JWS as a `str` (or `None` if unsigned).
- `get_identity()` / `get_identity_hashed()` / `get_salt()` / `get_serial_num()` — string accessors.
- `get_signkey_pem()` — the public key PEM used to sign.
- `BadgeSigned.read_from_file(path)` — load a baked `.svg`/`.png` back into a `BadgeSigned`, downloading the issuer's verify key referenced by the assertion (raises `ErrorParsingFile` if that key URL cannot be fetched).

### `Assertion`

The decoded JWS triple (`header`, `body`, `signature`, all Base64URL). `Assertion.decode(data)` parses `header.body.signature` bytes; `decode_header()` / `decode_body()` return the JSON objects; `get_assertion()` re-joins the three parts.

### `Verifier` and `VerifyInfo`

```python
Verifier(verify_key=None, identity=None)
```

- `verify_key` — a **trusted** public key PEM. When supplied it is used for signature checks; only when it is omitted does the verifier fall back to the key the badge points to. Always pass a trusted key in production — see [[Security Model]].
- `identity` — the expected recipient email; omit it to do signature-only verification (the recipient check is then skipped).

Methods all return a `VerifyInfo(status, msg)` where `status` is a `BadgeStatus`:

- `check_jws_signature(badge)` — cryptographic signature only.
- `get_badge_status(badge)` — the full pipeline: signature, then revocation, then expiration, then identity. Returns `VALID`/`OK` only if every check passes.
- `print_payload(badge)` — pretty-print the decoded assertion body.

### `extract_svg_assertion` / `extract_png_assertion`

Standalone helpers that pull the baked JWS out of raw image bytes and return an `Assertion`. They raise `ErrorParsingFile` / `AssertionFormatIncorrect` if no assertion is present.

## Complete in-memory example

This sign-then-verify round trip mirrors the test fixtures in `tests/conftest.py`, so it runs end to end with no files written and no network access. Point the PEM paths at your own keys (generate them with [[Keys and Errors]] / `openbadges-keygenerator`).

```python
from openbadgeslib.ob2 import (
    Badge, Signer, Verifier,
    BadgeImgType, BadgeType, BadgeStatus,
    extract_svg_assertion,
)
from openbadgeslib.keys import KeyType

# --- key material and image bytes (load your own) ---------------------------
priv_pem = open('test_sign_rsa.pem', 'rb').read()
pub_pem = open('test_verify_rsa.pem', 'rb').read()
svg_bytes = open('sample1.svg', 'rb').read()

identity = 'recipient@example.com'

# --- build the unsigned source Badge ----------------------------------------
badge = Badge(
    ini_name='demo_rsa_svg',
    name='Demo SVG RSA Badge',
    description='Awarded for reading the OB2 API guide',
    image_type=BadgeImgType.SVG,
    image=svg_bytes,
    image_url='https://example.com/badge.svg',
    criteria_url='https://example.com/criteria.html',
    json_url='https://example.com/badge.json',
    verify_key_url='https://example.com/verify_key.pem',
    key_type=KeyType.RSA,
    privkey_pem=priv_pem,
    pubkey_pem=pub_pem,
)

# --- sign: produce a BadgeSigned with the JWS baked into the SVG -------------
signer = Signer(identity=identity, badge_type=BadgeType.SIGNED)
signed = signer.sign_badge(badge)

print('Serial:', signed.get_serial_num())
print('Assertion JWS:', signed.get_assertion())
# signed.signed holds the baked SVG bytes; persist with signed.save_to_file(...)

# --- verify the signature only ----------------------------------------------
verifier = Verifier(verify_key=pub_pem, identity=identity)
sig = verifier.check_jws_signature(signed)
assert sig.status is BadgeStatus.VALID, sig.msg

# --- round-trip: pull the assertion back out of the baked image -------------
extracted = extract_svg_assertion(signed.signed)
assert extracted.get_assertion() == signed.assertion.get_assertion()
print('Decoded body:', extracted.decode_body())
```

`get_badge_status()` additionally checks revocation and expiration, which both require fetching the issuer's published JSON over the network:

```python
info = verifier.get_badge_status(signed)
if info.status is BadgeStatus.VALID:
    print('Badge is valid')
else:
    print('Verification failed:', info.status.name, '-', info.msg)
```

For PNG badges the flow is identical — use `BadgeImgType.PNG`, load PNG bytes, and call `extract_png_assertion(signed.signed)`.

## See also

- [[Signing and Verification]] — the end-to-end concepts behind these calls.
- [[Keys and Errors]] — `KeyType`, key generation, and the exception types raised here.
- [[Security Model]] — why you must pass a trusted `verify_key`.
- [[Python API OB3]] — the equivalent guide for Open Badges 3.0.
- [[CLI Reference]] — the same operations from the command line.
