Programmatic guide to the **strict Open Badges 2.0** API exposed by `openbadgeslib.ob2`. This layer produces conformant JSON-LD Badge Objects (every object carries `@context` and `type`, the assertion uses an IRI `id`, a `verification` object, a boolean `hashed`, and ISO 8601 dates) and signs the assertion as a JWS baked into an SVG/PNG image. For the legacy pre-2.0 format see [[Python API OB1]]; for the JWT-VC path see [[Python API OB3]]; for how the generations differ see [[OB2 vs OB3]].

> The full, always-up-to-date class/function reference is generated from the docstrings: **[API Reference](https://luisgf.github.io/openbadgeslib/)**.

All public OB2 names are re-exported from `openbadgeslib.ob2`:

```python
from openbadgeslib.ob2 import (
    OB2Signer, OB2Verifier, OB2VerificationError,
    Assertion, IdentityObject, Verification,
    BadgeClass, Profile, CryptographicKey, RevocationList,
    hash_identity, OB2_CONTEXT,
)
```

## The data model (dataclasses)

Each Badge Object is a `@dataclass` with a `to_dict()` that emits conformant JSON-LD; the ones read back from untrusted input also provide a validating `from_dict()`.

- **`IdentityObject`** — the recipient. `IdentityObject.create(email, salt)` builds the hashed form (`identity="sha256$<hex>"`, `hashed=True`). `from_dict` rejects the legacy string `"true"`.
- **`Verification`** — `Verification(type="SignedBadge", creator=<CryptographicKey IRI>)` or `Verification(type="HostedBadge")`. `from_dict` canonicalises the `signed`/`hosted` aliases.
- **`Assertion`** — the signed/hosted claim. `id` auto-generates as `urn:uuid:…` when omitted (pass the hosting URL explicitly for a HostedBadge); `issued_on` defaults to now (UTC).
- **`BadgeClass`**, **`Profile`**, **`CryptographicKey`**, **`RevocationList`** — the hosted metadata objects emitted by `openbadges-publish -V 2`.

```python
from datetime import datetime, timezone
from openbadgeslib.ob2 import Assertion, IdentityObject, Verification

assertion = Assertion(
    recipient=IdentityObject.create('recipient@example.com', salt='s4lt3d'),
    badge='https://example.com/badge_1/badge.json',
    verification=Verification(type='SignedBadge',
                              creator='https://example.com/badge_1/key.json'),
    issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
    image='https://example.com/badge_1/badge.svg',
)
```

## `OB2Signer`

```python
OB2Signer(privkey_pem, algorithm='RS256')
```

Signs an `Assertion` as a JWS whose payload is the full Assertion JSON-LD document. `algorithm` is bound to the key type (RS256 for RSA, ES256 for ECC P-256, EdDSA for Ed25519).

- `sign(assertion)` → the compact JWS string (`header.payload.signature`).
- `sign_into_svg(assertion, svg_bytes)` / `sign_into_png(assertion, png_bytes)` → the baked image bytes (OB 2.0 carrier: `<openbadges:assertion>` / the `openbadges` iTXt keyword).

## `OB2Verifier` and `OB2VerificationError`

```python
OB2Verifier(pubkey_pem=None)
```

- `pubkey_pem` — an optional **trusted** public key. When supplied it verifies SignedBadge assertions directly (trusted). When omitted, a SignedBadge is verified against the key resolved from `verification.creator`, whose CryptographicKey `owner`/`publicKey` back-link to the issuer is checked — internally consistent, but not proof of issuer identity.

`verify(token, expected_recipient=None, check_revocation=False)` returns the decoded `Assertion` or raises `OB2VerificationError`. It:

- verifies the signature (SignedBadge) or fetches the assertion from its `id` and enforces the issuer scope (HostedBadge);
- validates `@context`/`type` and rejects legacy shapes (string `hashed`, Unix dates, `uid`-only);
- checks expiry, and (with `check_revocation=True`, network) the issuer's `RevocationList`;
- with `expected_recipient`, re-hashes the email + salt and binds it to the recipient.

Token extraction: `OB2Verifier.extract_token_from_svg(bytes)` / `extract_token_from_png(bytes)`.

## Complete in-memory example (SignedBadge)

```python
from datetime import datetime, timezone
from openbadgeslib.ob2 import (
    OB2Signer, OB2Verifier, Assertion, IdentityObject, Verification,
)

priv = open('test_sign_rsa.pem', 'rb').read()
pub = open('test_verify_rsa.pem', 'rb').read()
svg = open('sample1.svg', 'rb').read()

assertion = Assertion(
    recipient=IdentityObject.create('recipient@example.com', salt='s4lt3d'),
    badge='https://example.com/badge_1/badge.json',
    verification=Verification(type='SignedBadge',
                              creator='https://example.com/badge_1/key.json'),
    issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
)

baked = OB2Signer(privkey_pem=priv, algorithm='RS256').sign_into_svg(assertion, svg)

token = OB2Verifier.extract_token_from_svg(baked)
result = OB2Verifier(pubkey_pem=pub).verify(token, expected_recipient='recipient@example.com')
print('verified:', result.id)
```

`check_revocation=True` (and HostedBadge verification) additionally fetch the issuer's hosted JSON over the network — see [[Security Model]] for the trust model.

## Hosted badges

For a HostedBadge, pass the hosting URL as the assertion `id`, sign with `Verification(type='HostedBadge')`, and publish `assertion.to_dict()` at that URL. On verification the (scope-checked) HTTPS retrieval of the `id` is the trust anchor. From the CLI this is `openbadges-signer -V 2 -H` (see [[CLI Reference]]), which also writes the `.assertion.json` to publish.

## See also

- [[Signing and Verification]] — the end-to-end concepts.
- [[Keys and Errors]] — `KeyType`, key generation, and exception types.
- [[Security Model]] — trusted keys, hosted trust, and scope enforcement.
- [[Python API OB1]] / [[Python API OB3]] — the other two generations.
- [[CLI Reference]] — the same operations from the command line (`-V 2`).
