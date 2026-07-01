Programmatic guide to the OpenBadges 3.0 layer of `openbadgeslib`: building [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/), signing them as JWT-VCs, baking them into images, and verifying them. Everything here lives in the `openbadgeslib.ob3` package. For the legacy 2.0 JWS format see [[Python API OB2]].

> The full, always-up-to-date class/function reference is generated from the docstrings: **[API Reference](https://luisgf.github.io/openbadgeslib/)**.

```python
from openbadgeslib.ob3 import (
    Achievement, Issuer, OpenBadgeCredential,
    OB3Signer, OB3Verifier, OB3VerificationError,
)
```

## Data model

Three dataclasses describe the credential. You build them top-down: an `Issuer`, an `Achievement`, then the `OpenBadgeCredential` that ties them to a recipient.

### `Issuer`

The profile of who awards the badge.

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Issuer identifier (typically an HTTPS URL or DID). |
| `name` | yes | Human-readable issuer name. |
| `url` | no | Issuer home page. |
| `email` | no | Contact email. |
| `image_url` | no | Logo; serialised as `{"id": ..., "type": "Image"}`. |

### `Achievement`

The badge class / achievement definition.

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Achievement identifier. |
| `name` | yes | Achievement name. |
| `description` | yes | What the badge represents. |
| `criteria_narrative` | yes | Serialised as `criteria.narrative`. |
| `image_url` | no | Badge image; serialised as an `Image` object. |
| `tags` | no | List of strings; serialised under `tag`. Defaults to `[]`. |

### `OpenBadgeCredential`

The credential itself. Several fields are auto-filled in `__post_init__`:

| Field | Required | Default |
| --- | --- | --- |
| `issuer` | yes | — |
| `recipient_id` | yes | A `mailto:` URI or a DID (see normalization below). |
| `achievement` | yes | — |
| `id` | no | `urn:uuid:<uuid4>` when omitted. |
| `name` | no | Falls back to `achievement.name`. |
| `issuance_date` | no | `datetime.now(timezone.utc)` when omitted. |
| `expiration_date` | no | Sets `validUntil` / JWT `exp` when present. |
| `evidence_url` | no | Adds an `Evidence` entry. |

Useful serialisation methods:

- `to_vc()` — the bare Verifiable Credential JSON object (VC Data Model 2.0, with the OB 3.0 context), no JWT wrapper.
- `to_jwt_payload()` — the OB 3.0 native JWT-VC payload: the credential's members at the top level (no `vc` wrapper) plus the registered claims `iss`, `sub`, `jti`, `nbf` (and `exp` when expiring).
- `OpenBadgeCredential.from_jwt_payload(payload)` — classmethod that reconstructs a credential from a decoded payload (accepts both `validFrom`/`validUntil` and the older `issuanceDate`/`expirationDate` names).

## Signing — `OB3Signer`

```python
OB3Signer(privkey_pem, algorithm='RS256')
```

`privkey_pem` may be PEM bytes, a PEM string, or a key object. `algorithm` must be one of `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `EdDSA` — anything else raises `ValueError` at construction. Use an `RS*` algorithm with an RSA key, an `ES*` algorithm with an EC key, and `EdDSA` with an Ed25519 key.

| Method | Returns | Purpose |
| --- | --- | --- |
| `sign(credential)` | `str` | Compact JWT-VC string. |
| `sign_into_svg(credential, svg_bytes)` | `bytes` | JWT-VC baked into an `<openbadges:credential verify="…"/>` element. |
| `sign_into_png(credential, png_bytes)` | `bytes` | JWT-VC baked into an `iTXt` chunk keyed `openbadgecredential`. |

The baking format matches OB 2.0, so existing badge viewers can extract the token regardless of version. See [[Signing and Verification]] for the shared baking concepts and [[Keys and Errors]] for generating compatible keys.

## Verifying — `OB3Verifier`

```python
OB3Verifier(pubkey_pem)
```

On construction the verifier detects the key type and **pins** the accepted JWS algorithms to that key family (`RS*` for RSA, `ES*` for EC, `EdDSA` for Ed25519). The token header can never dictate the algorithm, so `alg:none`, an HMAC downgrade, or cross-type confusion are all rejected up front. An unsupported key type raises `OB3VerificationError`.

```python
verify(token, expected_recipient=None) -> OpenBadgeCredential
```

`verify()` checks the signature, expiry and structure, validates that the `vc` is an `OpenBadgeCredential`, and cross-checks the registered `iss`/`sub` claims against the credential's issuer/subject. On success it returns a fully reconstructed `OpenBadgeCredential`; any failure raises `OB3VerificationError`.

**Recipient binding is opt-in.** By default `verify()` does *not* tie the credential to a recipient. Pass `expected_recipient` (a bare email, a `mailto:` URI, or a DID) to additionally require that `credentialSubject.id` matches; otherwise the caller must compare `credential.recipient_id` itself. See [[Security Model]] for why this matters.

Token extraction helpers are static methods:

- `OB3Verifier.extract_token_from_svg(svg_bytes) -> str`
- `OB3Verifier.extract_token_from_png(png_bytes) -> str`

A missing assertion raises `OB3VerificationError`; unparseable XML raises `ErrorParsingFile`.

### Recipient normalization

The signer and verifier share one normalization rule so they always agree: a bare email gains a `mailto:` scheme, while a value that already has a scheme — including a DID — is returned unchanged.

```text
recipient@example.com        -> mailto:recipient@example.com
mailto:recipient@example.com -> mailto:recipient@example.com   (unchanged)
did:example:abc123           -> did:example:abc123             (unchanged)
```

So `expected_recipient='recipient@example.com'` and `expected_recipient='mailto:recipient@example.com'` both match a credential issued to `mailto:recipient@example.com`, and a DID is never mangled into `mailto:did:...`.

## Errors

`OB3VerificationError` is the single exception for every verification failure (invalid signature, expired token, disallowed algorithm, recipient mismatch, wrong credential type, malformed payload, missing embedded token). It subclasses `LibOpenBadgesException`, so one `except` can catch both OB2 and OB3 failures. Token extraction may additionally raise `ErrorParsingFile` for unreadable images. See [[Keys and Errors]] for the full exception hierarchy.

```python
from openbadgeslib.ob3 import OB3VerificationError

try:
    credential = verifier.verify(token, expected_recipient='recipient@example.com')
except OB3VerificationError as exc:
    print("Verification failed:", exc)
```

## Full round-trip example

Build a credential, sign it into an SVG with an RSA key, then extract and verify it — pinning both the algorithm (via the public key's type) and the recipient.

```python
from openbadgeslib.ob3 import (
    Achievement, Issuer, OpenBadgeCredential,
    OB3Signer, OB3Verifier, OB3VerificationError,
)

# 1. Build the credential
issuer = Issuer(
    id='https://example.com/issuer',
    name='Example Org',
    url='https://example.com',
)
achievement = Achievement(
    id='https://example.com/achievements/1',
    name='Python Wizard',
    description='Awarded for mastering openbadgeslib',
    criteria_narrative='Sign and verify an OB 3.0 credential',
    image_url='https://example.com/badge.svg',
    tags=['python', 'openbadges'],
)
credential = OpenBadgeCredential(
    issuer=issuer,
    recipient_id='recipient@example.com',   # normalised to mailto: on sign
    achievement=achievement,
)

# 2. Sign into an SVG image (RSA key -> RS256 token)
privkey_pem = open('test_sign_rsa.pem', 'rb').read()
svg_bytes = open('badge.svg', 'rb').read()

signer = OB3Signer(privkey_pem, algorithm='RS256')
signed_svg = signer.sign_into_svg(credential, svg_bytes)
open('badge-signed.svg', 'wb').write(signed_svg)

# 3. Extract and verify
pubkey_pem = open('test_verify_rsa.pem', 'rb').read()
verifier = OB3Verifier(pubkey_pem)        # algorithm pinned to RSA here

token = OB3Verifier.extract_token_from_svg(signed_svg)
try:
    restored = verifier.verify(token, expected_recipient='recipient@example.com')
    print('Verified credential for', restored.recipient_id)
    print('Achievement:', restored.achievement.name)
except OB3VerificationError as exc:
    print('Verification failed:', exc)
```

For PNGs, swap `sign_into_png` / `extract_token_from_png` and pass PNG bytes. EC keys work the same way with `algorithm='ES256'`.

## See also

- [[Python API OB2]] — the 2.0 JWS-in-image API.
- [[Keys and Errors]] — key generation, key objects, and the exception hierarchy.
- [[Security Model]] — algorithm pinning, recipient binding, and the threat model.
