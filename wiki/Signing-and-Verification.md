This page explains, end to end, how `openbadgeslib` signs an Open Badge and how it later proves that signature is genuine. It covers both badge generations — OB2 (a detached JWS) and OB3 (a JWT-VC) — and the shared "baking" step that hides the signed token inside an SVG or PNG image so a single picture file *is* the verifiable credential.

For the trust assumptions behind all of this (which key is trusted, why downloaded keys are not), see [[Security Model]]. For key types, formats and the exception hierarchy, see [[Keys and Errors]].

## The big picture

Both versions follow the same three-stage pipeline:

1. **Build a token** — a signed string. OB2 builds a compact JWS over a badge assertion; OB3 builds a JWT-VC whose payload carries a W3C Verifiable Credential under a `vc` claim.
2. **Bake it into an image** — the token is written into the badge image as an SVG element or a PNG chunk, using the shared `openbadgeslib.baking` module. OB2 and OB3 use the *exact same* on-disk carrier format, so any conformant viewer can pull the token out regardless of which version produced it.
3. **Reverse it on verify** — extract the token from the image, then cryptographically check the signature with a trusted public key and report a status.

The signing algorithm is bound to the key type, in both directions: an RSA key produces and verifies `RS256`, an EC key produces and verifies `ES256`. The verifier never lets the token header choose the algorithm — see [[Security Model]] for why that matters.

## Supported algorithms

The low-level JWS engine in `openbadgeslib/_jws/__init__.py` is backed by PyJWT's algorithm implementations and registers six algorithms:

| Key family | Algorithms |
|------------|-----------|
| RSA        | `RS256`, `RS384`, `RS512` |
| ECC        | `ES256`, `ES384`, `ES512` |

In practice the signers emit the 256-bit variant — `RS256` for RSA, `ES256` for ECC. The wider family is *accepted* on verification for interoperability, but every verifier pins the allowed set to the key's own type, so an RSA key can never validate an `ES*` token and vice versa. There is deliberately no symmetric (`HS*`) or `alg: none` entry.

## OB2: the JWS path

For OB2 the unit of trust is a **signed assertion** serialized as a JWS. The work happens in `openbadgeslib/ob2/signer.py`.

`Signer.generate_jws()` assembles two dicts — a JOSE header and a payload:

- The header's `alg` comes from the key type (`alg_for_key_type(...)`).
- The payload is the OpenBadges assertion: a `uid`, a hashed `recipient` (`sha256$…` of the email plus a salt, `hashed: true`), `image`, `badge`, an `issuedOn` timestamp, and a `verify` block. The `verify` block is `type: signed` pointing at the public-key URL by default, or `type: hosted` pointing at the badge JSON URL when `badge_type` is `BadgeType.HOSTED`. Optional `expires` and `evidence` are added when present.

`generate_assertion()` then signs header + payload via `_jws.sign(...)` and stores the base64url-encoded header, body and signature on an `Assertion` object. The signature is computed over `base64url(header) . base64url(payload)`.

```python
from openbadgeslib.ob2.signer import Signer

signer = Signer(identity='recipient@example.org')
signed = signer.sign_badge(badge_obj)   # raises ErrorSigningFile if already signed
# signed.signed holds the baked image bytes
```

A determinism switch exists for reproducible output: `Signer(deterministic=True)` fixes the salt and zeroes `uid`/`issuedOn` so the same inputs produce byte-identical badges (useful for tests).

Verification lives in `openbadgeslib/ob2/verifier.py`. `Verifier.get_badge_status()` runs the full gauntlet in order and returns a `VerifyInfo(status, msg)`:

1. **Signature** — `check_jws_signature()` calls `_jws.verify_block(...)`. It verifies against the operator-supplied trusted key when one was given, and only falls back to the key the badge points to when none was.
2. **Revocation** — `check_revocation()` walks badge JSON → issuer JSON → optional `revocationList`. A missing list simply means "not revoked".
3. **Expiration** — `check_expiration()` compares `expires` against *now*.
4. **Identity** — `check_identity()` re-hashes the supplied email with the badge salt and compares to the assertion's recipient. With no identity supplied it skips this step (signature-only verification).

```python
from openbadgeslib.ob2.verifier import Verifier

v = Verifier(verify_key=trusted_pub_key, identity='recipient@example.org')
info = v.get_badge_status(badge)
print(info.status, info.msg)
```

See [[Python API OB2]] for the full object model and [[CLI Reference]] for the `openbadges-signer` / `openbadges-verifier` commands.

## OB3: the JWT-VC path

For OB3 the unit of trust is a **JWT-VC** — a JWT whose payload nests a W3C Verifiable Credential under the `vc` claim. Signing is in `openbadgeslib/ob3/signer.py`.

`OB3Signer.sign()` calls `credential.to_jwt_payload()` and hands it to PyJWT's `jwt.encode(...)` with the chosen algorithm (default `RS256`; RSA keys must use `RS*`, EC keys `ES*`). The result is a compact `header.payload.signature` JWT string.

```python
from openbadgeslib.ob3.signer import OB3Signer

signer = OB3Signer(privkey_pem, algorithm='ES256')   # ES256 for an EC key
token = signer.sign(credential)                       # compact JWT-VC string
svg = signer.sign_into_svg(credential, svg_bytes)     # or sign_into_png(...)
```

Verification is in `openbadgeslib/ob3/verifier.py`. `OB3Verifier.verify()`:

1. **Reads the header** and rejects the token unless its `alg` is in the set allowed for this key's type (`RS*` for RSA, `ES*` for ECC) — the token cannot pick its own algorithm.
2. **Decodes** with `jwt.decode(...)`, which checks the signature and expiry (`ExpiredSignatureError` → `OB3VerificationError("Credential has expired")`).
3. **Validates structure** — the payload must carry a `vc` claim whose `type` includes `OpenBadgeCredential` (a token missing `vc` is flagged as a possible OB2 JWS), and the JWT `iss`/`sub` registered claims must match the credential's issuer id and `credentialSubject.id` when present.
4. **Optionally binds the recipient** — pass `expected_recipient` (an email, a `mailto:` URI, or a DID) and verification additionally requires `credentialSubject.id` to match; without it, only the signature, expiry and structure are checked.

```python
from openbadgeslib.ob3.verifier import OB3Verifier

v = OB3Verifier(pubkey_pem)
credential = v.verify(token, expected_recipient='recipient@example.org')
```

Every failure raises `OB3VerificationError` (a subclass of `LibOpenBadgesException`, so one `except` catches both OB2 and OB3 errors). See [[Python API OB3]] for the credential model, and [[OB2 vs OB3]] for how the two generations differ.

## Baking: hiding the token in an image

Both versions share `openbadgeslib/baking.py`. Keeping one implementation stops the OB2 and OB3 paths from drifting into two slightly different readers. The carrier format is identical for both versions.

### SVG — an `<openbadges:assertion>` element

`bake_svg()` parses the SVG, appends an `<openbadges:assertion>` element to the root `<svg>`, and stores the token in its `verify` attribute (plus a namespace declaration and an optional XML comment):

```xml
<openbadges:assertion xmlns:openbadges="http://openbadges.org" verify="eyJhbGciOi…"/>
```

`extract_svg()` reverses it: it finds the `openbadges:assertion` node and returns the `verify` attribute value, or `None` if the element is absent. `has_svg()` reports whether an assertion is already present (so re-signing is refused). XML is parsed with `defusedxml` to neutralize entity-expansion attacks.

### PNG — an `openbadges` iTXt chunk

`bake_png()` inserts an `iTXt` chunk (keyword `openbadges`) just before the trailing `IEND` chunk, with an optional `tEXt` comment chunk, and re-serializes the PNG with correct per-chunk CRCs:

```text
iTXt: "openbadges" \0 <comp_flag> <comp_method> <lang> \0 <translated> \0 <token>
```

`extract_png()` does not trust a fixed byte offset — it parses the real iTXt structure (keyword, compression flag/method, language tag, translated keyword, then text), so tokens baked by any conformant tool, including compressed ones, are recovered. `has_png()` reports presence of the chunk.

Because extraction runs on **untrusted input before any signature check**, compressed iTXt text is inflated through a bounded decompressor capped at 256 KiB (`MAX_ITXT_DECOMPRESSED`); a crafted zlib bomb raises `DecompressionLimitExceeded` instead of exhausting memory.

### Extraction in the verifiers

The OB3 verifier exposes the reverse step directly as `extract_token_from_svg()` and `extract_token_from_png()`, which call the baking helpers and turn a missing token into an `OB3VerificationError` (and a parse failure into `ErrorParsingFile`). The OB2 path reads the assertion back through its badge/`Assertion` objects. Either way the flow is the same: **extract the token from the image, then verify the signature with a trusted key.**

See [[Security Model]] for the threat model behind the bounded inflate and key-trust rules, and [[Keys and Errors]] for the exceptions raised along the way.
