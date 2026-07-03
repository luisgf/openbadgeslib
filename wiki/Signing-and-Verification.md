This page explains, end to end, how `openbadgeslib` signs an Open Badge and how it later proves that signature is genuine. It covers strict Open Badges 2.0 (a JWS assertion, or a hosted assertion) and OB 3.0 (a JWT-VC) — plus the shared "baking" step that hides the signed token inside an SVG or PNG image so a single picture file *is* the verifiable credential. (The frozen pre-2.0 format uses the same JWS pipeline under `-V 1`; see [[Python API OB1]].)

For the trust assumptions behind all of this (which key is trusted, why downloaded keys are not), see [[Security Model]]. For key types, formats and the exception hierarchy, see [[Keys and Errors]].

## The big picture

Both versions follow the same three-stage pipeline:

1. **Build a token** — a signed string. OB2 builds a compact JWS over a badge assertion; OB3 builds a native VC-JWT whose payload IS a W3C Verifiable Credential (§8.2).
2. **Bake it into an image** — the token is written into the badge image as an SVG element or a PNG chunk, using the shared `openbadgeslib.baking` module. OB2 and OB3 use the *exact same* on-disk carrier format, so any conformant viewer can pull the token out regardless of which version produced it.
3. **Reverse it on verify** — extract the token from the image, then cryptographically check the signature with a trusted public key and report a status.

The signing algorithm is bound to the key type, in both directions: an RSA key produces and verifies `RS256`, an EC key produces and verifies `ES256`, and an Ed25519 key produces and verifies `EdDSA`. The verifier never lets the token header choose the algorithm — see [[Security Model]] for why that matters.

## Supported algorithms

The low-level JWS engine in `openbadgeslib/_jws/__init__.py` is backed by PyJWT's algorithm implementations and registers seven algorithms:

| Key family | Algorithms |
|------------|-----------|
| RSA        | `RS256`, `RS384`, `RS512` |
| ECC        | `ES256`, `ES384`, `ES512` |
| Ed25519    | `EdDSA` |

In practice the signers emit the 256-bit variant — `RS256` for RSA, `ES256` for ECC (Ed25519 has the single `EdDSA` variant). The wider RSA/EC family is *accepted* on verification for interoperability, but every verifier pins the allowed set to the key's own type, so an RSA key can never validate an `ES*` token and vice versa. There is deliberately no symmetric (`HS*`) or `alg: none` entry.

## OB2: the strict JWS / hosted path

For strict Open Badges 2.0 the unit of trust is a conformant **Assertion** — a JSON-LD Badge Object signed as a JWS. The work happens in `openbadgeslib/ob2/`.

`OB2Signer.sign()` serialises an `Assertion` dataclass to its JSON-LD form and signs it:

- The header's `alg` is bound to the key type (`RS256`/`ES256`/`EdDSA`).
- The payload is the Assertion document: `@context` (`https://w3id.org/openbadges/v2`), `type` `"Assertion"`, an IRI `id` (`urn:uuid:…` for a SignedBadge, or the hosting URL for a HostedBadge), a hashed `recipient` (`sha256$…` + salt, `hashed: true` as a real **boolean**), `badge`, an **ISO 8601** `issuedOn`, and a `verification` object — `{"type": "SignedBadge", "creator": <CryptographicKey IRI>}` or `{"type": "HostedBadge"}`. Optional `expires` (ISO 8601), `image` and `evidence` are added when present.

The signature is computed over `base64url(header) . base64url(payload)`; `sign_into_svg()` / `sign_into_png()` bake the compact JWS into the image.

```python
from datetime import datetime, timezone
from openbadgeslib.ob2 import OB2Signer, Assertion, IdentityObject, Verification

assertion = Assertion(
    recipient=IdentityObject.create('recipient@example.org', salt='s4lt3d'),
    badge='https://example.com/badge_1/badge.json',
    verification=Verification(type='SignedBadge', creator='https://example.com/badge_1/key.json'),
    issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
)
svg = OB2Signer(privkey_pem, algorithm='RS256').sign_into_svg(assertion, svg_bytes)
```

Verification lives in `openbadgeslib/ob2/verifier.py`. `OB2Verifier.verify()` returns the decoded `Assertion` or raises `OB2VerificationError`, running:

1. **Structure** — validates `@context`/`type` and parses the Assertion, rejecting legacy shapes (a string `hashed`, a Unix `issuedOn`, a `uid` without an `id`).
2. **Signature / hosted anchor** — a **SignedBadge** JWS is verified against the operator-supplied trusted key, or, when none is given, the key resolved from `verification.creator` (a `CryptographicKey` whose `owner`/`publicKey` back-link to the issuer is checked). A **HostedBadge** is instead fetched from its own `id` over HTTPS and scope-checked against the issuer's origin — that retrieval is the trust anchor, and the baked JWS is only non-gating defence-in-depth.
3. **Expiration** — compares `expires` against *now*.
4. **Revocation** (with `check_revocation=True`) — walks badge JSON → issuer JSON → `revocationList`, matching the assertion `id` in `revokedAssertions`.
5. **Identity** — with `expected_recipient`, re-hashes the email with the badge salt and compares to the recipient.

```python
from openbadgeslib.ob2 import OB2Verifier

v = OB2Verifier(pubkey_pem=trusted_pub_key)
assertion = v.verify(token, expected_recipient='recipient@example.org', check_revocation=True)
```

The legacy pre-2.0 flow (`Signer`/`Verifier`/`get_badge_status`, with `uid`, a `verify` block and Unix timestamps) is unchanged in `openbadgeslib/ob1/` and selected with `-V 1`. See [[Python API OB2]] for the strict object model, [[Python API OB1]] for the legacy one, and [[CLI Reference]] for the commands.

## OB3: the JWT-VC path

For OB3 the unit of trust is a **JWT-VC** — an OB 3.0 native VC-JWT (§8.2) whose payload **is** the W3C Verifiable Credential (its members at the top level, not nested under a `vc` claim). Signing is in `openbadgeslib/ob3/signer.py`.

`OB3Signer.sign()` calls `credential.to_jwt_payload()` and hands it to PyJWT's `jwt.encode(...)` with the chosen algorithm (default `RS256`; RSA keys must use `RS*`, EC keys `ES*`, Ed25519 `EdDSA`). `validFrom` is encoded as the `nbf` claim, and the JOSE header carries the issuer's public key as a `jwk` (§8.2.3). The result is a compact `header.payload.signature` JWT string.

```python
from openbadgeslib.ob3.signer import OB3Signer

signer = OB3Signer(privkey_pem, algorithm='ES256')   # ES256 for an EC key
token = signer.sign(credential)                       # compact JWT-VC string
svg = signer.sign_into_svg(credential, svg_bytes)     # or sign_into_png(...)
```

Verification is in `openbadgeslib/ob3/verifier.py`. `OB3Verifier.verify()`:

1. **Reads the header** and rejects the token unless its `alg` is in the set allowed for this key's type (`RS*` for RSA, `ES*` for ECC, `EdDSA` for Ed25519) — the token cannot pick its own algorithm.
2. **Decodes** with `jwt.decode(...)`, which checks the signature and expiry (`ExpiredSignatureError` → `OB3VerificationError("Credential has expired")`).
3. **Validates structure** — the payload's `type` must include `VerifiableCredential` and either `OpenBadgeCredential` or its alias `AchievementCredential` (a token with neither is flagged as a possible OB2 JWS); `@context` must be the VC 2.0 + OB v3p0 pair; and the registered claims `iss`/`nbf` must be present, with `iss` equal to the issuer id and `sub` equal to `credentialSubject.id` when the subject carries one.
4. **Optionally binds the recipient** — pass `expected_recipient` (an email, a `mailto:` URI, or a DID) and verification additionally requires `credentialSubject.id` to match; without it, only the signature, expiry and structure are checked.

```python
from openbadgeslib.ob3.verifier import OB3Verifier

v = OB3Verifier(pubkey_pem)
credential = v.verify(token, expected_recipient='recipient@example.org')
```

Every failure raises `OB3VerificationError` (a subclass of `LibOpenBadgesException`, so one `except` catches both OB2 and OB3 errors). See [[Python API OB3]] for the credential model, and [[OB2 vs OB3]] for how the two generations differ.

## OB3: the Data Integrity (LDP) path

OB 3.0's second proof format embeds a **W3C Data Integrity proof** in the
credential JSON itself instead of wrapping it in a JWT. Both directions live
in `openbadgeslib/ob3/ldp.py` (cryptosuite `eddsa-rdfc-2022`, Ed25519 only;
needs the `[ldp]` extra — see [[Installation]]) and share the same
canonicalization core: the document (without `proof`) and the proof options
(with the document's `@context` injected) are RDFC-1.0-canonicalized, hashed
(`SHA-256(config) || SHA-256(document)`), and the Ed25519 signature travels as
a multibase base58btc `proofValue`. `@context` documents are **never fetched
from the network** — only the contexts bundled with the library are accepted.

```python
from openbadgeslib.ob3 import OB3LdpSigner, OB3LdpVerifier

signer = OB3LdpSigner(ed25519_priv_pem)          # or -P ldp on the CLI
signed = signer.sign(credential)                 # dict with embedded proof
svg    = signer.sign_into_svg(credential, svg_bytes)

credential = OB3LdpVerifier(pubkey_pem=pub_pem).verify(signed)
```

The proof's `verificationMethod` decides what a verifier can trust:

| Issuer configuration | verificationMethod | Verifier trust |
| --- | --- | --- |
| `[issuer] did = auto` (or an explicit `did:web:…`) | `did:web:…#badge_N` — the method id `openbadges-publish -V 3` publishes in `did.json` | **trusted** via `--resolve-did` (DNS + TLS) |
| explicit `did:key:…` | the signing key's did:key (must match the configured DID) | valid but **self-asserted** |
| plain URL issuer (no `did`) | did:key derived from the signing key | self-asserted; verifiers must pin the key with `-k`/`-l` |

Status lists are unaffected: `openbadges-publish -V 3` signs Bitstring Status
List credentials as **VC-JWT regardless of the badge's proof format**, and
`check_status` on an LDP credential consumes them as-is (see
[[Security Model]]).

## Baking: hiding the token in an image

Both versions share `openbadgeslib/baking.py`. Keeping one implementation stops the OB2 and OB3 paths from drifting into two slightly different readers. The carrier **mechanism** is the same; only the element/keyword identifiers differ, because OB 2.0 and OB 3.0 specify different ones (selected via keyword-only args). OB2 uses `<openbadges:assertion>` / the `openbadges` iTXt keyword; OB3 uses `<openbadges:credential>` (namespace `https://purl.imsglobal.org/ob/v3p0`) / the `openbadgecredential` keyword.

### SVG — an `<openbadges:assertion>` (OB2) or `<openbadges:credential>` (OB3) element

`bake_svg()` parses the SVG, appends the version's element to the root `<svg>`, and stores the token in its `verify` attribute (plus a namespace declaration and an optional XML comment):

```xml
<openbadges:credential xmlns:openbadges="https://purl.imsglobal.org/ob/v3p0" verify="eyJhbGciOi…"/>
```

A Data Integrity credential is a JSON document rather than a compact token, so it is stored as the element's **text content** instead of the `verify` attribute (`bake_svg(..., as_text=True)`); the OB3 verifier falls back to the text node automatically and auto-detects the format by the leading `{`.

`extract_svg()` reverses it: it finds the version's node and returns the `verify` attribute value, or `None` if the element is absent. `has_svg()` reports whether one is already present (so re-signing is refused). XML is parsed with `defusedxml` to neutralize entity-expansion attacks.

### PNG — an `openbadges` (OB2) or `openbadgecredential` (OB3) iTXt chunk

`bake_png()` inserts an `iTXt` chunk (keyword `openbadges` for OB2, `openbadgecredential` for OB3) just before the trailing `IEND` chunk, with an optional `tEXt` comment chunk, and re-serializes the PNG with correct per-chunk CRCs:

```text
iTXt: "openbadgecredential" \0 <comp_flag> <comp_method> <lang> \0 <translated> \0 <token>
```

`extract_png()` does not trust a fixed byte offset — it parses the real iTXt structure (keyword, compression flag/method, language tag, translated keyword, then text), so tokens baked by any conformant tool, including compressed ones, are recovered. `has_png()` reports presence of the chunk.

Because extraction runs on **untrusted input before any signature check**, compressed iTXt text is inflated through a bounded decompressor capped at 256 KiB (`MAX_ITXT_DECOMPRESSED`); a crafted zlib bomb raises `DecompressionLimitExceeded` instead of exhausting memory.

### Extraction in the verifiers

Both the OB2 and OB3 verifiers expose the reverse step directly as `extract_token_from_svg()` and `extract_token_from_png()`, which call the baking helpers and turn a missing token into an `OB2VerificationError`/`OB3VerificationError` (and a parse failure into `ErrorParsingFile`). The legacy OB 1.0 path reads the assertion back through its `Badge`/`Assertion` objects. Either way the flow is the same: **extract the token from the image, then verify the signature (or, for a HostedBadge, fetch the authoritative copy) against a trusted anchor.**

See [[Security Model]] for the threat model behind the bounded inflate and key-trust rules, and [[Keys and Errors]] for the exceptions raised along the way.
