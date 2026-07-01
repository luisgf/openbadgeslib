This page explains what openbadgeslib actually proves when it verifies a badge, and how to drive it so a positive verdict means something. The short version: a valid signature alone never establishes *who* issued a badge — you must supply a trusted key. See also [[Signing and Verification]] and the [[CLI Reference]].

## Trust starts with a key you supply

A cryptographic signature only proves that *whoever holds the matching private key* signed the badge. It says nothing about whether that key belongs to the issuer you trust. An OB2 badge can even point at its own verification key (`badge.source.pub_key`, downloaded from a URL baked inside the untrusted badge), so trusting that key blindly would let an attacker self-sign forgeries and have them "verify".

openbadgeslib therefore distinguishes a **trusted operator key** from the **badge-embedded key**:

- When you pass a trusted public key (`--local` to resolve it from your config, or `--pubkey FILE` to point at a PEM directly), OB2 verification runs against that key. A success is a real positive verdict — `[+]`.
- When you pass **no** trusted key, OB2 falls back to the key the badge itself points to. The signature can still be checked for internal consistency, but the verdict is downgraded to *internally consistent only* and reported with the `[~]` warning marker, because the embedded key proves nothing about issuer identity.

In `ob2/verifier.py` this is the `Verifier.check_jws_signature` logic:

```python
verify_key = self.verify_key if self.verify_key is not None else badge.source.pub_key
```

For a verdict you can rely on, always supply your own key:

```bash
# OB2 — trusted key from the badge's config section ([badge_python2026])
openbadges-verifier -i badge_signed.svg -r recipient@example.org --local python2026

# OB2 or OB3 — trusted key straight from a PEM file
openbadges-verifier -i badge_signed.svg -r recipient@example.org --pubkey ./issuer_pub.pem
```

For OB3, `OB3Verifier` is constructed *from* the public key you give it, so there is no "embedded key" fallback to worry about — but the same principle holds: the key you hand it is your root of trust.

### Algorithm pinning to the key type

A classic attack on JWT/JWS is to rewrite the token header to `alg: none` or to an HMAC algorithm (`HS256`), tricking a verifier into accepting an unsigned or attacker-keyed token (an algorithm-confusion downgrade). openbadgeslib refuses to let the token header choose the algorithm.

The accepted algorithm is **derived from the key type**, not read from the token. In `ob3/verifier.py`:

```python
_ALGORITHMS_BY_KEY_TYPE = {
    KeyType.RSA: ['RS256', 'RS384', 'RS512'],
    KeyType.ECC: ['ES256', 'ES384', 'ES512'],
    KeyType.ED25519: ['EdDSA'],
}
```

`OB3Verifier` detects the key type, restricts `jwt.decode` to that family, and additionally rejects any header `alg` outside the allowed set *before* decoding. An RSA key can never validate an `ES*` token and vice-versa, and an Ed25519 key accepts only `EdDSA`; `none` and HMAC are never in the allowed list. The OB2 `_jws.verify_block` enforces the same pinning. This blocks `none`/HMAC downgrades and cross-type confusion in one step.

## Safe handling of untrusted input

A badge file (and the URLs inside it) is attacker-controlled until proven otherwise. The library hardens every point where untrusted bytes are read or fetched — and crucially, the parsing/decompression hardening runs *before* any signature check, so a malformed badge cannot exhaust resources just by being parsed.

### HTTPS-only downloads

Verification fetches the badge JSON, the issuer profile and the revocation list over the network. `util.download_file` rejects any non-HTTPS URL by default, because an unauthenticated channel would let an active network attacker substitute their own verification key and forge badges:

```python
if u.scheme != 'https':
    if not allow_insecure:
        raise ValueError('Refusing to download ... HTTPS is required ...')
```

TLS certificate validation is on (urllib's default context), downloads time out after 30 seconds, and plain HTTP is only ever used if a caller explicitly passes `allow_insecure=True`. A redirect to a non-HTTPS target is also rejected — an HTTPS URL can't be silently downgraded via a 302 — and the response body is capped at 5 MiB to bound memory use against an oversized or attacker-influenced response.

### defusedxml for SVG (billion-laughs)

Baked SVG badges are XML. Parsing untrusted XML with a naive parser is vulnerable to entity-expansion ("billion laughs") denial-of-service. The `baking` module parses every SVG through `defusedxml.minidom.parseString`, which disables the entity-expansion vectors:

```python
from defusedxml.minidom import parseString
```

This applies to extraction (`extract_svg`), the presence check (`has_svg`) and baking itself.

### Bounded zlib decompression for PNG iTXt

A baked PNG stores the token in an `openbadges` iTXt chunk, which may be zlib-compressed. A crafted "zip bomb" could inflate a few KB into gigabytes. `baking.extract_png` caps decompression at 256 KB and raises `DecompressionLimitExceeded` rather than allocating without limit:

```python
MAX_ITXT_DECOMPRESSED = 256 * 1024
# ... _bounded_inflate raises DecompressionLimitExceeded past the cap
```

The iTXt structure is parsed properly (keyword, compression flag/method, language tag, translated keyword, then text) instead of trusting a fixed byte offset, so a malformed chunk is rejected rather than misread.

## Validity beyond the signature

A cryptographically valid signature is necessary but not sufficient. For OB2, `Verifier.get_badge_status` only returns `VALID` after the following checks also pass.

### Expiration vs now

A badge is expired when its expiration timestamp is in the past relative to the **current time**, not relative to its own issue date. From `ob2/verifier.py`:

```python
if badge.expiration < time():
    return strftime(...)   # expired
```

An expired badge is reported with status `EXPIRED`. (Badges with no expiration are simply never expired.)

### Revocation via the hosted revocationList

OB2 revocation is checked by downloading the badge JSON, following its `issuer` URL to the issuer profile, and reading the optional `revocationList`. If the issuer publishes one and the badge's serial number appears in it, verification returns `REVOKED` with the published reason:

```python
revocation_url = issuer.get('revocationList')   # optional in OB 2.0
if not revocation_url:
    return None                                 # issuer publishes no revocations
```

Note the trust implication: revocation is fetched from the **issuer's host** over HTTPS. The result is only as trustworthy as that host and its TLS. An absent `revocationList` means "no revocations published", which is treated as not-revoked. All issuer/revocation downloads and JSON parses are guarded — a missing or malformed document raises a clean library error instead of a raw crash.

### OB3 revocation via credentialStatus

The OB3 equivalent is `credentialStatus` (W3C Bitstring Status List v1.0, or the legacy StatusList2021). It is **opt-in** — `OB3Verifier.verify(..., check_status=True)` or the `--check-status` CLI flag — because verification is otherwise fully offline. When enabled, each status entry's `statusListCredential` is fetched over HTTPS, its `encodedList` is base64url-decoded and GZIP-inflated under a size cap (a bounded inflate, so a crafted status list cannot exhaust memory), and the bit at `statusListIndex` is read (MSB-first). A set revocation/suspension bit fails verification.

The check is **fail-closed**: if the status list cannot be fetched or parsed, verification fails rather than passing. It verifies the *published status bit* only — it does **not** verify the status-list credential's own signature, which is a separate trust chain (often a different key); a deployment needing that guarantee must verify the status-list credential independently.

### Recipient / identity binding

The signature does not, by itself, bind a badge to a particular recipient — you must request that check explicitly, otherwise it is skipped (not silently failed).

- **OB2:** pass `-r / --receptor` (an email). `check_identity` recomputes `sha256$ + hash_email(identity, salt)` and compares it to the badge's identity hash; on mismatch the status is `IDENTITY_ERROR`. With no identity given, the recipient check is skipped.
- **OB3:** pass `expected_recipient` to `OB3Verifier.verify()`. It is normalised (a bare email gains a `mailto:` scheme, a DID is left untouched) and compared to `credentialSubject.id`. If you do not pass it, *you* must compare `credential.recipient_id` yourself.

### OB3 cross-checks the JWT claims against the credential

A signed JWT-VC could pair valid registered claims with a mismatched credential body. After verifying the signature, `OB3Verifier._build_credential` cross-checks the JWT's `iss`/`sub` against the embedded VC:

```python
if iss is not None and iss != (vc.get("issuer") or {}).get("id"):
    raise OB3VerificationError("JWT 'iss' does not match the credential issuer")
if sub is not None and sub != (vc.get("credentialSubject") or {}).get("id"):
    raise OB3VerificationError("JWT 'sub' does not match the credentialSubject id")
```

It also requires the `vc` claim to be present and to carry the `OpenBadgeCredential` type, so an OB2 JWS token (which has no `vc` claim) is rejected with a clear message rather than misinterpreted.

### DID-based issuer identity (OB3)

`OB3Verifier.for_issuer_did(did)` (and the verifier's `--resolve-did` flag) turn an issuer DID into a verification key. Two methods are supported, each with a different trust anchor:

- **did:key** is *self-certifying*: the public key is encoded directly in the identifier (multibase base58btc of a multicodec-prefixed key). Resolving it needs no network and no external trust — the key **is** the identifier.
- **did:web** trusts the host's **DNS and TLS**: the DID document is fetched from `https://<host>/.well-known/did.json` (or a path-based `did.json`) using the same HTTPS-only, size-capped downloader, and its first verification method (`publicKeyJwk` or `publicKeyMultibase`) is used.

When `--resolve-did` is used, the DID is read from the still-unverified token and resolved; the signature is then checked against the resolved key. Because the DID is the issuer's own claimed identity, this is legitimate trust anchoring for `did:key`/`did:web` — but it is only as strong as that method's anchor (nothing for did:key beyond the key itself; DNS+TLS for did:web). Ledger/anchored methods (did:ion, did:ethr, …) are not resolved.

Beyond the claim cross-checks, the credential body itself is untrusted input, so `from_jwt_payload` validates its **structure** explicitly: `@context` must be the required VC 2.0 + OB v3p0 pair; `issuer` must be a Profile object or a string IRI; `credentialSubject` and `achievement` must be JSON objects; the required identity fields (`id`, `issuer.id`, `achievement.id`/`name`) must be present and non-empty; `credentialSubject.id` is optional (identity may travel via `identifier`); dates must be valid ISO 8601; and `credentialSubject` may be a single object or a non-empty array. A malformed credential is rejected with an `OB3VerificationError` that names the offending field, never a raw `KeyError`/`TypeError`.

## What the signature binds — the assertion, not the image

The signature covers the **assertion / credential** (recipient, achievement, issuer, dates, URLs), **not the bytes of the carrier image**. This is by design in OpenBadges: the embedded assertion is the canonical, verifiable artifact, and a correct consumer reads and validates those signed fields — it does not trust the surrounding pixels.

A practical consequence: a *valid* assertion can be lifted from one badge image and embedded into a different image, and it will still verify. That is **not a forgery** — the recipient, achievement and issuer are unchanged and still validly signed; only the decorative image differs. Nothing in the signed claims can be altered without breaking the signature.

Binding the signature to the image bytes (e.g. hashing the pixels into the payload) is deliberately **not** done: it is not part of the OB 2.0/3.0 specifications (other verifiers would ignore it, hurting interoperability) and it is fragile — baking the token changes the image, and any later re-encoding, optimisation or metadata edit would break the hash and flag legitimate badges as tampered. Trust the assertion, not the picture.

## Guidance for safe use

- **Always supply a trusted key** (`--local` or `--pubkey`) when you need a real positive verdict. Treat a `[~]` "internally consistent only" result as *unverified provenance*, never as proof of issuer identity.
- **Obtain the issuer's public key out of band** (a channel you trust), not from the badge.
- **Pass the recipient** (`-r` for OB2, `expected_recipient` for OB3) whenever the badge is meant for a specific person; otherwise the binding is your responsibility.
- **Keep `allow_insecure` off.** Do not downgrade downloads to plain HTTP.
- **Trust revocation only as far as you trust the issuer host** that serves the `revocationList`.

See the [[CLI Reference]] for the exact flags and [[Signing and Verification]] for the end-to-end workflow.
