This page explains what openbadgeslib actually proves when it verifies a badge, and how to drive it so a positive verdict means something. The short version: a valid signature alone never establishes *who* issued a badge — you must supply a trusted key. See also [[Signing and Verification]] and the [[CLI Reference]].

## Trust starts with a key you supply

A cryptographic signature only proves that *whoever holds the matching private key* signed the badge. It says nothing about whether that key belongs to the issuer you trust. An OB2 badge can even point at its own verification key (`verification.creator`, a URL baked inside the untrusted badge that resolves to a `CryptographicKey`), so trusting that key blindly would let an attacker self-sign forgeries and have them "verify".

openbadgeslib therefore distinguishes a **trusted operator key** from the **badge-embedded key**:

- When you pass a trusted public key (`--local` to resolve it from your config, or `--pubkey FILE` to point at a PEM directly), OB2 verification runs against that key. A success is a real positive verdict — `[+]`.
- When you pass **no** trusted key, OB2 falls back to the key the badge itself points to. The signature can still be checked for internal consistency, but the verdict is downgraded to *internally consistent only* and reported with the `[~]` warning marker, because the embedded key proves nothing about issuer identity.

In `ob2/verifier.py` this is the `OB2Verifier._verify_signed` logic — a trusted operator key is used directly, otherwise the key the badge declares (`verification.creator`) is resolved and the verdict is downgraded:

```python
if self.trusted_pubkey_pem is not None:
    self._verify_jws(token, self.trusted_pubkey_pem)             # trusted -> [+]
else:
    key = self._resolve_creator(assertion.verification.creator)  # badge-declared -> [~]
    self._verify_jws(token, key.public_key_pem.encode('utf-8'))
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

A cryptographically valid signature is necessary but not sufficient. For strict OB 2.0 `OB2Verifier.verify` (and, equivalently, the legacy `Verifier.get_badge_status`) only accepts a badge after the following checks also pass.

### Expiration vs now

A badge is expired when its expiration timestamp is in the past relative to the **current time**, not relative to its own issue date. Strict OB 2.0 (`ob2/verifier.py`) compares ISO 8601 datetimes; the legacy `-V 1` path (`ob1/verifier.py`) compares Unix timestamps:

```python
if badge.expiration < time():
    return strftime(...)   # expired
```

An expired badge is reported with status `EXPIRED`. (Badges with no expiration are simply never expired.)

### Revocation via the hosted revocationList

Revocation is checked by downloading the badge JSON, following its `issuer` URL to the issuer profile, and reading the optional `revocationList`. If the issuer publishes one and the badge appears in it — the assertion `id` inside the strict OB 2.0 `revokedAssertions` array, or the serial number in the legacy `-V 1` flat map — verification fails as revoked:

```python
revocation_url = issuer.get('revocationList')   # optional in OB 2.0
if not revocation_url:
    return None                                 # issuer publishes no revocations
```

Note the trust implication: revocation is fetched from the **issuer's host** over HTTPS. The result is only as trustworthy as that host and its TLS. An absent `revocationList` means "no revocations published", which is treated as not-revoked. All issuer/revocation downloads and JSON parses are guarded — a missing or malformed document raises a clean library error instead of a raw crash.

### OB3 revocation via credentialStatus

The OB3 equivalent is `credentialStatus` (W3C Bitstring Status List v1.0, or the legacy StatusList2021). It is **opt-in** — `OB3Verifier.verify(..., check_status=True)` or the `--check-status` CLI flag — because verification is otherwise fully offline. When enabled, each status entry's `statusListCredential` is fetched over HTTPS, its `encodedList` is base64url-decoded and GZIP-inflated under a size cap (a bounded inflate, so a crafted status list cannot exhaust memory), and the bit at `statusListIndex` is read (MSB-first). A set revocation/suspension bit fails verification.

The check is **fail-closed**: if the status list cannot be fetched or parsed, verification fails rather than passing. Two further guards close the classic status-list trust gaps:

- **Freshness (always on).** The list's `validFrom`/`validUntil` window is enforced: a lapsed list — a stale copy, or an issuer that stopped republishing — is rejected, so a replayed old `revocation.jwt` cannot silently resurrect a revoked badge. Issuers opt in to a bound with `status_validity_days` (a `validUntil = now + N days`) and republish within the window; a list with no `validUntil` never expires (backward compatible).
- **List proof + issuer binding (opt-in).** By default the check reads the *published status bit* only and does **not** verify the status-list credential's own signature. Pass `verify_list=True` (`check_credential_status(..., verify_list=True)` or `OB3Verifier.check_status(..., verify_list=True)`) to also verify the list's JWT-VC proof and require its issuer to equal the badge's issuer — closing the gap where a compromised status host could serve a validly-shaped list that silently un-revokes. The lists `openbadges-publish -V 3` writes are JWT-VCs signed with the **badge's own key**, so the same public key that verified the badge verifies the list (reused automatically by `OB3Verifier.check_status`); a `did:web`/`did:key` issuer is resolved otherwise. Off by default so a status check stays a single offline-friendly fetch.

On the issuer side, the index each credential occupies is recorded in a private per-badge registry under `[paths] base_status`, written with a `0o077` umask and atomically (temp file + rename). Treat it like the signer log: it names recipients, and losing it makes the outstanding credentials unrevocable. Indices are allocated randomly (`secrets`), per the spec's privacy recommendation — sequential allocation would leak issuance order and volume to anyone reading the public list.

### Recipient / identity binding

The signature does not, by itself, bind a badge to a particular recipient — you must request that check explicitly, otherwise it is skipped (not silently failed).

- **OB2:** pass `-r / --receptor` (an email). `check_identity` recomputes `sha256$ + hash_email(identity, salt)` and compares it to the badge's identity hash; on mismatch the status is `IDENTITY_ERROR`. With no identity given, the recipient check is skipped.
- **OB3:** pass `expected_recipient` to `OB3Verifier.verify()`. It is normalised (a bare email gains a `mailto:` scheme, a DID is left untouched) and compared to `credentialSubject.id`. If you do not pass it, *you* must compare `credential.recipient_id` yourself.

### OB3 cross-checks the JWT claims against the credential

OB 3.0 here is a **native** VC-JWT (§8.2.4.1): the JWT payload *is* the credential (its members at the top level, with no `vc` claim wrapper). A signed token could still pair the registered claims with a mismatched credential body, so after verifying the signature `OB3Verifier._build_credential` **requires** the mandatory claims and binds them to the credential (`iss` and `nbf` are required — their absence fails, it is not merely a when-present cross-check):

```python
iss = payload.get("iss")
if iss is None:
    raise OB3VerificationError("JWT payload is missing the required 'iss' claim")
if iss != _claim_object_id(vc.get("issuer")):        # issuer as object, IRI, or array
    raise OB3VerificationError("JWT 'iss' does not match the credential issuer")
if payload.get("nbf") is None:
    raise OB3VerificationError("JWT payload is missing the required 'nbf' claim")
sub = payload.get("sub")
subject_id = _claim_object_id(vc.get("credentialSubject"))
if subject_id is not None and sub is None:           # sub required when subject has an id
    raise OB3VerificationError("JWT payload is missing the required 'sub' claim")
if sub is not None and sub != subject_id:
    raise OB3VerificationError("JWT 'sub' does not match the credentialSubject id")
```

The payload's top-level `type` must include `VerifiableCredential` and either `OpenBadgeCredential` or its alias `AchievementCredential`; a token carrying neither (e.g. an OB2 JWS assertion, which is not a native VC-JWT) is rejected with a clear message rather than misinterpreted.

### DID-based issuer identity (OB3)

`OB3Verifier.for_issuer_did(did)` (and the verifier's `--resolve-did` flag) turn an issuer DID into a verification key. Two methods are supported, each with a different trust anchor:

- **did:key** is *self-certifying*: the public key is encoded directly in the identifier (multibase base58btc of a multicodec-prefixed key). Resolving it needs no network and no external trust — the key **is** the identifier.
- **did:web** trusts the host's **DNS and TLS**: the DID document is fetched from `https://<host>/.well-known/did.json` (or a path-based `did.json`) using the same HTTPS-only, size-capped downloader. The verification method (`publicKeyJwk` or `publicKeyMultibase`) is chosen by the JWT `kid` header when present, otherwise the first method is used (see below).

When `--resolve-did` is used, the DID is read from the still-unverified token and resolved; the signature is then checked against the resolved key. Because the DID is the issuer's own claimed identity, this is legitimate trust anchoring for `did:key`/`did:web` — but it is only as strong as that method's anchor (nothing for did:key beyond the key itself; DNS+TLS for did:web). Ledger/anchored methods (did:ion, did:ethr, …) are not resolved.

A `did.json` published by `openbadges-publish -V 3` lists one verification method **per badge**. JWT verification honours the token's `kid` header: it selects the exact `verificationMethod` the kid names (an absolute `did:web:…#badge_N` URL, or a bare `#badge_N` resolved against the issuer DID), so multi-key issuers and key rotation verify without pinning `-k`/`-l`. The kid must name a method **of the issuer's own DID** — a kid pointing at a different DID fails closed, since the token header is attacker-controlled and could otherwise redirect trust to a key the attacker publishes. A token that carries no kid still falls back to `verificationMethod[0]` (so order that method first for kid-less interop tokens).

Beyond the claim cross-checks, the credential body itself is untrusted input, so `from_jwt_payload` validates its **structure** explicitly: `@context` must be the required VC 2.0 + OB v3p0 pair; `issuer` must be a Profile object or a string IRI; `credentialSubject` and `achievement` must be JSON objects; the required identity fields (`id`, `issuer.id`, `achievement.id`/`name`) must be present and non-empty; `credentialSubject.id` is optional (identity may travel via `identifier`); dates must be valid ISO 8601; and `credentialSubject` may be a single object or a non-empty array. A malformed credential is rejected with an `OB3VerificationError` that names the offending field, never a raw `KeyError`/`TypeError`.

### Data Integrity (eddsa-rdfc-2022) issuance and verification

`OB3LdpVerifier` (the `[ldp]` extra) verifies the other proof format OB 3.0 allows: a JSON-LD credential with an embedded W3C Data Integrity proof; `OB3LdpSigner` issues them with the same canonicalization core. The algorithm follows the vc-di-eddsa Recommendation — RDFC-1.0 canonicalization of the unsecured document and of the proof configuration, SHA-256 hashing, Ed25519 signature over the combined hashes — and both directions are validated byte-for-byte against the official W3C test vectors. Security properties specific to this path:

- **JSON-LD contexts are never fetched from the network.** Canonicalization resolves every `@context` a credential names; fetching them remotely would be an SSRF vector and would let a context host silently change what a signature covers. The exact context documents (VC 2.0, the published OB v3p0 revisions, `data-integrity/v2`, `multikey/v1`) ship pinned inside the wheel with recorded provenance, behind an exact-match allowlist — a credential naming any other context URL fails closed.
- **Documents are capped at 256 KiB** before canonicalization: RDF canonicalization cost grows super-linearly on crafted blank-node graphs ("poison graphs"), and the document is attacker-supplied.
- **Proof validation is fail-closed**: exactly one `DataIntegrityProof` with a supported cryptosuite is required; `proofPurpose` must be `assertionMethod`; `proofValue` must be a 64-byte multibase signature; an expired proof or credential is rejected; an unknown cryptosuite (e.g. `ecdsa-sd-2023`, not yet supported) is rejected naming the supported ones.
- **Key binding mirrors the JWT path**: an operator-pinned key wins and must be Ed25519 for this cryptosuite. Without a pinned key, the key comes from `proof.verificationMethod`, resolved to the *exact* method the proof names (the JWT path resolves the same way from the token's `kid`); if the credential names a DID issuer, the method must belong to that DID — otherwise any keyholder could re-sign someone else's credential. A did:key is self-asserted and reported as untrusted by the CLI, exactly like the JWT `--resolve-did` case.
- **Issuance is fail-closed too**: `OB3LdpSigner` rejects non-Ed25519 keys at construction, refuses to add a second proof to an already-secured document (the verifier would reject the ambiguity), signs only against the bundled context allowlist, and derives the did:key verification method from the *private* key's public half so a stale `public_key` file cannot produce an unverifiable badge. With a did:web issuer the proof names the exact `did:web:…#badge_N` method `openbadges-publish -V 3` publishes.
- **Status lists stay VC-JWT**: `openbadges-publish -V 3` signs Bitstring Status List credentials as JWT-VCs regardless of the badge's proof format, and `check_status` on a Data Integrity credential consumes them unchanged — the status-bit trust chain is identical for both proof formats.

### X.509 / eIDAS issuer trust (SD-JWT VC) — a delegated trust boundary

The EUDI SD-JWT VC track (`openbadgeslib.ob3.eudi`, the `[eudi]` extra) can anchor issuer trust in **X.509 / an EU Trusted List** instead of a pinned key or a DID: `verify_badge_sd_jwt(token, x5c_trust_anchors=[…roots…])` verifies a badge whose issuer JWT carries an `x5c` certificate chain. This binds it to the eIDAS trust model as the binding EU Trusted List cutover proceeds (TLv6 since 2026‑04). It is important to understand where the trust decision is actually made, because it is **delegated to [openvc-core](https://github.com/luisgf/openvc)** (which builds on `cryptography`'s `PolicyBuilder`):

- **openbadgeslib guarantees the envelope, not the chain verdict.** It confirms the issuer JWT actually carries an `x5c` header before delegating, so the trust anchors can **never be silently bypassed** by a fallback to DID / issuer‑URL key resolution (a `did:jwk`/`did:key` issuer is self‑certifying and would otherwise verify against its own key) — this fails closed. Any openvc‑core failure is surfaced as `EudiError`.
- **openvc‑core owns the chain verdict:** path validation (signatures, the leaf/intermediate **temporal validity windows**, name chaining, `basicConstraints`), the leaf `SAN` ↔ `iss` binding, and a P‑256 leaf key. openbadgeslib re‑asserts these at the boundary with dedicated tests (`tests/test_ob3_eudi_x5c.py`) that run against **both** the pinned floor and the latest openvc‑core release in CI, so a drift in that external behaviour turns the build red.
- **Certificate revocation (CRL / OCSP) is NOT checked — by either layer.** `cryptography`'s path validation does not consult CRL Distribution Points or perform OCSP, and openvc‑core adds none. **A leaf that has been revoked but is still inside its validity window, with an otherwise‑valid chain, will verify.** A deployment that must honour revocation has to obtain it out of band (for example the EU Trusted List's own revocation signalling) — do not assume this call applies it. This gap is pinned by a regression test, so a future openvc‑core that starts enforcing revocation is caught by the drift job and prompts a contract/doc update.

Separately — and not to be confused with the certificate revocation above — an SD‑JWT VC badge **can** be revoked at the credential level, through the **IETF OAuth Token Status List** (#270). The issuer passes `issue_badge_sd_jwt(..., status=build_token_status_reference(uri=…, index=…))`, which is carried as an **always‑disclosed** `status` claim: a holder able to withhold the pointer could present a revoked badge as an unrevokable one, so selective disclosure never covers it. A verifier opts in with `verify_badge_sd_jwt(..., resolve_status_list_token=…)` — checked on **both** trust paths — and everything about not knowing the status fails closed: an unresolvable, wrongly‑signed, expired or URL‑swapped list raises rather than reading as "not revoked", and `require_status=True` turns a status that cannot be checked into a failure. See [[Python API OB3]] for the API.

Two limits an operator must know. First, **status format ≠ status format**: this track's IETF Token Status List and the W3C Bitstring Status List used by the VC‑JWT / Data Integrity tracks are different wire formats over different lists, so a credential carrying a `credentialStatus` is still refused at SD‑JWT issuance rather than silently mapped, and a badge issued on both tracks needs an index in each list. Second, the status list is only as trustworthy as the key you pin for it: `status_list_token_resolver(pubkey_pem=…)` verifies the list token's signature and enforces the IETF anti‑swap check (`sub` = the URL it was fetched from), which is what stops a compromised status host from un‑revoking badges.

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
- **For SD‑JWT VC / eIDAS `x5c` trust, apply certificate revocation yourself.** `verify_badge_sd_jwt(x5c_trust_anchors=…)` validates the chain and its temporal validity but does **not** consult CRL/OCSP (see the X.509 boundary above) — check revocation against the EU Trusted List out of band before trusting a leaf.

See the [[CLI Reference]] for the exact flags and [[Signing and Verification]] for the end-to-end workflow.
