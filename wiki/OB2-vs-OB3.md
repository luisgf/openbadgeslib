openbadgeslib implements three generations of the IMS Global Open Badges specification side by side, selectable with the `-V` flag (`1`, `2`, or `3`). This page explains what each one is, when to pick which, and how they interoperate.

> **Naming note.** What earlier releases shipped as `-V 2` was, in wire-format terms, the pre-2.0 model (no `@context`/`type`, a `uid` instead of an IRI `id`, a `verify` object, `hashed` as the string `"true"`, and Unix-timestamp dates). As of v3.0.0 that legacy format is honestly relabelled **OpenBadges 1.0 (`-V 1`)**, and `-V 2` is a **new, strict Open Badges 2.0** implementation. The default is now the newest version, **`-V 3`**.

## The three specifications

### OpenBadges 1.0 — legacy JWS assertion (`-V 1`)

The original pre-2.0 model, frozen for backward compatibility. It builds a JSON assertion (SHA-256 hashed recipient email + salt, badge URLs, a Unix `issuedOn`) and signs it with **JWS compact serialisation** (RS256/ES256/EdDSA). It uses `uid`, a `verify: {type, url}` object, and `hashed: "true"` (a string). No `@context`/`type` are emitted.

The implementation lives in `openbadgeslib.ob1` (with top-level `badge`, `signer`, `verifier` modules kept as backward-compatible shims for `from openbadgeslib.signer import Signer`). See [[Python API OB1]].

### OpenBadges 2.0 — strict, conformant JWS/hosted assertion (`-V 2`)

A ground-up, spec-conformant Open Badges 2.0 implementation. The assertion is a valid JSON-LD Badge Object:

* `@context` is `https://w3id.org/openbadges/v2` and `type` is `"Assertion"`
* the assertion `id` is an IRI — `urn:uuid:…` for a **SignedBadge**, or the resolvable hosting URL for a **HostedBadge** (no `uid`)
* recipient `hashed` is a real JSON **boolean**; identity is `sha256$<hex>` + salt
* dates (`issuedOn`, `expires`) are **ISO 8601** strings with a UTC offset
* verification is a `verification` object: `{"type": "SignedBadge", "creator": <CryptographicKey IRI>}` or `{"type": "HostedBadge"}`

Two verification models are supported:

* **SignedBadge** — the baked JWS is verified. The key is the operator-supplied trusted key, or (untrusted) resolved from `verification.creator` → a published `CryptographicKey` document whose `owner`/`publicKey` back-link to the issuer Profile is checked.
* **HostedBadge** — the assertion is fetched over HTTPS from its own `id`; that retrieval, scoped to the issuer's origin (default same-origin, or the issuer's `startsWith`/`allowedOrigins`), is the trust anchor. The baked JWS is checked only as non-gating defence-in-depth.

`openbadges-publish -V 2` emits conformant hosted metadata: an issuer `Profile` (with a `publicKey` array), a `BadgeClass` and a `CryptographicKey` (`key.json`) per badge, and a `RevocationList`. The implementation lives in `openbadgeslib.ob2` (`OB2Signer`, `OB2Verifier`, and dataclasses `Assertion`, `BadgeClass`, `Profile`, `CryptographicKey`, `RevocationList`). See [[Python API OB2]].

### OpenBadges 3.0 — W3C Verifiable Credential (JWT-VC) (`-V 3`, default)

OB 3.0 models the badge as a **W3C Verifiable Credential** (VC 2.0 data model) signed as a **JWT-VC** (PyJWT, RS256/ES256/EdDSA). The recipient is a `mailto:` URI or a DID (not hashed). The implementation lives in `openbadgeslib.ob3`. See [[Python API OB3]].

## Comparison at a glance

| Aspect | OB 1.0 (`-V 1`) | OB 2.0 (`-V 2`) | OB 3.0 (`-V 3`) |
| --- | --- | --- | --- |
| Token format | JWS compact | JWS compact | JWT-VC, or JSON-LD + Data Integrity proof (`-P ldp`) |
| JSON-LD `@context`/`type` | no | **yes** | yes |
| Assertion identifier | `uid` (SHA-1) | `id` IRI (`urn:uuid:`/URL) | `id` (`urn:uuid:`) |
| Verification field | `verify {type,url}` | `verification {type,creator}` | JWT proof, or Data Integrity `proof` (`eddsa-rdfc-2022`, issue and verify with the `[ldp]` extra) |
| `hashed` | string `"true"` | boolean `true` | n/a (not hashed) |
| Dates | Unix timestamp | ISO 8601 | ISO 8601 (`validFrom`/`validUntil`) |
| Recipient identity | SHA-256 email + salt | SHA-256 email + salt | `mailto:` URI **or** DID |
| Hosted verification | no (relabelled URL only) | **yes (real)** | n/a |
| CryptographicKey / RevocationList | no | **yes** | did.json + Bitstring Status Lists |
| Issuer-side revocation | edit `revoked.json` by hand | edit `revocationList` by hand | **`openbadges-publish --revoke/--suspend/--unsuspend`** |
| Python package | `openbadgeslib.ob1` | `openbadgeslib.ob2` | `openbadgeslib.ob3` |
| Core classes | `Badge`, `Signer`, `Verifier` | `OB2Signer`, `OB2Verifier`, `Assertion` | `OB3Signer`, `OB3Verifier`, `OpenBadgeCredential` |

## How the version is selected

The four versioned CLI tools — `openbadges-keygenerator`, `openbadges-signer`, `openbadges-verifier`, `openbadges-publish` — accept **`-V {1,2,3}`**. The default is **`3`** (the newest version). (`openbadges-init` has no `-V` flag.)

```bash
# Strict OB 2.0, signed (default verification model)
openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/ -V 2 -E

# Strict OB 2.0, hosted (also writes a .assertion.json to publish)
openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/ -V 2 -H -E

# Verify an OB 2.0 badge against a trusted key
openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg -r recipient@example.com \
    -V 2 -k ./config/keys/verify_rsa_key_1.pem

# Legacy OB 1.0
openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/ -V 1 -E
```

In Python, choose the version by importing from the matching package:

```python
from openbadgeslib.ob1 import Signer, Verifier, Badge          # OB 1.0 (legacy)
from openbadgeslib.ob2 import OB2Signer, OB2Verifier, Assertion  # OB 2.0 (strict)
from openbadgeslib.ob3 import OB3Signer, OB3Verifier, OpenBadgeCredential  # OB 3.0
```

## When to choose which

* **OB 2.0 (`-V 2`)** — you need a standards-conformant Open Badges 2.0 document that interoperates with the 2.0 ecosystem (backpacks, displayers, third-party verifiers).
* **OB 3.0 (`-V 3`)** — you want the modern W3C Verifiable Credentials model (DID recipients, structured issuer/achievement metadata, the broader VC tooling ecosystem).
* **OB 1.0 (`-V 1`)** — only to keep verifying badges already issued in the old pre-2.0 format; do not choose it for new deployments.

## Interoperability notes

* **Same crypto, same carrier.** All three use the same key types (RSA 2048, ECC P-256, Ed25519) and the same SVG/PNG baking module. They differ in the carrier identifiers: OB1/OB2 use `openbadges:assertion` / the `openbadges` iTXt keyword; OB3 uses `openbadges:credential` / `openbadgecredential`.
* **The token inside differs.** A verifier must use the matching `-V` value — there is no automatic cross-format detection.
* **Migration.** OB 1.0 and OB 2.0 both hash the recipient email; OB 3.0 binds to a `mailto:`/DID in clear.

See also [[Signing and Verification]] for the end-to-end flows, and [[Python API OB1]], [[Python API OB2]], [[Python API OB3]] for the programmatic interfaces.
