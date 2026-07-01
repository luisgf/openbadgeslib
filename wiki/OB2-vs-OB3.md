openbadgeslib supports two generations of the IMS Global Open Badges specification side by side. This page explains what each one is, when to pick which, how they interoperate, and how the `-V` flag and the Python packages select between them.

## The two specifications

### OpenBadges 2.0 — JWS-signed assertion

OB 2.0 builds a JSON **Assertion** payload (recipient's SHA-256 hashed email plus salt, badge metadata URLs, issuance timestamp) and signs it with the issuer's private key using **JWS compact serialisation** (RS256 for RSA, ES256 for ECC, EdDSA for Ed25519). The resulting token is baked directly into the badge image:

* **SVG** — an `<openbadges:assertion verify="…"/>` XML element
* **PNG** — an `iTXt` chunk with keyword `openbadges`

Recipient identity is *hashed* (SHA-256 + salt), so the email is not stored in clear text. Verification re-hashes the supplied email and compares it. OB 2.0 also supports expiration and revocation-list checking.

The implementation lives in `openbadgeslib.ob2` (with top-level `badge`, `signer`, `verifier` modules kept as backward-compatible shims). See [[Python API OB2]].

### OpenBadges 3.0 — W3C Verifiable Credential (JWT-VC)

OB 3.0 models the badge as a **W3C Verifiable Credential** using the **VC 2.0 data model** and signs it as a **JWT-VC** (PyJWT, RS256/ES256/EdDSA). The credential is an `OpenBadgeCredential` with structured `Issuer`, `Achievement`, and `credentialSubject` objects.

Key data-model details from `openbadgeslib/ob3/credential.py`:

* `@context` is `["https://www.w3.org/ns/credentials/v2", "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"]`
* `type` is `["VerifiableCredential", "OpenBadgeCredential"]`
* Dates use VC 2.0 field names **`validFrom` / `validUntil`** (VC 1.1 `issuanceDate` / `expirationDate` are still accepted on read)
* The credential `id` auto-generates as `urn:uuid:…` when absent
* The recipient (`recipient_id` / `credentialSubject.id`) is either `mailto:email@example.com` **or a DID** — it is *not* hashed
* The JWT wrapper carries `iss` (issuer id), `sub` (recipient), `jti`, `iat`, and optional `exp`; `OB3Verifier.verify()` cross-checks these claims against the credential body

The credential can also be baked into SVG/PNG images using the same carrier format as OB 2.0. The implementation lives in `openbadgeslib.ob3`. See [[Python API OB3]].

## Comparison at a glance

| Aspect | OpenBadges 2.0 | OpenBadges 3.0 |
| --- | --- | --- |
| `-V` value | `2` (default) | `3` |
| Token format | JWS compact serialisation | JWT-VC |
| Data model | OB 2.0 Assertion | W3C Verifiable Credentials 2.0 |
| Python package | `openbadgeslib.ob2` | `openbadgeslib.ob3` |
| Core classes | `Badge`, `Signer`, `Verifier` | `OpenBadgeCredential`, `Issuer`, `Achievement`, `OB3Signer`, `OB3Verifier` |
| Recipient identity | SHA-256 hashed email (+ salt) | `mailto:` URI **or** DID, in clear |
| Date fields | issuance + expiration in assertion | `validFrom` / `validUntil` |
| Algorithms | RS256 / ES256 / EdDSA (RSA 2048, ECC P-256, Ed25519) | RS256 / ES256 / EdDSA (RSA 2048, ECC P-256, Ed25519) |
| Image baking | SVG `<openbadges:assertion>`, PNG `iTXt` | same SVG/PNG carrier format |
| Revocation list | yes | not modelled |

## How the version is selected

The four versioned CLI tools — `openbadges-keygenerator`, `openbadges-signer`, `openbadges-verifier`, `openbadges-publish` — accept the **`-V {2,3}`** flag to select the specification version. The default is `2`. (`openbadges-init` has no `-V` flag.)

```bash
# Sign as OpenBadges 2.0 (default — -V 2 is implied)
openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/

# Sign as OpenBadges 3.0
openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/ -V 3

# Verify an OB 2.0 badge (recipient re-hashed against the assertion)
openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg -r recipient@example.com

# Verify an OB 3.0 badge, supplying the PEM public key directly with -k
openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg -r recipient@example.com \
    -V 3 -k ./config/keys/verify_rsa_key_1.pem
```

In Python, you choose the version simply by importing from the matching package:

```python
# OpenBadges 2.0
from openbadgeslib.ob2 import Badge, Signer, Verifier

# OpenBadges 3.0
from openbadgeslib.ob3 import (
    Issuer, Achievement, OpenBadgeCredential,
    OB3Signer, OB3Verifier,
)
```

For the full signing and verification workflow shared by both versions, see [[Signing and Verification]].

## When to choose which

**Choose OB 2.0** when you need to interoperate with the large existing ecosystem of Open Badges 2.0 backpacks, displayers and verifiers, or when you want the recipient's email kept as a salted hash rather than in clear text inside the credential.

**Choose OB 3.0** when you want the modern W3C Verifiable Credentials data model — DID-based recipients, structured issuer/achievement metadata, and alignment with the broader VC tooling ecosystem — or when a consumer specifically requires JWT-VC credentials.

## Interoperability notes

* **Same crypto, same images.** Both versions use the same key types (RSA 2048, ECC P-256, or Ed25519 keys generated by `openbadges-keygenerator`) and bake into the same SVG and PNG carrier format, so the image pipeline is shared. A single PEM key pair can serve either version.
* **The token inside differs.** An OB 2.0 image carries a JWS assertion; an OB 3.0 image carries a JWT-VC. A verifier must use the matching `-V` value (or the matching `OB2`/`OB3` Verifier class) — there is no automatic cross-format detection.
* **OB 3.0 reads older VC fields.** On verification, OB 3.0 accepts both VC 2.0 (`validFrom`/`validUntil`) and VC 1.1 (`issuanceDate`/`expirationDate`) field names, but always *writes* the VC 2.0 names.
* **Recipient binding differs.** OB 2.0 compares a SHA-256 hash of the supplied email; OB 3.0 binds to a `mailto:` URI or DID and `OB3Verifier.verify()` accepts an optional `expected_recipient` to assert it.

See also [[Signing and Verification]] for the end-to-end flows, [[Python API OB2]] and [[Python API OB3]] for the programmatic interfaces.
