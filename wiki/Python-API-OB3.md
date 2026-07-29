Programmatic guide to the OpenBadges 3.0 layer of `openbadgeslib`: building [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/), signing them as JWT-VCs, baking them into images, and verifying them. Everything here lives in the `openbadgeslib.ob3` package. For strict Open Badges 2.0 (JWS) see [[Python API OB2]], and for the legacy pre-2.0 format see [[Python API OB1]].

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
| `achievement_type` | no | OB 3.0 `achievementType` (e.g. `'Badge'`, `'Certificate'`, `'Competency'`). |
| `credits_available` | no | Academic credit (`creditsAvailable`, a float). |
| `alignments` | no | List of `Alignment` — competency-framework mappings; serialised under `alignment`. Defaults to `[]`. |
| `result_descriptions` | no | List of `ResultDescription` — the possible results this achievement can convey; serialised under `resultDescription`. Defaults to `[]`. |
| `endorsement_jwts` | no | List of compact `endorsementJwt` strings (see Endorsements). |

An **`Alignment`** (`from openbadgeslib.ob3 import Alignment`) aligns the achievement to a framework node: required `target_name`, `target_url`; optional `target_framework`, `target_code`, `target_description`. This is what an LMS reads to map a badge to a competency.

A **`ResultDescription`** (`from openbadgeslib.ob3 import ResultDescription`) declares a result the achievement can convey: required `id`, `name`, `result_type` (a `ResultType` such as `'LetterGrade'`, `'Percent'`, `'Status'`, or an `ext:` value); optional `allowed_values`, `required_value`, `required_level`, `value_min`, `value_max`, `alignments`. A `Result` on the credential subject links back to it by `id`.

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
| `evidence_url` | no | Convenience for a single-URL `Evidence`. |
| `evidence` | no | List of `Evidence` (id, narrative, name, description, genre, audience) — the full OB 3.0 `evidence` array. When set it wins over `evidence_url`; parsing populates both. Defaults to `[]`. |
| `credits_earned` | no | Academic credit the subject earned (`creditsEarned`, a float); pairs with `achievement.credits_available`. |
| `identifiers` | no | List of `IdentityObject` — hashed/plaintext `credentialSubject.identifier`, an alternative or supplement to `recipient_id`. A credential must carry at least one of `recipient_id` or `identifiers`. Defaults to `[]`. |
| `results` | no | List of `Result` — measured outcomes for the subject, each optionally linking to an achievement `ResultDescription`. Defaults to `[]`. |

An **`IdentityObject`** (`from openbadgeslib.ob3 import IdentityObject`) is a subject identity: required `identity_hash`, `identity_type` (an `IdentifierType` such as `'emailAddress'`, or an `ext:` value) and `hashed` (bool); optional `salt`. A **`Result`** (`from openbadgeslib.ob3 import Result`) records a measured outcome: optional `value`, `status` (a `ResultStatus` such as `'Completed'`), `achieved_level`, `result_description` (the `id` of the linked `ResultDescription`) and `alignments`.

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

## Issuing from a config file — `openbadgeslib.issue`

`OB3Signer` signs a credential you built yourself. To go straight from a config section to a signed badge — the orchestration `openbadges-signer` performs — call the library API instead of copying the CLI:

```python
from openbadgeslib import issue_from_conf          # or: from openbadgeslib.issue import issue_from_conf
from openbadgeslib.confparser import read_config_or_exit

conf = read_config_or_exit('config.ini')
result = issue_from_conf(conf, 'badge_1', 'learner@example.com', ob_version='3')

with open(result.badge_filename, 'wb') as f:       # writing the badge is your call
    f.write(result.badge_bytes)
print(result.jti, result.proof_format, result.status_index)
```

`issue_from_conf(conf, badge, recipient, ob_version='3', *, evidence=None, expires=None, hosted=False, proof_format=None)` builds the credential from the `[badge]` section, allocates a status-list index for a revocable badge (persisting the registry **before** signing, so a delivered badge is always revocable), applies the Data Integrity `verificationMethod` policy, signs, and returns a `SignResult`. It performs **no** user-facing I/O — no prints, no `sys.exit`, no file write:

| `SignResult` field | Notes |
| --- | --- |
| `ob_version` | `'2'` or `'3'`. |
| `badge_bytes` | The signed badge image — **you** write it. |
| `badge_filename` | Suggested basename `<badge>_<recipient>.<ext>`. |
| `jti` / `status_index` / `proof_format` | OB3 credential id, status-list index (or `None`), `'vc-jwt'`/`'ldp'`. |
| `credential` / `assertion` | The issued OB3 `OpenBadgeCredential` / OB2 `Assertion`. |
| `assertion_id` / `hosted_json` | OB2 HostedBadge URL + the assertion JSON to publish. |
| `notices` | Informational hints (e.g. the self-asserted did:key warning for a non-DID LDP issuer). |

A bad config or a policy violation — an OB2 signed badge without `crypto_key`, an `ldp` proof on a non-Ed25519 key, a did:key issuer that is not the signing key — raises `IssuanceError` (no `sys.exit`, so a caller handles it). OpenBadges 1.0 issuance is CLI-only (it is a legacy version).

To issue to **many recipients at once**, call `issue_batch_from_conf(conf, badge, recipients, ob_version='3', ...)`. It returns one `BatchResult` per recipient (each carrying a `SignResult` or an `error`), and for a revocable OB3 badge allocates every status-list index in a **single registry transaction** (load once, save once) — the piece that makes thousands-scale issuance practical. A per-recipient signing failure is captured, not raised, so it never aborts the rest; a config-level problem (or a status list without room for the whole batch) raises `IssuanceError` and nothing is issued. This is what `openbadges-signer`'s batch mode (several `-r` / `--recipients-file`) is built on.

## Verifying — `OB3Verifier`

```python
OB3Verifier(pubkey_pem)
```

On construction the verifier detects the key type and **pins** the accepted JWS algorithms to that key family (`RS*` for RSA, `ES*` for EC, `EdDSA` for Ed25519). The token header can never dictate the algorithm, so `alg:none`, an HMAC downgrade, or cross-type confusion are all rejected up front. An unsupported key type raises `OB3VerificationError`.

```python
verify(token, expected_recipient=None, check_status=False) -> OpenBadgeCredential
```

`verify()` checks the signature, expiry and structure, validates that the payload's top-level `type` is an `OpenBadgeCredential` (a `VerifiableCredential` plus `OpenBadgeCredential`/`AchievementCredential` — the native VC-JWT payload has no `vc` wrapper), and cross-checks the registered `iss`/`sub` claims against the credential's issuer/subject. On success it returns a fully reconstructed `OpenBadgeCredential`; any failure raises `OB3VerificationError`.

**Status checking is opt-in.** Verification is otherwise fully offline; pass `check_status=True` (the `--check-status` CLI flag) to additionally fetch each `credentialStatus` list over HTTPS and reject a revoked or suspended credential. The check is fail-closed and enforces the list's `validFrom`/`validUntil` window (a lapsed list is rejected — replay protection). Pass `verify_list=True` to `OB3Verifier.check_status` (or `check_credential_status`) to also verify the status list credential's own JWT-VC proof and bind its issuer to the badge's. See [[Security Model]].

**Recipient binding is opt-in.** By default `verify()` does *not* tie the credential to a recipient. Pass `expected_recipient` (a bare email, a `mailto:` URI, or a DID) to additionally require that `credentialSubject.id` matches; otherwise the caller must compare `credential.recipient_id` itself. See [[Security Model]] for why this matters.

Token extraction helpers are static methods:

- `OB3Verifier.extract_token_from_svg(svg_bytes) -> str`
- `OB3Verifier.extract_token_from_png(png_bytes) -> str`

A missing assertion raises `OB3VerificationError`; unparseable XML raises `ErrorParsingFile`.

### Endorsements (`endorsementJwt`)

An **endorsement** is a Verifiable Credential a *third party* signs to vouch for an achievement, issuer or credential (OB 3.0 `endorsementJwt`, added to context 3.0.3 by errata v1.6). The model exposes them as compact JWT strings — `credential.endorsement_jwts`, `credential.issuer.endorsement_jwts`, `credential.achievement.endorsement_jwts`, and `credential.all_endorsement_jwts()` which gathers all three levels. `openbadges-verifier --json` reports the count as `endorsements`.

Verify one with `verify_endorsement_jwt(token, download=None, endorser_pubkey_pem=None) -> dict`:

```python
from openbadgeslib.ob3 import verify_endorsement_jwt

for token in credential.all_endorsement_jwts():
    info = verify_endorsement_jwt(token)   # endorser resolved from its issuer DID
    print(info['issuer'], 'endorses', info['endorses'], '—', info['comment'])
```

It checks the endorsement's signature under the **endorser's** key (resolved from its own issuer `did:web`/`did:key`, or `endorser_pubkey_pem` when the endorser is not a DID), that it is an `EndorsementCredential`, and that its `validFrom`/`validUntil` window is current — raising `OB3VerificationError` otherwise. (`OB3Verifier.verify()` cannot be used directly: an `EndorsementCredential` is not an `OpenBadgeCredential`.)

### Recipient normalization

The signer and verifier share one normalization rule so they always agree: a bare email gains a `mailto:` scheme, while a value that already has a scheme — including a DID — is returned unchanged.

```text
recipient@example.com        -> mailto:recipient@example.com
mailto:recipient@example.com -> mailto:recipient@example.com   (unchanged)
did:example:abc123           -> did:example:abc123             (unchanged)
```

So `expected_recipient='recipient@example.com'` and `expected_recipient='mailto:recipient@example.com'` both match a credential issued to `mailto:recipient@example.com`, and a DID is never mangled into `mailto:did:...`.

## Verifying Data Integrity (LDP) credentials — `OB3LdpVerifier`

OB 3.0 allows a second proof format besides VC-JWT: a JSON-LD credential with
an embedded **W3C Data Integrity proof**. `OB3LdpVerifier` verifies those with
the same API and trust model as `OB3Verifier`, across two cryptosuites:
`eddsa-rdfc-2022` (whole-document; the `[ldp]` extra) and, for selective
disclosure, `ecdsa-sd-2023` (verify delegated to `openvc-core`; the `[ldp-sd]`
extra) — see [[Installation]]:

```python
from openbadgeslib.ob3 import OB3LdpVerifier

# Trusted key pinned by the operator:
credential = OB3LdpVerifier(pubkey_pem=pub_pem).verify(
    document, expected_recipient='recipient@example.com', check_status=False)

# Or resolve the key from the proof's verificationMethod (did:key offline,
# did:web over HTTPS). A did:key is self-asserted: internal consistency only.
credential = OB3LdpVerifier().verify(document)

# Anchor to an issuer DID (issuer AND verificationMethod must belong to it):
credential = OB3LdpVerifier.for_issuer_did('did:web:issuer.example').verify(document)
```

`document` may be the JSON string/bytes extracted from a baked image or an
already-parsed `dict`; the return value and every failure mode
(`OB3VerificationError`) match the JWT verifier, and `expected_recipient` /
`check_status` behave identically. When the key is not pinned, a proof whose
`verificationMethod` does not belong to the credential's DID issuer is
rejected fail-closed.

For advanced uses (e.g. non-OB3 Verifiable Credentials or the official W3C
test vectors) the crypto core is exposed as
`verify_data_integrity_proof(document, pubkey_pem, *, expected_proof_purpose='assertionMethod', extra_contexts=None)`,
which checks only the proof itself. `@context` documents are **never fetched
from the network** — canonicalization uses the contexts bundled with the
library (see [[Security Model]]); `extra_contexts` extends that allowlist per
call. `ecdsa-sd-2023` (selective disclosure) is verified by delegating to
`openvc-core` (the `[ldp-sd]` extra); a cryptosuite the library supports
neither natively nor by delegation (e.g. `ecdsa-rdfc-2019`) fails closed naming
the supported ones.

## Issuing Data Integrity (LDP) credentials — `OB3LdpSigner`

The issuance counterpart of `OB3LdpVerifier` (cryptosuite `eddsa-rdfc-2022`;
requires an **Ed25519** key and the `[ldp]` extra). Its API mirrors
`OB3Signer`, but the output is the signed JSON document (a `dict` with the
proof embedded under `proof`), not a compact JWT:

```python
from openbadgeslib.ob3 import OB3LdpSigner

signer = OB3LdpSigner(priv_pem)                 # did:key verificationMethod
signed = signer.sign(credential)                # dict with embedded proof
svg    = signer.sign_into_svg(credential, svg_bytes)   # baked badge image
png    = signer.sign_into_png(credential, png_bytes)
```

Without a `verification_method` argument the proof carries a **did:key**
derived from the signing key's public half — self-asserted, so verifiers must
pin the public key. Issuers publishing a DID document should pass the method
id `openbadges-publish -V 3` publishes, which verifiers resolve as trusted:

```python
signer = OB3LdpSigner(priv_pem,
                      verification_method='did:web:issuer.example#badge_1')
```

A non-Ed25519 key raises `ErrorSigningFile` at construction; signing without
the `[ldp]` extra raises it with the install hint. The schema-agnostic core is
`add_data_integrity_proof(document, privkey_pem, verification_method, *,
proof_purpose='assertionMethod', created=None, extra_contexts=None)` — the
mirror of `verify_data_integrity_proof`, able to reproduce the official W3C
vc-di-eddsa test vectors byte for byte (`created` is injectable for
deterministic output; contexts come from the same bundled allowlist).

## Issuer-side status lists

`openbadgeslib.ob3.status_list` writes what `check_credential_status` reads, and `StatusRegistry` tracks which credential owns which index:

```python
from datetime import datetime, timezone
from openbadgeslib.ob3 import (
    StatusRegistry, build_status_list_credential,
    sign_status_list_credential, status_entry,
)

LIST_URL = 'https://example.com/issuer/badge_1/revocation.jwt'

# At issue time: allocate an index and attach the credentialStatus entry.
registry = StatusRegistry.load('status/badge_1.json')
index = registry.allocate(credential.id, credential.recipient_id,
                          credential.issuance_date)
registry.save()                      # persist BEFORE signing
credential.credential_status = [status_entry(LIST_URL, 'revocation', index)]

# At publish time: rebuild and sign the list from the registry.
registry.revoke(credential.id, datetime.now(tz=timezone.utc), reason='oops')
registry.save()
vc = build_status_list_credential('https://example.com/issuer/', LIST_URL,
                                  'revocation', registry.revoked_indices(),
                                  registry.size_bits)
token = sign_status_list_credential(vc, priv_pem, 'RS256')   # host at LIST_URL
```

`StatusRegistry` also offers `suspend`/`unsuspend`, `find` (by jti or recipient email) and `suspended_indices`. Transitions raise the typed exceptions in `openbadgeslib.errors` (`AlreadyRevoked`, `NotSuspended`, `StatusListFull`, ...); revocation is permanent by design. `encode_bitstring` is exposed for tooling that only needs the raw `encodedList`.

## did:web documents

```python
from openbadgeslib.keys import public_jwk_from_pem
from openbadgeslib.ob3 import build_did_document, did_web_from_url

did = did_web_from_url('https://example.com/issuer/')   # did:web:example.com:issuer
doc = build_did_document(did, [('badge_1', public_jwk_from_pem(pub_pem))])
```

The document round-trips through `resolve_did`. JWT verification picks the method the token's `kid` header names (multi-key issuers / key rotation), so a per-badge `did:web:…#badge_N` key is selected correctly; a token with no `kid` falls back to `verificationMethod[0]`, so order the method most kid-less interop tokens need first.

## EUDI SD-JWT VC (selective disclosure)

An **additive** track — it does not touch the VC-JWT or Data Integrity issuance above: issue the same badge as an IETF **SD-JWT VC**, the credential format the EU Digital Identity Wallet / ARF converges on, delegating the crypto to [`openvc-core`](https://pypi.org/project/openvc-core/). It needs the `[eudi]` extra (see [[Installation]]):

```
pip install "openbadgeslib[eudi]"
```

The achievement is always disclosed; the recipient identity (`credentialSubject`) is *selectively disclosable*, so a holder can present the badge while withholding who they are.

**Keys:** Ed25519 (EdDSA), NIST P-256 (ES256), or NIST P-384 (ES384) — the signing algorithms `openvc-core` accepts for this track; RSA keys are rejected. The OpenID4VC High Assurance Interoperability Profile (HAIP) that EUDI wallets adopt restricts algorithms to the **P-256 (ES256)** family, so prefer a P-256 key for wallet interoperability; Ed25519 / P-384 work where HAIP-strict acceptance is not required.

```python
from openbadgeslib.ob3.eudi import issue_badge_sd_jwt, verify_badge_sd_jwt

priv_pem = open('sign_p256.pem', 'rb').read()      # P-256 -> ES256 (HAIP)

# Issue the compact SD-JWT VC: <issuer-jwt>~<disclosure>~…
token = issue_badge_sd_jwt(credential, privkey_pem=priv_pem)

# Verify the issuer form (the recipient disclosure is present):
pub_pem = open('verify_p256.pem', 'rb').read()
result = verify_badge_sd_jwt(token, pubkey_pem=pub_pem)
print(result.claims['achievement']['name'])
```

`badge_to_sd_jwt_claims(credential)` returns the flat claim set that gets signed, if you want to inspect it.

**Key binding (holder presentation).** Bind the credential to a holder key at issue time with `holder_jwk`, then verify a wallet's presentation against the transaction's audience and nonce:

```python
token = issue_badge_sd_jwt(credential, privkey_pem=priv_pem, holder_jwk=holder_public_jwk)
# … the holder builds a Key-Binding presentation with openvc-core …
result = verify_badge_sd_jwt(presentation, pubkey_pem=pub_pem,
                             audience='https://verifier.example', nonce='n-123',
                             require_key_binding=True)
assert result.key_bound
```

The OID4VCI / OID4VP wallet-exchange protocol itself lives in `openvc-core`, not here: this module maps a badge to and from SD-JWT VC claims and runs the issuer/holder crypto through it.

### Publishing Type Metadata for the badge type

A HAIP wallet self-validates a credential by resolving the **SD-JWT VC Type Metadata** its `vct` points to (draft-ietf-oauth-sd-jwt-vc §4; openvc-core ≥1.2 does this fail-closed). To make a library-issued badge self-describing, build that document for the OB 3.0 badge claim set, pin it with `vct#integrity`, and serve it at an issuer-hosted `vct`:

```python
from openbadgeslib.ob3.eudi import (badge_type_metadata, issue_badge_sd_jwt,
                                    type_metadata_document_bytes,
                                    type_metadata_integrity)

vct = 'https://issuer.example/vct/openbadge'     # a URL you host
metadata = badge_type_metadata(vct)              # achievement/name/validFrom mandatory
served = type_metadata_document_bytes(metadata)  # the exact bytes to serve at `vct`
token = issue_badge_sd_jwt(credential, privkey_pem=priv_pem, vct=vct,
                           vct_integrity=type_metadata_integrity(metadata))
```

The `vct#integrity` claim (a W3C SRI hash over the served bytes) pins the metadata, so a wallet fails closed on any tampering. `badge_type_metadata` / `type_metadata_document_bytes` / `type_metadata_integrity` are pure-Python (no `[eudi]` extra). For issuers who publish a did:web, `openbadges-publish -V 3` **emits this document for you**: set `[issuer] sd_jwt_vct` to a vct under `publish_url` and it is written into the webroot alongside `did.json` (byte-exact, `--check-live`-verified). The default `vct` stays the imsglobal purl, which ships no metadata.

### Advertising the badge over OpenID4VCI (`credential_configurations_supported`)

An OpenID4VCI issuer publishes what it can issue in the `credential_configurations_supported` object of its Credential Issuer Metadata, and a wallet picks one by `credential_configuration_id`. The *content* of the Open Badge entry is Open Badges knowledge — the `vct`, the claim set, which claims are selectively disclosable — so build it rather than hand-copying it from the spec:

```python
from openbadgeslib.ob3.eudi import badge_credential_configuration

metadata = {                                    # your document, your policy
    'credential_issuer': 'https://issuer.example',
    'credential_endpoint': 'https://issuer.example/credential',
    'nonce_endpoint': 'https://issuer.example/nonce',
    'authorization_servers': ['https://as.example'],
    'credential_configurations_supported': {
        'openbadge_sd_jwt_vc': badge_credential_configuration(
            display=[{'name': 'Python 101', 'locale': 'en'}]),
    },
}
```

The entry's `vct` is the one `issue_badge_sd_jwt()` actually stamps and its `claims` are derived from the same `badge_type_metadata()` document you serve at that `vct` — the two artifacts cannot drift, which is the failure this prevents (a wallet that rejects the credential, or displays nothing). `credential_signing_alg_values_supported` defaults to `ES256`, the HAIP algorithm for EUDI wallets; `cryptographic_binding_methods_supported` to `jwk`, matching the `holder_jwk=` key binding above. Pure-Python: no `[eudi]` extra needed.

#### Key attestations

The `jwt` proof type can also declare `key_attestations_required` — what the issuer expects a wallet to prove about where it keeps the holder's key. It is **omitted by default, and that is the normative default**, not a conservative one. OpenID4VCI 1.0 §12.2.4: *"If the Credential Issuer does not require a key attestation, this parameter MUST NOT be present in the metadata."* An empty object is not a neutral placeholder either — it is the positive claim *"a key attestation is needed without additional constraints"*. So do not add it to satisfy a strict wallet parser: you would be telling every holder that your badge demands a hardware-backed attestation, and the software wallets that cannot produce one would be locked out of an ordinary Open Badge.

An issuer that genuinely requires one asks for it, either bare or with the Appendix D.2 resistance values it accepts:

```python
badge_credential_configuration(key_attestations_required={})   # required, unconstrained

badge_credential_configuration(key_attestations_required={
    'key_storage': ['iso_18045_moderate'],
    'user_authentication': ['iso_18045_moderate'],
})
```

The shape is validated — an unknown key, an empty array (the spec says *non-empty*), a bare string where an array belongs, or a non-string level all raise `EudiError` at build time rather than at a holder's wallet. The resistance *values* are not checked: D.2 defines `iso_18045_high` / `iso_18045_moderate` / `iso_18045_enhanced-basic` / `iso_18045_basic` but lets each ecosystem define its own. Note that HAIP requires *wallets* to support key attestations (§4.5.1); it does not require issuers to demand them.

**Out of scope on purpose:** the enclosing `/.well-known/openid-credential-issuer` document (endpoints, authorization servers, per-tenant display — deployment policy, and one document per tenant in a multi-tenant issuer), the Credential Offer, the Credential Response and the nonce store. The protocol endpoints are the application's; this library supplies the format knowledge. Note that OpenID4VCI 1.0 Final carries `claims`/`display` at the top level of the configuration, which is what this emits; the EU reference issuer nests them under `credential_metadata` — nest them yourself if you must match that deployment.

### Verifying a third-party badge via eIDAS X.509 / EU Trusted Lists

`verify_badge_sd_jwt` is **JWK-pinned** by default (`pubkey_pem=…`) — right when you hold the issuer's key. To verify a badge from an **unknown** issuer whose trust root is the eIDAS X.509 world, pass `x5c_trust_anchors` instead: a received badge whose issuer JWT carries an `x5c` chain is path-validated to those roots and **bound to `iss`** before its key is used (delegated to openvc-core's `verify_credential`; the JWK-pin path cannot do X.509 trust). Needs the `[eudi]` extra.

```python
from openbadgeslib.ob3.eudi import verify_badge_sd_jwt

# Build the anchors from an EU Trusted List with openvc.trustlist (LOTL ->
# national TLs; fail-closed, caller-pinned LOTL signers, XXE-hardened). See
# openvc's docs for walk_lotl(); it returns a TrustAnchorSet whose
# `.certificates` are the trusted roots — or pass your own x509 roots.
from openvc.trustlist import walk_lotl
anchors = walk_lotl(...)                          # -> TrustAnchorSet

verified = verify_badge_sd_jwt(received_badge,
                               x5c_trust_anchors=anchors.certificates)
print('trusted issuer:', verified.issuer)         # bound to the x5c-validated chain
```

Exactly one of `pubkey_pem` / `x5c_trust_anchors` is required; the return value is the same `VerifiedSdJwt` either way. The trust-list walk is **fail-closed** (a Trusted List that can't be fetched or whose signature can't be verified contributes zero anchors) and **caller-pinned** (no implicit root); `walk_lotl`'s `select=` filters by qualified-service type. Credential revocation is checked on both paths when you pass a resolver — see the next section. (Certificate revocation, CRL/OCSP, is a different thing and is checked by neither layer; see [[Security Model]].)

### Revoking an SD-JWT VC badge (IETF Token Status List)

This track revokes through the **IETF OAuth Token Status List** — the JOSE status format SD-JWT VC uses — *not* the W3C Bitstring Status List of the VC-JWT / Data Integrity tracks. **Two formats, two lists:** they differ in bit order and compression, so a badge issued on both tracks needs two status entries pointing at two lists, not one list read two ways. Decide that before allocating indices; a credential carrying a W3C `credentialStatus` is refused by `issue_badge_sd_jwt` rather than silently mapped onto the wrong wire format.

The list itself — packing, signing, publishing — is `openvc-core`'s (`openvc.status`); openbadgeslib carries the reference into the badge and checks it at verification.

```python
from openbadgeslib.ob3.eudi import (issue_badge_sd_jwt, verify_badge_sd_jwt,
                                    status_list_token_resolver)
from openvc.status.issue import (build_status_list_token,
                                 build_token_status_reference)
from openvc.status.token_status_list import new_status_list, set_status

LIST_URI = 'https://issuer.example/status/badges-1.jwt'

# 1. Issue: the badge points at index 7 of that list. The `status` claim is
#    ALWAYS disclosed — a holder must not be able to withhold it.
token = issue_badge_sd_jwt(
    credential, privkey_pem=priv_pem,
    status=build_token_status_reference(uri=LIST_URI, index=7))

# 2. Publish the list (serve these bytes at LIST_URI):
bits = new_status_list(131072)                     # all valid
list_token = build_status_list_token(signing_key=key, uri=LIST_URI,
                                     status_list=bits)

# 3. Verify with the status check wired in:
resolve = status_list_token_resolver(pubkey_pem=pub_pem)   # fetch + verify
result = verify_badge_sd_jwt(token, pubkey_pem=pub_pem,
                             require_status=True,
                             resolve_status_list_token=resolve)

# 4. Revoke: flip the bit, re-sign, re-publish. The same badge now fails.
set_status(bits, 7, 1)                             # 1 = INVALID (revoked)
```

`resolve_status_list_token` is any `uri -> claims` callable; `status_list_token_resolver` builds the safe default — it fetches over HTTPS (SSRF-guarded, size-capped) and verifies the list token's signature with a key you pin, including the IETF anti-swap check that the token's `sub` equals the URL it came from. Without it a list served at one URL could be replayed at another to un-revoke a badge.

The two knobs are independent, and both fail closed:

| | no resolver | resolver supplied |
|---|---|---|
| `require_status=False` (default) | status not checked; badge verifies | status checked; revoked/suspended → `EudiError` |
| `require_status=True` | badge that *declares* a status → `EudiError` | same as above |

`require_status` is about a status that cannot be **checked**, not about demanding every badge carry one: a badge issued without `status=` verifies under either setting and is simply not revocable. An unreadable list — fetch failure, wrong signing key, expired token, wrong `sub` — always raises rather than being read as "not revoked".

## Presenting a Data Integrity badge over OpenID4VP (`ldp_vc`)

A wallet presents an OB 3.0 **Data Integrity** badge to a relying party as an OpenID4VP 1.0 `ldp_vc` credential: a W3C **Verifiable Presentation** wrapping the badge, secured by a holder **`authentication`** proof bound to the request (`challenge` = the request `nonce`, `domain` = the full, prefixed `client_id`). Building and verifying that presentation is the wallet-exchange rail — it lives in [`openvc-core`](https://pypi.org/project/openvc-core/), not here: openbadgeslib issues the badge, openvc-core carries it. Needs the `[ldp-sd]` extra (see [[Installation]]).

```python
from openvc.proof.data_integrity import DataIntegrityProofSuite  # eddsa-rdfc-2022
from openvc.openid4vp import verify_vp_token
from openbadgeslib.ob3.contexts import bundled_contexts

# openbadgeslib issued `secured_badge` (an OB3LdpSigner document). The holder
# wraps it in a VP and signs an `authentication` proof bound to the request:
vp = DataIntegrityProofSuite().add_proof(
    {'@context': ['https://www.w3.org/ns/credentials/v2'],
     'type': ['VerifiablePresentation'], 'holder': holder_did,
     'verifiableCredential': [secured_badge]},
    signing_key=holder_key, verification_method=holder_vm,
    proof_purpose='authentication', challenge=nonce, domain=client_id,
    extra_contexts=bundled_contexts())         # OB3 @context, fail-closed

# The verifier checks the vp_token against its DCQL query and request binding:
result = verify_vp_token(
    {'c1': [vp]}, dcql_query={'credentials': [{'id': 'c1', 'format': 'ldp_vc'}]},
    nonce=nonce, client_id=client_id, extra_contexts=bundled_contexts(),
    require_holder_binding=True)                # embedded subject must be the holder
(p,) = result.presentations
assert p.format == 'ldp_vc' and p.holder == holder_did
```

Pass openbadgeslib's `bundled_contexts()` as `extra_contexts` so openvc-core canonicalizes the badge against the same pinned OB 3.0 `@context` set, never the network. The reported `holder` is the **authenticated** signer (never a self-asserted `holder` field); `require_holder_binding=True` additionally demands every embedded credential's `credentialSubject.id` equal that holder. Runnable end to end in [`examples/ob3_openid4vp_presentation.py`](https://github.com/luisgf/openbadgeslib/blob/master/examples/ob3_openid4vp_presentation.py).

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

- [[Python API OB2]] — the strict 2.0 JWS/hosted API.
- [[Python API OB1]] — the legacy pre-2.0 JWS API.
- [[Keys and Errors]] — key generation, key objects, and the exception hierarchy.
- [[Security Model]] — algorithm pinning, recipient binding, and the threat model.
