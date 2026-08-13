Issuing a badge to a digital wallet inverts the direction this library normally works in. The CLI pushes: you name a recipient, it produces a signed badge image. [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (OID4VCI 1.0, Final 2025-09-16) pulls: you publish an *offer*, a wallet claims it, and the credential is bound to a key the wallet proves it holds. The EU ARF names OID4VCI the issuance protocol for PID and attestations, so this is the rail an EUDI-compatible wallet expects.

`openbadgeslib.oid4vci` implements the issuer side of that, for the **pre-authorized code flow**.

## What this is, and what it is not

**It is not a server.** There are no routes, no framework, no TLS and no HTTP dependency. The package gives you handlers that take what a request carries and return what the response body should be; you mount them in whatever web framework you already run. This is the same boundary `openbadges-publish` keeps — it writes files for you to serve, it does not serve them.

**It is not HAIP-conformant, and nothing built on it may claim to be.** The [OpenID4VC High Assurance Interoperability Profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) requires DPoP, verified key attestations, client authentication and the authorization code flow. None of the four are implemented. Concretely:

- Access tokens are bearer tokens (RFC 6750). Within their short lifetime, a stolen token is replayable.
- Key attestations that arrive in a proof header are parsed and structurally checked by openvc-core (and App. D's MUST — the proof must be signed by one of the attestation's `attested_keys` — is enforced), but the attestation's own **signature is not verified** unless you opt in with `resolve_proof_key_in_context` and anchor it yourself, so by default no claim about hardware binding is possible.
- There is no rate limiting, no IP reputation and no request throttling. That is yours, at the edge.
- `vc+sd-jwt` badges are **irrevocable** — see [[Signing and Verification]].

## How the pieces divide

| Concern | Owner |
|---|---|
| Verifying the wallet's key proof — signature, `typ`, `aud`, `iat` freshness in both directions, exactly one key parameter, batch invariants | `openvc-core` |
| Parsing the Credential Request's shape (§8.2) | `openvc-core` |
| Codes, tokens, nonces, grants; their lifetimes and atomicity | `openbadgeslib` |
| Offers, discovery documents, response bodies | `openbadgeslib` |
| Routes, TLS, status codes, rate limiting, sessions | you |

The cryptography lives in openvc because it runs over attacker-supplied bytes and needs that library's raw-JWS layer; reimplementing it here would mean a second signature check free to drift from the first. Everything with a lifetime lives here, because openvc holds no state by design.

Install the extra:

```sh
pip install "openbadgeslib[oid4vci]"
```

## Configuration

```ini
[oid4vci]
; The Credential Issuer Identifier: the https base URL where you serve
; /.well-known/openid-credential-issuer. Every wallet key proof binds its
; 'aud' to this exact string. Default: [issuer] publish_url.
credential_issuer   = https://openbadges.issuer.badge/issuer/
; Where the short-lived state lives. SQLite, single host, NOT on NFS/SMB.
store_path          = ${paths:base}/oid4vci.sqlite3
offer_ttl_s         = 600
nonce_ttl_s         = 120
token_ttl_s         = 300
proof_max_age_s     = 300
tx_code_length      = 6

[badge_1]
; ... the usual keys ...
; Opt-in. Without it the badge is not published in the issuer metadata and
; cannot be offered. jwt_vc_json is revocable; vc+sd-jwt is the EUDI track and
; needs key_type = ED25519 or ECC.
oid4vci_formats = jwt_vc_json
```

`credential_issuer` must be `https`. A key proof's `aud` binds the wallet's signature to that exact string; over plaintext an attacker who can rewrite your metadata also chooses what the wallet signs for, which makes the binding decorative.

## The four endpoints

You mount these; the library computes the bodies.

| Route | Handler |
|---|---|
| `GET /.well-known/openid-credential-issuer` | `build_issuer_metadata(conf)` |
| `GET /.well-known/oauth-authorization-server` | `build_authorization_server_metadata(conf)` |
| `POST /token` | `handle_token_request(conf, code=…, tx_code=…, store=…)` |
| `POST /nonce` | `handle_nonce_request(conf, nonces=…)` |
| `POST /credential` | `handle_credential_request(conf, body, access_token=…, store=…, nonces=…)` |

Do not skip the RFC 8414 document. Without it a wallet that assumes the Credential Issuer is its own authorization server cannot find the token endpoint, and the flow stops before its first request.

With the `[oid4vci]` extra installed, both discovery documents — and every Credential Offer `build_credential_offer` returns — are passed through openvc-core's own fail-closed wire parsers before they leave the builder: a document no conformant wallet would accept becomes a `ConfigError` at build time, while you are looking, instead of a QR nobody can scan. The offer check runs before the grant is persisted, so a rejected offer leaves nothing behind.

Serve every response with `Cache-Control: no-store`.

## Wiring it up

```python
from openbadgeslib.confparser import load_config
from openbadgeslib.oid4vci import (NonceIssuer, SqliteOID4VCIStore,
                                   build_issuer_metadata,
                                   handle_credential_request,
                                   handle_nonce_request, handle_token_request)
from openbadgeslib.oid4vci.errors import OID4VCIError

conf = load_config('config.ini')
store = SqliteOID4VCIStore(oid4vci_config(conf).store_path)
nonces = NonceIssuer(store, ttl_s=120)

@app.post('/credential')
def credential(request):
    try:
        response = handle_credential_request(
            conf, request.json,
            access_token=bearer_token(request.headers),
            store=store, nonces=nonces)
    except OID4VCIError as exc:
        return json_response(exc.to_dict(), status=exc.http_status,
                             headers={'Cache-Control': 'no-store'})
    return json_response(response.to_dict(), status=200,
                         headers={'Cache-Control': 'no-store'})
```

Every `OID4VCIError` carries the spec's error code and the status to serve it with — 400 for everything except a bad access token, which RFC 6750 requires be a 401. An `IssuanceError` is **not** translated: it means your config, key or status list is broken, so it must surface as a 500. Dressing it up as `invalid_credential_request` would have the wallet retry a request that can never succeed.

### Wallets with key attestations (EU wallet stacks)

By default only proofs that carry their key **inline** (the `jwk` header parameter) are accepted. EU wallet stacks instead send the attested-key form — `{typ, alg, kid, key_attestation}` per OID4VCI 1.0 Appendix D — where the signing key lives *inside* a wallet-provider-signed attestation. To accept those, pass `resolve_proof_key_in_context=` to `handle_credential_request` (needs openvc-core ≥ 1.24):

```python
def resolve(ctx):  # ctx is openvc's ProofKeyContext — all UNVERIFIED
    attestation = ctx.key_attestation
    if attestation is None:
        raise KeyError(ctx.kid)            # inline-jwk proofs, if you allow them
    # YOUR trust decision here: verify the attestation's signature against
    # your wallet-provider anchor, check key_storage / user_authentication
    # levels, then pick which attested key ctx.kid names.
    verify_attestation_with_your_anchor(attestation)
    return dict(attestation.attested_keys[0])

handle_credential_request(conf, body, access_token=…, store=store,
                          nonces=nonces,
                          resolve_proof_key_in_context=resolve)
```

openvc enforces the one thing that is safe to enforce without trust: App. D's MUST that the proof be signed by one of the attestation's `attested_keys` (compared by RFC 7638 thumbprint). That check can only *reject* — it catches an honest wallet, or your own resolver, handing over a key the wallet never claimed. Whether the attestation itself is genuine is the resolver's job; without one, the attested-key form is refused like any other unresolved `kid`.

### Validating offers you receive

A platform that relays offers, or that wants to cross-check the by-reference documents it serves, can run the same fail-closed parser a wallet runs:

```python
from openbadgeslib.oid4vci import parse_received_credential_offer

parsed = parse_received_credential_offer(received_json)   # dict, extensions preserved
```

It requires an absolute https `credential_issuer` and a non-empty, duplicate-free `credential_configuration_ids`, and raises `OID4VCIError` (`invalid_request`) otherwise. A by-reference `credential_offer_uri` is **not** dereferenced — this library fetches nothing it was not explicitly asked to fetch.

## Making an offer

```python
from openbadgeslib.oid4vci import build_credential_offer

offer = build_credential_offer(conf, 'badge_1', 'learner@example.org',
                               store=store, tx_code=True)
print(offer.uri)       # openid-credential-offer://?credential_offer=...
print(offer.tx_code)   # 429517 — send this by a DIFFERENT channel
```

Encode `offer.uri` in a QR code with whatever library you like — the package returns the URI rather than an image, because generating one is presentation, not protocol. If `offer.fits_in_a_qr_code` is False (a long offer scans unreliably from a phone camera), serve `offer.offer_json` somewhere and use `offer.uri_by_reference(that_url)` instead.

`offer.tx_code` exists exactly once and is never recoverable — the store keeps only a scrypt digest. Deliver it over a different channel from the offer itself (email, SMS, a screen the learner is already looking at). Sending both together protects nothing, since whoever intercepts one intercepts the other. Three wrong attempts kill the grant.

## What the wallet gets

For `jwt_vc_json`, `credentialSubject.id` becomes the `did:jwk` of the key the wallet proved it holds, and the recipient's address moves to `credentialSubject.identifier` as a salted SHA-256. Both matter: without the first the credential is not bound to the wallet, and without the second the badge stops being attributable to a person. The salt is fresh per credential, so two badges for the same learner do not correlate.

For `vc+sd-jwt`, the key goes into `cnf` and the credential is selectively disclosable — but it cannot carry status, so it is permanent. `build_credential_offer` refuses to combine `vc+sd-jwt` with `status_lists` rather than hand out a badge you believe is revocable and is not.

## Choosing a store

`SqliteOID4VCIStore` is the reference implementation: stdlib, correct across processes and threads on one host, and the right default. It is **not** safe on NFS or SMB, where SQLite's locking does not work, and it cannot detect that it is on one.

For several hosts, implement the `OID4VCIStore` protocol over Redis or a shared SQL database. If you do, the contract that matters is **atomicity**: `burn_nonce`, `redeem_grant`, `record_tx_failure` and `claim_issuance` each decide something *and* record it, and each must do so indivisibly — a `SET NX`, an `INSERT … ON CONFLICT`, a `DELETE … RETURNING`. Implementing any of them as a read followed by a write reopens the replay window the key proof exists to close, and no test that runs one request at a time will notice.

`InMemoryOID4VCIStore` is for tests and demos only. It reports `multiprocess_safe = False`; under more than one worker each gets its own dictionaries, so a nonce is accepted once per worker and a code can be redeemed as many times as there are workers, with nothing in the logs to say so.

The store file holds recipient addresses and live token digests. Its directory is created `0700` and the database `0600`. **Do not back it up** — that preserves secrets and personal data past the lifetimes that are the entire point of them.

## Revocation and unclaimed reservations

A revocable badge's status-list slot is reserved when the **offer** is built, not when the wallet claims. That keeps the status registry's exclusive lock and full-file rewrite out of a concurrent HTTP path — and off the platforms where that lock silently does nothing.

The cost is that an offer nobody claims leaves its index occupied. `openbadges-publish -V 3 --list` shows those as `reserved`, and:

```sh
openbadges publish -V 3 --reclaim-unclaimed --dry-run
```

reports what could be freed. Without `--dry-run` it frees them. An index is released only when the status registry **and** the OID4VCI store agree nothing was issued against it; a reservation whose credential reached a wallet is marked delivered and keeps its index permanently, because reusing it would tie two credentials to one revocation bit. This is deliberately a manual operator action — never automatic, never on a request path.

Revoking a wallet-issued credential is the ordinary path: `openbadges-publish -V 3 --revoke <jti>`. The reservation is recorded under the credential's real `jti` from the start, precisely so this works.

## Related

- [[Signing and Verification]] — the credential formats and their proofs
- [[Security Model]] — the threat model, and what this rail does not defend
- [[Configuration]] — the full INI reference
- [[CLI Reference]] — `--reclaim-unclaimed` and the status commands
