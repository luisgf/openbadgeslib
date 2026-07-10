Build an issuer into your own application with `openbadgeslib` as a library — no shelling out to the CLI. This page narrates the runnable scripts under [`examples/`](https://github.com/luisgf/openbadgeslib/tree/master/examples) in the repo; each one is self-contained (it generates its own key and writes to a temp dir) and is executed in CI (`tests/test_examples.py`) so it can never silently drift from the API.

For the reference of every class and method see [[Python API OB3]], [[Python API OB2]] and [[Python API OB1]]; for the config file, [[Configuration]]; for the command-line equivalents, [[CLI Reference]].

## Install

```sh
pip install "openbadgeslib[ldp]"     # [ldp] adds the Data Integrity proof format
```

The base install issues and verifies OB 2.0 and OB 3.0 JWT-VC. The `[ldp]` extra adds the embedded W3C Data Integrity proof (eddsa-rdfc-2022); `[eudi]` adds the SD-JWT VC (EUDI) track.

## 1. Issue and verify an OB 3.0 credential (JWT-VC)

The core flow — build the credential from your domain objects, sign it, verify it on the receiving side. Full script: [`examples/ob3_jwt_vc.py`](https://github.com/luisgf/openbadgeslib/blob/master/examples/ob3_jwt_vc.py).

```python
from openbadgeslib.keys import KeyFactory, KeyType
from openbadgeslib.ob3 import (Achievement, Issuer, OB3Signer, OB3Verifier,
                               OpenBadgeCredential)

priv_pem, pub_pem = KeyFactory(KeyType.ED25519).generate_keypair()

credential = OpenBadgeCredential(
    issuer=Issuer(id='https://issuer.example/organization.json',
                  name='Example University'),
    recipient_id='mailto:learner@example.com',
    achievement=Achievement(id='https://issuer.example/badges/python-101',
                            name='Python 101', description='…',
                            criteria_narrative='…'))

token = OB3Signer(privkey_pem=priv_pem, algorithm='EdDSA').sign(credential)      # issue
verified = OB3Verifier(pubkey_pem=pub_pem).verify(                               # verify
    token, expected_recipient='learner@example.com')
```

Key points: the signer picks the JWS algorithm from the key type (`RS256`/`ES256`/`EdDSA`); the verifier **pins** the algorithm to the key family, so a header-declared `alg` can never downgrade it. `expected_recipient` binds the credential to the learner. To bake the token into the badge image instead of handling the raw string, use `sign_into_svg` / `sign_into_png`.

## 2. Issue with a Data Integrity proof (LDP)

The credential becomes a self-contained JSON-LD document carrying its own `proof` — no external token. Needs the `[ldp]` extra. Full script: [`examples/ob3_data_integrity.py`](https://github.com/luisgf/openbadgeslib/blob/master/examples/ob3_data_integrity.py).

```python
from openbadgeslib.ob3 import add_data_integrity_proof, OB3LdpVerifier
from openbadgeslib.ob3.did import did_key_from_pem

did = did_key_from_pem(pub_pem)                         # the issuer IS its key
vm = '%s#%s' % (did, did[len('did:key:'):])
signed = add_data_integrity_proof(credential.to_vc(), priv_pem, vm)
OB3LdpVerifier(pubkey_pem=pub_pem).verify(signed, expected_recipient='learner@example.com')
```

Here the issuer is a self-asserted `did:key`. To be a *trusted* issuer, publish a `did:web` (below) and sign with the method it declares; see the verificationMethod policy in [[Python API OB3]].

## 3. Issue from a config section (the high-level API)

`openbadgeslib.issue` is the orchestration the CLI wraps — build-from-config, salt, the status-registry→sign transaction and the proof policy — returning a `SignResult` and doing no I/O. This is the seam to integrate issuance without copying the CLI. Full script: [`examples/issue_from_config.py`](https://github.com/luisgf/openbadgeslib/blob/master/examples/issue_from_config.py).

```python
from openbadgeslib.confparser import read_config_or_exit
from openbadgeslib.issue import issue_from_conf, issue_batch_from_conf

conf = read_config_or_exit('config.ini')

result = issue_from_conf(conf, 'badge_python_101', 'learner@example.com', ob_version='3')
open('learner.svg', 'wb').write(result.badge_bytes)     # you decide where the bytes go

# A whole cohort in one call — one status-registry transaction for a revocable
# badge; a per-recipient failure is captured, not raised.
batch = issue_batch_from_conf(conf, 'badge_python_101',
                              ['a@example.com', 'b@example.com'], ob_version='3')
signed = [r for r in batch if r.result is not None]
```

`badge` is the config **section** name (`[badge_python_101]`). The `SignResult` carries `badge_bytes`, `jti`, `status_index`, `proof_format` and the `credential`; `BatchResult` carries a `SignResult` or an `error` per recipient. See the field tables in [[Python API OB3]].

## 4. Publish the issuer artefacts, then revoke

Issuing a *revocable* OB 3.0 badge (a badge section with `status_lists = revocation`) allocates a status-list index at signing time. To make verification work end to end you publish, on your web server:

- the issuer **did:web document** (`did.json`) — run `openbadges-publish -V 3 -o <webroot>`, which also writes each badge's `verify.pem` and the signed **status lists** (`revocation.jwt`);
- to **revoke** later: `openbadges-publish -V 3 --revoke <jti|email>` flips the bit and re-signs the list.

The publish/revoke lifecycle runs on the CLI (`openbadges-publish`, see [[CLI Reference]]) and programmatically via `openbadgeslib.ob3.publish_ob3(conf, output, revoke=jti_or_email) -> PublishResult` — it regenerates `did.json` and the signed status lists, applying a revoke/suspend/unsuspend first, and returns what changed without printing. The status-list internals are in [[Signing and Verification]] and [[Security Model]]. A verifier then checks revocation with `OB3Verifier(...).verify(token, check_status=True)` (or `--check-status` on the CLI), which fetches the published list and verifies **its own signature** by default (bound to the badge issuer), so a compromised status host cannot silently un-revoke a badge.

### Verifying a batch efficiently

Verification is one-shot by default, so verifying many credentials from the same issuer re-fetches the same `did.json` and status list each time. Pass a shared `CachingDownloader` as `download=` to fetch each URL once for the whole batch (a short TTL keeps revocation fresh):

```python
from openbadgeslib.ob3 import OB3Verifier, CachingDownloader

dl = CachingDownloader(ttl_seconds=300)
verifier = OB3Verifier.for_issuer_did(issuer_did, download=dl)
for token in batch:
    verifier.verify(token, check_status=True, download=dl)
```

`OB3LdpVerifier` additionally memoizes each resolved `verificationMethod` per instance, so a reused verifier does not re-resolve the issuer DID per credential.

## OpenBadges 2.0 and 1.0

The same shape applies to strict OB 2.0 (`from openbadgeslib.ob2 import OB2Signer, OB2Verifier`, see [[Python API OB2]]) and, for existing badges, the supported-legacy OB 1.0 surface (see [[Python API OB1]]). `issue_from_conf(..., ob_version='2')` issues OB 2.0; OB 1.0 issuance stays on the CLI.

## See also

- [[Certification Cookbook]] — how these credentials pass the official 1EdTech conformance tests.
- [[Quick Start]] · [[CLI Reference]] · [[Configuration]] · [[Signing and Verification]]
