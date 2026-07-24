# OpenBadgesLib

[![CI](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml/badge.svg)](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/openbadgeslib.svg)](https://pypi.org/project/openbadgeslib/)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue.svg)](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-LGPLv3%20%2F%20BSD-blue.svg)](#license)

**A production-ready Python library & CLI for the full Open Badges 3.0 issuer
lifecycle** — issue [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
as JWT-VC or W3C Data Integrity (LDP) proofs, bake them into SVG/PNG, verify them,
and **revoke or suspend** them
with W3C Bitstring Status Lists and `did:web`. It also ships strict
**OpenBadges 2.0** (JWS / hosted assertions) and a frozen **OpenBadges 1.0**
legacy format, selected with `-V {1,2,3}` (default `3`).

> **4.0.0 is released** (2026-07-22). It groups the breaking changes so upgrades stay rare: every CLI unifies on one `0/1/2` exit-code contract (a valid-but-untrusted badge now exits `2`, and the 255s are gone), and the legacy pycryptodome/python-ecdsa compat shim is removed — a live key **object** from either is no longer accepted, though key *files* are plain PEM and round-trip unchanged. OpenBadges 1.0 and the `openbadges-<command>` scripts stay, and a new unified `openbadges <command>` front-end joins them. **Python 3.10 is still supported** (`requires-python >= 3.10`, tested in CI on 3.10–3.14); dropping it is deferred to its end of life. See **[Upgrading to 4.0](https://github.com/luisgf/openbadgeslib/wiki/Upgrading-to-4.0)** before pinning a major.

## Features

- Sign badge images (SVG and PNG) as strict OB 2.0 JWS / hosted assertions (with a frozen OB 1.0 legacy format)
- Issue and verify OpenBadges 3.0 JWT-VC credentials
- Bake OB 3.0 credentials (JWT-VC or Data Integrity JSON-LD) into SVG and PNG badge images
- RSA 2048-bit (RS256), ECC NIST P-256 (ES256), and Ed25519 (EdDSA) key support
- SHA-256 hashed recipient identity with salt (OB 2.0)
- Expiration and revocation checking
- Issuer-side OB 3.0 revocation and suspension: W3C Bitstring Status List
  publication and `--revoke` / `--suspend` / `--unsuspend` management
- Issue and verify OB 3.0 W3C Data Integrity credentials (`eddsa-rdfc-2022`,
  optional `[ldp]` extra) in addition to JWT-VC
- Issue and verify badges as EUDI **SD-JWT VC** (the EU wallet / ARF format)
  with selective disclosure, via the optional `[eudi]` extra
- did:web issuer identity: `did.json` generation and DID resolution
- Five command-line tools included

## Why openbadgeslib

- **The complete OB 3.0 issuer lifecycle in Python** — not just issuing, but
  publishing trust artefacts (`did:web`) and revoking/suspending credentials via
  Bitstring Status Lists, driven from the CLI or the library.
- **Native VC-JWT signing** with RSA (RS256), ECC P-256 (ES256) and Ed25519
  (EdDSA) — *plus* native **W3C Data Integrity / LDP** signing
  (`eddsa-rdfc-2022`, Ed25519, optional `[ldp]` extra). Both proof formats
  issue *and* verify offline, no external service.
- **Lean and typed** — `mypy --strict`, CI on Python 3.10–3.14, a small
  dependency set, dataclasses + explicit validation (no Pydantic).
- **Dual-licensed** LGPLv3 (library) / BSD-2-Clause (CLI tools).

### How it compares

Best-effort comparison from each project's public documentation as of July 2026;
"not documented" is shown as `—`. Corrections welcome via issue/PR. The Python
Open Badges landscape splits into three groups: 1EdTech's **verify-only** OB 2.0
reference validator, heavyweight **Django server platforms** (the Badgr lineage),
and a thin tail of **standalone libraries** — of which openbadgeslib is the only
actively-maintained, pip-installable, offline one that covers all three OB
versions, both native OB 3.0 proof formats (VC-JWT and Data Integrity), and an
additive EUDI SD-JWT VC wallet track.

| Capability | **openbadgeslib** | [validator-core](https://github.com/1EdTech/openbadges-validator-core) | [Badgr / open-educational-badges](https://github.com/open-educational-badges/badgr-server) (a) | [pyopenbadges](https://github.com/CoopCodeCommun/pyopenbadges) | [didkit](https://github.com/spruceid/didkit-python) (b) |
| --- | --- | --- | --- | --- | --- |
| Open Badges versions | 1.0, 2.0, **3.0** | 0.5–2.0 | 1.1, 2.0, 3.0 | 3.0 only | generic VC |
| Issue / verify | ✅ both | verify only | issue; partial verify | both | both (VC + VP) |
| OB 3.0 proof: VC-JWT (JOSE) | ✅ RS/ES/EdDSA | — | — | roadmap | ✅ not OB-aware |
| OB 3.0 proof: Data Integrity / LDP | ✅ issue + verify (`eddsa-rdfc-2022`) | — | issue only (Ed25519) | home-grown, non-conformant | older suites; no `rdfc-2022` in wheel |
| OB 3.0 as EUDI SD-JWT VC (selective disclosure) | ✅ issue + verify (Ed25519/P-256/P-384, `[eudi]` extra) | — | — | — | — |
| Revocation / suspension | ✅ W3C Bitstring Status List | hosted check | `1EdTechRevocationList` | ad-hoc flag | — |
| `did:web` (generate + resolve) | ✅ | — | — | — | resolve only |
| Image baking (SVG + PNG) | ✅ | unbake only | ✅ | — | — |
| Form factor | library + 5 CLI tools | library + CLI | Django server | library | binding |
| Typing / CI | `mypy --strict`, CI 3.10–3.14 | — | — | Pydantic | — |
| License | LGPLv3 / BSD-2 | Apache-2.0 | AGPL-3.0 | MIT/LGPL | Apache-2.0 |

(a) The actively-maintained community fork (open-educational-badges): it
genuinely issues OB 3.0 Data Integrity credentials, but only as a server (not a
pip library) and only with Ed25519 (no VC-JWT). The classic Concentric Sky
`badgr-server` is OB 2.0 and its canonical repo is gone; SURF's
`edubadges-server` delegates OB 3.0 signing to external agents.
(b) Generic W3C VC/DID toolkit (Rust `ssi` bindings), not Open Badges-aware, and
archived (read-only since July 2025).

For authoritative OB 2.0 *validation* semantics, 1EdTech's Python
[`openbadges-validator-core`](https://github.com/1EdTech/openbadges-validator-core)
and Node [`openbadges-validator`](https://github.com/mozilla/openbadges-validator)
remain the reference; openbadgeslib focuses on the full issuer lifecycle across
all three OB versions.

## Requirements

- Python >= 3.10 (tested on 3.10–3.14)
- [pypng](https://pypi.org/project/pypng/) >= 0.20220715.0
- [PyJWT[crypto]](https://pypi.org/project/PyJWT/) >= 2.8
- [cryptography](https://pypi.org/project/cryptography/) >= 42
- [defusedxml](https://pypi.org/project/defusedxml/) >= 0.7

## Installation

```bash
pip install openbadgeslib
```

All dependencies are installed automatically. The two OB 3.0 side-tracks ship
as optional extras (the base install stays lean):

```bash
pip install "openbadgeslib[ldp]"    # W3C Data Integrity issuance/verification
pip install "openbadgeslib[eudi]"   # EUDI SD-JWT VC (pulls openvc-core)
```

For a development checkout with the test suite and linters:

```bash
pip install -e ".[dev]"
```

## Quick Start

```bash
# 1. Initialize a configuration directory
openbadges-init ./config/

# 2. Generate a key pair for a badge
openbadges-keygenerator -c ./config/config.ini -g 1

# 3a. Sign a badge — OpenBadges 3.0 (default)
openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/ -E

# 3b. Sign a badge — strict OpenBadges 2.0
openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/ -E -V 2

# 4a. Verify — OpenBadges 3.0
openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -V 3 -k ./config/keys/verify_rsa_key_1.pem

# 4b. Verify — strict OpenBadges 2.0 (pin a trusted key with -l/--local or -k/--pubkey)
openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -V 2 -l 1

# 5. OpenBadges 3.0 revocation (opt-in: set 'status_lists = revocation, suspension'
#    in the badge section before signing). Publish the issuer's did.json and the
#    signed Bitstring Status Lists, then revoke and re-publish.
openbadges-publish -c ./config/config.ini -o ./public -V 3
openbadges-publish -c ./config/config.ini -o ./public -V 3 \
    --revoke recipient@example.com --reason "issued in error"
```

See the [Quick Start](https://github.com/luisgf/openbadgeslib/wiki/Quick-Start)
and [CLI Reference](https://github.com/luisgf/openbadgeslib/wiki/CLI-Reference)
wiki pages for the full walkthrough and every flag.

## Using the library — OpenBadges 2.0 (strict)

```python
from datetime import datetime, timezone
from openbadgeslib.ob2 import OB2Signer, Assertion, IdentityObject, Verification

with open('sign.pem', 'rb') as f:
    priv_pem = f.read()
with open('badge.svg', 'rb') as f:
    image = f.read()

assertion = Assertion(
    recipient=IdentityObject.create('recipient@example.com', salt='s4lt3d'),
    badge='https://example.com/badge_1/badge.json',
    verification=Verification(type='SignedBadge',
                              creator='https://example.com/badge_1/key.json'),
    issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
)

signer = OB2Signer(privkey_pem=priv_pem, algorithm='RS256')
baked_svg = signer.sign_into_svg(assertion, image)
with open('/tmp/signed_badge.svg', 'wb') as f:
    f.write(baked_svg)
```

For the frozen OpenBadges 1.0 legacy API (`Badge` / `Signer` / `Verifier`), import from `openbadgeslib.ob1` instead.

## Using the library — OpenBadges 3.0

OB 3.0 credentials can be secured with either of the two proof formats the
spec allows: a compact **VC-JWT** (`OB3Signer`, RS256/ES256/EdDSA) or an
embedded **Data Integrity** proof (`OB3LdpSigner`, cryptosuite
`eddsa-rdfc-2022`, Ed25519 only — needs the `[ldp]` extra). Both bake into
the same SVG/PNG carriers and the verifier auto-detects the format.

### VC-JWT (JOSE)

```python
from openbadgeslib.ob3 import (
    Issuer, Achievement, OpenBadgeCredential, OB3Signer, OB3Verifier,
)

issuer = Issuer(id='https://example.com/issuer', name='Example Org')
achievement = Achievement(
    id='https://example.com/achievements/python',
    name='Python Developer',
    description='Awarded for Python proficiency',
    criteria_narrative='Must pass the Python assessment',
)
credential = OpenBadgeCredential(
    issuer=issuer,
    recipient_id='mailto:recipient@example.com',
    achievement=achievement,
)

with open('sign.pem', 'rb') as f:
    priv_pem = f.read()
signer = OB3Signer(privkey_pem=priv_pem, algorithm='RS256')

# Bake the signed JWT-VC into a badge image
with open('badge.svg', 'rb') as f:
    baked_svg = signer.sign_into_svg(credential, f.read())

# Verify
with open('verify.pem', 'rb') as f:
    verifier = OB3Verifier(pubkey_pem=f.read())
token = OB3Verifier.extract_token_from_svg(baked_svg)
restored = verifier.verify(token, expected_recipient='recipient@example.com')
print('Recipient:', restored.recipient_id)
```

### Data Integrity (LDP)

Same credential, an embedded JSON-LD proof instead of a JWT. Requires an
Ed25519 signing key and the `[ldp]` extra (`pip install openbadgeslib[ldp]`).
Reuse the `credential` built above:

```python
from openbadgeslib.ob3 import OB3LdpSigner, OB3LdpVerifier

with open('sign_ed25519.pem', 'rb') as f:
    priv_pem = f.read()

# Bake a credential carrying an eddsa-rdfc-2022 DataIntegrityProof into an SVG
signer = OB3LdpSigner(priv_pem)
with open('badge.svg', 'rb') as f:
    baked_svg = signer.sign_into_svg(credential, f.read())

# Verify (the LDP credential travels as JSON in the baked image)
with open('verify_ed25519.pem', 'rb') as f:
    verifier = OB3LdpVerifier(pubkey_pem=f.read())
document = OB3Verifier.extract_token_from_svg(baked_svg)
restored = verifier.verify(document, expected_recipient='recipient@example.com')
print('Recipient:', restored.recipient_id)
```

From the CLI, select the format with `openbadges-signer -P ldp` (OB 3.0 only),
or set `proof_format = ldp` in the badge's INI section; the default stays
`vc-jwt`. Status lists remain VC-JWT regardless of the badge's proof format.

### EUDI SD-JWT VC (selective disclosure)

An **additive** track: issue the same badge as an IETF **SD-JWT VC** — the
format the EU Digital Identity Wallet / ARF converges on — delegating the
crypto to the generic [`openvc-core`](https://pypi.org/project/openvc-core/)
library. It does not touch the native VC-JWT / Data Integrity issuance above:
it is a separate credential format for wallet flows, not a third image proof.
Needs the `[eudi]` extra (`pip install "openbadgeslib[eudi]"`) and an Ed25519
(EdDSA), NIST P-256 (ES256) or P-384 (ES384) key — SD-JWT's algorithm set (RSA
is rejected). HAIP profiles the P-256 family, so P-256 stays the safe default
for EUDI wallets; P-384 may be refused by HAIP-strict verifiers.
The achievement is always disclosed; the recipient identity is *selectively
disclosable*, so a holder can prove the badge while withholding who they are.

```python
from openbadgeslib.ob3.eudi import issue_badge_sd_jwt, verify_badge_sd_jwt

with open('sign_ed25519.pem', 'rb') as f:
    priv_pem = f.read()

# Issue the compact SD-JWT VC (<issuer-jwt>~<disclosure>~…). Reuse `credential`.
token = issue_badge_sd_jwt(credential, privkey_pem=priv_pem)

# Verify the issuer form (or a later holder presentation)
with open('verify_ed25519.pem', 'rb') as f:
    pub_pem = f.read()
result = verify_badge_sd_jwt(token, pubkey_pem=pub_pem)
print('Achievement:', result.claims['achievement']['name'])
```

Pass `holder_jwk=` at issuance to bind the credential to a holder key, then
build a Key-Binding presentation (`SdJwtVcProofSuite.create_presentation`,
bound to an audience + nonce) for the EUDI wallet flow. This track is
library-only — there is no CLI tool for it.

## Documentation

- **User & developer guide** — the project [**Wiki**](https://github.com/luisgf/openbadgeslib/wiki):
  installation, configuration, concepts, the security model, CLI reference and
  how-to guides.
- **API reference** — generated from the docstrings and published at
  [**luisgf.github.io/openbadgeslib**](https://luisgf.github.io/openbadgeslib/).

## Running the test suite

```bash
pytest
pytest --cov=openbadgeslib      # with coverage report
flake8 openbadgeslib tests      # lint
mypy                            # type check (config in pyproject.toml)
```

## Contributing

Bug reports,
[capability requests](https://github.com/luisgf/openbadgeslib/issues/new/choose)
(the roadmap's demand signal), and pull requests are welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow and the supported-Python
policy, and [`GOVERNANCE.md`](GOVERNANCE.md) for maintenance and release
governance. Security issues go through [`SECURITY.md`](SECURITY.md), never a
public issue.

## Changelog

See [`Changelog.txt`](Changelog.txt) for the full history, and the
[GitHub Releases](https://github.com/luisgf/openbadgeslib/releases) page for
release notes.

## License

The **library** (`openbadgeslib/` package) is licensed under the
[GNU Lesser General Public License v3](https://opensource.org/licenses/lgpl-3.0.html)
(LGPLv3). The **command-line wrapper tools** are licensed under the
[BSD 2-Clause](https://opensource.org/licenses/BSD-2-Clause) license.

## Authors

- Luis González Fernández <luisgf@luisgf.es>
- Jesús Cea Avión <jcea@jcea.es>
