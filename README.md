# OpenBadgesLib

[![CI](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml/badge.svg)](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/openbadgeslib.svg)](https://pypi.org/project/openbadgeslib/)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue.svg)](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-LGPLv3%20%2F%20BSD-blue.svg)](#license)

A Python library and CLI for signing and verifying
[Open Badges](https://www.imsglobal.org/activity/digital-badges) embedded in SVG
and PNG image files. It supports strict **OpenBadges 2.0** (JWS / hosted
assertions) and **OpenBadges 3.0** (W3C Verifiable Credentials / JWT-VC), plus a
frozen **OpenBadges 1.0** legacy format — selected with `-V {1,2,3}` (default `3`).

## Features

- Sign badge images (SVG and PNG) as strict OB 2.0 JWS / hosted assertions (with a frozen OB 1.0 legacy format)
- Issue and verify OpenBadges 3.0 JWT-VC credentials
- Bake OB 3.0 JWT tokens into SVG and PNG badge images
- RSA 2048-bit (RS256), ECC NIST P-256 (ES256), and Ed25519 (EdDSA) key support
- SHA-256 hashed recipient identity with salt (OB 2.0)
- Expiration and revocation checking
- Five command-line tools included

## Requirements

- Python >= 3.10 (tested on 3.10–3.13)
- [pycryptodome](https://pypi.org/project/pycryptodome/) >= 3.20
- [ecdsa](https://pypi.org/project/ecdsa/) >= 0.19
- [pypng](https://pypi.org/project/pypng/) >= 0.20220715.0
- [PyJWT[crypto]](https://pypi.org/project/PyJWT/) >= 2.8
- [cryptography](https://pypi.org/project/cryptography/) >= 42
- [defusedxml](https://pypi.org/project/defusedxml/) >= 0.7

## Installation

```bash
pip install openbadgeslib
```

All dependencies are installed automatically. For a development checkout with
the test suite and linters:

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

## Using the library — OpenBadges 3.0 (JWT-VC)

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
