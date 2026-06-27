[![CI](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml/badge.svg)](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/openbadgeslib.svg)](https://pypi.org/project/openbadgeslib/)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue.svg)](https://github.com/luisgf/openbadgeslib/actions/workflows/ci.yml)

**openbadgeslib** is a Python library and CLI for signing and verifying [Open Badges](https://www.imsglobal.org/activity/digital-badges) baked into SVG and PNG image files. It supports both **OpenBadges 2.0** (JWS assertions) and **OpenBadges 3.0** (W3C Verifiable Credentials as JWT-VC).

**OB 2.0 (JWS) vs OB 3.0 (JWT-VC):** OB2 embeds a JWS-signed assertion in the badge image; OB3 issues a W3C Verifiable Credential as a JWT-VC and bakes that token into the image instead. See [[OB2 vs OB3]] for the full comparison.

## Install

```bash
pip install openbadgeslib
```

All dependencies (pycryptodome, ecdsa, pypng, PyJWT[crypto], defusedxml) are installed automatically. See [[Installation]] for development setup and extras.

## What next

- [[Installation]] — requirements and how to install
- [[Quick Start]] — init, generate keys, sign, and verify a badge in four commands
- [[CLI Reference]] — the five console scripts: `openbadges-init`, `openbadges-keygenerator`, `openbadges-signer`, `openbadges-verifier`, `openbadges-publish`
- [[Python API OB2]] — `Badge`, `Signer`, `Verifier` for OpenBadges 2.0
- [[Python API OB3]] — `OpenBadgeCredential`, `OB3Signer`, `OB3Verifier` for OpenBadges 3.0
- [[Security Model]] — algorithm pinning, trusted keys, and hardened parsing

## Version

Tested on Python 3.10–3.13 (see the CI badge above). For what's in the current
release and the full history, see the
[Changelog](https://github.com/luisgf/openbadgeslib/blob/master/Changelog.txt);
for how releases are cut, see [[Releasing]].
