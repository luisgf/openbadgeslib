This page covers installing **openbadgeslib** with pip or conda, including a development setup. Once installed, head to [[Quick Start]] to sign your first badge and [[Configuration]] for the `config.ini` reference.

## Requirements

* **Python >= 3.10** (tested in CI on 3.10, 3.11, 3.12 and 3.13)
* A web server (Apache, Nginx, or IIS) and a valid TLS certificate if you intend to publish badge metadata online

### Runtime dependencies

These are resolved automatically when you install via pip:

| Package | Version | Purpose |
| --- | --- | --- |
| `pycryptodome` | `>=3.20` | RSA key generation and PEM handling |
| `ecdsa` | `>=0.19` | ECC key generation and PEM handling |
| `pypng` | `>=0.20220715.0` | PNG image manipulation |
| `PyJWT[crypto]` | `>=2.8` | JWS / JWT-VC signing and verification (pulls in `cryptography`) |
| `defusedxml` | `>=0.7` | Hardened XML parsing of untrusted SVG badges |

## Install from PyPI

```sh
pip install openbadgeslib
```

All dependencies are resolved and installed automatically. To install inside an isolated virtual environment (recommended):

```sh
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install openbadgeslib
```

To upgrade an existing install:

```sh
pip install openbadgeslib --upgrade
```

## Development install

Clone the repository and install in editable mode together with the test and lint dependencies:

```sh
git clone https://github.com/luisgf/openbadgeslib.git
cd openbadgeslib
pip install -e ".[dev]"
```

The `[dev]` extra installs `pytest>=8.0`, `pytest-cov>=5.0`, `flake8>=7.0`, `mypy>=1.8`, `pdoc>=14`, and `gitlint>=0.19`.

## Install with conda

The repository ships an `environment.yml` that pins the runtime, test, and documentation dependencies and installs the library itself in editable mode:

```sh
conda env create -f environment.yml
conda activate openbadgeslib
```

> Note: conda does not support the `[crypto]` extra syntax, so `environment.yml` lists `pyjwt` and `cryptography` separately to achieve the same result as `PyJWT[crypto]`.

## Console scripts

After installation, five command-line tools are available in the active environment's `bin/` directory (`Scripts/` on Windows):

| Command | What it does |
| --- | --- |
| `openbadges-init` | First command to run. Creates a sample `config.ini` and the directory structure (`keys/`, `images/`, `log/`). |
| `openbadges-keygenerator` | Generates an RSA or ECC key pair for a badge section defined in `config.ini`. |
| `openbadges-signer` | Signs a badge image (SVG or PNG) for a given recipient email address. |
| `openbadges-verifier` | Extracts and verifies the assertion embedded in a signed badge. |
| `openbadges-publish` | Creates the directory structure required to publish badge metadata on a web server. |

For full flags and usage of each command, see the [[CLI Reference]].

## Next steps

* [[Quick Start]] — initialise a workspace, generate keys, and sign a badge end to end.
* [[Configuration]] — the complete `config.ini` reference.
