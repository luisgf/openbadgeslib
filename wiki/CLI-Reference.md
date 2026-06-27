Reference for the five console scripts installed with `openbadgeslib`. Every flag, default and example below is taken directly from the source. For the meaning of config keys see [[Configuration]]; for an end-to-end walkthrough see [[Quick Start]].

All scripts except `openbadges-init` accept `-v / --version` (prints the library version and exits) and default `-c / --config` to `config.ini` in the current directory.

## openbadges-init

Bootstraps a working directory: creates the directory plus `keys/`, `images/` and `log/` subdirectories (with a restrictive `0o077` umask) and copies the bundled `config.ini.example` to `<DIRECTORY>/config.ini`.

This script does **not** use argparse. It takes a single positional argument and only recognises `-h` (which prints the usage line). It fails if the target path already exists.

### Synopsis

```sh
openbadges-init DIRECTORY
```

| Argument | Meaning | Default |
|----------|---------|---------|
| `DIRECTORY` (positional) | Directory to create and populate | required |
| `-h` | Print the usage line and exit | — |

### Example

```sh
$ openbadges-init ./myissuer
$ ls myissuer
config.ini  images  keys  log
```

If the directory already exists the script raises `FileExistsError`. Edit the generated `config.ini` before running any other command — see [[Configuration]].

## openbadges-keygenerator

Generates a PEM key pair (private signing key + public verification key) for a badge section. The key algorithm is read from the badge's `key_type` field (`RSA` or `ECC`; default `RSA`), not from a command-line flag. With no `-g`, it prints help and exits.

### Synopsis

```sh
openbadges-keygenerator -g BADGE [-c FILE] [-V {2,3}] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-g` | `--genkey BADGE` | Generate a key pair for section `[badge_<BADGE>]` (the suffix after `badge_`) | none (prints help) |
| `-V` | `--ob-version {2,3}` | OB spec version; key material is identical for both | `2` |
| `-d` | `--debug` | Show debug messages at runtime | off |
| `-v` | `--version` | Print version and exit | — |

The command refuses to overwrite: if either key file already exists it prints `[!] Key file is present at <path>` and exits with status 1.

### Example

```sh
$ openbadges-keygenerator -c ./config/config.ini -g 1
INFO - Generating OpenBadges 2 RSA key pair for issuer 'My Organisation'
INFO - Private key saved at: ./config/keys/sign_rsa_key_1.pem
INFO - Public key saved at:  ./config/keys/verify_rsa_key_1.pem
```

`-V 3` is accepted for consistency but produces identical key material:

```sh
$ openbadges-keygenerator -c ./config/config.ini -g 1 -V 3
```

## openbadges-signer

Signs a badge image (SVG or PNG) defined in `config.ini` for a recipient email and writes the baked file to the output directory. OB2 embeds a JWS assertion; OB3 embeds a JWT-VC token. The output filename is `<badge>_<receptor>.<ext>`; the script exits if that file already exists.

You **must** choose exactly one of `-e / --evidence` or `-E / --no-evidence`. Supplying neither or both exits with `Please, choose '-e' OR '-E'`.

### Synopsis

```sh
openbadges-signer -b BADGE -r RECEPTOR (-e URL | -E) [-c FILE] [-o DIR] [-M] [-x DAYS] [-V {2,3}] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-b` | `--badge` | Badge name to sign (**required**) | required |
| `-r` | `--receptor` | Recipient email of the badge (**required**) | required |
| `-o` | `--output` | Output directory for the signed badge | current dir |
| `-M` | `--mail-badge` | Email the signed badge to the recipient | off |
| `-e` | `--evidence URL` | URL to the recipient's evidence (mutually exclusive with `-E`) | none |
| `-E` | `--no-evidence` | Sign without evidence (mutually exclusive with `-e`) | off |
| `-x` | `--expires DAYS` | Expire the badge after `DAYS` days | none |
| `-V` | `--ob-version {2,3}` | `2` = JWS, `3` = JWT-VC | `2` |
| `-d` | `--debug` | Show debug messages at runtime | off |
| `-v` | `--version` | Print version and exit | — |

`-M / --mail-badge` requires an `[smtp]` section in `config.ini` (server, port, `use_ssl`, `mail_from`, optional `username`/`password`) and a `mail` entry in the badge section pointing to a text file (first line = subject, rest = body). See [[Configuration]].

### Example (OB2, JWS)

```sh
$ openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/
2026-04-22T10:00:00 badge_1 SIGNED for recipient@example.com UID 73f8981f...c0bddcbb8e24f4 at: /tmp/badge_1_recipient@example.com.svg
```

### Example (OB3, JWT-VC)

```sh
$ openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -E -o /tmp/ -V 3
2026-04-22T10:00:00 badge_1 OB3 SIGNED for recipient@example.com at: /tmp/badge_1_recipient@example.com.svg
```

For OB3 the signer auto-detects the algorithm from the private key (RS256 for RSA, ES256 for ECC).

## openbadges-verifier

Extracts the embedded assertion/credential from a signed badge image, checks the cryptographic signature, and verifies that the recipient identity matches `-r`.

**Trust note:** to get a `[+]` trusted result you must supply the issuer's public key out-of-band, via `-l BADGE` (read from `config.ini`) or `-k FILE` (a PEM path). For OB2, if you supply neither, the verifier falls back to the key the badge itself points to and reports a `[~]` warning — the signature is only *internally consistent*, which does not prove issuer identity. For OB3, supplying neither is a hard error. See [[Security Model]].

### Synopsis

```sh
openbadges-verifier -i FILE -r RECEPTOR [-l BADGE | -k FILE] [-c FILE] [-s] [-V {2,3}] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-i` | `--filein` | Signed badge file to verify (**required**) | required |
| `-r` | `--receptor` | Recipient email to check against (**required**) | required |
| `-l` | `--local BADGE` | Verify against the public key from this badge section in `config.ini` | none |
| `-k` | `--pubkey FILE` | Verify against this trusted PEM public key file (OB2 and OB3) | none |
| `-s` | `--show` | Print the assertion/credential before the result | off |
| `-V` | `--ob-version {2,3}` | `2` = JWS, `3` = JWT-VC | `2` |
| `-d` | `--debug` | Show debug messages at runtime | off |
| `-v` | `--version` | Print version and exit | — |

### Example (OB2, trusted via local config)

```sh
$ openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -l 1
[+] Signature is correct for the identity recipient@example.com
```

Without `-l` or `-k`, the same badge yields the untrusted warning:

```sh
$ openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com
[~] Signature is internally consistent for recipient@example.com, but it was verified against the key embedded in the badge itself, not a trusted issuer key. This does NOT prove issuer identity. Re-run with --local BADGE or --pubkey FILE to anchor trust.
```

### Example (OB3, trusted via PEM file)

```sh
$ openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -V 3 \
    -k ./config/keys/verify_rsa_key_1.pem
[+] OB3 signature is valid for the identity recipient@example.com
```

OB3 without `-l`/`-k` exits with `[!] OB3 verification requires --local BADGE or --pubkey FILE`. OB3 verification only supports `.svg` and `.png` inputs.

## openbadges-publish

Generates the static metadata files an OB2 issuer must host: `organization.json`, an empty `revoked.json`, and per-badge `badge.json` + `verify.pem` (the public key copied from each `[badge_*]` section). For OB3 there is nothing to publish — credentials are self-contained — and the command just prints guidance and exits.

The output directory is created with a `0o077` umask and must not already exist.

### Synopsis

```sh
openbadges-publish -o DIR [-c FILE] [-V {2,3}]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-o` | `--output` | Output directory for the public files (**required**) | required |
| `-V` | `--ob-version {2,3}` | `2` writes metadata; `3` prints guidance only | `2` |
| `-v` | `--version` | Print version and exit | — |

### Example (OB2)

```sh
$ openbadges-publish -c ./config/config.ini -o ./public
Please configure your Web server to publish the folder ./public as https://example.com/issuer/
```

### Example (OB3)

```sh
$ openbadges-publish -o ./public -V 3
[i] OpenBadges 3.0 credentials are self-contained JWT-VC tokens.
[i] No centralised metadata publication is required.
[i] Distribute the signed badge images (.svg / .png) directly to recipients.
[i] Recipients verify credentials offline using the issuer's public key.
```

If the output directory already exists, the OB2 path raises `FileExistsError`.
