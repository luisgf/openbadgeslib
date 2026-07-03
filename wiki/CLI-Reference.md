Reference for the five console scripts installed with `openbadgeslib`. Every flag, default and example below is taken directly from the source. For the meaning of config keys see [[Configuration]]; for an end-to-end walkthrough see [[Quick Start]].

All scripts except `openbadges-init` accept `-v / --version` (prints the library version and exits) and default `-c / --config` to `config.ini` in the current directory.

## openbadges-init

Bootstraps a working directory: creates the directory plus `keys/`, `images/`, `log/` and `status/` subdirectories (with a restrictive `0o077` umask) and copies the bundled `config.ini.example` to `<DIRECTORY>/config.ini`.

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
config.ini  images  keys  log  status
```

If the target path already exists the script prints `[!] <path> already exists` and exits with a non-zero status. Edit the generated `config.ini` before running any other command — see [[Configuration]].

## openbadges-keygenerator

Generates a PEM key pair (private signing key + public verification key) for a badge section. The key algorithm is read from the badge's `key_type` field (`RSA`, `ECC`, or `ED25519`; default `RSA`), not from a command-line flag. With no `-g`, it prints help and exits.

### Synopsis

```sh
openbadges-keygenerator -g BADGE [-c FILE] [-V {1,2,3}] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-g` | `--genkey BADGE` | Generate a key pair for section `[badge_<BADGE>]` (the suffix after `badge_`) | none (prints help) |
| `-V` | `--ob-version {1,2,3}` | OB spec version; key material is identical for all | `3` |
| `-d` | `--debug` | Show debug messages at runtime | off |
| `-v` | `--version` | Print version and exit | — |

The command refuses to overwrite: if either key file already exists it prints `[!] Key file is present at <path>` and exits with status 1.

### Example

```sh
$ openbadges-keygenerator -c ./config/config.ini -g 1
INFO - Generating OpenBadges 3 RSA key pair for issuer 'OpenBadge issuer'
INFO - Private key saved at: ./config/keys/sign_rsa_key_1.pem
INFO - Public key saved at:  ./config/keys/verify_rsa_key_1.pem
```

Key material is identical for every version, so `-V` changes only the version shown in the log line; `-V 1` / `-V 2` produce the same keys:

```sh
$ openbadges-keygenerator -c ./config/config.ini -g 1 -V 2
```

## openbadges-signer

Signs a badge image (SVG or PNG) defined in `config.ini` for a recipient email and writes the baked file to the output directory. OB2 embeds a JWS assertion; OB3 embeds a JWT-VC token. The output filename is `<badge>_<receptor>.<ext>`; the script exits if that file already exists.

You **must** choose exactly one of `-e / --evidence` or `-E / --no-evidence`. Supplying neither or both exits with `Please, choose '-e' OR '-E'`.

### Synopsis

```sh
openbadges-signer -b BADGE -r RECEPTOR (-e URL | -E) [-c FILE] [-o DIR] [-M] [-H] [-x DAYS] [-V {1,2,3}] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-b` | `--badge` | Badge name to sign (**required**) | required |
| `-r` | `--receptor` | Recipient email of the badge (**required**) | required |
| `-o` | `--output` | Output directory for the signed badge | current dir |
| `-M` | `--mail-badge` | Email the signed badge to the recipient (OB 1.0 only) | off |
| `-H` | `--hosted` | OB 2.0 only (`-V 2`): use HostedBadge verification (publish the assertion JSON at its own URL) instead of a SignedBadge JWS; requires `hosted_assertions_base` in the badge section | off |
| `-e` | `--evidence URL` | URL to the recipient's evidence (mutually exclusive with `-E`) | none |
| `-E` | `--no-evidence` | Sign without evidence (mutually exclusive with `-e`) | off |
| `-x` | `--expires DAYS` | Expire the badge after `DAYS` days | none |
| `-V` | `--ob-version {1,2,3}` | `1` = legacy JWS (OB 1.0), `2` = strict OB 2.0 JWS, `3` = JWT-VC | `3` |
| `-d` | `--debug` | Show debug messages at runtime | off |
| `-v` | `--version` | Print version and exit | — |

`-M / --mail-badge` requires an `[smtp]` section in `config.ini` (server, port, `use_ssl`, `mail_from`, optional `username`/`password`) and a `mail` entry in the badge section pointing to a text file (first line = subject, rest = body). See [[Configuration]].

### Example (OB2, JWS)

```sh
$ openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/ -V 2
2026-04-22T10:00:00 badge_1 OB2 SIGNED for recipient@example.com at: /tmp/badge_1_recipient@example.com.svg
```

### Example (OB3, JWT-VC)

```sh
$ openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -E -o /tmp/ -V 3
2026-04-22T10:00:00 badge_1 OB3 SIGNED for recipient@example.com at: /tmp/badge_1_recipient@example.com.svg
```

For OB3 the signer auto-detects the algorithm from the private key (RS256 for RSA, ES256 for ECC, EdDSA for Ed25519).

## openbadges-verifier

Extracts the embedded assertion/credential from a signed badge image, checks the cryptographic signature, and verifies that the recipient identity matches `-r`.

For OB3 the baked payload's format is **autodetected**: a compact JWT-VC is verified as before, while a JSON credential document secured with a W3C Data Integrity proof (`eddsa-rdfc-2022`) is verified through the same flags — no new options — provided the `[ldp]` extra is installed (`pip install "openbadgeslib[ldp]"`; without it the failure reason carries that hint). See [[Installation]] and [[Python API OB3]].

**Trust note:** to get a `[+]` trusted result you must supply the issuer's public key out-of-band, via `-l BADGE` (read from `config.ini`) or `-k FILE` (a PEM path). For OB2, if you supply neither, the verifier falls back to the key the badge itself points to and reports a `[~]` warning — the signature is only *internally consistent*, which does not prove issuer identity. For OB3, supplying neither is a hard error (or pass `--resolve-did`, which for a Data Integrity credential resolves the proof's `verificationMethod`). See [[Security Model]].

### Synopsis

```sh
openbadges-verifier -i FILE -r RECEPTOR [-l BADGE | -k FILE] [-c FILE] [-s] [--check-status] [--resolve-did] [--json] [-V {1,2,3}] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-i` | `--filein` | Signed badge file to verify (**required**) | required |
| `-r` | `--receptor` | Recipient email to check against (**required**) | required |
| `-l` | `--local BADGE` | Verify against the public key from this badge section in `config.ini` | none |
| `-k` | `--pubkey FILE` | Verify against this trusted PEM public key file (OB2 and OB3) | none |
| `-s` | `--show` | Print the assertion/credential before the result | off |
| | `--check-status` | OB3 only: fetch the `credentialStatus` list and reject a revoked/suspended credential (requires network) | off |
| | `--resolve-did` | OB3 only: when no trusted key is given, resolve the issuer DID (did:key/did:web) from the token to obtain the verification key | off |
| | `--json` | Emit a machine-readable JSON result instead of the human output (exit `0` = valid and issuer-trusted, `2` = valid signature but issuer untrusted, `1` = failure) | off |
| `-V` | `--ob-version {1,2,3}` | `1` = legacy JWS (OB 1.0), `2` = strict OB 2.0 JWS, `3` = JWT-VC | `3` |
| `-d` | `--debug` | Show debug messages at runtime | off |
| `-v` | `--version` | Print version and exit | — |

For OB3, `--check-status` resolves each `credentialStatus` entry (W3C Bitstring Status List v1.0 or the legacy StatusList2021), fetches the referenced status list over HTTPS, and rejects the badge if its revocation/suspension bit is set. It is **fail-closed**: an unreachable or malformed status list is treated as a verification failure, not a pass. Only the published status bit is checked, not the status-list credential's own signature. See [[Security Model]].

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

OB3 without `-l`/`-k`/`--resolve-did` exits with `[!] OB3 verification requires --local BADGE, --pubkey FILE, or --resolve-did`. OB3 verification only supports `.svg` and `.png` inputs.

With `--resolve-did` and no explicit key, the issuer DID is read from the (still-unverified) token and resolved to a key, and the signature is then checked against it. `did:key` is self-certifying (the key is encoded in the identifier) and needs no network; `did:web` fetches `https://<host>/.well-known/did.json` (or a path-based `did.json`) and therefore trusts the host's DNS and TLS. See [[Security Model]].

### JSON output

With `--json`, the verifier prints a single JSON object instead of the human `[+]/[-]/[~]` lines. Its exit status reflects issuer trust, not merely signature validity: `0` when the badge is valid **and** the issuer is trusted, `2` when the signature is valid but the issuer is not anchored (an OB2 badge-embedded key or a self-asserted `did:key`), and `1` on any failure — so a CI gate keying on exit `0` never accepts a signature that does not prove issuer identity. Common fields: `valid` (bool), `ob_version` (`"2"`/`"3"`), `recipient`, `trusted` (bool), and `reason` (`null` on success, a message otherwise). OB2 adds `status` (`VALID`/`EXPIRED`/`REVOKED`/…); OB3 adds `issuer`, `achievement`, `issued_on`, `expires`, `evidence`, `proof_format` (`"vc-jwt"` or `"ldp"`, per the autodetected payload), and `issuer_did` when the key came from `--resolve-did`.

```sh
$ openbadges-verifier -i badge.svg -r recipient@example.com -V 3 -k verify.pem --json
{"ob_version": "3", "recipient": "recipient@example.com", "trusted": true, "valid": true, "proof_format": "vc-jwt", "issuer": "Issuer", "achievement": "A", "issued_on": "2026-01-01T00:00:00+00:00", "expires": null, "evidence": null, "reason": null}
```

## openbadges-publish

Generates the static files an issuer must host, and (for OB3) manages credential status.

- **OB1/OB2**: `organization.json`, an empty `revoked.json`, and per-badge `badge.json` + `verify.pem` (OB 2.0 adds `key.json`). The output directory must not already exist.
- **OB3** (default): the issuer's did:web document (`did.json`) and, for every badge with `status_lists` configured, its signed [[Bitstring Status List|Glossary]] credentials (`badge_N/revocation.jwt`, `badge_N/suspension.jwt`) plus `verify.pem`. Everything is regenerated from the per-badge status registries on each run, so the output directory **may** already exist and managed files are replaced atomically. Re-run and re-upload after every status change.

The output directory is created with a `0o077` umask.

### Synopsis

```sh
openbadges-publish -o DIR [-c FILE] [-V {1,2,3}]
openbadges-publish -o DIR -V 3 [--revoke ID | --suspend ID | --unsuspend ID] [--reason TEXT] [-b BADGE]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-o` | `--output` | Output directory for the public files (**required**) | required |
| `-V` | `--ob-version {1,2,3}` | `1`/`2` write hosted metadata (OB 2.0 adds `key.json`); `3` writes `did.json` + status lists | `3` |
| — | `--revoke ID` | OB3 only: permanently revoke a credential. `ID` is its jti (`urn:uuid:...`, printed and logged by the signer) or the recipient email | — |
| — | `--suspend ID` | OB3 only: suspend a credential (reversible) | — |
| — | `--unsuspend ID` | OB3 only: lift a suspension | — |
| — | `--reason TEXT` | Free-text reason recorded with `--revoke`/`--suspend` | — |
| `-b` | `--badge NAME` | Scope the `ID` lookup to one badge's registry | all badges |
| `-v` | `--version` | Print version and exit | — |

`--revoke`, `--suspend` and `--unsuspend` are mutually exclusive and update the badge's status registry **before** regenerating the lists. A recipient email that matches several issued credentials is rejected with the candidate jtis — re-run with the jti. Revocation is permanent (there is no `--unrevoke`); suspension of a revoked credential is likewise rejected.

### Example (OB2)

```sh
$ openbadges-publish -c ./config/config.ini -o ./public -V 2
Please configure your Web server to publish the folder ./public as https://example.com/issuer/
```

If the output directory already exists, the OB1/OB2 path prints `[!] <path> already exists` and exits with a non-zero status.

### Example (OB3)

```sh
$ openbadges-publish -c ./config/config.ini -o ./public
Please configure your Web server to publish the folder ./public as https://example.com/issuer/
[i] Issuer DID: did:web:example.com:issuer

$ openbadges-publish -c ./config/config.ini -o ./public --revoke urn:uuid:7586fd5d-... --reason cheating
[+] REVOKED badge_1 urn:uuid:7586fd5d-... (index 40712)
...
[!] Re-upload ./public so the change takes effect
```
