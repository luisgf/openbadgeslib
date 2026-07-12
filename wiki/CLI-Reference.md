Reference for the console tools installed with `openbadgeslib`. Every flag, default and example below is taken directly from the source. For the meaning of config keys see [[Configuration]]; for an end-to-end walkthrough see [[Quick Start]].

Every tool accepts `-v / --version` (prints the library version and exits), and the config-driven ones (`keygenerator`, `signer`, `verifier`, `publish`) default `-c / --config` to `config.ini` in the current directory and accept `-d / --debug`.

## openbadges (unified front-end)

A single `openbadges <command>` entry point dispatches to the tools below; each command owns everything after its name and behaves exactly like the standalone script (same flags, output and [exit codes](#machine-readable-output-and-exit-codes)). The five `openbadges-<command>` scripts remain installed as aliases.

### Synopsis

```sh
openbadges COMMAND [ARGS ...]
openbadges --help            # list the commands
openbadges COMMAND --help    # a command's own options
```

| Command | Runs | Alias |
|---------|------|-------|
| `init` | Create a working directory | `openbadges-init` |
| `keygen` | Generate a key pair | `openbadges-keygenerator` |
| `sign` | Issue (sign) a badge | `openbadges-signer` |
| `verify` | Verify a badge | `openbadges-verifier` |
| `publish` | Publish OB3 artefacts / manage status | `openbadges-publish` |

```sh
$ openbadges sign -c ./config/config.ini -b 1 -r recipient@example.com -E -V 3
```

## openbadges-init

Bootstraps a working directory: creates the directory plus `keys/`, `images/`, `log/` and `status/` subdirectories (with a restrictive `0o077` umask) and copies the bundled `config.ini.example` to `<DIRECTORY>/config.ini`.

It takes a single positional argument (the directory, which must not already exist) plus the standard `-h / --help` and `-v / --version`.

Bootstraps a working directory: creates the directory plus `keys/`, `images/`, `log/` and `status/` subdirectories (with a restrictive `0o077` umask) and copies the bundled `config.ini.example` to `<DIRECTORY>/config.ini`.

This script does **not** use argparse. It takes a single positional argument and only recognises `-h` (which prints the usage line). It fails if the target path already exists.

### Synopsis

```sh
openbadges-init DIRECTORY
```

| Argument | Meaning | Default |
|----------|---------|---------|
| `DIRECTORY` (positional) | Directory to create and populate | required |
| `-h` / `--help` | Print help and exit | — |
| `-v` / `--version` | Print version and exit | — |

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
openbadges-keygenerator -g BADGE [-c FILE] [--json] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-g` | `--genkey BADGE` | Generate a key pair for section `[badge_<BADGE>]` (the suffix after `badge_`) | none (prints help) |
| `-d` | `--debug` | Show debug messages at runtime | off |
| — | `--json` | Emit a machine-readable JSON result (`{key_type, private_key, public_key}`) instead of the human log lines. See [Machine-readable output](#machine-readable-output-and-exit-codes) | off |
| `-v` | `--version` | Print version and exit | — |

The command refuses to overwrite: if either key file already exists it prints `[!] Key file is present at <path>` and exits with status 1.

### Example

```sh
$ openbadges-keygenerator -c ./config/config.ini -g 1
INFO - Generating a RSA key pair for issuer 'OpenBadge issuer'
INFO - Private key saved at: ./config/keys/sign_rsa_key_1.pem
INFO - Public key saved at:  ./config/keys/verify_rsa_key_1.pem
```

The key algorithm comes from the badge's `key_type` field, not from a flag, so key material does not depend on the OpenBadges version.

## openbadges-signer

Signs a badge image (SVG or PNG) defined in `config.ini` for one or more recipients and writes the baked file(s) to the output directory. OB2 embeds a JWS assertion; OB3 embeds a JWT-VC token. The output filename is `<badge>_<receptor>.<ext>`; an existing file is skipped (batch) or aborts (single badge) unless `--force` is given. Several `-r` flags or a `--recipients-file` issue to many recipients in one run — OB3 allocates all their revocation-list indices in a **single registry transaction** — and a per-recipient summary (`--json`: `{signed, skipped, failed}`) reports the outcome.

You **must** choose exactly one of `-e / --evidence` or `-E / --no-evidence`. Supplying neither or both exits with `Please, choose '-e' OR '-E'`.

### Synopsis

```sh
openbadges-signer -b BADGE (-r EMAIL [-r EMAIL ...] | --recipients-file FILE) (-e URL | -E) [-c FILE] [-o DIR] [--force] [-M] [-H] [-x DAYS] [-V {1,2,3}] [-P {vc-jwt,ldp}] [--json] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-b` | `--badge` | Badge name to sign (**required**) | required |
| `-r` | `--receptor EMAIL` | Recipient email. Repeat `-r` to issue to several recipients in one run (batch mode); required unless `--recipients-file` is given | required |
| — | `--recipients-file FILE` | Read recipient emails from `FILE` (one per line or comma-separated; blank lines and `#`-comments ignored), combined with any `-r`. Any file recipient triggers batch mode | none |
| `-o` | `--output` | Output directory for the signed badge(s) | current dir |
| — | `--force` / `--overwrite` | Overwrite an existing output badge file instead of skipping it (batch) or aborting (single badge) | off |
| `-M` | `--mail-badge` | Email the signed badge to the recipient (OB 1.0 only) | off |
| `-H` | `--hosted` | OB 2.0 only (`-V 2`): use HostedBadge verification (publish the assertion JSON at its own URL) instead of a SignedBadge JWS; requires `hosted_assertions_base` in the badge section | off |
| `-e` | `--evidence URL` | URL to the recipient's evidence (mutually exclusive with `-E`) | none |
| `-E` | `--no-evidence` | Sign without evidence (mutually exclusive with `-e`) | off |
| `-x` | `--expires DAYS` | Expire the badge after `DAYS` days | none |
| `-V` | `--ob-version {1,2,3}` | `1` = legacy JWS (OB 1.0), `2` = strict OB 2.0 JWS, `3` = JWT-VC | `3` |
| `-P` | `--proof-format {vc-jwt,ldp}` | OB 3.0 only (`-V 3`): `vc-jwt` = compact JWT-VC, `ldp` = embedded W3C Data Integrity proof (`eddsa-rdfc-2022`; needs an Ed25519 key and the `[ldp]` extra). Overrides the badge's `proof_format` config key | `vc-jwt` |
| `-d` | `--debug` | Show debug messages at runtime | off |
| — | `--json` | Emit a machine-readable JSON result instead of the human output: a single-badge object (`{ob_version, badge_file, jti, status_index, proof_format}`) or, in batch mode, a summary (`{signed, skipped, failed}`). See [Machine-readable output](#machine-readable-output-and-exit-codes) | off |
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

### Example (OB3, Data Integrity / LDP)

```sh
$ openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -E -o /tmp/ -V 3 -P ldp
2026-07-03T10:00:00 badge_1 OB3 SIGNED for recipient@example.com JTI urn:uuid:… PROOF ldp at: /tmp/badge_1_recipient@example.com.svg
```

Data Integrity issuance requires an Ed25519 key (`key_type = ED25519`, see [[Keys and Errors]]) and the `[ldp]` extra. The proof's `verificationMethod` is the `did:web:…#badge_N` method that `openbadges-publish -V 3` publishes when `[issuer] did` is configured (trusted); without a DID it falls back to a self-asserted `did:key`, which verifiers must pin with `-k`/`-l`. A badge permanently issued as LDP can set `proof_format = ldp` in its config section instead of passing `-P`. See [[Signing and Verification]].

### Example (batch, many recipients)

```sh
$ openbadges-signer -c ./config/config.ini -b 1 \
    -r alice@example.com -r bob@example.com \
    --recipients-file cohort.csv \
    -E -o /tmp/ -V 3 --json
{"ob_version": "3", "badge": "badge_1", "signed": [...], "skipped": [], "failed": []}
```

A single `-r` keeps the historical single-badge behaviour (same output and exit codes). Two or more recipients, or any `--recipients-file`, switch to **batch mode**: for a revocable OB3 badge every status-list index is allocated in one registry load/save (not one per recipient), an already-existing output file is **skipped** unless `--force` is passed, and one bad recipient does not abort the rest. Exit status: `0` all signed, `2` some skipped or failed, `1` a batch-level error. The library entry point is `openbadgeslib.issue.issue_batch_from_conf` (see [[Python API OB3]]).

## openbadges-verifier

Extracts the embedded assertion/credential from a signed badge image, checks the cryptographic signature, and verifies that the recipient identity matches `-r`.

For OB3 the baked payload's format is **autodetected**: a compact JWT-VC is verified as before, while a JSON credential document secured with a W3C Data Integrity proof (`eddsa-rdfc-2022`) is verified through the same flags — no new options — provided the `[ldp]` extra is installed (`pip install "openbadgeslib[ldp]"`; without it the failure reason carries that hint). See [[Installation]] and [[Python API OB3]].

**Trust note:** to get a `[+]` trusted result you must supply the issuer's public key out-of-band, via `-l BADGE` (read from `config.ini`) or `-k FILE` (a PEM path). For OB2, if you supply neither, the verifier falls back to the key the badge itself points to and reports a `[~]` warning — the signature is only *internally consistent*, which does not prove issuer identity. For OB3, supplying neither is a hard error (or pass `--resolve-did`, which for a Data Integrity credential resolves the proof's `verificationMethod`). See [[Security Model]].

### Synopsis

```sh
openbadges-verifier -i FILE -r RECEPTOR [-l BADGE | -k FILE] [-c FILE] [-s] [--check-status] [--no-verify-status-list] [--resolve-did] [--json] [-V {1,2,3}] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-i` | `--filein` | Signed badge file to verify (**required**) | required |
| `-r` | `--receptor` | Recipient email to check against (**required**) | required |
| `-l` | `--local BADGE` | Verify against the public key from this badge section in `config.ini` | none |
| `-k` | `--pubkey FILE` | Verify against this trusted PEM public key file (OB2 and OB3) | none |
| `-s` | `--show` | Print the assertion/credential before the result | off |
| | `--check-status` | OB3 only: fetch the `credentialStatus` list and reject a revoked/suspended credential (requires network). The status list's own signature is verified by default, bound to the badge issuer | off |
| | `--no-verify-status-list` | OB3 only: with `--check-status`, do **not** verify the status list's own signature — trust the revocation bit on the serving host's word. Only for issuers that serve an unsigned list; insecure otherwise | off |
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
openbadges-publish -o DIR [-c FILE] [-V {1,2,3}] [--check-live] [-d]
openbadges-publish -o DIR -V 3 [--revoke ID | --suspend ID | --unsuspend ID] [--reason TEXT] [-b BADGE] [--check-live] [--json] [-d]
openbadges-publish -V 3 (--list | --status ID) [-c FILE] [-b BADGE] [--json] [-d]
```

| Short | Long | Meaning | Default |
|-------|------|---------|---------|
| `-c` | `--config` | Config file to use | `config.ini` |
| `-o` | `--output` | Output directory for the public files (required to publish; **not** needed for `--list`/`--status`) | required to publish |
| `-V` | `--ob-version {1,2,3}` | `1`/`2` write hosted metadata (OB 2.0 adds `key.json`); `3` writes `did.json` + status lists | `3` |
| — | `--revoke ID` | OB3 only: permanently revoke a credential. `ID` is its jti (`urn:uuid:...`, printed and logged by the signer) or the recipient email | — |
| — | `--suspend ID` | OB3 only: suspend a credential (reversible) | — |
| — | `--unsuspend ID` | OB3 only: lift a suspension | — |
| — | `--list` | OB3 only: tabulate issued credentials — jti, recipient, issue date, state (read-only) | — |
| — | `--status ID` | OB3 only: full status record of a credential by jti or recipient email, revocation/suspension reason included (read-only) | — |
| — | `--reason TEXT` | Free-text reason recorded with `--revoke`/`--suspend` | — |
| — | `--check-live` | OB3 only: after publishing, download each written artifact (`did.json`, status lists, `verify.pem`) from `publish_url` and byte-compare it against the local copy — verifying the web server serves the freshly-regenerated versions. Exit `2` if any is stale or missing | off |
| — | `--json` | OB3 only: emit a machine-readable JSON result instead of the human output — `{did, files_written, status_operation, skipped}` when publishing, the queried records for `--list`/`--status`. See [Machine-readable output](#machine-readable-output-and-exit-codes) | off |
| `-b` | `--badge NAME` | Scope the lookup/listing to one badge's registry | all badges |
| `-d` | `--debug` | Show debug messages at runtime | off |
| `-v` | `--version` | Print version and exit | — |

`--revoke`, `--suspend`, `--unsuspend`, `--list` and `--status` are mutually exclusive. The three state changes update the badge's status registry **before** regenerating the lists; a recipient email that matches several issued credentials is rejected with the candidate jtis — re-run with the jti. Revocation is permanent (there is no `--unrevoke`); suspension of a revoked credential is likewise rejected.

`--list` and `--status` are read-only audits of the private status registries: they need **no** output directory and never touch the published files. `--list` prints one row per issued credential (state is `active`, `REVOKED` or `SUSPENDED`); `--status <jti|email>` prints the full record, including the revocation or suspension date and reason. Together with issue and revoke they close the credential lifecycle from the CLI: issue → revoke → **audit**.

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

### Example (OB3 audit — no output directory)

```sh
$ openbadges-publish -c ./config/config.ini -V 3 --list

# badge_1 — 2 credentials
JTI                                            RECIPIENT                 ISSUED                STATE
urn:uuid:388b309b-...                          mailto:alice@example.com  2026-07-08T05:26:11Z  active
urn:uuid:83e1c0de-...                          mailto:bob@example.com    2026-07-08T05:26:11Z  REVOKED

2 credentials total across 1 badge

$ openbadges-publish -c ./config/config.ini -V 3 --status bob@example.com
badge:      badge_1
jti:        urn:uuid:83e1c0de-...
index:      53936
recipient:  mailto:bob@example.com
issued:     2026-07-08T05:26:11Z
state:      REVOKED
revoked:    2026-07-08T05:26:12Z  (reason: issued in error)
```

`--status` exits non-zero when the credential is not found, so it composes in scripts.

## Machine-readable output and exit codes

Every CLI accepts `--json` for scripting: it prints exactly **one JSON object** to stdout and nothing else (human `[+]`/`[!]` lines and logs are suppressed or go to stderr), so automation can parse the result without scraping text.

Success payloads:

| Command | `--json` object |
|---------|-----------------|
| `openbadges-keygenerator` | `{key_type, private_key, public_key}` |
| `openbadges-signer` | `{ob_version, badge_file, jti, status_index, proof_format}` (`jti`/`status_index`/`proof_format` are OB3; `null` where not applicable) |
| `openbadges-publish -V 3` | `{did, files_written, status_operation, skipped, live_check}` (`live_check` is `null` unless `--check-live`) |
| `openbadges-publish -V 3 --list` | `{badges: [{badge, credentials: [...]}], total}` |
| `openbadges-publish -V 3 --status` | `{matches: [...]}` |
| `openbadges-verifier` | the verification result (`valid`, `trusted`, `issuer`, `achievement`, …) |

On error the object is `{"error": "<message>"}`.

Exit-code contract (identical in human and `--json` modes):

| Code | Meaning |
|------|---------|
| `0` | success |
| `2` | partial success — verifier: valid signature but the issuer is untrusted; signer/publish: some work was skipped, or `--check-live` found a stale/missing artifact |
| `1` | any error |

`openbadges-publish -V 3 --json` is defined for OpenBadges 3.0 only (the OB1/OB2 hosted-metadata paths have no JSON contract); combining `--json` with `-V 1`/`-V 2` is rejected.

> Note: the exit status is the same with or without `--json`. A valid, trusted badge exits `0`; a valid but untrusted one exits `2`; an invalid badge or any error exits `1` — so `verifier … && grant` is safe in either mode (earlier versions exited `0` on an invalid OB1/OB2 badge, or surfaced the untrusted `2` only under `--json`).
