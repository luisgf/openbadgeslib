Task-oriented how-tos for the most common openbadgeslib workflows. Each section is a self-contained recipe with copy-pasteable commands. For exhaustive flag listings see [[CLI Reference]], and for the config keys these commands read see [[Configuration]].

All recipes assume you have already run `openbadges-init`, generated a key pair with `openbadges-keygenerator`, and have a `config.ini` with at least one `[badge_N]` section. See [[Quick Start]] if you have not.

## Issue an Open Badges 2.0 badge (JWS)

Strict OB 2.0 bakes a JWS assertion into the badge image (an `<openbadges:assertion>` element for SVG, an `iTXt` chunk for PNG). Pass `-V 2` (the default is `-V 3`); signed mode reads `crypto_key` from the badge section. You must declare whether the badge carries evidence: pass either `-e URL` or `-E` (no evidence). Supplying neither, or both, is an error.

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/ -V 2
```

To issue a badge with no evidence, swap `-e URL` for `-E`:

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -E \
    -o /tmp/ -V 2
```

The signer writes `badge_1_recipient@example.com.svg` (or `.png`) into the output directory. The badge image type comes from the badge section's `local_image`. If a file already exists for that badge/recipient pair, the signer refuses to overwrite it and exits.

Optional flags:
- `-x DAYS` sets an expiration that many days in the future.
- `-H` produces a **HostedBadge** (requires `hosted_assertions_base`): the assertion is also written as a `.assertion.json` to publish at its own URL, which becomes the trust anchor on verification.
- `-M` (email after signing) is available in the legacy `-V 1` flow (see the email recipe below).

## Issue an OB3 credential (JWT-VC)

OB3 produces a W3C Verifiable Credential signed as a JWT-VC and baked into the same SVG/PNG image. Add `-V 3`:

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/ -V 3
```

The signer auto-detects the signing algorithm from the private key (`RS256` for RSA keys, `ES256` for ECC keys, `EdDSA` for Ed25519 keys). The issuer block is built from the `[issuer]` section (using `publish_url`, falling back to `url`), and the achievement from the badge section (`badge`, `name`, `description`, `criteria_narrative` or `criteria`, `image`). The recipient email is normalized to a `mailto:` identifier inside the credential.

For the differences between the two formats, see [[OB2 vs OB3]].

## Verify a badge you received

Verification extracts the embedded token, checks the cryptographic signature, and binds the recipient identity. The output prefix tells you what was actually proven:

- `[+]` — verified against a trusted issuer key you supplied.
- `[~]` — internally consistent only; verified against the key embedded in the badge itself, which a forged self-signed badge would also pass. (OB2 only.)
- `[-]` — verification failed.

**You must anchor trust with an out-of-band key.** Supply it with `-l BADGE` (reads the `public_key` PEM from `config.ini`) or `-k FILE` (a PEM file directly). Without one, OB2 falls back to the badge's own embedded key and downgrades the result to `[~]`; OB3 refuses to run at all. See [[Security Model]] for why this matters, and [[Signing and Verification]] for the full check sequence.

OB2, trusting a key from config:

```sh
openbadges-verifier -c ./config/config.ini \
    -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -V 2 -l 1
```

OB3, trusting a PEM file directly:

```sh
openbadges-verifier \
    -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -V 3 \
    -k ./config/keys/verify_rsa_key_1.pem
```

Add `-s` to print the decoded assertion (OB2) or the issuer, achievement, dates and evidence URL (OB3) before the result.

## Publish badges to a web server

For OB 1.0/2.0, `openbadges-publish` generates the static metadata files that hosted badges point to. Pass `-V 2` for strict Open Badges 2.0 (the default `-V 3` only prints a notice). The output directory must not already exist; it is created with restrictive permissions:

```sh
openbadges-publish -c ./config/config.ini -o ./public -V 2
```

This produces, under the output directory:
- `organization.json` — the issuer `Profile` (`@context`, `type`, `id`, name, url, email, image, a `publicKey` array, `revocationList`), built from the `[issuer]` section.
- `revoked.json` — a conformant `RevocationList` document (an empty `revokedAssertions` array until a badge is revoked). The filename is the `[issuer]` section's `revocationList` value (`revoked.json` in the scaffolded config).
- One folder per `[badge_N]` section, each containing `badge.json` (a conformant `BadgeClass`), `key.json` (the `CryptographicKey` that `verification.creator` points at), and a copy of that badge's public key as `verify.pem`.

(Legacy `-V 1` writes the same tree in the pre-2.0 shape: no `@context`/`type`, an empty `revoked.json` object, and no `key.json`.)

URLs in the metadata are resolved against `publish_url` from `[issuer]`, so set that to where the folder will live. After running, configure your web server to serve the output folder at exactly that `publish_url`.

## Publish OB3 trust artefacts and manage revocation

OB3 credentials are self-contained JWT-VC tokens verified offline, but two issuer-side artefacts still need hosting: the did:web document and the status lists.

Opt a badge into credential status by adding to its section (before signing):

```ini
[badge_1]
status_lists = revocation, suspension
```

From then on `openbadges-signer -V 3` embeds `credentialStatus` entries in every new credential and records the assigned index in a private registry (`${base}/status/badge_1.json` — keep it safe; a lost registry makes outstanding credentials unrevocable). Then:

```sh
openbadges-publish -c ./config/config.ini -o ./public -V 3
```

produces, under the output directory:
- `did.json` — the issuer's did:web document (one `verificationMethod` per badge, built from each badge's public key). Served automatically at `<publish_url>/did.json`; for a bare-host DID serve it at `/.well-known/did.json`.
- Per opted-in badge: `badge_N/revocation.jwt` and/or `badge_N/suspension.jwt` (the signed Bitstring Status List credentials) and a copy of the public key as `verify.pem`.

To revoke, suspend or unsuspend, pass the credential's jti (printed and logged by the signer) or the recipient email, then re-upload the folder:

```sh
openbadges-publish -c ./config/config.ini -o ./public -V 3 \
    --revoke urn:uuid:7586fd5d-... --reason "issued in error"
```

Revocation is permanent; suspension is lifted with `--unsuspend`. A verifier running with `--check-status` rejects the credential as soon as the re-uploaded list is live. See [[CLI Reference]] for every flag.

## Email a signed badge

Pass `-M` to `openbadges-signer` to email the badge to the recipient immediately after signing (legacy `-V 1` path):

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/ -V 1 -M
```

Two pieces of configuration are required:

1. An `[smtp]` section in `config.ini`:

```ini
[smtp]
smtp_server = smtp.example.com
smtp_port = 465
use_ssl = True
mail_from = no-reply@issuer.badge
; Uncomment if your SMTP server needs authentication
;username = badges
;password = secret
```

When `use_ssl` is `True` the connection uses SMTP over SSL; otherwise plain SMTP. If `username` is set, `use_ssl` must be `True` so credentials are not sent over a plaintext connection.

2. A `mail` key in the badge section pointing to a text file. The file's first line becomes the email subject; the remaining lines are the body:

```ini
[badge_1]
; ... other keys ...
mail = ${paths:base}/badge_1_mail.txt
```

```text
You earned the Badge 1 OpenBadge!
Congratulations. Your signed badge is attached to this message.
Import it into your favourite badge backpack to share it.
```

The signed image is attached with the correct MIME subtype (`svg+xml` or `png`). If sending fails (connection refused, TLS mismatch, auth error, etc.) the badge has already been signed and saved to disk, and the tool reports the mail error rather than crashing.
