Task-oriented how-tos for the most common openbadgeslib workflows. Each section is a self-contained recipe with copy-pasteable commands. For exhaustive flag listings see [[CLI Reference]], and for the config keys these commands read see [[Configuration]].

All recipes assume you have already run `openbadges-init`, generated a key pair with `openbadges-keygenerator`, and have a `config.ini` with at least one `[badge_N]` section. See [[Quick Start]] if you have not.

## Issue an OB2 badge (JWS)

OB2 bakes a JWS assertion into the badge image (an `<openbadges:assertion>` element for SVG, an `iTXt` chunk for PNG). You must declare whether the badge carries evidence: pass either `-e URL` or `-E` (no evidence). Supplying neither, or both, is an error.

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/
```

To issue a badge with no evidence, swap `-e URL` for `-E`:

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -E \
    -o /tmp/
```

The signer writes `badge_1_recipient@example.com.svg` (or `.png`) into the output directory. The badge image type comes from the badge section's `local_image`. If a file already exists for that badge/recipient pair, the signer refuses to overwrite it and exits.

Optional flags:
- `-x DAYS` sets an expiration that many days in the future.
- `-M` emails the badge after signing (see the email recipe below).

## Issue an OB3 credential (JWT-VC)

OB3 produces a W3C Verifiable Credential signed as a JWT-VC and baked into the same SVG/PNG image. Add `-V 3`:

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/ -V 3
```

The signer auto-detects the signing algorithm from the private key (`RS256` for RSA keys, `ES256` for ECC keys). The issuer block is built from the `[issuer]` section (using `publish_url`, falling back to `url`), and the achievement from the badge section (`badge`, `name`, `description`, `criteria_narrative` or `criteria`, `image`). The recipient email is normalized to a `mailto:` identifier inside the credential.

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
    -r recipient@example.com -l 1
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

For OB2, `openbadges-publish` generates the static metadata files that hosted OB2 badges point to. The output directory must not already exist; it is created with restrictive permissions:

```sh
openbadges-publish -c ./config/config.ini -o ./public
```

This produces, under the output directory:
- `organization.json` — the issuer object (name, url, email, image, revocation list), built from the `[issuer]` section.
- `revoked.json` — the revocation list (currently emitted as an empty object).
- One folder per `[badge_N]` section, each containing `badge.json` (image, criteria, name, description, issuer link) and a copy of that badge's public key as `verify.pem`.

URLs in the metadata are resolved against `publish_url` from `[issuer]`, so set that to where the folder will live. After running, configure your web server to serve the output folder at exactly that `publish_url`.

OB3 needs no publication step. Credentials are self-contained JWT-VC tokens verified offline, so running `openbadges-publish -V 3` only prints a notice telling you to distribute the signed images directly.

## Email a signed badge

Pass `-M` to `openbadges-signer` to email the badge to the recipient immediately after signing (OB2 path):

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/ -M
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

When `use_ssl` is `True` the connection uses SMTP over SSL; otherwise plain SMTP. If `username` is set, the signer authenticates before sending.

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
