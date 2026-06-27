This walkthrough takes you from an empty directory to a signed, verified Open Badge in both OB2 (JWS) and OB3 (JWT-VC) formats. For the full flag list see [[CLI Reference]], and for the config keys referenced here see [[Configuration]].

## 1. Scaffold the configuration

Create the config directory and a starter `config.ini`:

```sh
openbadges-init
```

The example config ships with two badge sections (`[badge_1]`, `[badge_2]`), an `[issuer]` section, and `[paths]` pointing keys at `${base}/keys`. Edit the issuer details and at least one `[badge_*]` section before continuing. The default key type is RSA (`key_type = RSA`; `ECC` is the alternative).

## 2. Generate a key pair

Keys are generated per badge section. Pass the config file and the section suffix — the part after `badge_` — to `-g`. The algorithm comes from that section's `key_type`:

```sh
openbadges-keygenerator -c ./config/config.ini -g 1
```

```
INFO - Generating OpenBadges 2 RSA key pair for issuer 'My Organisation'
INFO - Private key saved at: ./config/keys/sign_rsa_key_1.pem
INFO - Public key saved at:  ./config/keys/verify_rsa_key_1.pem
```

The same key material works for both OB2 and OB3, so you only generate once. Back up `sign_rsa_key_1.pem`: if the private key is lost you cannot sign new badges, and if the public key is lost existing badges can no longer be verified.

## 3. OB2 flow (JWS, the default)

### Sign

`openbadges-signer` bakes a JWS assertion into the badge image. You **must** choose explicitly whether the badge carries evidence: pass either `-e / --evidence URL` **or** `-E / --no-evidence`. Supplying neither (or both) exits with `Please, choose '-e' OR '-E'`. OB2 is the default, so `-V 2` is optional.

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/
```

```
2026-04-22T10:00:00 badge_1 SIGNED for recipient@example.com UID 73f8981f...4f4 at: /tmp/badge_1_recipient@example.com.svg
```

The output filename is `<badge>_<recipient>.svg` (or `.png`, depending on the badge image type) inside `-o`. Signing a second time over an existing file is refused. To sign with no evidence, swap `-e URL` for `-E`. Add `-x DAYS` for an expiration, or `-M` to email the badge (requires the `[smtp]` section and a `mail` entry in the badge section).

### Verify

```sh
openbadges-verifier -c ./config/config.ini \
    -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -l 1
```

```
[+] Signature is correct for the identity recipient@example.com
```

The `-l BADGE` flag pins the trusted public key from `config.ini`; `-k / --pubkey FILE` does the same from an explicit PEM path. If you supply neither, the verifier falls back to the key the badge points to and prints a `[~]` warning instead of `[+]` — the signature is only internally consistent, not anchored to a trusted issuer. Add `-s / --show` to print the decoded assertion first.

## 4. OB3 flow (JWT-VC)

### Sign

Pass `-V 3`. The signer reuses the same badge section and auto-detects the algorithm from the private key (RS256 for RSA, ES256 for ECC). The `-e` / `-E` evidence choice still applies:

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/ -V 3
```

```
2026-04-22T10:00:00 badge_1 OB3 SIGNED for recipient@example.com at: /tmp/badge_1_recipient@example.com.svg
```

### Verify

OB3 verification **requires** a trusted key — there is no fallback. Supply it with `-k / --pubkey FILE` or `-l BADGE`:

```sh
# Using a PEM file directly
openbadges-verifier \
    -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -V 3 \
    -k ./config/keys/verify_rsa_key_1.pem
```

```
[+] OB3 signature is valid for the identity recipient@example.com
```

```sh
# Using the local config
openbadges-verifier -c ./config/config.ini \
    -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -V 3 -l 1
```

Omitting both `-k` and `-l` prints `[!] OB3 verification requires --local BADGE or --pubkey FILE` and exits. With `-s / --show`, the verifier also prints the issuer name, achievement name, issuance date, expiration (if set), and evidence URL.

## Next steps

- Task-oriented recipes (batch signing, emailing, publishing) live in [[Guides]].
- Every flag for all five console scripts is documented in [[CLI Reference]].
- All `config.ini` keys are explained in [[Configuration]].
