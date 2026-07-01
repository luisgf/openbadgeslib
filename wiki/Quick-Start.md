This walkthrough takes you from an empty directory to a signed, verified Open Badge in both strict OB 2.0 (JWS) and OB 3.0 (JWT-VC) formats. Select the version with `-V {1,2,3}` — the default is `-V 3`. For the full flag list see [[CLI Reference]], and for the config keys referenced here see [[Configuration]].

## 1. Scaffold the configuration

Create the config directory and a starter `config.ini`:

```sh
openbadges-init ./config
```

The example config ships with two badge sections (`[badge_1]`, `[badge_2]`), an `[issuer]` section, and `[paths]` pointing keys at `${base}/keys`. Edit the issuer details and at least one `[badge_*]` section before continuing. The default key type is RSA (`key_type = RSA`; `ECC` is the alternative).

## 2. Generate a key pair

Keys are generated per badge section. Pass the config file and the section suffix — the part after `badge_` — to `-g`. The algorithm comes from that section's `key_type`:

```sh
openbadges-keygenerator -c ./config/config.ini -g 1
```

```
INFO - Generating OpenBadges 3 RSA key pair for issuer 'OpenBadge issuer'
INFO - Private key saved at: ./config/keys/sign_rsa_key_1.pem
INFO - Public key saved at:  ./config/keys/verify_rsa_key_1.pem
```

The same key material works for both OB2 and OB3, so you only generate once. Back up `sign_rsa_key_1.pem`: if the private key is lost you cannot sign new badges, and if the public key is lost existing badges can no longer be verified.

## 3. OB 2.0 flow (strict JWS)

### Sign

`openbadges-signer` bakes a JWS assertion into the badge image. Pass `-V 2` for strict Open Badges 2.0 (the default is `-V 3`). You **must** choose explicitly whether the badge carries evidence: pass either `-e / --evidence URL` **or** `-E / --no-evidence`. Supplying neither (or both) exits with `Please, choose '-e' OR '-E'`. Strict signed mode reads `crypto_key` from the badge section (the scaffolded config includes it).

```sh
openbadges-signer -c ./config/config.ini -b 1 \
    -r recipient@example.com \
    -e https://example.com/proof \
    -o /tmp/ -V 2
```

```
2026-04-22T10:00:00 badge_1 OB2 SIGNED for recipient@example.com at: /tmp/badge_1_recipient@example.com.svg
```

The output filename is `<badge>_<recipient>.svg` (or `.png`, depending on the badge image type) inside `-o`. Signing a second time over an existing file is refused. To sign with no evidence, swap `-e URL` for `-E`. Add `-x DAYS` for an expiration, or `-H` to produce a HostedBadge (which also writes a `.assertion.json` to publish alongside the image). Emailing via `-M` is available in the legacy `-V 1` flow.

### Verify

```sh
openbadges-verifier -c ./config/config.ini \
    -i /tmp/badge_1_recipient@example.com.svg \
    -r recipient@example.com -V 2 -l 1
```

```
[+] Signature is correct for the identity recipient@example.com
```

(Verification of a strict OB 2.0 badge fetches the issuer's hosted `badge.json`/`organization.json` to check revocation, so those must be reachable — publish them with `openbadges-publish -V 2`.)

The `-l BADGE` flag pins the trusted public key from `config.ini`; `-k / --pubkey FILE` does the same from an explicit PEM path. If you supply neither, the verifier falls back to the key the badge points to and prints a `[~]` warning instead of `[+]` — the signature is only internally consistent, not anchored to a trusted issuer. Add `-s / --show` to print the decoded assertion first.

## 4. OB 3.0 flow (JWT-VC, the default)

### Sign

Pass `-V 3`. The signer reuses the same badge section and auto-detects the algorithm from the private key (RS256 for RSA, ES256 for ECC, EdDSA for Ed25519). The `-e` / `-E` evidence choice still applies:

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

Omitting `-k`, `-l`, and `--resolve-did` prints `[!] OB3 verification requires --local BADGE, --pubkey FILE, or --resolve-did` and exits. `--resolve-did` is a third trust source: it resolves the issuer DID (did:key/did:web) from the token to obtain the verification key (a resolved did:key is reported as untrusted, since the key is self-asserted). With `-s / --show`, the verifier also prints the issuer name, achievement name, issuance date, expiration (if set), and evidence URL.

## Next steps

- Task-oriented recipes (batch signing, emailing, publishing) live in [[Guides]].
- Every flag for all five console scripts is documented in [[CLI Reference]].
- All `config.ini` keys are explained in [[Configuration]].
