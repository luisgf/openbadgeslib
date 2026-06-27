Credits, licensing terms, and answers to the questions that come up most often when signing and verifying badges with openbadgeslib 1.1.1. Start at [[Home]] for the full table of contents.

## Authors and Credits

openbadgeslib is written and maintained by (sorted alphabetically):

* Jesús Cea Avión `<jcea@jcea.es>`
* Luis González Fernández `<luisgf@luisgf.es>`

Copyright (c) 2014-2026 Luis González Fernández and Jesús Cea Avión.

Contributions are welcome — see [[Contributing]].

## License

openbadgeslib uses **dual licensing** so that linking the library into your own application does not impose copyleft on the wrapper CLI tools:

| Component | License |
| --- | --- |
| The **library** — the `openbadgeslib/` package (imported as `openbadgeslib`, `openbadgeslib.ob2`, `openbadgeslib.ob3`) | GNU Lesser General Public License v3 (LGPLv3) |
| The **command-line wrapper tools** — `openbadges-init`, `openbadges-keygenerator`, `openbadges-signer`, `openbadges-verifier`, `openbadges-publish` | BSD 2-Clause |

The full LGPLv3 text ships in `LICENSE.txt`. In short: you may use, redistribute, and link the library (including from closed-source applications) under the LGPLv3, while the CLI entry points carry the more permissive BSD 2-Clause terms.

* GNU Lesser General Public License v3: https://opensource.org/licenses/lgpl-3.0.html
* BSD 2-Clause: https://opensource.org/licenses/BSD-2-Clause

## FAQ and Troubleshooting

### Why does the program print an ECC disclaimer?

When you run with Elliptic Curve cryptography (ES256 / NIST P-256), the tools call `show_ecc_disclaimer()`, which prints:

```
    DISCLAIMER!

    You are running the program with support for Elliptic
    Curve cryptography.

    The implementation of ECC in JWS Draft is not clear about the
    signature/verification process and may lead to problems for
    you and others when verifying your badges.

    Use at your own risk!
```

The JWS draft is ambiguous about the ECC signature/verification process, so badges signed with ECC keys may not verify cleanly in other OpenBadges implementations. If interoperability with third-party verifiers matters to you, prefer RSA (RS256) keys. See [[Keys and Errors]] for key types and [[OB2 vs OB3]] for how each spec uses them.

### Why does verification print `[~]` instead of `[+]`?

For OpenBadges 2.0, `openbadges-verifier` prints `[+] Signature is correct` **only when you supply a trusted key** (`--local` / `--pubkey`). Without a trusted key it falls back to the verification key embedded in the badge itself, which proves the token is internally consistent but proves nothing about the issuer's identity — so it reports the weaker `[~]` result instead. This is by design: the verification key is the root of trust. Supply the issuer's known-good key to get the strong `[+]`. The full reasoning is in [[Security Model]]; verification flow details are in [[Signing and Verification]].

```bash
# Strong result: trusted key supplied
openbadges-verifier -i badge.svg -r recipient@example.com --pubkey verify.pem
```

### Verification fails on an SVG that has a DOCTYPE or XML header

That is fine — SVG files with an `<?xml ...?>` declaration and/or a `<!DOCTYPE ...>` are supported. Since v1.1.0 the SVG is parsed with `defusedxml`, which neutralises malicious entity-expansion (billion-laughs) attacks while still accepting normal, well-formed SVG markup. If a real SVG fails to parse, the error is now reported rather than masked; check that the file is valid XML and actually contains the baked `<openbadges:assertion>` element (OB2) or token.

### "Config file not found" / config errors

The CLI tools read a config file you point at with `-c`. Create one first with `openbadges-init`, then pass its path explicitly:

```bash
openbadges-init ./config/
openbadges-keygenerator -c ./config/config.ini -g 1
```

Use an absolute or correct relative path to `config.ini` for every `-c` argument. See [[Configuration]] for the file layout and [[Quick Start]] for the end-to-end flow.

### A downloaded verification key is rejected over HTTP

`download_file()` refuses non-HTTPS URLs by default, because the verification key is the OpenBadges 2.0 root of trust and fetching it over an unauthenticated channel would let an attacker substitute their own key. Host your verify key over HTTPS. (Programmatically, `allow_insecure=True` overrides this, but doing so is discouraged.)

### Where do I report issues?

Open an issue or pull request on the project's GitHub repository:

https://github.com/luisgf/openbadgeslib

Before filing a bug, please read [[Contributing]] for how to reproduce and report effectively.
