# Security Policy

`openbadgeslib` issues and verifies cryptographically-signed credentials, so we
take reports seriously and aim to respond quickly.

## Supported versions

Security fixes land in a new release on the latest minor line and are published
to [PyPI](https://pypi.org/project/openbadgeslib/). Always run the latest
release; older versions are not patched in place.

| Version        | Supported                     |
| -------------- | ----------------------------- |
| Latest release | ✅ security fixes              |
| Older releases | ❌ upgrade to the latest       |

## Reporting a vulnerability

**Please do not open a public issue for a suspected vulnerability.** Report it
privately instead:

- **Preferred:** GitHub private vulnerability reporting — the **“Report a
  vulnerability”** button under this repository’s
  [Security tab](https://github.com/luisgf/openbadgeslib/security/advisories).
- **Email:** `luisgf@luisgf.es` (you may encrypt to the same address’s public
  key if you have it).

Please include enough to reproduce: the affected version, a minimal example or
proof of concept, and the impact you observed. If it touches signature
verification, revocation, DID/key resolution, or the handling of untrusted
input (downloaded documents, baked images, status lists), say so — those are the
highest-priority areas.

## What to expect

- Acknowledgement of your report, normally within a few days.
- An assessment of severity and scope, and a fix or mitigation plan.
- Coordinated disclosure: we will agree a timeline with you and credit you in
  the release notes and advisory unless you prefer to stay anonymous.
- A patched release on PyPI and a published GitHub Security Advisory once the
  fix is available.

## Scope and threat model

What the library defends against, and what it delegates to the operator (key
custody, DNS/TLS for `did:web`, hosting of published documents), is documented
in the [Security Model](https://github.com/luisgf/openbadgeslib/wiki/Security-Model)
wiki page. Reports that fall within that model — a bypass of algorithm pinning,
signature or recipient-binding verification, the SSRF/decompression guards, the
context allowlist, or the status-list checks — are especially welcome.

Out of scope: issues that require the operator’s own private keys or config to
already be compromised, and hardening we already document as a deliberate,
human-owned decision (for example, passphrase-encrypted private keys at rest).
