How to demonstrate that credentials issued by `openbadgeslib` pass the **1EdTech Open Badges 3.0 conformance** tests — without paying for 1EdTech membership. Formal certification (a badge on the 1EdTech product directory) requires a paid membership and is deliberately out of the project's scope; this page captures the *technical* value — proving conformance — which is free.

The library is already built to be conformant: the technical bets match what the ecosystem standardised (VC 2.0 Recommendation 2025-05, the eddsa-rdfc-2022 and ecdsa-sd-2023 certification suites, EUDI SD-JWT), and every credential we issue is checked against 1EdTech's official JSON Schemas in CI (see below).

## What "conformant" means here

Two independent things, both covered:

1. **Structural conformance** — the credential validates against 1EdTech's official `AchievementCredential` / `Profile` JSON Schemas. This runs offline in every CI build (`tests/test_ob3_conformance_schema.py`, draft-2019-09, format assertions on). It validates the canonical `to_vc()`, the on-the-wire JWT-VC payload, and the LDP signed document — so a regression in any issuance path fails the build.
2. **Cryptographic conformance** — the proof verifies under an accepted suite. For OB 3.0 the accepted secured formats are the **compact JWT-VC** (`VC-JWT`) and the **Data Integrity** proof **`eddsa-rdfc-2022`** (Ed25519); both are what this library issues.

The heavier, container-based **official validators** are wired up behind an opt-in suite (`pytest -m conformance_docker`, see `tests/conformance/` and the `conformance.yml` workflow) — the Digital Credentials public validator for OB 3.0 and `openbadges-validator-core` for OB 2.0. They are deselected from the default run because they need Docker, but they are the same engines 1EdTech uses.

## Recipe: prove an OB 3.0 badge is conformant

1. **Issue a valid credential.** Follow [[Library Integration Tutorial]] (or `openbadges-signer -V 3`). Use an Ed25519 key if you want the `eddsa-rdfc-2022` Data Integrity form, or any supported key for JWT-VC.
2. **Publish the issuer artefacts** so the credential is resolvable and revocable: `openbadges-publish -V 3 -o <webroot>` writes the `did:web` document (`did.json`), each badge's `verify.pem`, and the signed status lists. Serve `<webroot>` over HTTPS at the origin your `[issuer] publish_url` names. (See [[CLI Reference]].)
3. **Self-check offline first** — run the schema gate locally so you never submit a structurally-invalid credential:

   ```sh
   pip install "openbadgeslib[dev]"
   pytest tests/test_ob3_conformance_schema.py -q
   ```

4. **Run the official validator.** Either point the opt-in Docker suite at your issuer, or upload the credential to the public Digital Credentials validator (`POST /api/validate?validatorId=OB30Inspector` with the credential file) and confirm `summary.outcome == "VALID"`.
5. **Submit for the 1EdTech Issuer conformance** (if pursuing it): issue a valid 3.0 badge to **conformance@imsglobal.org** and provide the retrieval/verification demonstration 1EdTech asks for. `eddsa-rdfc-2022` is on their accepted list.

## OpenBadges 2.0

The same idea applies to strict OB 2.0: the opt-in suite exercises both the **HostedBadge** and the crypto-sensitive **SignedBadge** paths against `openbadges-validator-core`. Publish the hosted graph (issuer Profile, BadgeClass, CryptographicKey, RevocationList) with `openbadges-publish -V 2 -o <webroot>` and validate the assertion URL.

## What is deliberately *not* here

- **Paid 1EdTech membership / the certification portal** — a business decision, not a technical gap. Everything needed to *pass* the tests is above.
- **Building an OID4VCI/OID4VP issuance rail** — that belongs in `openvc-core`, per the project's delegation pattern; this library issues the credentials, not the wallet-exchange protocol.

## See also

- [[Library Integration Tutorial]] · [[Signing and Verification]] · [[Security Model]] · [[OB2 vs OB3]]
