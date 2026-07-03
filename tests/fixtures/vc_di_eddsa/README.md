Official W3C `eddsa-rdfc-2022` test vectors, taken verbatim from the
vc-di-eddsa Recommendation's TestVectors directory
(https://github.com/w3c/vc-di-eddsa/tree/main/TestVectors), captured
2026-07-03:

- `signed-credential.json` — TestVectors/eddsa-rdfc-2022/signedDataInt.json
- `key-pair.json`          — TestVectors/keyPair.json
- `doc-hash.txt`           — TestVectors/eddsa-rdfc-2022/docHashDataInt.txt
- `proof-config-hash.txt`  — TestVectors/eddsa-rdfc-2022/proofHashDataInt.txt

`credentials-examples-v2.json` is the https://www.w3.org/ns/credentials/examples/v2
context the vector's @context names; it is injected into tests via
`extra_contexts` and deliberately NOT part of the library's bundled allowlist.
