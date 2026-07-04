Official 1EdTech Open Badges 3.0 JSON Schemas, taken verbatim from the
canonical schema directory
(https://purl.imsglobal.org/spec/ob/v3p0/schema/json/), captured 2026-07-04:

- `ob_v3p0_achievementcredential_schema.json` — the AchievementCredential
  (a.k.a. OpenBadgeCredential) schema. The "JSON-LD adaptation" variant, which
  tolerates JSON-LD value compaction (singular values as arrays); it is the
  correct one for the JSON-LD payloads this library emits.
- `ob_v3p0_profile_schema.json` — the issuer Profile schema.

Both are JSON Schema **draft 2019-09** and self-contained (every `$ref` is an
internal `#/$defs/...` pointer — no external URL is fetched), so the stock
`jsonschema` library validates against them offline. These are the same schema
artifacts an official validator applies; `test_ob3_conformance_schema.py`
checks that the credentials we issue conform to them.

This is conformance to the official *schemas*, not the 1EdTech certification
programme (certification.imsglobal.org), which is a membership portal a human
drives and cannot be a headless test.

Re-fetch / re-pin with `./refresh.sh` (review the diff before committing — a
schema change is a spec change and may need matching code changes).
