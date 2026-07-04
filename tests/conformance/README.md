# Conformance against 1EdTech's official validators (opt-in)

This directory holds the **opt-in, non-blocking** conformance layer: it issues
badges with this library and runs them through 1EdTech's *official open-source
validators* running as local Docker services. It is the high-fidelity
counterpart to `tests/test_ob3_conformance_schema.py`, which checks issued
OB 3.0 credentials against the official JSON Schemas offline and DOES run in the
normal suite / release gate.

## Why it is separate

These tests are marked `conformance_docker` and **deselected by default** (via
`addopts = -m 'not conformance_docker'` in `pyproject.toml`). They need Docker,
build a Java image, and touch the network — none of which belong on the release
path. They run in the nightly `conformance.yml` workflow, or on demand.

Each test **skips** (never fails) when its validator service — or `requests` —
is absent, so running `pytest -m conformance_docker` without the services up is
a clean no-op.

## What "official validator" means here (honest scope)

The paid 1EdTech **certification** (certification.imsglobal.org) is a membership
portal a human drives; it cannot be a headless test and is out of scope. What
*is* automatable is the code 1EdTech open-sources:

| Version | Validator (Apache-2.0) | Runtime | Contract |
|---|---|---|---|
| OB 2.0 | [`openbadges-validator-core`](https://github.com/1EdTech/openbadges-validator-core) | Flask/gunicorn, `python:3.9-slim`, port 8000 | confirmed live |
| OB 3.0 | [`digital-credentials-public-validator`](https://github.com/1EdTech/digital-credentials-public-validator) | Spring Boot, `eclipse-temurin:17`, port 8080 | confirmed live |

Both validators and all five tests were run end to end against these images
(2026-07-04); the contracts below are what those live runs use, not guesses.

## Running locally

```sh
docker compose -f tests/conformance/docker-compose.yml up -d --build   # slow: OB3 Maven build (~4 min)
OB2_VALIDATOR_URL=http://localhost:8000 \
OB3_VALIDATOR_URL=http://localhost:8080 \
    .venv/bin/pytest -m conformance_docker -v
docker compose -f tests/conformance/docker-compose.yml down -v
```

Networking: the OB2 validator fetches the hosted badge graph the test serves on
an ephemeral host port, so it must reach back to the host. Both validators use
standard port mappings and the OB2 service maps `host.docker.internal` to the
host gateway (`extra_hosts`), so the default
`CONFORMANCE_ADVERTISE_HOST=host.docker.internal` works on Docker Desktop and
Linux/CI alike — no host networking needed.

## Confirmed contract (from live runs + `/v3/api-docs`)

**OB 2.0:** `POST /results` with form field `data=<assertion URL | JSON | JWS>`
(or an `image=` file upload); response `{"report": {"valid": bool, ...}}`. It
accepts plain-HTTP URLs and fetches the referenced issuer/BadgeClass — so
`test_ob2_hosted_badge_is_valid` serves a real hosted graph (built with our
OB 2.0 models) and hands over the assertion URL. Result: **valid**.

**OB 3.0:** `POST /api/validate?validatorId=OB30Inspector` with a multipart
`file`; the verdict is `summary.outcome` ∈ {VALID, WARNING, ERROR, FATAL,
EXCEPTION, NOT_RUN}, per-probe detail in `fatals`/`errors`. The tests feed
*self-contained* credentials (did:key LDP proof; VC-JWT with an embedded `jwk`
header) so verification needs no DID resolution or outbound network. Results:

- did:key **Data Integrity** (eddsa-rdfc-2022) → **VALID**
- **VC-JWT RS256** and **ES256** → **VALID**
- **VC-JWT EdDSA** → **FATAL**: the validator's `ExternalProofProbe` accepts
  only RS256/ES256, though OB 3.0 permits EdDSA. This is a validator limitation,
  not a defect in our issuance; `test_ob3_vc_jwt_eddsa_is_rejected_by_validator`
  pins that boundary so we notice if it ever changes.

## Files

- `docker-compose.yml` — both validators as services.
- `Dockerfile.ob3` — multi-stage (Maven build + runtime) for the OB 3.0
  validator, whose upstream Dockerfile assumes a pre-built jar.
- `conftest.py` — service-URL fixtures (skip if down) + an ephemeral static
  file server.
- `test_official_validators.py` — the opt-in tests.
- `../../.github/workflows/conformance.yml` — the nightly / on-demand runner.
