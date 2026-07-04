"""Validate the badges we ISSUE against 1EdTech's official validators running
as local Docker services — the high-fidelity counterpart to the offline schema
check in ``tests/test_ob3_conformance_schema.py``.

Opt-in only: every test here is marked ``conformance_docker`` (deselected by
default) and skips when its validator service or ``requests`` is absent, so it
never touches the release gate. See ``README.md`` in this directory for how to
stand the services up and for which parts of each validator's contract are
confirmed vs. still to be pinned on a first live run.

Design choices that keep the checks hermetic and meaningful:

* **OB 2.0** — we publish a real hosted badge graph (issuer Profile,
  BadgeClass, hosted Assertion) with the library's own OB 2.0 models onto an
  ephemeral localhost HTTP server, then hand the validator the assertion URL;
  it fetches and cross-checks the whole graph exactly as it would in production.
* **OB 3.0** — we feed *self-contained* credentials (a did:key Data Integrity
  proof and a VC-JWT whose JOSE header embeds the public ``jwk``), so the
  validator verifies the signature with zero outbound network / DID resolution.
"""
import dataclasses
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.conformance_docker

# Only dependency these opt-in tests add; kept out of [dev] on purpose.
requests = pytest.importorskip('requests')


# ── Open Badges 2.0: hosted badge graph → official validator ─────────────────

def _write_ob2_hosted_graph(root: Path, base: str, pub_pem: bytes,
                            svg_bytes: bytes) -> str:
    """Publish a strict OB 2.0 hosted badge graph under *root*, with every IRI
    rooted at *base* (the ephemeral server URL). Returns the hosted Assertion
    URL — the single input the validator needs to pull and verify the graph.

    Built with the library's own models so this exercises our real OB 2.0
    JSON-LD serialisation, the thing conformance is about.
    """
    from openbadgeslib.ob2.models import (Assertion, BadgeClass, IdentityObject,
                                          Profile, RevocationList, Verification)

    issuer_id = '%s/organization.json' % base
    rev_url = '%s/revoked.json' % base
    badge_id = '%s/badge_1/badge.json' % base
    image_url = '%s/badge_1/badge.svg' % base
    assertion_url = '%s/badge_1/assertion.json' % base

    (root / 'badge_1').mkdir(parents=True, exist_ok=True)

    profile = Profile(id=issuer_id, name='Conformance Test Issuer',
                      url=base, email='issuer@example.com',
                      revocation_list=rev_url)
    (root / 'organization.json').write_text(json.dumps(profile.to_dict()))

    revocation = RevocationList(id=rev_url, issuer=issuer_id,
                                revoked_assertions=[])
    (root / 'revoked.json').write_text(json.dumps(revocation.to_dict()))

    badge = BadgeClass(id=badge_id, name='Conformance Test Badge',
                       description='Issued to exercise the official validator.',
                       image=image_url, criteria='%s/criteria.html' % base,
                       issuer=issuer_id)
    (root / 'badge_1' / 'badge.json').write_text(json.dumps(badge.to_dict()))
    (root / 'badge_1' / 'badge.svg').write_bytes(svg_bytes)

    # Hosted: the trust anchor is the HTTP fetch, so id == its own URL and the
    # verification is a HostedBadge (no signature/creator).
    assertion = Assertion(
        recipient=IdentityObject.create('recipient@example.com', 's4lt'),
        badge=badge_id,
        verification=Verification(type='HostedBadge'),
        id=assertion_url,
    )
    (root / 'badge_1' / 'assertion.json').write_text(
        json.dumps(assertion.to_dict()))
    return assertion_url


def test_ob2_hosted_badge_is_valid(ob2_validator_url, serve_directory,
                                   tmp_path, rsa_pub_pem, svg_image):
    base = serve_directory(str(tmp_path))
    assertion_url = _write_ob2_hosted_graph(
        tmp_path, base, rsa_pub_pem, svg_image)

    # openbadges-validator-core: POST /results with the assertion URL in `data`;
    # it fetches the graph and returns {"report": {"valid": bool, ...}}.
    resp = requests.post('%s/results' % ob2_validator_url,
                         data={'data': assertion_url},
                         headers={'Accept': 'application/json'}, timeout=60)
    resp.raise_for_status()
    body = resp.json()
    report = body.get('report', {})
    assert report.get('valid') is True, (
        'official OB2 validator rejected our hosted badge:\n%s'
        % json.dumps(report.get('messages', body), indent=2))


# ── Open Badges 3.0: self-contained credentials → official validator ─────────

def _did_key_credential(ob3_credential, pub_pem):
    from openbadgeslib.ob3 import Issuer
    from openbadgeslib.ob3.did import did_key_from_pem
    return dataclasses.replace(
        ob3_credential,
        issuer=Issuer(id=did_key_from_pem(pub_pem), name='Conformance Issuer'))


def _validate_ob3(base_url: str, file_bytes: bytes, filename: str) -> dict:
    """POST a credential file to the official OB 3.0 validator (OB30Inspector)
    and return its Report.

    CONFIRMED live against digital-credentials-public-validator (see
    /v3/api-docs): ``POST /api/validate?validatorId=OB30Inspector`` with a
    multipart ``file`` field; the overall verdict is ``summary.outcome`` ∈
    {VALID, WARNING, ERROR, FATAL, EXCEPTION, NOT_RUN}, with per-probe detail in
    the ``fatals``/``errors`` arrays.
    """
    resp = requests.post('%s/api/validate' % base_url,
                         params={'validatorId': 'OB30Inspector'},
                         files={'file': (filename, file_bytes)}, timeout=90)
    resp.raise_for_status()
    return resp.json()


def _assert_ob3_valid(report: dict, what: str) -> None:
    summary = report.get('summary', {})
    assert summary.get('outcome') == 'VALID', (
        'official OB3 validator did not return VALID for %s (outcome=%s):\n%s'
        % (what, summary.get('outcome'),
           json.dumps(report.get('fatals') or report.get('errors') or summary,
                      indent=2)))


def test_ob3_ldp_did_key_is_valid(ob3_validator_url, ob3_credential,
                                  ed25519_keypair):
    pytest.importorskip('pyld')
    from openbadgeslib.ob3 import OB3LdpSigner
    priv_pem, pub_pem = ed25519_keypair
    credential = _did_key_credential(ob3_credential, pub_pem)
    signed = OB3LdpSigner(priv_pem).sign(credential)    # embedded did:key proof

    report = _validate_ob3(ob3_validator_url,
                           json.dumps(signed).encode(), 'credential.json')
    _assert_ob3_valid(report, 'a did:key Data Integrity credential')


# The validator's ExternalProofProbe only accepts RS256/ES256 for VC-JWT — so
# these are the algorithms to prove interop with (EdDSA JWT is exercised, and
# its validator-side rejection documented, in the test below).
@pytest.mark.parametrize('algorithm, key_fixture', [
    ('RS256', 'rsa_priv_pem'),
    ('ES256', 'ecc_priv_pem'),
])
def test_ob3_vc_jwt_is_valid(request, algorithm, key_fixture,
                             ob3_validator_url, ob3_credential):
    from openbadgeslib.ob3 import OB3Signer
    priv_pem = request.getfixturevalue(key_fixture)
    token = OB3Signer(priv_pem, algorithm=algorithm).sign(ob3_credential)

    report = _validate_ob3(ob3_validator_url, token.encode(), 'credential.jwt')
    _assert_ob3_valid(report, 'a %s VC-JWT' % algorithm)


def test_ob3_vc_jwt_eddsa_is_rejected_by_validator(ob3_validator_url,
                                                   ob3_credential,
                                                   ed25519_keypair):
    """Living documentation of an interop boundary: OB 3.0 permits EdDSA VC-JWTs
    and we issue them, but the official validator's ExternalProofProbe currently
    accepts only RS256/ES256 and fails EdDSA as FATAL. If this ever starts
    passing, the validator gained EdDSA support — revisit and promote EdDSA into
    the parametrized test above."""
    from openbadgeslib.ob3 import OB3Signer
    priv_pem, _ = ed25519_keypair
    token = OB3Signer(priv_pem, algorithm='EdDSA').sign(ob3_credential)

    report = _validate_ob3(ob3_validator_url, token.encode(), 'credential.jwt')
    outcome = report.get('summary', {}).get('outcome')
    assert outcome != 'VALID', (
        'validator now accepts EdDSA VC-JWTs — move EdDSA into the passing test')
    fatals = json.dumps(report.get('fatals', []))
    assert 'RS256' in fatals or 'ES256' in fatals, (
        'EdDSA VC-JWT failed for an unexpected reason, not the alg allow-list:\n%s'
        % json.dumps(report.get('fatals'), indent=2))
