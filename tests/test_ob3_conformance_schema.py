"""Conformance of the credentials we ISSUE against 1EdTech's official OB 3.0
JSON Schemas.

These are the same schema artifacts an official validator applies: the
``AchievementCredential`` and ``Profile`` schemas published at
``https://purl.imsglobal.org/spec/ob/v3p0/schema/json/`` — vendored verbatim
under ``fixtures/ob_schemas/`` (see that directory's README for provenance) so
the check runs offline and reproducibly, nothing fetched at test time. They are
JSON Schema **draft 2019-09**, self-contained (only internal ``#/$defs`` refs),
so the stock ``jsonschema`` library validates against them directly.

Scope, stated honestly: this proves our issued credentials are *structurally
conformant to the official schemas*. It is NOT the paid 1EdTech certification
(certification.imsglobal.org — a membership portal a human drives), and it does
not exercise the cryptographic proof (that is covered by the signer/verifier and
W3C-vector tests). The heavier Docker-based official validators live behind the
opt-in ``conformance_docker`` suite, out of the default/release gate.

We validate the canonical VC (``to_vc()``) AND the real on-the-wire form each
proof format emits — the decoded JWT-VC payload and the LDP signed document — so
a regression in either issuance path surfaces here.
"""
import base64
import json
from pathlib import Path

import pytest

# The whole module is about schema validation; without jsonschema there is
# nothing to assert (it ships in the [dev] extra, so CI always has it).
jsonschema = pytest.importorskip('jsonschema')
from jsonschema import Draft201909Validator  # noqa: E402

from openbadgeslib.ob3.credential import OB3_CONTEXT  # noqa: E402

SCHEMA_DIR = Path(__file__).parent / 'fixtures' / 'ob_schemas'
_SCHEMA_BASE = 'https://purl.imsglobal.org/spec/ob/v3p0/schema/json'

# JWT-VC is key-type-dependent (RS256/ES256/EdDSA), so every algorithm is a
# distinct issuance path worth validating; the credential body it carries is
# the same, which is exactly what the schema checks.
_JWT_SIGNERS = ['ob3_rsa_signer', 'ob3_ecc_signer', 'ob3_ed25519_signer']


def _load_validator(filename: str) -> 'Draft201909Validator':
    """Build a draft-2019-09 validator from a vendored official schema, with
    format assertion on (so ``validFrom`` must be a real ``date-time``, which
    jsonschema otherwise treats as an annotation only)."""
    schema = json.loads((SCHEMA_DIR / filename).read_text())
    return Draft201909Validator(
        schema, format_checker=Draft201909Validator.FORMAT_CHECKER)


@pytest.fixture(scope='session')
def credential_validator() -> 'Draft201909Validator':
    return _load_validator('ob_v3p0_achievementcredential_schema.json')


@pytest.fixture(scope='session')
def profile_validator() -> 'Draft201909Validator':
    return _load_validator('ob_v3p0_profile_schema.json')


def _assert_conformant(validator, document: dict) -> None:
    """Fail with every schema violation spelled out (path + message), not just
    the first — a partial credential is far quicker to fix when the report is
    complete."""
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    if errors:
        lines = ['%s: %s' % ('/'.join(map(str, e.path)) or '<root>', e.message)
                 for e in errors]
        raise AssertionError(
            'credential is not schema-conformant:\n  ' + '\n  '.join(lines))


def _jwt_payload(token: str) -> dict:
    """Decode a compact JWT's payload WITHOUT verifying the signature — we are
    checking the shape of what a consumer reconstructs, not the crypto (the
    verifier tests cover that). The middle segment is base64url with padding
    stripped."""
    segment = token.split('.')[1]
    padded = segment + '=' * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# ── the vendored schemas really are the official draft-2019-09 artifacts ─────

class TestVendoredSchemas:
    """Guard the provenance in-code: a bad refresh (wrong file, wrong draft)
    should fail loudly here rather than silently weaken every other check."""

    @pytest.mark.parametrize('filename', [
        'ob_v3p0_achievementcredential_schema.json',
        'ob_v3p0_profile_schema.json',
    ])
    def test_is_self_contained_draft_2019_09(self, filename):
        schema = json.loads((SCHEMA_DIR / filename).read_text())
        assert schema['$schema'] == 'https://json-schema.org/draft/2019-09/schema#'
        assert schema['$id'] == '%s/%s' % (_SCHEMA_BASE, filename)
        # Self-contained: no $ref points off to an external URL (all are #/$defs).
        for ref in _iter_refs(schema):
            assert ref.startswith('#'), 'unexpected external $ref: %s' % ref


def _iter_refs(node):
    """Yield every ``$ref`` string anywhere in a schema document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == '$ref' and isinstance(value, str):
                yield value
            else:
                yield from _iter_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_refs(item)


# ── the credentials we issue conform ─────────────────────────────────────────

class TestIssuedCredentialConforms:
    def test_context_prefix_is_official(self, ob3_credential):
        # The exact two-element prefix the official schema's Context $def pins.
        assert ob3_credential.to_vc()['@context'][:2] == OB3_CONTEXT

    def test_canonical_vc_conforms(self, ob3_credential, credential_validator):
        _assert_conformant(credential_validator, ob3_credential.to_vc())

    def test_issuer_is_a_conformant_profile(self, ob3_credential,
                                            profile_validator):
        _assert_conformant(profile_validator, ob3_credential.to_vc()['issuer'])

    @pytest.mark.parametrize('signer_fixture', _JWT_SIGNERS)
    def test_jwt_vc_payload_conforms(self, request, signer_fixture,
                                     ob3_credential, credential_validator):
        signer = request.getfixturevalue(signer_fixture)
        payload = _jwt_payload(signer.sign(ob3_credential))
        _assert_conformant(credential_validator, payload)

    def test_ldp_signed_credential_conforms(self, ob3_credential,
                                            ed25519_keypair,
                                            credential_validator):
        # The embedded-proof form is only producible with the [ldp] extra.
        pytest.importorskip('pyld')
        from openbadgeslib.ob3 import add_data_integrity_proof
        from openbadgeslib.ob3.did import did_key_from_pem
        priv_pem, pub_pem = ed25519_keypair
        did = did_key_from_pem(pub_pem)
        vm = '%s#%s' % (did, did[len('did:key:'):])
        signed = add_data_integrity_proof(ob3_credential.to_vc(), priv_pem, vm)
        _assert_conformant(credential_validator, signed)

    def test_revocable_credential_conforms(self, ob3_credential,
                                           credential_validator):
        # A credential carrying a BitstringStatusListEntry — the shape
        # openbadges-publish wires in — must still validate.
        import dataclasses
        status = {
            'id': 'https://issuer.example/badge_1/revocation.jwt#0',
            'type': 'BitstringStatusListEntry',
            'statusPurpose': 'revocation',
            'statusListIndex': '0',
            'statusListCredential':
                'https://issuer.example/badge_1/revocation.jwt',
        }
        revocable = dataclasses.replace(ob3_credential, credential_status=[status])
        _assert_conformant(credential_validator, revocable.to_vc())

    def test_fully_populated_credential_conforms(self, credential_validator):
        # #162: a credential exercising the whole broadened model — identifier
        # (subject with no id), result + linked resultDescription, alignment,
        # achievementType, creditsAvailable/creditsEarned, rich evidence — must
        # still validate against the official AchievementCredential schema.
        from openbadgeslib.ob3 import (OpenBadgeCredential, Issuer, Achievement,
                                       Alignment, Evidence, IdentityObject,
                                       Result, ResultDescription)
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://issuer.example', name='Issuer',
                          url='https://issuer.example', email='i@example.com'),
            recipient_id=None,
            achievement=Achievement(
                id='https://a.example/1', name='A', description='d',
                criteria_narrative='c', achievement_type='Competency',
                credits_available=3.0,
                alignments=[Alignment(target_name='Skill',
                                      target_url='https://f/x',
                                      target_framework='F', target_code='X.1')],
                result_descriptions=[ResultDescription(
                    id='urn:uuid:rd-1', name='Grade', result_type='LetterGrade',
                    allowed_values=['A', 'B', 'C'], required_value='B')]),
            credits_earned=3.0,
            evidence=[Evidence(id='https://ev.example/1', narrative='did it')],
            identifiers=[IdentityObject(identity_hash='sha256$abc',
                                        identity_type='emailAddress',
                                        hashed=True, salt='NaCl')],
            results=[Result(value='A', status='Completed',
                            result_description='urn:uuid:rd-1')])
        _assert_conformant(credential_validator, cred.to_vc())


# ── negative control: the check actually discriminates ───────────────────────

class TestSchemaDiscriminates:
    """Without this, an always-passing validator (e.g. a schema that reduced to
    ``true``) would look identical to a correct one. These prove real rejection."""

    def test_missing_required_field_is_rejected(self, ob3_credential,
                                                credential_validator):
        broken = ob3_credential.to_vc()
        del broken['issuer']            # 'issuer' is required by the schema
        assert list(credential_validator.iter_errors(broken)), \
            'schema accepted a credential with no issuer'

    def test_malformed_validFrom_is_rejected(self, ob3_credential,
                                             credential_validator):
        broken = ob3_credential.to_vc()
        broken['validFrom'] = 'not-a-date'   # violates format: date-time
        assert list(credential_validator.iter_errors(broken)), \
            'schema accepted a non-date-time validFrom'
