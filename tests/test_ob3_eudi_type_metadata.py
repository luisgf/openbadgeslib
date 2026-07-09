"""Tests for SD-JWT VC Type Metadata generation (openbadgeslib.ob3.eudi).

The document builder and its SRI integrity are pure-Python and run always; the
round-trip — issue a badge, then validate its payload with openvc-core's Type
Metadata verifier — needs the [eudi] extra and skips without it.
"""
import base64
import hashlib
import json

import pytest

from openbadgeslib.ob3.eudi import (
    OB3_SD_JWT_VCT,
    badge_type_metadata,
    issue_badge_sd_jwt,
    type_metadata_document_bytes,
    type_metadata_integrity,
    verify_badge_sd_jwt,
)

VCT = 'https://issuer.example/vct/openbadge'


def _resolver(url, served):
    """A Type Metadata resolver serving *served* bytes for *url* only."""
    def resolve(requested):
        if requested == url:
            return served
        raise LookupError('no metadata at %r' % requested)
    return resolve


class TestTypeMetadataDocument:
    def test_shape_marks_always_disclosed_claims_mandatory(self):
        doc = badge_type_metadata(VCT)
        assert doc['vct'] == VCT
        by_path = {tuple(c['path']): c for c in doc['claims']}
        for always in (('name',), ('achievement',), ('achievement', 'name'),
                       ('validFrom',)):
            assert by_path[always]['mandatory'] is True
        # the recipient identity is selectively disclosable -> not mandatory
        assert not by_path[('credentialSubject',)].get('mandatory')

    def test_default_vct(self):
        assert badge_type_metadata()['vct'] == OB3_SD_JWT_VCT

    def test_optional_description(self):
        assert 'description' not in badge_type_metadata(VCT)
        assert badge_type_metadata(VCT, description='d')['description'] == 'd'

    def test_integrity_is_sri_over_served_bytes(self):
        doc = badge_type_metadata(VCT)
        served = type_metadata_document_bytes(doc)
        expected = 'sha256-' + base64.b64encode(
            hashlib.sha256(served).digest()).decode('ascii')
        assert type_metadata_integrity(doc) == expected

    def test_served_bytes_are_deterministic(self):
        assert type_metadata_document_bytes(badge_type_metadata(VCT)) == \
            type_metadata_document_bytes(badge_type_metadata(VCT))

    def test_served_bytes_parse_back_to_the_document(self):
        doc = badge_type_metadata(VCT)
        assert json.loads(type_metadata_document_bytes(doc))['vct'] == VCT


class TestTypeMetadataRoundtrip:
    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip('openvc')

    def test_issued_badge_validates_against_openvc(
            self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        from openvc.type_metadata import validate_type_metadata
        doc = badge_type_metadata(VCT, description='An OB 3.0 badge as SD-JWT VC.')
        served = type_metadata_document_bytes(doc)
        integrity = type_metadata_integrity(doc)
        token = issue_badge_sd_jwt(
            ob3_credential, privkey_pem=ed25519_priv_pem, vct=VCT,
            vct_integrity=integrity)
        payload = verify_badge_sd_jwt(
            token, pubkey_pem=ed25519_pub_pem, expected_vct=VCT).claims
        assert payload['vct#integrity'] == integrity
        result = validate_type_metadata(
            payload, vct=payload['vct'], vct_integrity=payload['vct#integrity'],
            resolve=_resolver(VCT, served))
        assert result.vct == VCT

    def test_default_issue_has_no_integrity_pin(
            self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        token = issue_badge_sd_jwt(
            ob3_credential, privkey_pem=ed25519_priv_pem, vct=VCT)
        payload = verify_badge_sd_jwt(
            token, pubkey_pem=ed25519_pub_pem, expected_vct=VCT).claims
        assert 'vct#integrity' not in payload

    def test_tampered_metadata_fails_the_integrity_pin(
            self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        from openvc.type_metadata import (TypeMetadataError,
                                          validate_type_metadata)
        doc = badge_type_metadata(VCT)
        integrity = type_metadata_integrity(doc)
        token = issue_badge_sd_jwt(
            ob3_credential, privkey_pem=ed25519_priv_pem, vct=VCT,
            vct_integrity=integrity)
        payload = verify_badge_sd_jwt(
            token, pubkey_pem=ed25519_pub_pem, expected_vct=VCT).claims
        tampered = type_metadata_document_bytes(
            badge_type_metadata(VCT, name='Tampered'))
        with pytest.raises(TypeMetadataError):
            validate_type_metadata(
                payload, vct=payload['vct'],
                vct_integrity=payload['vct#integrity'],
                resolve=_resolver(VCT, tampered))

    def test_mandatory_claim_absent_is_rejected(self):
        from openvc.type_metadata import (TypeMetadataClaimsInvalid,
                                          validate_type_metadata)
        served = type_metadata_document_bytes(badge_type_metadata(VCT))
        # a payload missing the mandatory `achievement` claim
        payload = {'vct': VCT, 'name': 'x', 'validFrom': '2026-01-01T00:00:00Z'}
        with pytest.raises(TypeMetadataClaimsInvalid):
            validate_type_metadata(
                payload, vct=VCT, vct_integrity=None,
                resolve=_resolver(VCT, served))
