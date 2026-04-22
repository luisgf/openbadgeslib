"""Tests for the OpenBadges 3.0 credential data model."""
import pytest
from datetime import datetime, timezone, timedelta

from openbadgeslib.ob3.credential import (
    Achievement, Issuer, OpenBadgeCredential, OB3_CONTEXT, _iso, _parse_iso,
)


# ── Issuer ─────────────────────────────────────────────────────────────────────

class TestIssuer:
    def test_required_fields_present(self):
        d = Issuer(id='https://example.com', name='Acme').to_dict()
        assert d['id'] == 'https://example.com'
        assert d['name'] == 'Acme'
        assert d['type'] == ['Profile']

    def test_optional_fields_omitted_when_none(self):
        d = Issuer(id='https://x.com', name='X').to_dict()
        assert 'url' not in d
        assert 'email' not in d
        assert 'image' not in d

    def test_optional_fields_included_when_set(self):
        d = Issuer(
            id='https://x.com', name='X',
            url='https://x.com', email='hi@x.com', image_url='https://x.com/logo.png',
        ).to_dict()
        assert d['url'] == 'https://x.com'
        assert d['email'] == 'hi@x.com'
        assert d['image'] == {'id': 'https://x.com/logo.png', 'type': 'Image'}


# ── Achievement ────────────────────────────────────────────────────────────────

class TestAchievement:
    def test_required_fields_present(self):
        d = Achievement(
            id='https://example.com/a/1',
            name='Badge',
            description='Desc',
            criteria_narrative='Do the thing',
        ).to_dict()
        assert d['id'] == 'https://example.com/a/1'
        assert d['name'] == 'Badge'
        assert d['description'] == 'Desc'
        assert d['criteria'] == {'narrative': 'Do the thing'}
        assert d['type'] == ['Achievement']

    def test_image_omitted_when_none(self):
        d = Achievement(id='x', name='n', description='d', criteria_narrative='c').to_dict()
        assert 'image' not in d

    def test_image_included_when_set(self):
        d = Achievement(
            id='x', name='n', description='d', criteria_narrative='c',
            image_url='https://example.com/img.svg',
        ).to_dict()
        assert d['image'] == {'id': 'https://example.com/img.svg', 'type': 'Image'}

    def test_tags_omitted_when_empty(self):
        d = Achievement(id='x', name='n', description='d', criteria_narrative='c').to_dict()
        assert 'tag' not in d

    def test_tags_included_when_set(self):
        d = Achievement(
            id='x', name='n', description='d', criteria_narrative='c',
            tags=['python', 'testing'],
        ).to_dict()
        assert d['tag'] == ['python', 'testing']


# ── OpenBadgeCredential ────────────────────────────────────────────────────────

def _make_credential(**kwargs):
    issuer = Issuer(id='https://issuer.example.com', name='Issuer')
    achievement = Achievement(
        id='https://example.com/a/1', name='Badge',
        description='Desc', criteria_narrative='Do the thing',
    )
    defaults = dict(
        issuer=issuer,
        recipient_id='mailto:user@example.com',
        achievement=achievement,
        issuance_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(kwargs)
    return OpenBadgeCredential(**defaults)


class TestOpenBadgeCredential:
    def test_auto_generates_id_when_not_provided(self):
        cred = _make_credential()
        assert cred.id.startswith('urn:uuid:')

    def test_provided_id_is_preserved(self):
        cred = _make_credential(id='urn:uuid:fixed')
        assert cred.id == 'urn:uuid:fixed'

    def test_auto_sets_name_from_achievement(self):
        cred = _make_credential()
        assert cred.name == 'Badge'

    def test_explicit_name_overrides_achievement_name(self):
        cred = _make_credential(name='Custom Name')
        assert cred.name == 'Custom Name'

    def test_auto_sets_issuance_date_when_none(self):
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://x.com', name='X'),
            recipient_id='mailto:x@x.com',
            achievement=Achievement(id='x', name='n', description='d', criteria_narrative='c'),
        )
        assert cred.issuance_date is not None
        assert cred.issuance_date.tzinfo is not None

    # ── to_vc ──────────────────────────────────────────────────────────────────

    def test_to_vc_context(self):
        vc = _make_credential().to_vc()
        assert vc['@context'] == OB3_CONTEXT

    def test_to_vc_type(self):
        vc = _make_credential().to_vc()
        assert 'VerifiableCredential' in vc['type']
        assert 'OpenBadgeCredential' in vc['type']

    def test_to_vc_issuer_is_dict(self):
        vc = _make_credential().to_vc()
        assert isinstance(vc['issuer'], dict)
        assert vc['issuer']['id'] == 'https://issuer.example.com'

    def test_to_vc_credential_subject(self):
        vc = _make_credential().to_vc()
        subj = vc['credentialSubject']
        assert subj['id'] == 'mailto:user@example.com'
        assert 'AchievementSubject' in subj['type']
        assert subj['achievement']['name'] == 'Badge'

    def test_to_vc_issuance_date_format(self):
        vc = _make_credential().to_vc()
        assert vc['issuanceDate'] == '2026-01-01T00:00:00Z'

    def test_to_vc_expiration_date_included_when_set(self):
        exp = datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        vc = _make_credential(expiration_date=exp).to_vc()
        assert vc['expirationDate'] == '2030-12-31T23:59:59Z'

    def test_to_vc_expiration_omitted_when_none(self):
        vc = _make_credential().to_vc()
        assert 'expirationDate' not in vc

    def test_to_vc_evidence_included_when_set(self):
        vc = _make_credential(evidence_url='https://example.com/proof').to_vc()
        assert vc['evidence'][0]['id'] == 'https://example.com/proof'

    def test_to_vc_evidence_omitted_when_none(self):
        vc = _make_credential().to_vc()
        assert 'evidence' not in vc

    # ── to_jwt_payload ────────────────────────────────────────────────────────

    def test_to_jwt_payload_standard_claims(self):
        cred = _make_credential(id='urn:uuid:test')
        p = cred.to_jwt_payload()
        assert p['iss'] == 'https://issuer.example.com'
        assert p['sub'] == 'mailto:user@example.com'
        assert p['jti'] == 'urn:uuid:test'
        assert p['iat'] == int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp())

    def test_to_jwt_payload_contains_vc(self):
        p = _make_credential().to_jwt_payload()
        assert 'vc' in p
        assert p['vc']['type'] == ['VerifiableCredential', 'OpenBadgeCredential']

    def test_to_jwt_payload_exp_present_when_expiration_set(self):
        exp = datetime(2030, 1, 1, tzinfo=timezone.utc)
        p = _make_credential(expiration_date=exp).to_jwt_payload()
        assert p['exp'] == int(exp.timestamp())

    def test_to_jwt_payload_no_exp_when_no_expiration(self):
        p = _make_credential().to_jwt_payload()
        assert 'exp' not in p

    # ── from_jwt_payload roundtrip ────────────────────────────────────────────

    def test_roundtrip_preserves_all_fields(self):
        exp = datetime(2030, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        original = _make_credential(
            id='urn:uuid:roundtrip',
            expiration_date=exp,
            evidence_url='https://example.com/proof',
        )
        restored = OpenBadgeCredential.from_jwt_payload(original.to_jwt_payload())

        assert restored.id == original.id
        assert restored.issuer.id == original.issuer.id
        assert restored.issuer.name == original.issuer.name
        assert restored.recipient_id == original.recipient_id
        assert restored.achievement.id == original.achievement.id
        assert restored.achievement.name == original.achievement.name
        assert restored.achievement.criteria_narrative == original.achievement.criteria_narrative
        assert restored.issuance_date == original.issuance_date
        assert restored.expiration_date == original.expiration_date
        assert restored.evidence_url == original.evidence_url

    def test_roundtrip_without_optionals(self):
        original = _make_credential()
        restored = OpenBadgeCredential.from_jwt_payload(original.to_jwt_payload())
        assert restored.expiration_date is None
        assert restored.evidence_url is None


# ── helpers ────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_iso_utc_format(self):
        dt = datetime(2026, 4, 22, 10, 30, 0, tzinfo=timezone.utc)
        assert _iso(dt) == '2026-04-22T10:30:00Z'

    def test_parse_iso_z_suffix(self):
        dt = _parse_iso('2026-01-01T00:00:00Z')
        assert dt == datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_parse_iso_roundtrip(self):
        dt = datetime(2026, 7, 15, 8, 0, 0, tzinfo=timezone.utc)
        assert _parse_iso(_iso(dt)) == dt
