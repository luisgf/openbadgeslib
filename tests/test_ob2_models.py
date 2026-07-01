"""Tests for the strict OpenBadges 2.0 data model (openbadgeslib.ob2.models)."""
from datetime import datetime, timezone

import pytest

from openbadgeslib.ob2 import (
    Assertion, IdentityObject, Verification,
    BadgeClass, Profile, CryptographicKey, RevocationList,
    hash_identity, OB2_CONTEXT,
)


# ── IdentityObject ──────────────────────────────────────────────────────────────

class TestIdentityObject:
    def test_create_hashes_email(self):
        recip = IdentityObject.create('a@b.com', salt='s4lt3d')
        assert recip.hashed is True
        assert recip.salt == 's4lt3d'
        assert recip.type == 'email'
        assert recip.identity == hash_identity('a@b.com', 's4lt3d')
        assert recip.identity.startswith('sha256$')

    def test_to_dict_emits_boolean_hashed(self):
        d = IdentityObject.create('a@b.com', salt='x').to_dict()
        assert d['hashed'] is True
        assert d['type'] == 'email'
        assert d['salt'] == 'x'

    def test_from_dict_rejects_string_hashed(self):
        # The legacy OB 1.0 string "true" must be rejected by strict OB 2.0.
        with pytest.raises(ValueError):
            IdentityObject.from_dict({'identity': 'sha256$abc', 'hashed': 'true', 'salt': 'x'})

    def test_from_dict_accepts_boolean_hashed(self):
        recip = IdentityObject.from_dict(
            {'identity': 'sha256$abc', 'hashed': True, 'salt': 'x', 'type': 'email'})
        assert recip.hashed is True
        assert recip.identity == 'sha256$abc'

    def test_from_dict_requires_identity(self):
        with pytest.raises(ValueError):
            IdentityObject.from_dict({'hashed': True})


# ── Verification ────────────────────────────────────────────────────────────────

class TestVerification:
    @pytest.mark.parametrize('raw,canonical', [
        ('SignedBadge', 'SignedBadge'), ('signed', 'SignedBadge'),
        ('HostedBadge', 'HostedBadge'), ('hosted', 'HostedBadge'),
    ])
    def test_from_dict_canonicalizes_type(self, raw, canonical):
        v = Verification.from_dict({'type': raw})
        assert v.type == canonical

    def test_from_dict_rejects_unknown_type(self):
        with pytest.raises(ValueError):
            Verification.from_dict({'type': 'Nonsense'})

    def test_to_dict_signed_includes_creator(self):
        d = Verification(type='SignedBadge', creator='https://e/k.json').to_dict()
        assert d == {'type': 'SignedBadge', 'creator': 'https://e/k.json'}

    def test_to_dict_hosted_has_no_creator(self):
        assert Verification(type='HostedBadge').to_dict() == {'type': 'HostedBadge'}


# ── Assertion ───────────────────────────────────────────────────────────────────

def _assertion(**kw):
    kw.setdefault('recipient', IdentityObject.create('a@b.com', salt='s'))
    kw.setdefault('badge', 'https://example.com/badge.json')
    kw.setdefault('verification', Verification(type='SignedBadge', creator='https://e/k.json'))
    kw.setdefault('issued_on', datetime(2026, 1, 1, tzinfo=timezone.utc))
    return Assertion(**kw)


class TestAssertion:
    def test_to_dict_is_strict_ob2_shape(self):
        d = _assertion(image='https://e/img.svg').to_dict()
        assert d['@context'] == OB2_CONTEXT
        assert d['type'] == 'Assertion'
        assert d['recipient']['hashed'] is True
        assert d['verification'] == {'type': 'SignedBadge', 'creator': 'https://e/k.json'}
        assert d['issuedOn'] == '2026-01-01T00:00:00Z'
        # No legacy OB 1.0 fields.
        assert 'uid' not in d
        assert 'verify' not in d

    def test_auto_id_is_urn_uuid(self):
        d = _assertion().to_dict()
        assert d['id'].startswith('urn:uuid:')

    def test_explicit_hosted_id_preserved(self):
        d = _assertion(id='https://example.com/assertions/x.json',
                       verification=Verification(type='HostedBadge')).to_dict()
        assert d['id'] == 'https://example.com/assertions/x.json'

    def test_auto_issued_on_defaults_to_now(self):
        a = Assertion(recipient=IdentityObject.create('a@b.com', salt='s'),
                      badge='https://e/b.json',
                      verification=Verification(type='HostedBadge'))
        assert a.issued_on is not None
        assert a.issued_on.tzinfo is not None

    def test_from_dict_roundtrip(self):
        d = _assertion(expires=datetime(2027, 1, 1, tzinfo=timezone.utc)).to_dict()
        parsed = Assertion.from_dict(d)
        assert parsed.id == d['id']
        assert parsed.badge == d['badge']
        assert parsed.verification.type == 'SignedBadge'
        assert parsed.issued_on == datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert parsed.expires == datetime(2027, 1, 1, tzinfo=timezone.utc)

    def test_from_dict_rejects_missing_context(self):
        d = _assertion().to_dict()
        del d['@context']
        with pytest.raises(ValueError):
            Assertion.from_dict(d)

    def test_from_dict_rejects_wrong_context(self):
        d = _assertion().to_dict()
        d['@context'] = 'https://example.com/other'
        with pytest.raises(ValueError):
            Assertion.from_dict(d)

    def test_from_dict_accepts_context_array(self):
        d = _assertion().to_dict()
        d['@context'] = [OB2_CONTEXT, 'https://example.com/extension']
        assert Assertion.from_dict(d).badge == d['badge']

    def test_from_dict_rejects_wrong_type(self):
        d = _assertion().to_dict()
        d['type'] = 'BadgeClass'
        with pytest.raises(ValueError):
            Assertion.from_dict(d)

    def test_from_dict_requires_id(self):
        d = _assertion().to_dict()
        del d['id']
        with pytest.raises(ValueError):
            Assertion.from_dict(d)

    def test_from_dict_rejects_unix_timestamp_issued_on(self):
        # OB 2.0 requires ISO 8601; a legacy Unix timestamp must be rejected.
        d = _assertion().to_dict()
        d['issuedOn'] = 1767225600
        with pytest.raises(ValueError):
            Assertion.from_dict(d)

    def test_from_dict_rejects_naive_datetime(self):
        d = _assertion().to_dict()
        d['issuedOn'] = '2026-01-01T00:00:00'   # no offset
        with pytest.raises(ValueError):
            Assertion.from_dict(d)


# ── other Badge Objects ─────────────────────────────────────────────────────────

class TestOtherObjects:
    def test_cryptographic_key_roundtrip(self):
        d = CryptographicKey(id='https://e/k.json', owner='https://e/org.json',
                             public_key_pem='PEM').to_dict()
        assert d['@context'] == OB2_CONTEXT
        assert d['type'] == 'CryptographicKey'
        key = CryptographicKey.from_dict(d)
        assert key.owner == 'https://e/org.json'
        assert key.public_key_pem == 'PEM'

    def test_profile_public_key_single_vs_list(self):
        one = Profile(id='i', name='n', public_key=['k1']).to_dict()
        assert one['publicKey'] == 'k1'
        many = Profile(id='i', name='n', public_key=['k1', 'k2']).to_dict()
        assert many['publicKey'] == ['k1', 'k2']
        assert many['type'] == 'Issuer'

    def test_badgeclass_shape(self):
        d = BadgeClass(id='b', name='n', description='d', image='img',
                       criteria='c', issuer='i').to_dict()
        assert d['type'] == 'BadgeClass'
        assert d['@context'] == OB2_CONTEXT
        assert d['issuer'] == 'i'

    def test_revocation_list_shape(self):
        d = RevocationList(id='r', issuer='i', revoked_assertions=['urn:uuid:1']).to_dict()
        assert d['type'] == 'RevocationList'
        assert d['revokedAssertions'] == ['urn:uuid:1']
