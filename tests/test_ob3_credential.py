"""Tests for the OpenBadges 3.0 credential data model."""
import copy
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from openbadgeslib.ob3.credential import (
    Achievement, Issuer, OpenBadgeCredential, OB3_CONTEXT, _iso, _parse_iso, _parse_date,
    _require,
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
        assert vc['validFrom'] == '2026-01-01T00:00:00Z'

    def test_to_vc_emits_credential_schema(self):
        vc = _make_credential().to_vc()
        schema = vc['credentialSchema']
        assert isinstance(schema, list) and len(schema) == 1
        assert schema[0]['type'] == '1EdTechJsonSchemaValidator2019'
        assert schema[0]['id'].startswith(
            'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/')

    def test_to_vc_expiration_date_included_when_set(self):
        exp = datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        vc = _make_credential(expiration_date=exp).to_vc()
        assert vc['validUntil'] == '2030-12-31T23:59:59Z'

    def test_to_vc_expiration_omitted_when_none(self):
        vc = _make_credential().to_vc()
        assert 'validUntil' not in vc

    def test_from_jwt_payload_accepts_legacy_vc11_fields(self):
        # Backward compat: a VC 1.1 credential (issuanceDate/expirationDate)
        # must still be readable.
        payload = _make_credential().to_jwt_payload()
        payload['issuanceDate'] = payload.pop('validFrom')
        restored = OpenBadgeCredential.from_jwt_payload(payload)
        assert restored.issuance_date == datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_from_jwt_payload_accepts_array_credential_subject(self):
        # credentialSubject may be a single object or a non-empty array; an
        # array must be accepted and its first element used.
        payload = _make_credential().to_jwt_payload()
        subject = payload['credentialSubject']
        payload['credentialSubject'] = [subject]
        restored = OpenBadgeCredential.from_jwt_payload(payload)
        assert restored.recipient_id == 'mailto:user@example.com'
        assert restored.achievement.name == 'Badge'

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
        # OB3 native VC-JWT: validFrom maps to nbf (there is no iat claim).
        assert p['nbf'] == int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp())
        assert 'iat' not in p

    def test_to_jwt_payload_is_native_credential(self):
        # OB3 native VC-JWT: the payload IS the credential (top-level members),
        # NOT nested under a 'vc' claim.
        p = _make_credential().to_jwt_payload()
        assert 'vc' not in p
        assert p['type'] == ['VerifiableCredential', 'OpenBadgeCredential']
        assert p['@context'][0] == 'https://www.w3.org/ns/credentials/v2'
        assert 'credentialSubject' in p and 'issuer' in p and 'validFrom' in p

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


class TestFromVcDocument:
    def test_vc_roundtrip_without_jwt_claims(self):
        # A JSON-LD VC document (the Data Integrity shape) has no iss/nbf/sub
        # registered claims; from_vc_document must reconstruct it all the same.
        original = _make_credential()
        doc = original.to_vc()
        assert 'iss' not in doc and 'nbf' not in doc
        restored = OpenBadgeCredential.from_vc_document(doc)
        assert restored.id == original.id
        assert restored.issuer.id == original.issuer.id
        assert restored.recipient_id == original.recipient_id
        assert restored.achievement.id == original.achievement.id

    def test_proof_member_is_ignored(self):
        doc = _make_credential().to_vc()
        doc['proof'] = {'type': 'DataIntegrityProof',
                        'cryptosuite': 'eddsa-rdfc-2022', 'proofValue': 'z1'}
        restored = OpenBadgeCredential.from_vc_document(doc)
        assert restored.id == doc['id']

    def test_same_validation_as_jwt_payload(self):
        # The shared _from_vc body enforces the same structural checks.
        doc = _make_credential().to_vc()
        del doc['credentialSubject']
        with pytest.raises(ValueError):
            OpenBadgeCredential.from_vc_document(doc)
        doc2 = _make_credential().to_vc()
        doc2['@context'] = ['https://evil.example/context']
        with pytest.raises(ValueError):
            OpenBadgeCredential.from_vc_document(doc2)

    @staticmethod
    def _with_images(issuer_image, achievement_image):
        doc = _make_credential().to_vc()
        doc['issuer']['image'] = issuer_image
        doc['credentialSubject']['achievement']['image'] = achievement_image
        return OpenBadgeCredential.from_vc_document(doc)

    def test_image_given_as_a_string_is_its_id(self):
        # "image": X and "image": {"id": X} are one statement in JSON-LD.
        restored = self._with_images('https://x.example/logo.png',
                                     'https://x.example/badge.png')
        assert restored.issuer.image_url == 'https://x.example/logo.png'
        assert restored.achievement.image_url == 'https://x.example/badge.png'

    def test_image_object_is_read_as_before(self):
        restored = self._with_images(
            {'id': 'https://x.example/logo.png', 'type': 'Image', 'caption': 'c'},
            {'id': 'https://x.example/badge.png'})
        assert restored.issuer.image_url == 'https://x.example/logo.png'
        assert restored.achievement.image_url == 'https://x.example/badge.png'

    @pytest.mark.parametrize('image', [
        None, '', 5, True, {}, {'type': 'Image', 'caption': 'no id'}])
    def test_anything_else_is_no_image(self, image):
        restored = self._with_images(image, image)
        assert restored.issuer.image_url is None
        assert restored.achievement.image_url is None

    def test_string_image_is_not_what_is_emitted(self):
        # Only the read is wider: an image is still written as an object.
        restored = self._with_images('https://x.example/logo.png',
                                     'https://x.example/badge.png')
        doc = restored.to_vc()
        assert doc['issuer']['image'] == {
            'id': 'https://x.example/logo.png', 'type': 'Image'}
        assert doc['credentialSubject']['achievement']['image'] == {
            'id': 'https://x.example/badge.png', 'type': 'Image'}


# ── a value, its one-entry array and the value written twice ──────────────────

_ALIGNMENT = {'type': ['Alignment'], 'targetName': 'Competency',
              'targetUrl': 'https://f.example/1', 'targetFramework': 'F',
              'targetCode': 'c1', 'targetDescription': 'd'}


def _rich_vc():
    """A credential document with every member the model reads, each list
    with one entry."""
    doc = _make_credential(
        id='urn:uuid:00000000-0000-0000-0000-0000000000c1',
        expiration_date=datetime(2099, 1, 1, tzinfo=timezone.utc)).to_vc()
    doc['name'] = 'A badge'
    doc['endorsementJwt'] = ['a.b.c']
    doc['credentialStatus'] = [{
        'id': 'https://issuer.example.com/status/1#5',
        'type': 'BitstringStatusListEntry', 'statusPurpose': 'revocation',
        'statusListIndex': '5',
        'statusListCredential': 'https://issuer.example.com/status/1'}]
    doc['issuer'].update(
        url='https://issuer.example.com/home', email='i@issuer.example.com',
        image={'id': 'https://issuer.example.com/logo.png', 'type': 'Image'},
        endorsementJwt=['d.e.f'])
    subject = doc['credentialSubject']
    subject['creditsEarned'] = 3.5
    subject['identifier'] = [{
        'type': 'IdentityObject', 'identityHash': 'user@example.com',
        'identityType': 'emailAddress', 'hashed': False, 'salt': 's'}]
    subject['result'] = [{
        'type': ['Result'], 'value': 'A', 'status': 'Completed',
        'achievedLevel': 'urn:level:1', 'resultDescription': 'urn:rd:1',
        'alignment': [dict(_ALIGNMENT)]}]
    subject['achievement'].update(
        image={'id': 'https://example.com/a/1.png', 'type': 'Image'},
        tag=['one'], achievementType='Badge', creditsAvailable=4.0,
        alignment=[dict(_ALIGNMENT)], endorsementJwt=['g.h.i'],
        resultDescription=[{
            'id': 'urn:rd:1', 'type': ['ResultDescription'], 'name': 'Grade',
            'resultType': 'LetterGrade', 'allowedValue': ['A'],
            'requiredValue': 'C', 'requiredLevel': 'urn:level:1',
            'valueMin': 'D', 'valueMax': 'A',
            'alignment': [dict(_ALIGNMENT)]}])
    doc['evidence'] = [{
        'id': 'https://example.com/e/1', 'type': ['Evidence'],
        'narrative': 'n', 'name': 'e', 'description': 'd', 'genre': 'g',
        'audience': 'a'}]
    return doc


def _at(doc, path):
    for key in path:
        doc = doc[key]
        doc = doc[0] if isinstance(doc, list) else doc
    return doc


def _shown(doc):
    """The model of *doc*, written out: its values and their Python types."""
    return repr(replace(OpenBadgeCredential.from_vc_document(doc), raw=None))


_ACH = ('credentialSubject', 'achievement')
# the three places an alignment is read at
_ALIGNMENTS = (_ACH + ('alignment',), _ACH + ('resultDescription', 'alignment'),
               ('credentialSubject', 'result', 'alignment'))
# read as one value, and silently read wrong from an array before the fix
ONE_VALUE = [
    ((), 'name'),
    (('issuer',), 'name'), (('issuer',), 'url'), (('issuer',), 'email'),
    (('issuer',), 'image'),
    (('credentialSubject',), 'creditsEarned'),
    (_ACH, 'description'), (_ACH, 'criteria'), (_ACH + ('criteria',), 'narrative'),
    (_ACH, 'image'), (_ACH, 'achievementType'), (_ACH, 'creditsAvailable'),
    (_ACH + ('resultDescription',), 'requiredValue'),
    (_ACH + ('resultDescription',), 'requiredLevel'),
    (_ACH + ('resultDescription',), 'valueMin'),
    (_ACH + ('resultDescription',), 'valueMax'),
    (('credentialSubject', 'identifier'), 'salt'),
    (('credentialSubject', 'result'), 'value'),
    (('credentialSubject', 'result'), 'status'),
    (('credentialSubject', 'result'), 'achievedLevel'),
    (('credentialSubject', 'result'), 'resultDescription'),
    (('evidence',), 'narrative'), (('evidence',), 'name'),
    (('evidence',), 'description'), (('evidence',), 'genre'),
    (('evidence',), 'audience'),
] + [(alignment, key) for alignment in _ALIGNMENTS
     for key in ('targetFramework', 'targetCode', 'targetDescription')]
# read as a list, and silently read as nothing (or as a str) from one value
MANY_VALUES = [
    (_ACH, 'tag'), (_ACH, 'resultDescription'),
    (('credentialSubject',), 'identifier'), (('credentialSubject',), 'result'),
]
# read from a value and from a list of them alike, before and after
EITHER_ALREADY = [
    ((), 'credentialSubject'), ((), 'evidence'), ((), 'credentialStatus'),
    ((), 'endorsementJwt'), (('issuer',), 'endorsementJwt'),
    (_ACH, 'endorsementJwt'), (_ACH, 'alignment'),
    (_ACH + ('resultDescription',), 'alignment'),
    (_ACH + ('resultDescription',), 'allowedValue'),
    (('credentialSubject', 'result'), 'alignment'),
]
# read as one value, and refused when given as an array: before and after
REFUSED_AS_ARRAY = [
    ((), 'issuer'), ((), 'validFrom'), ((), 'validUntil'),
    (('credentialSubject',), 'achievement'), (_ACH, 'name'),
    (_ACH + ('resultDescription',), 'name'),
    (_ACH + ('resultDescription',), 'resultType'),
    (('credentialSubject', 'identifier'), 'identityHash'),
    (('credentialSubject', 'identifier'), 'identityType'),
    (('credentialSubject', 'identifier'), 'hashed'),
] + [(alignment, key) for alignment in _ALIGNMENTS
     for key in ('targetName', 'targetUrl')]


class TestSpellingsReadAsOne:
    """In JSON-LD ``x``, ``[x]`` and ``[x, x]`` are one statement. The model
    reads them as one, so re-spelling a member -- which a holder can do under
    a valid Data Integrity proof -- neither drops it nor changes its type."""

    @pytest.mark.parametrize('path, key', ONE_VALUE)
    def test_one_value_from_its_array(self, path, key):
        plain = _rich_vc()
        value = _at(plain, path)[key]
        for spelling in ([value], [value, copy.deepcopy(value)]):
            respelled = _rich_vc()
            _at(respelled, path)[key] = spelling
            assert _shown(respelled) == _shown(plain)

    @pytest.mark.parametrize('path, key', MANY_VALUES + EITHER_ALREADY)
    def test_list_from_a_single_value(self, path, key):
        plain = _rich_vc()
        value = _at(plain, path)[key]
        respelled = _rich_vc()
        if isinstance(value, list):
            (_at(respelled, path)[key],) = value
        else:                           # the credentialSubject
            _at(respelled, path)[key] = [value]
        assert _shown(respelled) == _shown(plain)

    @pytest.mark.parametrize('path, key', REFUSED_AS_ARRAY)
    def test_refusals_are_unchanged(self, path, key):
        # Failing closed on the other spelling is not the defect: these
        # refused it before and still do.
        respelled = _rich_vc()
        _at(respelled, path)[key] = [_at(respelled, path)[key]]
        with pytest.raises(ValueError):
            OpenBadgeCredential.from_vc_document(respelled)

    def test_values_that_differ_are_read_as_before(self):
        # Only an issuer can sign two different values of one member; the
        # model reads those as it always did, site by site.
        doc = _rich_vc()
        achievement = doc['credentialSubject']['achievement']
        achievement['criteria'] = [{'narrative': 'one'}, {'narrative': 'two'}]
        achievement['image'] = ['https://x.example/1.png', 'https://x.example/2.png']
        achievement['creditsAvailable'] = [1.0, 2.0]
        achievement['description'] = ['one', 'two']
        doc['issuer']['name'] = ['one', {'@value': 'one', '@language': 'en'}]
        restored = OpenBadgeCredential.from_vc_document(doc)
        assert restored.achievement.criteria_narrative == ''
        assert restored.achievement.image_url is None
        assert restored.achievement.credits_available is None
        assert restored.achievement.description == ['one', 'two']
        assert restored.issuer.name == ['one', {'@value': 'one', '@language': 'en'}]

    @pytest.mark.parametrize('image, image_url', [
        ([{'id': 'urn:i', 'type': 'Image'}], 'urn:i'),
        (['urn:i'], 'urn:i'),
        ([{'id': 'urn:i', 'type': 'Image'}, 'urn:i', {'id': 'urn:i'}], 'urn:i'),
        # two objects of one image that differ in a spelling nobody reads
        ([{'id': 'urn:i', 'type': 'Image', 'caption': 'c'},
          {'id': 'urn:i', 'type': ['Image'], 'caption': ['c']}], 'urn:i'),
        (['urn:i', 'urn:j'], None),
        (['urn:i', {'type': 'Image'}], None),
        ([['urn:i']], None),
        ([], None),
    ])
    def test_image_in_an_array(self, image, image_url):
        doc = _rich_vc()
        doc['issuer']['image'] = image
        doc['credentialSubject']['achievement']['image'] = image
        restored = OpenBadgeCredential.from_vc_document(doc)
        assert restored.issuer.image_url == image_url
        assert restored.achievement.image_url == image_url

    @pytest.mark.parametrize('criteria, narrative', [
        ([{'narrative': 'n'}], 'n'),
        ([{'narrative': 'n'}, {'narrative': 'n'}], 'n'),
        # two objects of one criteria that differ in a spelling nobody reads
        ([{'id': '_:c', 'type': 'Criteria', 'narrative': 'n'},
          {'id': '_:c', 'type': ['Criteria'], 'narrative': ['n']}], 'n'),
        ({'narrative': ['n', 'n']}, 'n'),
        # really different, or not a criteria at all: none, as before
        ([{'narrative': 'n'}, {'narrative': 'm'}], ''),
        ([{'narrative': 'n'}, 'urn:criteria'], ''),
        ([{'narrative': 'n'}, [{'narrative': 'n'}]], ''),
        ([], ''), ('urn:criteria', ''), (None, ''), ({}, ''),
    ])
    def test_criteria_in_an_array(self, criteria, narrative):
        doc = _rich_vc()
        doc['credentialSubject']['achievement']['criteria'] = criteria
        restored = OpenBadgeCredential.from_vc_document(doc)
        assert restored.achievement.criteria_narrative == narrative

    def test_what_counts_as_the_same_value(self):
        from openbadgeslib.ob3.credential import _many, _one, _same
        assert _same(42, 42.0) and _same('a', 'a') and _same(None, None)
        assert not _same(True, 1) and not _same(1, True) and _same(True, True)
        assert not _same('1', 1) and not _same('a', ['a'])
        assert _same({'a': [1, {'b': 2}]}, {'a': [1.0, {'b': 2}]})
        assert not _same({'a': 1}, {'a': 1, 'b': 2})
        assert not _same([1, 2], [1]) and not _same([1, 2], [2, 1])
        assert _one([4.0, 4]) == 4.0 and _one(['a']) == 'a'
        assert _one([]) == [] and _one(['a', 'b']) == ['a', 'b']
        assert _one([True, 1]) == [True, 1]
        assert _many('a') == ['a'] and _many({'a': 1}) == [{'a': 1}]
        assert _many(['a']) == ['a'] and _many(None) is None


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

    @pytest.mark.parametrize('bad_value', [12345, None, [], {}, True])
    def test_parse_date_non_string_raises_clean_value_error(self, bad_value):
        # A non-string date claim must not leak a raw AttributeError from
        # _parse_iso's str.replace() call.
        with pytest.raises(ValueError):
            _parse_date(bad_value, 'vc.validFrom')

    def test_parse_iso_naive_datetime_raises_value_error(self):
        # A UTC/offset-less date-time is valid ISO 8601 but would produce a
        # naive datetime that can't be compared against the tz-aware "now"
        # used in verify() — reject it here instead of letting a TypeError
        # surface downstream.
        with pytest.raises(ValueError):
            _parse_iso('2026-01-01T00:00:00')

    @pytest.mark.parametrize('bad_value', [12345, True, ['a'], {'x': 1}])
    def test_require_non_string_raises_value_error(self, bad_value):
        # id/name fields are consumed as strings downstream (recipient binding
        # calls .lower()); a non-string must be rejected here.
        with pytest.raises(ValueError, match="must be a string"):
            _require({'id': bad_value}, 'id', 'vc.credentialSubject')


class TestNaiveDatetimeAssumedUtc:
    def test_naive_issuance_date_coerced_to_utc(self):
        # A naive datetime is assumed UTC, so validFrom (string) and nbf (epoch)
        # agree instead of diverging by the host's local offset.
        cred = _make_credential(issuance_date=datetime(2026, 1, 1, 12, 0, 0))
        assert cred.issuance_date.tzinfo is not None
        assert cred.to_vc()['validFrom'] == '2026-01-01T12:00:00Z'
        aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert cred.to_jwt_payload()['nbf'] == int(aware.timestamp())

    def test_naive_expiration_date_coerced_to_utc(self):
        cred = _make_credential(expiration_date=datetime(2030, 6, 1, 0, 0, 0))
        assert cred.expiration_date.tzinfo is not None
        assert cred.to_vc()['validUntil'] == '2030-06-01T00:00:00Z'


# ── #162: broadened model — Evidence, Alignment, achievementType, credits ────

from openbadgeslib.ob3.credential import (  # noqa: E402
    Alignment, Evidence, IdentityObject, Result, ResultDescription)


class TestBroadenedModel:
    def _credential(self, **achievement_kw):
        return OpenBadgeCredential(
            issuer=Issuer(id='https://issuer.example', name='I'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c',
                                    **achievement_kw))

    def test_alignment_round_trip(self):
        cred = self._credential(alignments=[
            Alignment(target_name='Competency X',
                      target_url='https://framework.example/x',
                      target_framework='EU Framework', target_code='X.1'),
        ])
        vc = cred.to_vc()
        assert vc['credentialSubject']['achievement']['alignment'] == [{
            'type': ['Alignment'],
            'targetName': 'Competency X',
            'targetUrl': 'https://framework.example/x',
            'targetFramework': 'EU Framework',
            'targetCode': 'X.1',
        }]
        again = OpenBadgeCredential.from_vc_document(vc)
        assert again.achievement.alignments[0].target_name == 'Competency X'
        assert again.achievement.alignments[0].target_code == 'X.1'

    def test_achievement_type_and_credits_round_trip(self):
        cred = self._credential(achievement_type='Competency',
                                credits_available=3.5)
        ach = cred.to_vc()['credentialSubject']['achievement']
        assert ach['achievementType'] == 'Competency'
        assert ach['creditsAvailable'] == 3.5
        again = OpenBadgeCredential.from_vc_document(cred.to_vc())
        assert again.achievement.achievement_type == 'Competency'
        assert again.achievement.credits_available == 3.5

    def test_evidence_list_round_trip(self):
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://issuer.example', name='I'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
            evidence=[
                Evidence(id='https://ev.example/1', narrative='Did the thing',
                         name='Project'),
                Evidence(narrative='No URL, just a narrative'),
            ])
        vc = cred.to_vc()
        assert len(vc['evidence']) == 2
        assert vc['evidence'][0] == {
            'type': ['Evidence'], 'id': 'https://ev.example/1',
            'narrative': 'Did the thing', 'name': 'Project'}
        assert vc['evidence'][1] == {
            'type': ['Evidence'], 'narrative': 'No URL, just a narrative'}
        again = OpenBadgeCredential.from_vc_document(vc)
        assert [e.narrative for e in again.evidence] == \
            ['Did the thing', 'No URL, just a narrative']
        # backward-compatible convenience: first evidence URL
        assert again.evidence_url == 'https://ev.example/1'

    def test_evidence_url_still_works(self):
        # The single-URL convenience keeps issuing one Evidence object.
        cred = self._credential()
        cred.evidence_url = 'https://ev.example/only'
        vc = cred.to_vc()
        assert vc['evidence'] == [
            {'type': ['Evidence'], 'id': 'https://ev.example/only'}]

    def test_parse_from_raw_vc(self):
        vc = {
            '@context': OB3_CONTEXT,
            'id': 'urn:uuid:00000000-0000-0000-0000-0000000000f1',
            'type': ['VerifiableCredential', 'OpenBadgeCredential'],
            'issuer': 'https://issuer.example',
            'validFrom': '2024-01-01T00:00:00Z',
            'credentialSubject': {
                'id': 'mailto:r@example.com',
                'type': ['AchievementSubject'],
                'achievement': {
                    'id': 'https://a.example/1', 'type': ['Achievement'],
                    'name': 'A', 'description': 'd',
                    'criteria': {'narrative': 'c'},
                    'achievementType': 'Certificate',
                    'creditsAvailable': 2,
                    'alignment': [{'type': ['Alignment'],
                                   'targetName': 'C', 'targetUrl': 'https://f/x'}],
                },
            },
            'evidence': [{'type': ['Evidence'], 'id': 'https://ev/1',
                          'narrative': 'n'}],
        }
        cred = OpenBadgeCredential.from_vc_document(vc)
        assert cred.achievement.achievement_type == 'Certificate'
        assert cred.achievement.credits_available == 2.0
        assert cred.achievement.alignments[0].target_url == 'https://f/x'
        assert cred.evidence[0].narrative == 'n'

    def test_signed_credential_preserves_new_fields(self, rsa_priv_pem,
                                                    rsa_pub_pem):
        # End-to-end: the fields survive signing and verification.
        from openbadgeslib.ob3 import OB3Signer, OB3Verifier
        cred = self._credential(achievement_type='Competency',
                                credits_available=1.0,
                                alignments=[Alignment(
                                    target_name='Skill',
                                    target_url='https://f/skill')])
        token = OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256').sign(cred)
        verified = OB3Verifier(pubkey_pem=rsa_pub_pem).verify(token)
        assert verified.achievement.achievement_type == 'Competency'
        assert verified.achievement.alignments[0].target_name == 'Skill'

    # ── Result / ResultDescription / IdentityObject / creditsEarned ─────────────

    def test_identity_object_round_trip(self):
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://issuer.example', name='I'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
            identifiers=[IdentityObject(identity_hash='sha256$abc',
                                        identity_type='emailAddress',
                                        hashed=True, salt='NaCl')])
        subject = cred.to_vc()['credentialSubject']
        assert subject['identifier'] == [{
            'type': 'IdentityObject', 'hashed': True,
            'identityHash': 'sha256$abc', 'identityType': 'emailAddress',
            'salt': 'NaCl'}]
        again = OpenBadgeCredential.from_vc_document(cred.to_vc())
        assert again.identifiers[0].identity_hash == 'sha256$abc'
        assert again.identifiers[0].hashed is True
        assert again.identifiers[0].salt == 'NaCl'

    def test_identity_object_is_additional_properties_false(self):
        # The schema forbids extra keys on IdentityObject; to_dict emits exactly
        # the five allowed ones (no id, no stray members).
        d = IdentityObject(identity_hash='sha256$x', identity_type='emailAddress',
                           hashed=False).to_dict()
        assert set(d) == {'type', 'hashed', 'identityHash', 'identityType'}

    def test_identity_object_requires_boolean_hashed(self):
        with pytest.raises(ValueError, match='hashed must be a boolean'):
            IdentityObject.from_dict({'identityHash': 'x',
                                      'identityType': 'emailAddress',
                                      'hashed': 'true'})

    def test_subject_with_only_identifier_round_trips(self):
        # A subject conveying identity solely via `identifier` (no id) must
        # re-serialise WITH that identifier — before #162 it parsed but the
        # identifier was dropped, yielding a subject with neither id nor
        # identifier (non-conformant).
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://issuer.example', name='I'),
            recipient_id=None,
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
            identifiers=[IdentityObject(identity_hash='sha256$abc',
                                        identity_type='emailAddress',
                                        hashed=True)])
        again = OpenBadgeCredential.from_vc_document(cred.to_vc())
        assert again.recipient_id is None
        assert 'id' not in again.to_vc()['credentialSubject']
        assert again.to_vc()['credentialSubject']['identifier']

    def test_result_and_result_description_round_trip(self):
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://issuer.example', name='I'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(
                id='https://a.example/1', name='A', description='d',
                criteria_narrative='c',
                result_descriptions=[ResultDescription(
                    id='urn:uuid:rd-1', name='Final grade',
                    result_type='LetterGrade',
                    allowed_values=['A', 'B', 'C'], required_value='C',
                    alignments=[Alignment(target_name='Grd',
                                          target_url='https://f/g')])]),
            results=[Result(value='A', status='Completed',
                            result_description='urn:uuid:rd-1')])
        vc = cred.to_vc()
        assert vc['credentialSubject']['result'] == [{
            'type': ['Result'], 'status': 'Completed', 'value': 'A',
            'resultDescription': 'urn:uuid:rd-1'}]
        rd = vc['credentialSubject']['achievement']['resultDescription'][0]
        assert rd['id'] == 'urn:uuid:rd-1'
        assert rd['type'] == ['ResultDescription']
        assert rd['resultType'] == 'LetterGrade'
        assert rd['allowedValue'] == ['A', 'B', 'C']
        assert rd['requiredValue'] == 'C'
        again = OpenBadgeCredential.from_vc_document(vc)
        assert again.results[0].value == 'A'
        assert again.results[0].result_description == 'urn:uuid:rd-1'
        assert again.achievement.result_descriptions[0].result_type == 'LetterGrade'
        assert again.achievement.result_descriptions[0].allowed_values == \
            ['A', 'B', 'C']
        assert again.achievement.result_descriptions[0].alignments[0].target_name \
            == 'Grd'

    def test_credits_earned_round_trip(self):
        cred = self._credential()
        cred.credits_earned = 3.5
        assert cred.to_vc()['credentialSubject']['creditsEarned'] == 3.5
        again = OpenBadgeCredential.from_vc_document(cred.to_vc())
        assert again.credits_earned == 3.5

    def test_integral_credits_are_emitted_as_integers(self):
        # xsd:float terms: an integral value gets the integer lexical form in
        # JSON-LD, so emitting 3 (not 3.0) signs the same statement on every
        # JSON-LD processor version. Non-integral values stay floats.
        cred = self._credential(credits_available=3.0)
        cred.credits_earned = 2.0
        vc = cred.to_vc()
        assert type(vc['credentialSubject']['creditsEarned']) is int
        assert type(vc['credentialSubject']['achievement']['creditsAvailable']) is int
        assert vc['credentialSubject']['creditsEarned'] == 2
        again = OpenBadgeCredential.from_vc_document(vc)
        assert again.credits_earned == 2.0
        assert again.achievement.credits_available == 3.0
        cred.credits_earned = 1e21
        assert type(cred.to_vc()['credentialSubject']['creditsEarned']) is float

    def test_single_alignment_object_is_parsed(self):
        # The schema lets `alignment` be a single object, not only an array;
        # _alignment_list handles both so a lone alignment is not dropped.
        vc = self._credential().to_vc()
        vc['credentialSubject']['achievement']['alignment'] = {
            'type': ['Alignment'], 'targetName': 'Solo',
            'targetUrl': 'https://f/solo'}
        again = OpenBadgeCredential.from_vc_document(vc)
        assert [a.target_name for a in again.achievement.alignments] == ['Solo']
