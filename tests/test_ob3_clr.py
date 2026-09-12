"""Tests for the CLR 2.0 ClrCredential builder — ob3.clr."""
from datetime import datetime, timedelta, timezone

import pytest

from openbadgeslib.errors import LibOpenBadgesException
from openbadgeslib.ob3 import (
    CLR_CONTEXT_SHA256,
    CLR_CONTEXT_URL,
    OB_V3_CONTEXT,
    VCDM_V2_CONTEXT,
    build_clr_credential,
    bundled_clr_contexts,
    sign_clr_credential,
)


ISSUER = 'https://issuer.example/issuer'
CRED_ID = 'https://issuer.example/clr/1'
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
IDENTIFIER = [{
    'type': 'IdentityObject',
    'hashed': True,
    'identityHash': 'sha256$abc',
    'identityType': 'emailAddress',
    'salt': 's',
}]
MEMBER = {'id': 'https://issuer.example/credentials/1',
          'type': ['VerifiableCredential', 'OpenBadgeCredential']}


def _build(**kw):
    args = dict(
        issuer=ISSUER,
        identifier=IDENTIFIER,
        members=[MEMBER],
        credential_id=CRED_ID,
        valid_from=NOW,
    )
    args.update(kw)
    return build_clr_credential(**args)


class TestBundledClrContext:
    def test_hash_pin(self):
        import hashlib
        from importlib import resources
        raw = resources.files('openbadgeslib.ob3.contexts').joinpath(
            'clr_context_2.0.1.json').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == CLR_CONTEXT_SHA256
        ctx = bundled_clr_contexts()
        assert list(ctx) == [CLR_CONTEXT_URL]
        assert isinstance(ctx[CLR_CONTEXT_URL], dict)
        assert '@context' in ctx[CLR_CONTEXT_URL]

    def test_hash_mismatch_fails_closed(self, monkeypatch):
        monkeypatch.setattr(
            'openbadgeslib.ob3.clr._bundled_context_bytes', lambda: b'{}')
        with pytest.raises(LibOpenBadgesException, match='pinned hash'):
            bundled_clr_contexts()


class TestBuildClrCredential:
    def test_document_shape(self):
        doc = _build()
        assert doc['@context'] == [VCDM_V2_CONTEXT, OB_V3_CONTEXT, CLR_CONTEXT_URL]
        assert doc['type'] == ['VerifiableCredential', 'ClrCredential']
        assert doc['id'] == CRED_ID
        assert doc['issuer'] == ISSUER
        assert doc['validFrom'] == '2026-01-01T00:00:00Z'
        assert 'validUntil' not in doc
        assert 'credentialStatus' not in doc
        subject = doc['credentialSubject']
        assert subject['type'] == 'ClrSubject'
        assert subject['identifier'] == IDENTIFIER
        assert subject['verifiableCredential'] == [MEMBER]

    def test_member_id_must_not_collide_with_envelope(self):
        with pytest.raises(ValueError, match="collides"):
            _build(members=[{**MEMBER, "id": CRED_ID}])
        with pytest.raises(ValueError, match="collides"):
            _build(members=[{**MEMBER, "id": ISSUER}])

    def test_issuer_dict_and_optional_fields(self):
        issuer = {'id': ISSUER, 'type': 'Profile', 'name': 'Issuer'}
        status = {
            'id': 'https://issuer.example/status#1',
            'type': 'BitstringStatusListEntry',
            'statusPurpose': 'revocation',
            'statusListIndex': '1',
            'statusListCredential': 'https://issuer.example/status',
        }
        until = NOW + timedelta(days=365)
        doc = _build(issuer=issuer, valid_until=until, status=status)
        assert doc['issuer'] == issuer
        assert doc['validUntil'] == '2027-01-01T00:00:00Z'
        assert doc['credentialStatus'] == status

    def test_members_and_identifier_are_copied(self):
        members = [dict(MEMBER)]
        identifier = [dict(IDENTIFIER[0])]
        doc = _build(members=members, identifier=identifier)
        members[0]['id'] = 'mutated'
        identifier[0]['salt'] = 'mutated'
        assert doc['credentialSubject']['verifiableCredential'][0]['id'] == MEMBER['id']
        assert doc['credentialSubject']['identifier'][0]['salt'] == 's'

    def test_empty_members_rejected(self):
        with pytest.raises(ValueError, match='members'):
            _build(members=[])

    def test_non_dict_member_rejected(self):
        with pytest.raises(ValueError, match='members'):
            _build(members=['not-a-dict'])

    def test_empty_credential_id_rejected(self):
        with pytest.raises(ValueError, match='credential_id'):
            _build(credential_id='')

    def test_valid_until_not_after_valid_from(self):
        with pytest.raises(ValueError, match='validUntil'):
            _build(valid_until=NOW)
        with pytest.raises(ValueError, match='validUntil'):
            _build(valid_until=NOW - timedelta(days=1))


class TestSignClrCredential:
    def test_round_trip(self, ob3_credential, ed25519_keypair):
        pytest.importorskip('pyld')
        from openbadgeslib.ob3 import add_data_integrity_proof, verify_data_integrity_proof
        from openbadgeslib.ob3.did import did_key_from_pem

        priv_pem, pub_pem = ed25519_keypair
        did = did_key_from_pem(pub_pem)
        vm = '%s#%s' % (did, did[len('did:key:'):])
        member = add_data_integrity_proof(ob3_credential.to_vc(), priv_pem, vm)
        doc = _build(members=[member],
                     issuer={'id': did, 'type': ['Profile'], 'name': 'I'})
        signed = sign_clr_credential(doc, priv_pem, vm)
        assert signed['proof']['type'] == 'DataIntegrityProof'
        assert signed['proof']['cryptosuite'] == 'eddsa-rdfc-2022'
        assert 'proof' not in doc
        verify_data_integrity_proof(
            signed, pub_pem, extra_contexts=bundled_clr_contexts())
