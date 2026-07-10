"""#161 — OB3 endorsementJwt (errata v1.6): model exposure + verification."""
import json

import pytest

from openbadgeslib.ob3 import (Achievement, Issuer, OpenBadgeCredential,
                               OB3VerificationError, verify_endorsement_jwt)
from openbadgeslib.ob3.credential import OB3_CONTEXT
from openbadgeslib.ob3.did import did_key_from_pem


def _endorsement_jwt(priv_pem, endorser, endorses_id, comment='Great work',
                     valid_until=None, endorsement_type=True, valid_from=None):
    """Sign a compact EndorsementCredential JWT as a third-party endorser."""
    from openbadgeslib.ob3 import OB3Signer
    vc = {
        "@context": OB3_CONTEXT,
        "id": "urn:uuid:00000000-0000-0000-0000-0000000000e1",
        "type": (["VerifiableCredential", "EndorsementCredential"]
                 if endorsement_type else ["VerifiableCredential"]),
        "issuer": endorser,
        "validFrom": valid_from or "2020-01-01T00:00:00Z",
        "credentialSubject": {
            "id": endorses_id,
            "type": ["EndorsementSubject"],
            "endorsementComment": comment,
        },
    }
    if valid_until is not None:
        vc["validUntil"] = valid_until
    payload = dict(vc)
    payload['iss'] = endorser
    payload['jti'] = vc['id']
    payload['nbf'] = 1577836800                      # 2020-01-01
    return OB3Signer(privkey_pem=priv_pem, algorithm='EdDSA').sign_payload(payload)


# ── model: endorsementJwt is parsed and exposed at all three levels ──────────

class TestEndorsementModel:
    def _vc_with(self, cred=(), issuer=(), ach=()):
        vc = {
            "@context": OB3_CONTEXT,
            "id": "urn:uuid:00000000-0000-0000-0000-0000000000c1",
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "issuer": {"id": "https://issuer.example", "type": ["Profile"],
                       "name": "I", "endorsementJwt": list(issuer)},
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "mailto:r@example.com",
                "type": ["AchievementSubject"],
                "achievement": {"id": "https://a.example/1",
                                "type": ["Achievement"], "name": "A",
                                "description": "d",
                                "criteria": {"narrative": "c"},
                                "endorsementJwt": list(ach)},
            },
            "endorsementJwt": list(cred),
        }
        return vc

    def test_parses_all_three_levels(self):
        vc = self._vc_with(cred=['c1'], issuer=['i1', 'i2'], ach=['a1'])
        cred = OpenBadgeCredential.from_vc_document(vc)
        assert cred.endorsement_jwts == ['c1']
        assert cred.issuer.endorsement_jwts == ['i1', 'i2']
        assert cred.achievement.endorsement_jwts == ['a1']
        assert cred.all_endorsement_jwts() == ['c1', 'i1', 'i2', 'a1']

    def test_none_by_default(self):
        vc = self._vc_with()
        cred = OpenBadgeCredential.from_vc_document(vc)
        assert cred.all_endorsement_jwts() == []

    def test_single_string_tolerated(self):
        vc = self._vc_with()
        vc['endorsementJwt'] = 'just-one'            # not wrapped in an array
        cred = OpenBadgeCredential.from_vc_document(vc)
        assert cred.endorsement_jwts == ['just-one']

    def test_round_trip_emits_endorsementjwt(self):
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://i.example', name='I',
                          endorsement_jwts=['i1']),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c',
                                    endorsement_jwts=['a1']),
            endorsement_jwts=['c1'])
        vc = cred.to_vc()
        assert vc['endorsementJwt'] == ['c1']
        assert vc['issuer']['endorsementJwt'] == ['i1']
        assert vc['credentialSubject']['achievement']['endorsementJwt'] == ['a1']
        # …and it round-trips back.
        again = OpenBadgeCredential.from_vc_document(vc)
        assert again.all_endorsement_jwts() == ['c1', 'i1', 'a1']


# ── verify_endorsement_jwt ───────────────────────────────────────────────────

class TestVerifyEndorsement:
    def test_valid_endorsement_via_did_key(self, ed25519_keypair):
        priv, pub = ed25519_keypair
        did = did_key_from_pem(pub)                  # offline, self-certifying
        token = _endorsement_jwt(priv, did, 'https://a.example/1',
                                 comment='Endorsed by a peer')
        result = verify_endorsement_jwt(token)
        assert result['issuer'] == did
        assert result['endorses'] == 'https://a.example/1'
        assert result['comment'] == 'Endorsed by a peer'

    def test_valid_with_explicit_pubkey(self, ed25519_keypair):
        # A non-DID endorser: the key must be supplied.
        priv, pub = ed25519_keypair
        token = _endorsement_jwt(priv, 'https://endorser.example',
                                 'https://a.example/1')
        result = verify_endorsement_jwt(token, endorser_pubkey_pem=pub)
        assert result['endorses'] == 'https://a.example/1'

    def test_non_did_without_key_fails(self, ed25519_keypair):
        priv, _pub = ed25519_keypair
        token = _endorsement_jwt(priv, 'https://endorser.example',
                                 'https://a.example/1')
        with pytest.raises(OB3VerificationError, match='not a DID'):
            verify_endorsement_jwt(token)

    def test_wrong_signing_key_fails(self, ed25519_keypair):
        from openbadgeslib.keys import KeyEd25519
        priv, _pub = ed25519_keypair
        _priv2, pub2 = KeyEd25519().generate_keypair()
        # Signed by priv but claims the DID of pub2: resolving pub2 fails the sig.
        token = _endorsement_jwt(priv, did_key_from_pem(pub2),
                                 'https://a.example/1')
        with pytest.raises(OB3VerificationError, match='signature'):
            verify_endorsement_jwt(token)

    def test_wrong_type_fails(self, ed25519_keypair):
        priv, pub = ed25519_keypair
        token = _endorsement_jwt(priv, did_key_from_pem(pub),
                                 'https://a.example/1', endorsement_type=False)
        with pytest.raises(OB3VerificationError,
                           match='not an EndorsementCredential'):
            verify_endorsement_jwt(token)

    def test_expired_endorsement_fails(self, ed25519_keypair):
        priv, pub = ed25519_keypair
        token = _endorsement_jwt(priv, did_key_from_pem(pub),
                                 'https://a.example/1',
                                 valid_until='2020-06-01T00:00:00Z')
        with pytest.raises(OB3VerificationError, match='expired'):
            verify_endorsement_jwt(token)

    def test_malformed_validuntil_fails_closed(self, ed25519_keypair):
        # #218: a malformed validUntil must fail closed, like every other
        # window — previously it was swallowed and the endorsement accepted.
        priv, pub = ed25519_keypair
        token = _endorsement_jwt(priv, did_key_from_pem(pub),
                                 'https://a.example/1', valid_until='not-a-date')
        with pytest.raises(OB3VerificationError, match='invalid validUntil'):
            verify_endorsement_jwt(token)

    def test_future_endorsement_fails(self, ed25519_keypair):
        # #218: a validFrom in the future is not-yet-valid (only the expired
        # case was covered before).
        from datetime import datetime, timedelta, timezone
        priv, pub = ed25519_keypair
        far = (datetime.now(timezone.utc)
               + timedelta(days=2)).isoformat().replace('+00:00', 'Z')
        token = _endorsement_jwt(priv, did_key_from_pem(pub),
                                 'https://a.example/1', valid_from=far)
        with pytest.raises(OB3VerificationError, match='not yet valid'):
            verify_endorsement_jwt(token)

    def test_json_document_rejected(self):
        with pytest.raises(OB3VerificationError, match='compact JWT'):
            verify_endorsement_jwt('{"not": "a jwt"}')


# ── CLI: the verifier --json reports the endorsement count ───────────────────

def test_cli_json_reports_endorsement_count(tmp_path, rsa_priv_pem, rsa_pub_pem,
                                            svg_image, capsys):
    import sys
    from unittest.mock import patch
    from openbadgeslib import openbadges_verifier
    from openbadgeslib.ob3 import OB3Signer

    # A badge whose achievement carries two endorsement JWTs.
    cred = OpenBadgeCredential(
        issuer=Issuer(id='https://issuer.example', name='I'),
        recipient_id='mailto:r@example.com',
        achievement=Achievement(id='https://a.example/1', name='A',
                                description='d', criteria_narrative='c',
                                endorsement_jwts=['tokenA', 'tokenB']))
    badge = tmp_path / 'badge.svg'
    badge.write_bytes(OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')
                      .sign_into_svg(cred, svg_image))
    pub = tmp_path / 'verify.pem'
    pub.write_bytes(rsa_pub_pem)

    argv = ['openbadges-verifier', '-i', str(badge), '-r', 'r@example.com',
            '-V', '3', '-k', str(pub), '--json']
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_verifier.main()
    assert exc.value.code == 0
    result = json.loads(capsys.readouterr().out)
    assert result['valid'] is True
    assert result['endorsements'] == 2
