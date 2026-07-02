"""Tests for issuer-side status list writing — ob3.status_list.

Every encoding test round-trips through the real reader (ob3.status): the
writer is correct exactly when check_credential_status and the private
decoding helpers accept its output.
"""
import json

import pytest

from openbadgeslib.ob3 import check_credential_status
from openbadgeslib.ob3.credential import OpenBadgeCredential
from openbadgeslib.ob3.status import _bit_set, _decode_encoded_list
from openbadgeslib.ob3.status_list import (
    DEFAULT_SIZE_BITS,
    build_status_list_credential,
    encode_bitstring,
    sign_status_list_credential,
    status_entry,
)

ISSUER_ID = 'https://issuer.example/issuer'
LIST_URL = 'https://issuer.example/badge_1/revocation.jwt'


def _credential(entries):
    from openbadgeslib.ob3 import Achievement, Issuer
    return OpenBadgeCredential(
        id='urn:uuid:00000000-0000-0000-0000-0000000000bb',
        issuer=Issuer(id=ISSUER_ID, name='Issuer'),
        recipient_id='mailto:r@example.com',
        achievement=Achievement(id='https://issuer.example/a/1', name='A',
                                description='d', criteria_narrative='c'),
        credential_status=entries,
    )


# ── encode_bitstring ─────────────────────────────────────────────────────────

class TestEncodeBitstring:
    def test_empty_list_has_no_set_bits(self):
        bitstring = _decode_encoded_list(encode_bitstring([]))
        assert len(bitstring) == DEFAULT_SIZE_BITS // 8
        assert not any(bitstring)

    @pytest.mark.parametrize('index', [0, 1, 7, 8, 94, DEFAULT_SIZE_BITS - 1])
    def test_set_bit_round_trips(self, index):
        bitstring = _decode_encoded_list(encode_bitstring([index]))
        assert _bit_set(bitstring, index)
        # Neighbours stay clear (MSB-first ordering is byte-exact).
        for other in (index - 1, index + 1):
            if 0 <= other < DEFAULT_SIZE_BITS:
                assert not _bit_set(bitstring, other)

    def test_multiple_bits(self):
        indices = [0, 9, 94, 4095]
        bitstring = _decode_encoded_list(encode_bitstring(indices))
        assert all(_bit_set(bitstring, i) for i in indices)

    def test_custom_size(self):
        bitstring = _decode_encoded_list(encode_bitstring([15], size_bits=16))
        assert len(bitstring) == 2
        assert _bit_set(bitstring, 15)

    @pytest.mark.parametrize('index', [-1, DEFAULT_SIZE_BITS])
    def test_out_of_range_index_rejected(self, index):
        with pytest.raises(ValueError):
            encode_bitstring([index])

    @pytest.mark.parametrize('size', [0, -8, 12])
    def test_bad_size_rejected(self, size):
        with pytest.raises(ValueError):
            encode_bitstring([], size_bits=size)


# ── build_status_list_credential / status_entry ──────────────────────────────

class TestBuildStatusListCredential:
    def test_reader_accepts_unrevoked(self):
        vc = build_status_list_credential(ISSUER_ID, LIST_URL, 'revocation', [7])
        cred = _credential([status_entry(LIST_URL, 'revocation', 94)])
        check_credential_status(
            cred, download=lambda url: json.dumps(vc).encode('utf-8'))

    def test_reader_rejects_revoked(self):
        from openbadgeslib.ob3 import OB3VerificationError
        vc = build_status_list_credential(ISSUER_ID, LIST_URL, 'revocation', [94])
        cred = _credential([status_entry(LIST_URL, 'revocation', 94)])
        with pytest.raises(OB3VerificationError, match='revocation'):
            check_credential_status(
                cred, download=lambda url: json.dumps(vc).encode('utf-8'))

    def test_reader_rejects_suspended(self):
        from openbadgeslib.ob3 import OB3VerificationError
        vc = build_status_list_credential(ISSUER_ID, LIST_URL, 'suspension', [3])
        cred = _credential([status_entry(LIST_URL, 'suspension', 3)])
        with pytest.raises(OB3VerificationError, match='suspension'):
            check_credential_status(
                cred, download=lambda url: json.dumps(vc).encode('utf-8'))

    def test_purpose_mismatch_fails_closed(self):
        from openbadgeslib.ob3 import OB3VerificationError
        vc = build_status_list_credential(ISSUER_ID, LIST_URL, 'suspension', [])
        cred = _credential([status_entry(LIST_URL, 'revocation', 94)])
        with pytest.raises(OB3VerificationError, match='statusPurpose'):
            check_credential_status(
                cred, download=lambda url: json.dumps(vc).encode('utf-8'))

    def test_document_shape(self):
        vc = build_status_list_credential(ISSUER_ID, LIST_URL, 'revocation', [])
        assert vc['id'] == LIST_URL
        assert vc['issuer'] == ISSUER_ID
        assert 'BitstringStatusListCredential' in vc['type']
        subject = vc['credentialSubject']
        assert subject['id'] == LIST_URL + '#list'
        assert subject['type'] == 'BitstringStatusList'
        assert subject['statusPurpose'] == 'revocation'
        assert 'statusSize' not in subject          # single-bit only
        assert vc['validFrom'].endswith('Z')

    def test_unknown_purpose_rejected(self):
        with pytest.raises(ValueError):
            build_status_list_credential(ISSUER_ID, LIST_URL, 'message', [])
        with pytest.raises(ValueError):
            status_entry(LIST_URL, 'message', 1)

    def test_entry_shape(self):
        entry = status_entry(LIST_URL, 'revocation', 94)
        assert entry == {
            'id': LIST_URL + '#94',
            'type': 'BitstringStatusListEntry',
            'statusPurpose': 'revocation',
            'statusListIndex': '94',
            'statusListCredential': LIST_URL,
        }
        with pytest.raises(ValueError):
            status_entry(LIST_URL, 'revocation', -1)


# ── sign_status_list_credential ──────────────────────────────────────────────

class TestSignStatusListCredential:
    @pytest.mark.parametrize('key_fixture,algorithm', [
        ('rsa_priv_pem', 'RS256'),
        ('ecc_priv_pem', 'ES256'),
        ('ed25519_priv_pem', 'EdDSA'),
    ])
    def test_signed_list_round_trips_through_reader(self, request,
                                                    key_fixture, algorithm):
        from openbadgeslib.ob3 import OB3VerificationError
        priv_pem = request.getfixturevalue(key_fixture)
        vc = build_status_list_credential(ISSUER_ID, LIST_URL, 'revocation', [94])
        token = sign_status_list_credential(vc, priv_pem, algorithm)
        assert token.count('.') == 2

        cred = _credential([status_entry(LIST_URL, 'revocation', 94)])
        with pytest.raises(OB3VerificationError, match='revocation'):
            check_credential_status(
                cred, download=lambda url: token.encode('ascii'))

        clean = _credential([status_entry(LIST_URL, 'revocation', 7)])
        check_credential_status(
            clean, download=lambda url: token.encode('ascii'))

    def test_signature_verifies_with_public_key(self, rsa_priv_pem, rsa_pub_pem):
        import jwt as pyjwt
        vc = build_status_list_credential(ISSUER_ID, LIST_URL, 'revocation', [1])
        token = sign_status_list_credential(vc, rsa_priv_pem, 'RS256')
        payload = pyjwt.decode(token, rsa_pub_pem, algorithms=['RS256'])
        assert payload['iss'] == ISSUER_ID
        assert payload['jti'] == LIST_URL
        assert payload['credentialSubject']['statusPurpose'] == 'revocation'
