"""Tests for OB3 credentialStatus (revocation) checking — ob3.status."""
import base64
import gzip
import json

import pytest

from openbadgeslib.ob3 import OB3VerificationError, check_credential_status
from openbadgeslib.ob3.credential import OpenBadgeCredential


LIST_URL = 'https://issuer.example/status/1'


def _encoded_list(set_indices, size_bits=131072):
    """Build a Bitstring Status List `encodedList` (multibase base64url of a
    GZIP-compressed MSB-first bitstring) with *set_indices* flipped on."""
    ba = bytearray(size_bits // 8)
    for i in set_indices:
        ba[i // 8] |= (0x80 >> (i % 8))
    gz = gzip.compress(bytes(ba))
    return 'u' + base64.urlsafe_b64encode(gz).decode('ascii').rstrip('=')


def _status_list_doc(set_indices, purpose='revocation'):
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": LIST_URL,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "credentialSubject": {
            "id": LIST_URL + "#list",
            "type": "BitstringStatusList",
            "statusPurpose": purpose,
            "encodedList": _encoded_list(set_indices),
        },
    }


def _status_entry(index, purpose='revocation', type_='BitstringStatusListEntry'):
    return {
        "id": "%s#%d" % (LIST_URL, index),
        "type": type_,
        "statusPurpose": purpose,
        "statusListIndex": str(index),
        "statusListCredential": LIST_URL,
    }


def _credential(entries):
    from openbadgeslib.ob3 import Achievement, Issuer
    return OpenBadgeCredential(
        id='urn:uuid:00000000-0000-0000-0000-0000000000aa',
        issuer=Issuer(id='https://issuer.example', name='Issuer'),
        recipient_id='mailto:r@example.com',
        achievement=Achievement(id='https://issuer.example/a/1', name='A',
                                description='d', criteria_narrative='c'),
        credential_status=entries,
    )


def _downloader(doc):
    payload = json.dumps(doc).encode('utf-8')

    def _dl(url):
        assert url == LIST_URL
        return payload
    return _dl


# ── core checker ─────────────────────────────────────────────────────────────

class TestCheckCredentialStatus:
    def test_no_status_is_noop(self):
        check_credential_status(_credential([]), download=_downloader({}))

    def test_unrevoked_passes(self):
        cred = _credential([_status_entry(94)])
        check_credential_status(cred, download=_downloader(_status_list_doc(set_indices=[7])))

    def test_revoked_bit_rejected(self):
        cred = _credential([_status_entry(94)])
        with pytest.raises(OB3VerificationError, match='revocation'):
            check_credential_status(cred, download=_downloader(_status_list_doc(set_indices=[94])))

    def test_suspension_purpose_reported(self):
        cred = _credential([_status_entry(3, purpose='suspension')])
        doc = _status_list_doc(set_indices=[3], purpose='suspension')
        with pytest.raises(OB3VerificationError, match='suspension'):
            check_credential_status(cred, download=_downloader(doc))

    def test_legacy_statuslist2021_type_accepted(self):
        cred = _credential([_status_entry(94, type_='StatusList2021Entry')])
        with pytest.raises(OB3VerificationError):
            check_credential_status(cred, download=_downloader(_status_list_doc(set_indices=[94])))

    def test_jwt_vc_status_list_form(self):
        # Status list served as a compact JWT-VC (header.payload.signature).
        def _b64(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')
        doc = _status_list_doc(set_indices=[94])
        payload = {"iss": "https://issuer.example", "vc": doc}
        jwt_like = '%s.%s.%s' % (_b64({"alg": "none"}), _b64(payload), 'sig')
        cred = _credential([_status_entry(94)])
        with pytest.raises(OB3VerificationError):
            check_credential_status(cred, download=lambda url: jwt_like.encode('ascii'))

    def test_multibit_statussize_is_rejected(self):
        # statusSize > 1 (multi-bit entries) is not supported: _bit_set assumes
        # one bit per entry, so honouring it would read the wrong bits. Fail
        # closed rather than misreport a revoked credential as valid.
        doc = _status_list_doc(set_indices=[7])
        doc['credentialSubject']['statusSize'] = 2
        cred = _credential([_status_entry(94)])
        with pytest.raises(OB3VerificationError, match='statusSize'):
            check_credential_status(cred, download=_downloader(doc))

    def test_explicit_statussize_one_is_accepted(self):
        # An explicit statusSize of 1 is the default single-bit case.
        doc = _status_list_doc(set_indices=[7])
        doc['credentialSubject']['statusSize'] = 1
        cred = _credential([_status_entry(94)])  # index 94 unset -> not revoked
        check_credential_status(cred, download=_downloader(doc))

    # ── fail-closed paths ────────────────────────────────────────────────────

    def test_fetch_error_fails_closed(self):
        def _boom(url):
            raise ValueError('Refusing to download over insecure scheme')
        with pytest.raises(OB3VerificationError, match='could not fetch'):
            check_credential_status(_credential([_status_entry(1)]), download=_boom)

    def test_malformed_list_fails_closed(self):
        with pytest.raises(OB3VerificationError):
            check_credential_status(_credential([_status_entry(1)]),
                                    download=lambda url: b'not json, not jwt')

    def test_missing_encoded_list_fails_closed(self):
        doc = {"credentialSubject": {"type": "BitstringStatusList"}}
        with pytest.raises(OB3VerificationError, match='encodedList'):
            check_credential_status(_credential([_status_entry(1)]), download=_downloader(doc))

    def test_unknown_entry_type_fails_closed(self):
        cred = _credential([_status_entry(1, type_='SomethingElse')])
        with pytest.raises(OB3VerificationError, match='unsupported'):
            check_credential_status(cred, download=_downloader(_status_list_doc([])))

    def test_index_out_of_range_fails_closed(self):
        cred = _credential([_status_entry(9_999_999)])
        with pytest.raises(OB3VerificationError, match='out of range'):
            check_credential_status(cred, download=_downloader(_status_list_doc([])))

    def test_non_numeric_index_fails_closed(self):
        entry = _status_entry(1)
        entry['statusListIndex'] = 'not-a-number'
        with pytest.raises(OB3VerificationError, match='invalid statusListIndex'):
            check_credential_status(_credential([entry]), download=_downloader(_status_list_doc([])))


# ── bit ordering ─────────────────────────────────────────────────────────────

class TestBitOrdering:
    def test_bit_zero_is_msb_of_first_byte(self):
        from openbadgeslib.ob3.status import _bit_set
        assert _bit_set(b'\x80', 0) is True
        assert _bit_set(b'\x80', 1) is False
        assert _bit_set(b'\x01', 7) is True


# ── model parsing ────────────────────────────────────────────────────────────

class TestCredentialStatusParsing:
    def _payload(self, status):
        # OB3 native VC-JWT: the payload IS the credential (no 'vc' wrapper).
        return {
            "id": "urn:uuid:1",
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "issuer": {"id": "https://i.example", "name": "I"},
            "credentialStatus": status,
            "credentialSubject": {
                "id": "mailto:r@example.com",
                "achievement": {"id": "https://i.example/a", "name": "A"},
            },
        }

    def test_single_object_normalised_to_list(self):
        cred = OpenBadgeCredential.from_jwt_payload(self._payload(_status_entry(1)))
        assert cred.credential_status == [_status_entry(1)]

    def test_array_kept(self):
        entries = [_status_entry(1), _status_entry(2)]
        cred = OpenBadgeCredential.from_jwt_payload(self._payload(entries))
        assert cred.credential_status == entries

    def test_absent_is_empty(self):
        payload = self._payload(None)
        del payload['credentialStatus']
        cred = OpenBadgeCredential.from_jwt_payload(payload)
        assert cred.credential_status == []


# ── integration through verify(check_status=True) ────────────────────────────

class TestVerifyWithStatus:
    def _sign(self, signer, entries):
        return signer.sign(_credential(entries))

    def test_verify_rejects_revoked(self, ob3_rsa_signer, ob3_rsa_verifier, monkeypatch):
        import openbadgeslib.ob3.status as status_mod
        monkeypatch.setattr(status_mod, 'download_file',
                            _downloader(_status_list_doc(set_indices=[94])))
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        with pytest.raises(OB3VerificationError):
            ob3_rsa_verifier.verify(token, check_status=True)

    def test_verify_passes_unrevoked(self, ob3_rsa_signer, ob3_rsa_verifier, monkeypatch):
        import openbadgeslib.ob3.status as status_mod
        monkeypatch.setattr(status_mod, 'download_file',
                            _downloader(_status_list_doc(set_indices=[])))
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        cred = ob3_rsa_verifier.verify(token, check_status=True)
        assert cred.recipient_id == 'mailto:r@example.com'

    def test_check_status_off_by_default(self, ob3_rsa_signer, ob3_rsa_verifier, monkeypatch):
        # With check_status=False (default) no network call happens even when a
        # revoked status is present.
        import openbadgeslib.ob3.status as status_mod

        def _fail(url):
            raise AssertionError('network must not be touched when check_status=False')
        monkeypatch.setattr(status_mod, 'download_file', _fail)
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        assert ob3_rsa_verifier.verify(token) is not None
