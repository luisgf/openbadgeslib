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

    def test_other_purpose_set_bit_does_not_fail(self):
        # A non-revocation/suspension purpose (e.g. 'message') is informational:
        # a set bit there MUST NOT fail verification.
        cred = _credential([_status_entry(3, purpose='message')])
        doc = _status_list_doc(set_indices=[3], purpose='message')
        check_credential_status(cred, download=_downloader(doc))   # no raise

    def test_entry_purpose_must_match_list_purpose(self):
        # The entry says 'revocation' but the fetched list declares 'suspension':
        # a mismatch means the entry points at the wrong list — fail closed.
        cred = _credential([_status_entry(3, purpose='revocation')])
        doc = _status_list_doc(set_indices=[7], purpose='suspension')
        with pytest.raises(OB3VerificationError, match='statusPurpose'):
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

    def test_multibit_statussize_on_entry_is_rejected(self):
        # statusSize belongs on the entry (BitstringStatusListEntry) per the
        # spec; a conformant multi-bit issuer sets it there, not on the list
        # subject. It must be honoured, else _bit_set reads the wrong bit and a
        # revoked multi-bit entry could be misreported as valid.
        doc = _status_list_doc(set_indices=[7])   # list subject: no statusSize
        entry = _status_entry(94)
        entry['statusSize'] = 2                   # multi-bit declared on the entry
        cred = _credential([entry])
        with pytest.raises(OB3VerificationError, match='statusSize'):
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
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
            ],
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


# ── #164: validFrom/validUntil window + opt-in proof verification ────────────

def _iso(dt):
    return dt.isoformat(timespec='seconds').replace('+00:00', 'Z')


def _served_token(token):
    data = token.encode('utf-8') if isinstance(token, str) else token

    def _dl(url):
        assert url == LIST_URL
        return data
    return _dl


class TestStatusListWindow:
    def _doc(self, **extra):
        doc = _status_list_doc([])           # empty list: no bit set
        doc['issuer'] = 'https://issuer.example'
        doc.update(extra)
        return doc

    def test_no_validuntil_never_expires(self):
        # Backward compatible: a list without validUntil is accepted.
        check_credential_status(_credential([_status_entry(5)]),
                                download=_downloader(self._doc()))

    def test_future_validuntil_accepted(self):
        from datetime import datetime, timedelta, timezone
        doc = self._doc(validUntil=_iso(datetime.now(timezone.utc)
                                        + timedelta(days=7)))
        check_credential_status(_credential([_status_entry(5)]),
                                download=_downloader(doc))

    def test_expired_validuntil_rejected(self):
        from datetime import datetime, timedelta, timezone
        doc = self._doc(validUntil=_iso(datetime.now(timezone.utc)
                                        - timedelta(days=1)))
        with pytest.raises(OB3VerificationError, match='expired'):
            check_credential_status(_credential([_status_entry(5)]),
                                    download=_downloader(doc))

    def test_not_yet_valid_validfrom_rejected(self):
        from datetime import datetime, timedelta, timezone
        doc = self._doc(validFrom=_iso(datetime.now(timezone.utc)
                                       + timedelta(days=1)))
        with pytest.raises(OB3VerificationError, match='not yet valid'):
            check_credential_status(_credential([_status_entry(5)]),
                                    download=_downloader(doc))

    def test_malformed_validuntil_rejected(self):
        with pytest.raises(OB3VerificationError, match='invalid validUntil'):
            check_credential_status(
                _credential([_status_entry(5)]),
                download=_downloader(self._doc(validUntil='not-a-date')))


class TestVerifyListProof:
    def _signed(self, priv_pem, issuer_id, indices=()):
        from openbadgeslib.ob3.status_list import (
            build_status_list_credential, sign_status_list_credential)
        vc = build_status_list_credential(issuer_id, LIST_URL, 'revocation',
                                          indices)
        return sign_status_list_credential(vc, priv_pem, 'EdDSA')

    def _cred(self, issuer_id, entries):
        from openbadgeslib.ob3 import Achievement, Issuer
        return OpenBadgeCredential(
            id='urn:uuid:00000000-0000-0000-0000-0000000000ab',
            issuer=Issuer(id=issuer_id, name='I'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'),
            credential_status=entries)

    def test_verify_with_pubkey_passes(self, ed25519_keypair):
        priv, pub = ed25519_keypair
        token = self._signed(priv, 'https://issuer.example')
        check_credential_status(
            self._cred('https://issuer.example', [_status_entry(5)]),
            download=_served_token(token), verify_list=True, list_pubkey_pem=pub)

    def test_issuer_mismatch_fails(self, ed25519_keypair):
        priv, pub = ed25519_keypair
        token = self._signed(priv, 'https://attacker.example')
        with pytest.raises(OB3VerificationError,
                           match='does not match the badge issuer'):
            check_credential_status(
                self._cred('https://issuer.example', [_status_entry(5)]),
                download=_served_token(token), verify_list=True,
                list_pubkey_pem=pub)

    def test_bad_signature_fails(self, ed25519_keypair):
        from openbadgeslib.keys import KeyEd25519
        priv, _pub = ed25519_keypair
        _priv2, wrong_pub = KeyEd25519().generate_keypair()
        token = self._signed(priv, 'https://issuer.example')
        with pytest.raises(OB3VerificationError, match='proof is invalid'):
            check_credential_status(
                self._cred('https://issuer.example', [_status_entry(5)]),
                download=_served_token(token), verify_list=True,
                list_pubkey_pem=wrong_pub)

    def test_verify_via_did_key_resolution(self, ed25519_keypair):
        # No list_pubkey_pem: the issuer DID (did:key, offline) is resolved.
        from openbadgeslib.ob3.did import did_key_from_pem
        priv, pub = ed25519_keypair
        did = did_key_from_pem(pub)
        token = self._signed(priv, did)
        check_credential_status(self._cred(did, [_status_entry(5)]),
                                download=_served_token(token), verify_list=True)

    def test_unsigned_list_rejected_when_verify_requested(self):
        # verify_list=True on a plain JSON (unsigned) list fails closed.
        doc = _status_list_doc([])
        doc['issuer'] = 'https://issuer.example'
        with pytest.raises(OB3VerificationError, match='not a signed JWT-VC'):
            check_credential_status(
                self._cred('https://issuer.example', [_status_entry(5)]),
                download=_downloader(doc), verify_list=True,
                list_pubkey_pem=b'unused')
