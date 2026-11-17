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

    def test_negative_index_fails_closed(self):
        # A negative statusListIndex parses as an int but _bit_set must reject
        # it rather than index backwards into the bitstring.
        entry = _status_entry(1)
        entry['statusListIndex'] = '-1'
        with pytest.raises(OB3VerificationError, match='negative'):
            check_credential_status(_credential([entry]),
                                    download=_downloader(_status_list_doc([])))

    def test_gzip_bomb_list_fails_closed(self):
        # A crafted encodedList that inflates past the 5 MiB cap must be refused
        # (bounded inflate), not decompressed into memory. The list is fetched
        # from an attacker-influenced URL, so this is the anti-bomb guard.
        bomb = gzip.compress(b'\x00' * (6 * 1024 * 1024))       # 6 MiB inflated
        encoded = 'u' + base64.urlsafe_b64encode(bomb).decode('ascii').rstrip('=')
        doc = _status_list_doc([])
        doc['credentialSubject']['encodedList'] = encoded
        with pytest.raises(OB3VerificationError, match='exceeds'):
            check_credential_status(_credential([_status_entry(5)]),
                                    download=_downloader(doc))


# ── bit ordering ─────────────────────────────────────────────────────────────

class TestBitOrdering:
    def test_bit_zero_is_msb_of_first_byte(self):
        from openbadgeslib.ob3.status import _bit_set
        assert _bit_set(b'\x80', 0) is True
        assert _bit_set(b'\x80', 1) is False
        assert _bit_set(b'\x01', 7) is True


# ── public encodedList decoder (#322) ────────────────────────────────────────

class TestDecodeEncodedList:
    def test_round_trip_set_indices(self):
        from openbadgeslib.ob3 import decode_encoded_list, encode_bitstring, set_indices
        indices = {0, 9, 94, 4095}
        encoded = encode_bitstring(indices)
        assert set_indices(decode_encoded_list(encoded)) == frozenset(indices)

    def test_private_alias_still_works(self):
        from openbadgeslib.ob3.status import _decode_encoded_list, decode_encoded_list
        encoded = _encoded_list([7])
        assert _decode_encoded_list(encoded) == decode_encoded_list(encoded)

    def test_refuse_oversized_inflate(self):
        from openbadgeslib.ob3 import decode_encoded_list
        bomb = gzip.compress(b'\x00' * (6 * 1024 * 1024))
        encoded = 'u' + base64.urlsafe_b64encode(bomb).decode('ascii').rstrip('=')
        with pytest.raises(OB3VerificationError, match='exceeds'):
            decode_encoded_list(encoded)

    def test_refuse_garbage(self):
        from openbadgeslib.ob3 import decode_encoded_list
        with pytest.raises(ValueError):
            decode_encoded_list('not-a-valid-encoded-list')
        with pytest.raises(ValueError):
            decode_encoded_list('u!!!!')
        with pytest.raises(ValueError):
            decode_encoded_list('')

    def test_set_indices_msb_first(self):
        from openbadgeslib.ob3 import set_indices
        assert set_indices(b'\x80') == frozenset([0])
        assert set_indices(b'\x01') == frozenset([7])
        assert set_indices(b'\x00') == frozenset()


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
    """verify(check_status=True) checks revocation AND, by default, the status
    list's own signature — bound to the badge issuer (#213). openbadges-publish
    signs the list with the same key that signed the badge, so the badge's own
    verification key (reused here) validates it."""

    def _sign(self, signer, entries):
        return signer.sign(_credential(entries))

    @staticmethod
    def _signed_list(priv_pem, indices, issuer='https://issuer.example'):
        from openbadgeslib.keys import alg_for_key_type, detect_key_type
        from openbadgeslib.ob3.status_list import (
            build_status_list_credential, sign_status_list_credential)
        vc = build_status_list_credential(issuer, LIST_URL, 'revocation', indices)
        alg = alg_for_key_type(detect_key_type(priv_pem))
        return sign_status_list_credential(vc, priv_pem, alg)

    def test_verify_rejects_revoked(self, ob3_rsa_signer, ob3_rsa_verifier,
                                    rsa_priv_pem, monkeypatch):
        import openbadgeslib.ob3.status as status_mod
        monkeypatch.setattr(status_mod, 'download_file',
                            _served_token(self._signed_list(rsa_priv_pem, [94])))
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        with pytest.raises(OB3VerificationError, match='revocation'):
            ob3_rsa_verifier.verify(token, check_status=True)

    def test_verify_passes_unrevoked(self, ob3_rsa_signer, ob3_rsa_verifier,
                                     rsa_priv_pem, monkeypatch):
        import openbadgeslib.ob3.status as status_mod
        monkeypatch.setattr(status_mod, 'download_file',
                            _served_token(self._signed_list(rsa_priv_pem, [])))
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        cred = ob3_rsa_verifier.verify(token, check_status=True)
        assert cred.recipient_id == 'mailto:r@example.com'

    def test_unsigned_list_rejected_by_default(self, ob3_rsa_signer,
                                               ob3_rsa_verifier, monkeypatch):
        # #213: an unsigned (plain JSON) status list is refused by default —
        # its revocation bit would otherwise be trusted on the host's word.
        import openbadgeslib.ob3.status as status_mod
        doc = _status_list_doc(set_indices=[])
        doc['issuer'] = 'https://issuer.example'
        monkeypatch.setattr(status_mod, 'download_file', _downloader(doc))
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        with pytest.raises(OB3VerificationError, match='not a signed JWT-VC'):
            ob3_rsa_verifier.verify(token, check_status=True)

    def test_list_signed_by_wrong_key_rejected(self, ob3_rsa_signer,
                                               ob3_rsa_verifier,
                                               ed25519_priv_pem, monkeypatch):
        # #213 core: a status list whose issuer matches but which is signed by a
        # DIFFERENT key than the badge's (a compromised/rogue host serving its
        # own un-revoking list) fails the signature bound to the badge key.
        import openbadgeslib.ob3.status as status_mod
        wrong = self._signed_list(ed25519_priv_pem, [])   # empty => not revoked
        monkeypatch.setattr(status_mod, 'download_file', _served_token(wrong))
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        with pytest.raises(OB3VerificationError, match='proof is invalid'):
            ob3_rsa_verifier.verify(token, check_status=True)

    def test_verify_status_list_optout_accepts_unsigned(self, ob3_rsa_signer,
                                                        ob3_rsa_verifier, monkeypatch):
        # verify_status_list=False restores the lenient path for an issuer that
        # serves an unsigned list (the revocation bit is then trusted as-is).
        import openbadgeslib.ob3.status as status_mod
        doc = _status_list_doc(set_indices=[])
        doc['issuer'] = 'https://issuer.example'
        monkeypatch.setattr(status_mod, 'download_file', _downloader(doc))
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        cred = ob3_rsa_verifier.verify(token, check_status=True,
                                       verify_status_list=False)
        assert cred is not None

    def test_check_status_off_by_default(self, ob3_rsa_signer, ob3_rsa_verifier, monkeypatch):
        # With check_status=False (default) no network call happens even when a
        # revoked status is present.
        import openbadgeslib.ob3.status as status_mod

        def _fail(url):
            raise AssertionError('network must not be touched when check_status=False')
        monkeypatch.setattr(status_mod, 'download_file', _fail)
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        assert ob3_rsa_verifier.verify(token) is not None

    def test_injected_download_used_for_status(self, ob3_rsa_signer,
                                               ob3_rsa_verifier, rsa_priv_pem):
        # #228: verify(download=...) threads the fetcher to the status list, so
        # no global monkeypatch is needed and a CachingDownloader can be passed.
        served = self._signed_list(rsa_priv_pem, [])
        calls = {'n': 0}

        def dl(url):
            calls['n'] += 1
            return served.encode('utf-8')
        token = self._sign(ob3_rsa_signer, [_status_entry(94)])
        assert ob3_rsa_verifier.verify(token, check_status=True, download=dl)
        assert calls['n'] == 1

    def test_caching_downloader_batches_status_fetch(self, ob3_rsa_signer,
                                                     ob3_rsa_verifier, rsa_priv_pem):
        # #228 end-to-end: two badges pointing at the same status list URL are
        # verified through one CachingDownloader -> the list is fetched once.
        from openbadgeslib.util import CachingDownloader
        served = self._signed_list(rsa_priv_pem, [])
        calls = {'n': 0}

        def base(url):
            calls['n'] += 1
            return served.encode('utf-8')
        dl = CachingDownloader(base, ttl_seconds=60)
        t1 = self._sign(ob3_rsa_signer, [_status_entry(94)])
        t2 = self._sign(ob3_rsa_signer, [_status_entry(95)])
        ob3_rsa_verifier.verify(t1, check_status=True, download=dl)
        ob3_rsa_verifier.verify(t2, check_status=True, download=dl)
        assert calls['n'] == 1


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

    def test_non_did_issuer_without_pubkey_fails(self, ed25519_keypair):
        # verify_list=True with a signed list whose issuer is NOT a DID and no
        # list_pubkey_pem: there is no key to resolve, so fail closed rather
        # than skip the signature check.
        priv, _pub = ed25519_keypair
        token = self._signed(priv, 'https://issuer.example')
        with pytest.raises(OB3VerificationError, match='is not a DID'):
            check_credential_status(
                self._cred('https://issuer.example', [_status_entry(5)]),
                download=_served_token(token), verify_list=True)


# ── #336: bounded fan-out (entry cap, one fetch per list URL) ────────────────

def _counting(data):
    """A downloader serving *data* for any URL, and the list of URLs asked."""
    payload = (data if isinstance(data, bytes)
               else data.encode('utf-8') if isinstance(data, str)
               else json.dumps(data).encode('utf-8'))
    calls = []

    def _dl(url):
        calls.append(url)
        return payload
    return _dl, calls


def _entry_at(url, index=5, purpose='revocation'):
    entry = _status_entry(index, purpose=purpose)
    entry['statusListCredential'] = url
    return entry


class TestStatusFanOut:
    """The number of credentialStatus entries is chosen by whoever built the
    credential, and each one used to cost a download with its own time budget.
    More than MAX_STATUS_ENTRIES are refused before any fetch, and within one
    check each distinct statusListCredential URL is fetched once (#336)."""

    def test_cap_is_eight(self):
        from openbadgeslib.ob3.status import MAX_STATUS_ENTRIES
        assert MAX_STATUS_ENTRIES == 8

    def test_nine_entries_refused_before_any_download(self):
        dl, calls = _counting(_status_list_doc([]))
        cred = _credential([_status_entry(i) for i in range(9)])
        with pytest.raises(OB3VerificationError,
                           match='9 credentialStatus entries'):
            check_credential_status(cred, download=dl)
        assert calls == []

    def test_nine_entries_refused_even_when_the_first_is_revoked(self):
        # The cap is not a way to skip the check: nothing is read, and the
        # credential fails either way.
        dl, calls = _counting(_status_list_doc([0]))
        cred = _credential([_status_entry(i) for i in range(9)])
        with pytest.raises(OB3VerificationError, match='credentialStatus entries'):
            check_credential_status(cred, download=dl)
        assert calls == []

    def test_eight_entries_still_pass(self):
        dl, calls = _counting(_status_list_doc([]))
        cred = _credential([_status_entry(i) for i in range(8)])
        check_credential_status(cred, download=dl)
        assert calls == [LIST_URL]

    def test_eight_distinct_lists_are_each_fetched_once(self):
        dl, calls = _counting(_status_list_doc([]))
        urls = ['https://issuer.example/status/%d' % i for i in range(8)]
        check_credential_status(_credential([_entry_at(u) for u in urls]),
                                download=dl)
        assert calls == urls

    def test_two_entries_one_list_one_download(self):
        dl, calls = _counting(_status_list_doc([]))
        cred = _credential([_status_entry(5), _status_entry(6)])
        check_credential_status(cred, download=dl)
        assert calls == [LIST_URL]

    def test_default_downloader_is_shared_too(self, monkeypatch):
        import openbadgeslib.ob3.status as status_mod
        dl, calls = _counting(_status_list_doc([]))
        monkeypatch.setattr(status_mod, 'download_file', dl)
        check_credential_status(_credential([_status_entry(5), _status_entry(6)]))
        assert calls == [LIST_URL]

    def test_urls_are_compared_exactly(self):
        # No normalisation: two spellings are two lists (and two fetches,
        # within the cap), never one list answering for another.
        dl, calls = _counting(_status_list_doc([]))
        urls = [LIST_URL, LIST_URL + '?', 'https://ISSUER.example/status/1']
        check_credential_status(_credential([_entry_at(u) for u in urls]),
                                download=dl)
        assert calls == urls

    def test_the_memo_does_not_outlive_the_call(self):
        # A revocation published between two verifications must be seen.
        dl, calls = _counting(_status_list_doc([]))
        cred = _credential([_status_entry(5), _status_entry(6)])
        check_credential_status(cred, download=dl)
        check_credential_status(cred, download=dl)
        assert calls == [LIST_URL, LIST_URL]

    # Only the fetch is shared: every entry is still checked in full.

    def test_second_entry_revoked_on_a_shared_list(self):
        dl, calls = _counting(_status_list_doc([6]))
        cred = _credential([_status_entry(5), _status_entry(6)])
        with pytest.raises(OB3VerificationError, match='index 6'):
            check_credential_status(cred, download=dl)
        assert calls == [LIST_URL]

    def test_second_entry_purpose_checked_on_a_shared_list(self):
        dl, calls = _counting(_status_list_doc([]))
        cred = _credential([_status_entry(5),
                            _status_entry(6, purpose='suspension')])
        with pytest.raises(OB3VerificationError, match='statusPurpose'):
            check_credential_status(cred, download=dl)
        assert calls == [LIST_URL]

    def test_second_entry_index_checked_on_a_shared_list(self):
        dl, calls = _counting(_status_list_doc([]))
        cred = _credential([_status_entry(5), _status_entry(9_999_999)])
        with pytest.raises(OB3VerificationError, match='out of range'):
            check_credential_status(cred, download=dl)
        assert calls == [LIST_URL]

    def test_second_entry_statussize_checked_on_a_shared_list(self):
        dl, calls = _counting(_status_list_doc([]))
        multibit = _status_entry(6)
        multibit['statusSize'] = 2
        cred = _credential([_status_entry(5), multibit])
        with pytest.raises(OB3VerificationError, match='statusSize'):
            check_credential_status(cred, download=dl)
        assert calls == [LIST_URL]

    def test_list_proof_verified_for_every_entry(self, ed25519_keypair,
                                                 monkeypatch):
        import openbadgeslib.ob3.status as status_mod
        from openbadgeslib.ob3.status_list import (
            build_status_list_credential, sign_status_list_credential)
        priv, pub = ed25519_keypair
        token = sign_status_list_credential(
            build_status_list_credential('https://issuer.example', LIST_URL,
                                         'revocation', []), priv, 'EdDSA')
        dl, calls = _counting(token)
        verified = []
        real = status_mod._verify_list_proof

        def _spy(raw, doc, list_url, *args):
            verified.append(list_url)
            return real(raw, doc, list_url, *args)
        monkeypatch.setattr(status_mod, '_verify_list_proof', _spy)
        cred = _credential([_status_entry(5), _status_entry(6)])
        check_credential_status(cred, download=dl, verify_list=True,
                                list_pubkey_pem=pub)
        assert calls == [LIST_URL]
        assert verified == [LIST_URL, LIST_URL]

    def test_shared_list_with_a_bad_proof_is_rejected(self, ed25519_keypair):
        from openbadgeslib.keys import KeyEd25519
        from openbadgeslib.ob3.status_list import (
            build_status_list_credential, sign_status_list_credential)
        priv, _pub = ed25519_keypair
        _priv2, wrong_pub = KeyEd25519().generate_keypair()
        token = sign_status_list_credential(
            build_status_list_credential('https://issuer.example', LIST_URL,
                                         'revocation', []), priv, 'EdDSA')
        dl, calls = _counting(token)
        cred = _credential([_status_entry(5), _status_entry(6)])
        with pytest.raises(OB3VerificationError, match='proof is invalid'):
            check_credential_status(cred, download=dl, verify_list=True,
                                    list_pubkey_pem=wrong_pub)
        assert calls == [LIST_URL]

    def test_fetch_failure_fails_closed_and_is_not_remembered(self):
        calls = []

        def _boom(url):
            calls.append(url)
            raise ValueError('download budget exhausted')
        cred = _credential([_status_entry(5), _status_entry(6)])
        for _ in range(2):
            with pytest.raises(OB3VerificationError, match='could not fetch'):
                check_credential_status(cred, download=_boom)
        assert calls == [LIST_URL, LIST_URL]

    def test_failure_on_a_later_list_fails_closed(self):
        good = json.dumps(_status_list_doc([])).encode('utf-8')
        other = 'https://issuer.example/status/2'
        calls = []

        def _dl(url):
            calls.append(url)
            if url == other:
                raise ValueError('unreachable')
            return good
        cred = _credential([_status_entry(5), _entry_at(other),
                            _status_entry(6)])
        with pytest.raises(OB3VerificationError, match='could not fetch'):
            check_credential_status(cred, download=_dl)
        assert calls == [LIST_URL, other]

    # ── through the verifiers ────────────────────────────────────────────────

    def test_jwt_verify_refuses_nine_entries_without_fetching(
            self, ob3_rsa_signer, ob3_rsa_verifier):
        dl, calls = _counting(_status_list_doc([]))
        token = ob3_rsa_signer.sign(
            _credential([_status_entry(i) for i in range(9)]))
        with pytest.raises(OB3VerificationError, match='credentialStatus entries'):
            ob3_rsa_verifier.verify(token, check_status=True, download=dl)
        assert calls == []
        # The public OB3Verifier.check_status helper is the same code path.
        with pytest.raises(OB3VerificationError, match='credentialStatus entries'):
            ob3_rsa_verifier.check_status(
                _credential([_status_entry(i) for i in range(9)]), download=dl)
        assert calls == []

    def test_jwt_verify_fetches_a_shared_list_once(
            self, ob3_rsa_signer, ob3_rsa_verifier, rsa_priv_pem):
        dl, calls = _counting(
            TestVerifyWithStatus._signed_list(rsa_priv_pem, []))
        token = ob3_rsa_signer.sign(
            _credential([_status_entry(5), _status_entry(6)]))
        assert ob3_rsa_verifier.verify(token, check_status=True, download=dl)
        assert calls == [LIST_URL]

    def test_recipient_mismatch_costs_no_download(
            self, ob3_rsa_signer, ob3_rsa_verifier, rsa_priv_pem):
        # The recipient check is local and free: it runs before the status
        # check, so a credential presented by the wrong holder never reaches
        # the network.
        dl, calls = _counting(
            TestVerifyWithStatus._signed_list(rsa_priv_pem, []))
        token = ob3_rsa_signer.sign(_credential([_status_entry(94)]))
        with pytest.raises(OB3VerificationError, match='Recipient mismatch'):
            ob3_rsa_verifier.verify(
                token, expected_recipient='other@example.com',
                check_status=True, download=dl)
        assert calls == []

    def test_matching_recipient_still_has_its_status_checked(
            self, ob3_rsa_signer, ob3_rsa_verifier, rsa_priv_pem):
        dl, calls = _counting(
            TestVerifyWithStatus._signed_list(rsa_priv_pem, [94]))
        token = ob3_rsa_signer.sign(_credential([_status_entry(94)]))
        with pytest.raises(OB3VerificationError, match='revocation'):
            ob3_rsa_verifier.verify(
                token, expected_recipient='r@example.com',
                check_status=True, download=dl)
        assert calls == [LIST_URL]

    def test_data_integrity_verify_refuses_nine_entries_without_fetching(
            self, ob3_credential, ed25519_keypair):
        # OB3LdpVerifier.verify calls check_credential_status, so the cap
        # covers the Data Integrity path without a line of its own there.
        pytest.importorskip('pyld')
        from ldp_helpers import did_key, sign_ldp
        from openbadgeslib.ob3.ldp import OB3LdpVerifier
        priv_pem, pub_pem = ed25519_keypair
        doc = ob3_credential.to_vc()
        doc['issuer'] = {'id': did_key(pub_pem), 'type': ['Profile'],
                         'name': 'I'}
        doc['credentialStatus'] = [
            {'id': '%s#%d' % (LIST_URL, i),
             'type': 'BitstringStatusListEntry',
             'statusPurpose': 'revocation', 'statusListIndex': str(i),
             'statusListCredential': LIST_URL} for i in range(9)]
        signed = sign_ldp(doc, priv_pem, pub_pem)
        verifier = OB3LdpVerifier(pubkey_pem=pub_pem)
        assert verifier.verify(signed)              # without status: passes
        dl, calls = _counting(_status_list_doc([]))
        with pytest.raises(OB3VerificationError,
                           match='9 credentialStatus entries'):
            verifier.verify(signed, check_status=True, download=dl)
        assert calls == []
