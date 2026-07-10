"""Tests for the strict OpenBadges 2.0 verifier (openbadgeslib.ob2.verifier)."""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from openbadgeslib.ob2 import (
    OB2_CONTEXT, OB2Signer, OB2Verifier, OB2VerificationError,
    Assertion, IdentityObject, Verification,
)

ISSUER = 'https://example.com/organization.json'
BADGE = 'https://example.com/badge.json'
KEY = 'https://example.com/key.json'
REV = 'https://example.com/revocation.json'
RECIPIENT = 'recipient@example.com'
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

PATCH_TARGET = 'openbadgeslib.ob2.verifier.download_file'


def _dl(url_map):
    def fake(url, *a, **k):
        if url not in url_map:
            raise AssertionError('unexpected url %s' % url)
        return json.dumps(url_map[url]).encode()
    return fake


def _sign(priv, assertion):
    return OB2Signer(privkey_pem=priv, algorithm='RS256').sign(assertion)


def _signed(priv, *, creator=KEY, badge=BADGE, expires=None, issued=NOW, salt='s4lt3d'):
    a = Assertion(
        recipient=IdentityObject.create(RECIPIENT, salt=salt),
        badge=badge,
        verification=Verification(type='SignedBadge', creator=creator),
        issued_on=issued, expires=expires,
    )
    return _sign(priv, a), a


def _hosted(priv, *, aid='https://example.com/assertions/x.json', badge=BADGE, issued=NOW):
    a = Assertion(
        id=aid,
        recipient=IdentityObject.create(RECIPIENT, salt='s4lt3d'),
        badge=badge,
        verification=Verification(type='HostedBadge'),
        issued_on=issued,
    )
    return _sign(priv, a), a


def _key_doc(pub_pem):
    return {'@context': OB2_CONTEXT, 'type': 'CryptographicKey',
            'id': KEY, 'owner': ISSUER, 'publicKeyPem': pub_pem.decode('ascii')}


# ── signed, trusted operator key (offline) ──────────────────────────────────────

class TestSignedTrusted:
    def test_valid(self, rsa_priv_pem, rsa_pub_pem):
        token, _ = _signed(rsa_priv_pem)
        result = OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token, expected_recipient=RECIPIENT)
        assert result.verification.type == 'SignedBadge'

    def test_wrong_recipient(self, rsa_priv_pem, rsa_pub_pem):
        token, _ = _signed(rsa_priv_pem)
        with pytest.raises(OB2VerificationError):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token, expected_recipient='other@example.com')

    def test_tampered_signature(self, rsa_priv_pem, rsa_pub_pem):
        token, _ = _signed(rsa_priv_pem)
        h, p, s = token.split('.')
        tampered = '%s.%s.%sAAAA' % (h, p, s[:-4])
        with pytest.raises(OB2VerificationError):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify(tampered)

    def test_expired(self, rsa_priv_pem, rsa_pub_pem):
        token, _ = _signed(rsa_priv_pem, issued=NOW - timedelta(days=2),
                           expires=NOW - timedelta(days=1))
        with pytest.raises(OB2VerificationError):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token)

    def test_wrong_key_rejected(self, rsa_priv_pem, ecc_pub_pem):
        token, _ = _signed(rsa_priv_pem)
        with pytest.raises(OB2VerificationError):
            OB2Verifier(pubkey_pem=ecc_pub_pem).verify(token)


# ── signed, untrusted (creator resolution + ownership) ──────────────────────────

class TestSignedUntrusted:
    def test_creator_resolution_and_ownership_ok(self, rsa_priv_pem, rsa_pub_pem):
        token, _ = _signed(rsa_priv_pem)
        url_map = {KEY: _key_doc(rsa_pub_pem), BADGE: {'issuer': ISSUER},
                   ISSUER: {'id': ISSUER, 'name': 'I', 'publicKey': [KEY]}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            result = OB2Verifier().verify(token, expected_recipient=RECIPIENT)
        assert result.verification.creator == KEY

    def test_embedded_cryptographickey_in_publickey_accepted(self, rsa_priv_pem,
                                                             rsa_pub_pem):
        # A Profile may embed the CryptographicKey object in publicKey (a
        # conformant OB 2.0 shape), not only reference it by IRI; ownership must
        # still resolve via the embedded object's id (#194).
        token, _ = _signed(rsa_priv_pem)
        url_map = {KEY: _key_doc(rsa_pub_pem), BADGE: {'issuer': ISSUER},
                   ISSUER: {'id': ISSUER, 'name': 'I',
                            'publicKey': [_key_doc(rsa_pub_pem)]}}  # embedded obj
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            result = OB2Verifier().verify(token, expected_recipient=RECIPIENT)
        assert result.verification.creator == KEY

    def test_broken_ownership_rejected(self, rsa_priv_pem, rsa_pub_pem):
        token, _ = _signed(rsa_priv_pem)
        url_map = {KEY: _key_doc(rsa_pub_pem), BADGE: {'issuer': ISSUER},
                   ISSUER: {'id': ISSUER, 'name': 'I', 'publicKey': ['https://example.com/other.json']}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            with pytest.raises(OB2VerificationError):
                OB2Verifier().verify(token)

    def test_owner_mismatch_rejected(self, rsa_priv_pem, rsa_pub_pem):
        token, _ = _signed(rsa_priv_pem)
        key_doc = _key_doc(rsa_pub_pem)
        key_doc['owner'] = 'https://evil.test/org.json'
        url_map = {KEY: key_doc, BADGE: {'issuer': ISSUER},
                   ISSUER: {'id': ISSUER, 'name': 'I', 'publicKey': [KEY]}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            with pytest.raises(OB2VerificationError):
                OB2Verifier().verify(token)

    def test_missing_creator_and_no_trusted_key_rejected(self, rsa_priv_pem):
        token, _ = _signed(rsa_priv_pem, creator=None)
        with pytest.raises(OB2VerificationError):
            OB2Verifier().verify(token)


# ── hosted ──────────────────────────────────────────────────────────────────────

class TestHosted:
    def test_valid(self, rsa_priv_pem):
        token, a = _hosted(rsa_priv_pem)
        url_map = {a.id: a.to_dict(), BADGE: {'issuer': ISSUER}, ISSUER: {'id': ISSUER}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            result = OB2Verifier().verify(token, expected_recipient=RECIPIENT)
        assert result.verification.type == 'HostedBadge'

    def test_cross_origin_scope_rejected(self, rsa_priv_pem):
        token, a = _hosted(rsa_priv_pem)
        url_map = {a.id: a.to_dict(), BADGE: {'issuer': 'https://evil.test/org.json'},
                   'https://evil.test/org.json': {'id': 'https://evil.test/org.json'}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            with pytest.raises(OB2VerificationError):
                OB2Verifier().verify(token)

    def test_starts_with_scope_allows_cross_origin_issuer(self, rsa_priv_pem):
        token, a = _hosted(rsa_priv_pem)
        issuer = {'id': 'https://other.test/org.json',
                  'verification': {'startsWith': ['https://example.com/assertions/']}}
        url_map = {a.id: a.to_dict(), BADGE: {'issuer': 'https://other.test/org.json'},
                   'https://other.test/org.json': issuer}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            result = OB2Verifier().verify(token)
        assert result.verification.type == 'HostedBadge'

    def test_allowed_origins_scope(self, rsa_priv_pem):
        token, a = _hosted(rsa_priv_pem)
        issuer = {'id': 'https://other.test/org.json',
                  'verification': {'allowedOrigins': ['example.com']}}
        url_map = {a.id: a.to_dict(), BADGE: {'issuer': 'https://other.test/org.json'},
                   'https://other.test/org.json': issuer}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            assert OB2Verifier().verify(token).verification.type == 'HostedBadge'

    def test_starts_with_scope_rejects_outside_prefix(self, rsa_priv_pem):
        # Reject-side of startsWith: the assertion id matches no declared
        # prefix, so it is outside the issuer's hosted scope (the accept-side
        # is tested above; this guard is the one an id-spoofing badge trips).
        token, a = _hosted(rsa_priv_pem)
        issuer = {'id': 'https://other.test/org.json',
                  'verification': {'startsWith': ['https://example.com/OTHER/']}}
        url_map = {a.id: a.to_dict(), BADGE: {'issuer': 'https://other.test/org.json'},
                   'https://other.test/org.json': issuer}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            with pytest.raises(OB2VerificationError, match='startsWith'):
                OB2Verifier().verify(token)

    def test_allowed_origins_scope_rejects_foreign_origin(self, rsa_priv_pem):
        # Reject-side of allowedOrigins: the assertion host is not listed.
        token, a = _hosted(rsa_priv_pem)
        issuer = {'id': 'https://other.test/org.json',
                  'verification': {'allowedOrigins': ['not-example.test']}}
        url_map = {a.id: a.to_dict(), BADGE: {'issuer': 'https://other.test/org.json'},
                   'https://other.test/org.json': issuer}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            with pytest.raises(OB2VerificationError, match='allowedOrigins'):
                OB2Verifier().verify(token)

    def test_fetched_mismatch_rejected(self, rsa_priv_pem):
        token, a = _hosted(rsa_priv_pem)
        tampered = a.to_dict()
        tampered['recipient'] = {'type': 'email', 'hashed': True, 'identity': 'sha256$deadbeef'}
        url_map = {a.id: tampered, BADGE: {'issuer': ISSUER}, ISSUER: {'id': ISSUER}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            with pytest.raises(OB2VerificationError):
                OB2Verifier().verify(token)

    def test_fetch_failure_rejected(self, rsa_priv_pem):
        token, a = _hosted(rsa_priv_pem)
        with patch(PATCH_TARGET, side_effect=ValueError('unreachable')):
            with pytest.raises(OB2VerificationError):
                OB2Verifier().verify(token)

    def test_equivalent_issuedon_form_accepted(self, rsa_priv_pem):
        # A conformant host may serve the same instant as +00:00 instead of Z;
        # that must not false-reject the badge (compared as a timestamp).
        token, a = _hosted(rsa_priv_pem)
        hosted = a.to_dict()
        hosted['issuedOn'] = hosted['issuedOn'].replace('Z', '+00:00')
        url_map = {a.id: hosted, BADGE: {'issuer': ISSUER}, ISSUER: {'id': ISSUER}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            result = OB2Verifier().verify(token, expected_recipient=RECIPIENT)
        assert result.verification.type == 'HostedBadge'

    def test_different_issuedon_rejected(self, rsa_priv_pem):
        token, a = _hosted(rsa_priv_pem)
        hosted = a.to_dict()
        hosted['issuedOn'] = '2000-01-01T00:00:00+00:00'   # a different instant
        url_map = {a.id: hosted, BADGE: {'issuer': ISSUER}, ISSUER: {'id': ISSUER}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            with pytest.raises(OB2VerificationError):
                OB2Verifier().verify(token)

    def test_hosted_expires_stripped_locally_rejected(self, rsa_priv_pem):
        # A genuinely-hosted badge that has expired; the holder strips `expires`
        # from the local baked copy (the JWS is non-gating for a hosted badge).
        # The authoritative fetch still carries the past expires, so the expires
        # must be reconciled and verification must fail -- otherwise the local
        # _check_expiration sees no expiry and the expired badge verifies.
        token, a = _hosted(rsa_priv_pem)                # local copy: no expires
        hosted = a.to_dict()
        hosted['expires'] = '2000-01-01T00:00:00+00:00'  # authoritative: expired
        url_map = {a.id: hosted, BADGE: {'issuer': ISSUER}, ISSUER: {'id': ISSUER}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            with pytest.raises(OB2VerificationError, match='expires'):
                OB2Verifier().verify(token, expected_recipient=RECIPIENT)

    def test_hosted_expires_matching_ok(self, rsa_priv_pem):
        # Local and authoritative expires agree (same future instant): a valid,
        # non-expired hosted badge must not be false-rejected.
        a = Assertion(
            id='https://example.com/assertions/x.json',
            recipient=IdentityObject.create(RECIPIENT, salt='s4lt3d'),
            badge=BADGE, verification=Verification(type='HostedBadge'),
            issued_on=NOW, expires=NOW + timedelta(days=3650))
        token = _sign(rsa_priv_pem, a)
        url_map = {a.id: a.to_dict(), BADGE: {'issuer': ISSUER},
                   ISSUER: {'id': ISSUER}}
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            result = OB2Verifier().verify(token, expected_recipient=RECIPIENT)
        assert result.verification.type == 'HostedBadge'


# ── revocation ──────────────────────────────────────────────────────────────────

class TestRevocation:
    def _issuer_chain(self, revoked_assertions):
        return {BADGE: {'issuer': ISSUER},
                ISSUER: {'id': ISSUER, 'revocationList': REV},
                REV: {'@context': OB2_CONTEXT, 'type': 'RevocationList',
                      'id': REV, 'issuer': ISSUER, 'revokedAssertions': revoked_assertions}}

    def test_revoked_string_entry(self, rsa_priv_pem, rsa_pub_pem):
        token, a = _signed(rsa_priv_pem)
        with patch(PATCH_TARGET, side_effect=_dl(self._issuer_chain([a.id]))):
            with pytest.raises(OB2VerificationError):
                OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token, check_revocation=True)

    def test_revoked_object_entry(self, rsa_priv_pem, rsa_pub_pem):
        token, a = _signed(rsa_priv_pem)
        chain = self._issuer_chain([{'id': a.id, 'revocationReason': 'mistake'}])
        with patch(PATCH_TARGET, side_effect=_dl(chain)):
            with pytest.raises(OB2VerificationError):
                OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token, check_revocation=True)

    def test_not_revoked(self, rsa_priv_pem, rsa_pub_pem):
        token, a = _signed(rsa_priv_pem)
        with patch(PATCH_TARGET, side_effect=_dl(self._issuer_chain(['urn:uuid:other']))):
            result = OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token, check_revocation=True)
        assert result.verification.type == 'SignedBadge'

    def test_no_revocation_list_is_not_revoked(self, rsa_priv_pem, rsa_pub_pem):
        token, a = _signed(rsa_priv_pem)
        url_map = {BADGE: {'issuer': ISSUER}, ISSUER: {'id': ISSUER}}  # no revocationList
        with patch(PATCH_TARGET, side_effect=_dl(url_map)):
            assert OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token, check_revocation=True)


# ── construction / extraction ───────────────────────────────────────────────────

class TestConstructionAndExtraction:
    def test_garbage_key_rejected(self):
        with pytest.raises(OB2VerificationError):
            OB2Verifier(pubkey_pem=b'not a pem key at all')

    def test_extract_from_svg_without_assertion_raises(self, svg_image):
        with pytest.raises(OB2VerificationError):
            OB2Verifier.extract_token_from_svg(svg_image)

    def test_extract_from_png_without_assertion_raises(self, png_image):
        with pytest.raises(OB2VerificationError):
            OB2Verifier.extract_token_from_png(png_image)

    def test_malformed_token_rejected(self, rsa_pub_pem):
        with pytest.raises(OB2VerificationError):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify('not-a-jws')
