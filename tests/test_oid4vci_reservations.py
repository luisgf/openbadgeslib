"""Tests for status-list reservations and their reconciliation.

An OID4VCI offer reserves a revocation slot before it knows whether a wallet
will claim it. These cover the registry's schema-2 support for that, and the
offline pass that frees the slots of offers that lapsed unclaimed — including
the cases where it must refuse to free anything.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from openbadgeslib.errors import RegistryCorrupt
from openbadgeslib.ob3.status_registry import StatusRegistry
from openbadgeslib.oid4vci import (InMemoryOID4VCIStore,
                                   build_credential_offer,
                                   handle_token_request,
                                   reconcile_reservations)
from openbadgeslib.oid4vci.store import STATE_ISSUED

TESTS_DIR = Path(__file__).parent
NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
ISSUER = 'https://issuer.example/issuer/'


def _conf(tmp_path, *, offer_ttl_s=600):
    log = tmp_path / 'log'
    log.mkdir(exist_ok=True)
    text = '\n'.join([
        '[paths]', 'base = %s' % tmp_path, 'base_log = %s' % log,
        'base_image = %s' % (TESTS_DIR / 'images'), '',
        '[logs]', 'general = general.log', 'signer = signer.log', '',
        '[issuer]', 'name = Test Issuer', 'url = https://example.com',
        'publish_url = %s' % ISSUER, '',
        '[oid4vci]', 'credential_issuer = %s' % ISSUER,
        'offer_ttl_s = %d' % offer_ttl_s, '',
        '[badge_1]', 'name = Test Badge', 'description = A test badge',
        'local_image = sample1.svg',
        'image = https://example.com/badge.svg',
        'criteria = https://example.com/criteria.html',
        'verify_key = https://example.com/verify.pem',
        'badge = https://example.com/badge.json',
        'crypto_key = https://example.com/key.json',
        'private_key = %s/test_sign_rsa.pem' % TESTS_DIR,
        'public_key = %s/test_verify_rsa.pem' % TESTS_DIR,
        'key_type = RSA', 'oid4vci_formats = jwt_vc_json',
        'status_lists = revocation', '']) + '\n'
    path = tmp_path / 'cfg.ini'
    path.write_text(text)
    from openbadgeslib.confparser import read_config_or_exit
    return read_config_or_exit(str(path))


@pytest.fixture
def store():
    made = InMemoryOID4VCIStore()
    yield made
    made.close()


class TestRegistrySchema2:
    def test_reservation_round_trips(self, tmp_path):
        path = str(tmp_path / 'reg.json')
        registry = StatusRegistry(path)
        expiry = NOW + timedelta(minutes=10)
        index = registry.allocate('urn:uuid:a', 'r@example.org', NOW,
                                  pending=True, offer_expires_at=expiry)
        registry.save()

        reloaded = StatusRegistry.load(path)
        entry = reloaded.entries['urn:uuid:a']
        assert entry.index == index
        assert entry.pending is True
        assert entry.offer_expires_at == '2026-07-25T12:10:00Z'

    def test_a_version_1_file_still_loads(self, tmp_path):
        # Every entry in a schema-1 file is a delivered credential, which is
        # exactly what pending=False means — so there is no migration step.
        path = tmp_path / 'reg.json'
        path.write_text(json.dumps({
            'version': 1, 'size_bits': 131072,
            'entries': {'urn:uuid:old': {'index': 7,
                                         'recipient': 'mailto:r@example.org',
                                         'issued_on': '2026-01-01T00:00:00Z'}},
        }))
        registry = StatusRegistry.load(str(path))
        entry = registry.entries['urn:uuid:old']
        assert entry.pending is False
        assert entry.offer_expires_at is None

    def test_a_future_version_is_still_refused(self, tmp_path):
        path = tmp_path / 'reg.json'
        path.write_text(json.dumps({'version': 99, 'size_bits': 131072,
                                    'entries': {}}))
        with pytest.raises(RegistryCorrupt):
            StatusRegistry.load(str(path))

    def test_a_registry_without_reservations_serialises_as_before(self,
                                                                  tmp_path):
        # The pending keys are written only when set, so an ordinary issuing
        # deployment's file does not change shape.
        path = str(tmp_path / 'reg.json')
        registry = StatusRegistry(path)
        registry.allocate('urn:uuid:a', 'r@example.org', NOW)
        registry.save()
        entry = json.loads(Path(path).read_text())['entries']['urn:uuid:a']
        assert set(entry) == {'index', 'recipient', 'issued_on'}

    def test_a_reserved_index_is_not_handed_out_twice(self, tmp_path):
        registry = StatusRegistry(str(tmp_path / 'reg.json'), size_bits=8)
        reserved = {registry.allocate('urn:uuid:%d' % i, 'r@example.org', NOW,
                                      pending=True)
                    for i in range(8)}
        assert len(reserved) == 8

    def test_mark_delivered_clears_the_reservation(self, tmp_path):
        registry = StatusRegistry(str(tmp_path / 'reg.json'))
        registry.allocate('urn:uuid:a', 'r@example.org', NOW, pending=True,
                          offer_expires_at=NOW + timedelta(minutes=5))
        registry.mark_delivered('urn:uuid:a')
        entry = registry.entries['urn:uuid:a']
        assert entry.pending is False
        assert entry.offer_expires_at is None
        assert registry.pending_entries() == []

    def test_reclaim_frees_the_index(self, tmp_path):
        registry = StatusRegistry(str(tmp_path / 'reg.json'))
        index = registry.allocate('urn:uuid:a', 'r@example.org', NOW,
                                  pending=True)
        assert registry.reclaim('urn:uuid:a') == index
        assert 'urn:uuid:a' not in registry.entries
        # And the index is genuinely free again.
        assert registry.allocate('urn:uuid:b', 'r@example.org', NOW) is not None

    def test_reclaiming_a_delivered_credential_is_refused(self, tmp_path):
        # Reusing a delivered credential's index would tie two credentials to
        # one revocation bit: revoking either would revoke both.
        registry = StatusRegistry(str(tmp_path / 'reg.json'))
        registry.allocate('urn:uuid:a', 'r@example.org', NOW)
        with pytest.raises(ValueError, match='cannot be reclaimed'):
            registry.reclaim('urn:uuid:a')

    def test_reclaimable_needs_a_recorded_expiry(self, tmp_path):
        # "We do not know when this lapses" must not read as "it has lapsed".
        registry = StatusRegistry(str(tmp_path / 'reg.json'))
        registry.allocate('urn:uuid:no-expiry', 'r@example.org', NOW,
                          pending=True)
        registry.allocate('urn:uuid:lapsed', 'r@example.org', NOW,
                          pending=True,
                          offer_expires_at=NOW - timedelta(minutes=1))
        lapsed = [e.jti for e in registry.reclaimable(NOW)]
        assert lapsed == ['urn:uuid:lapsed']

    def test_a_live_reservation_is_not_reclaimable(self, tmp_path):
        registry = StatusRegistry(str(tmp_path / 'reg.json'))
        registry.allocate('urn:uuid:a', 'r@example.org', NOW, pending=True,
                          offer_expires_at=NOW + timedelta(minutes=5))
        assert registry.reclaimable(NOW) == []

    def test_revocation_of_a_delivered_credential_still_works(self, tmp_path):
        # The whole reason the reservation carries the real jti.
        registry = StatusRegistry(str(tmp_path / 'reg.json'))
        index = registry.allocate('urn:uuid:a', 'r@example.org', NOW,
                                  pending=True)
        registry.mark_delivered('urn:uuid:a')
        registry.revoke('urn:uuid:a', NOW, reason='mistake')
        assert registry.revoked_indices() == [index]


class TestOfferReservations:
    def test_offer_records_a_pending_entry(self, tmp_path, store):
        conf = _conf(tmp_path)
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, now=NOW)
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        entry = registry.entries[
            store.find_grant(offer.grant_id).credential_id]
        assert entry.pending is True
        assert entry.index == offer.status_index
        assert entry.offer_expires_at is not None

    def test_batch_size_plus_status_lists_does_not_reserve(self, tmp_path,
                                                           store):
        # The check used to run AFTER allocate, so a retry of this
        # misconfiguration burned a new index each time (#319).
        from openbadgeslib.errors import ConfigError
        conf = _conf(tmp_path)
        conf['oid4vci']['batch_size'] = '4'
        with pytest.raises(ConfigError, match='batch_size'):
            build_credential_offer(conf, 'badge_1', 'r@example.org',
                                   store=store)
        registry_path = tmp_path / 'status' / 'badge_1.json'
        assert not registry_path.exists() or \
            StatusRegistry.load(str(registry_path)).entries == {}

    def test_a_failed_grant_save_releases_the_reservation(self, tmp_path,
                                                          store):
        conf = _conf(tmp_path)

        def boom(grant):
            raise RuntimeError('disk full')
        store.save_grant = boom
        with pytest.raises(RuntimeError, match='disk full'):
            build_credential_offer(conf, 'badge_1', 'r@example.org',
                                   store=store)
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        assert registry.entries == {}

    def test_reserved_entries_do_not_appear_as_revoked(self, tmp_path, store):
        # A reservation must not affect the published bitstring.
        conf = _conf(tmp_path)
        build_credential_offer(conf, 'badge_1', 'r@example.org', store=store)
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        assert registry.revoked_indices() == []
        assert registry.suspended_indices() == []


class TestReconcile:
    def _offered(self, tmp_path, store, *, now=NOW, offer_ttl_s=600):
        conf = _conf(tmp_path, offer_ttl_s=offer_ttl_s)
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, now=now)
        return conf, offer

    def test_a_live_reservation_is_left_alone(self, tmp_path, store):
        conf, offer = self._offered(tmp_path, store)
        result = reconcile_reservations(conf, 'badge_1', store=store,
                                        reclaim=True, now=NOW)
        assert result.pending_total == 1
        assert result.reclaimed == []
        assert result.undecided
        assert not result.changed

    def test_a_lapsed_unclaimed_reservation_is_freed(self, tmp_path, store):
        conf, offer = self._offered(tmp_path, store)
        later = NOW + timedelta(hours=2)
        result = reconcile_reservations(conf, 'badge_1', store=store,
                                        reclaim=True, now=later)
        assert result.reclaimed == [offer.status_index]
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        assert registry.entries == {}

    def test_dry_run_changes_nothing(self, tmp_path, store):
        conf, offer = self._offered(tmp_path, store)
        later = NOW + timedelta(hours=2)
        result = reconcile_reservations(conf, 'badge_1', store=store,
                                        reclaim=False, now=later)
        assert result.reclaimed == [offer.status_index]
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        assert list(registry.entries)

    def test_a_claimed_reservation_is_marked_delivered_not_freed(
            self, tmp_path, store):
        # The critical case: this credential exists in a wallet, so its index
        # must stay assigned forever.
        conf, offer = self._offered(tmp_path, store)
        handle_token_request(conf, code=offer.pre_authorized_code, store=store,
                             now=NOW)
        from openbadgeslib.oid4vci.store import issuance_fingerprint
        store.claim_issuance(offer.grant_id,
                             issuance_fingerprint('badge_1_jwt_vc_json',
                                                  ['thumb']), now=NOW)
        assert store.find_grant(offer.grant_id).state == STATE_ISSUED

        later = NOW + timedelta(hours=2)
        result = reconcile_reservations(conf, 'badge_1', store=store,
                                        reclaim=True, now=later)
        credential_id = store.find_grant(offer.grant_id).credential_id
        assert result.delivered == [credential_id]
        assert result.reclaimed == []
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        entry = registry.entries[credential_id]
        assert entry.pending is False
        # And it is now revocable through the ordinary path.
        registry.revoke(credential_id, later)
        assert registry.revoked_indices() == [offer.status_index]

    def test_a_still_live_grant_blocks_reclaiming(self, tmp_path, store):
        # The registry's expiry says lapsed, the store's says not. Sources
        # disagreeing is not a licence to free anything.
        conf, offer = self._offered(tmp_path, store, offer_ttl_s=60)
        grant = store.find_grant(offer.grant_id)
        grant.expires_at = NOW + timedelta(days=1)
        store._grants[offer.grant_id] = grant
        later = NOW + timedelta(minutes=5)
        result = reconcile_reservations(conf, 'badge_1', store=store,
                                        reclaim=True, now=later)
        assert result.reclaimed == []
        assert result.undecided

    def test_a_missing_grant_with_a_lapsed_offer_is_left_alone(
            self, tmp_path, store):
        # "Gone" is not "never issued": a pre-fix GC could have deleted a
        # STATE_ISSUED grant, and freeing that index would tie two
        # credentials to one revocation bit (#303). Fail closed.
        conf, offer = self._offered(tmp_path, store)
        later = NOW + timedelta(hours=2)
        grant = store.find_grant(offer.grant_id)
        store.purge_expired(now=later)
        # Force the grant out of the store so we exercise the missing-row
        # path (today's GC no longer deletes STATE_ISSUED, but it still
        # deletes an unclaimed one — and a missing issued row must be
        # treated the same).
        if hasattr(store, '_grants'):
            store._grants.pop(grant.grant_id, None)
            store._codes.pop(grant.code_id, None)
        else:
            conn = store._conn()
            conn.execute('DELETE FROM grant_record WHERE grant_id = ?',
                         (grant.grant_id,))
        result = reconcile_reservations(conf, 'badge_1', store=store,
                                        reclaim=True, now=later)
        credential_id = grant.credential_id
        assert result.reclaimed == []
        assert credential_id not in result.delivered
        assert credential_id in result.undecided
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        assert credential_id in registry.entries

    def test_an_issued_grant_survives_gc_and_is_marked_delivered(
            self, tmp_path, store):
        # The critical case after the offer TTL: the grant has expired,
        # opportunistic GC has run, and the operator reclaims. The index
        # must stay assigned (#303).
        conf, offer = self._offered(tmp_path, store)
        handle_token_request(conf, code=offer.pre_authorized_code, store=store,
                             now=NOW)
        from openbadgeslib.oid4vci.store import issuance_fingerprint
        store.claim_issuance(offer.grant_id,
                             issuance_fingerprint('badge_1_jwt_vc_json',
                                                  ['thumb']), now=NOW)
        later = NOW + timedelta(hours=2)
        store.purge_expired(now=later)
        assert store.find_grant(offer.grant_id) is not None
        assert store.find_grant(offer.grant_id).state == STATE_ISSUED

        result = reconcile_reservations(conf, 'badge_1', store=store,
                                        reclaim=True, now=later)
        credential_id = store.find_grant(offer.grant_id).credential_id
        assert result.delivered == [credential_id]
        assert result.reclaimed == []
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        assert registry.entries[credential_id].pending is False

    def test_code_reuse_after_claim_does_not_free_the_index(
            self, tmp_path, store):
        # A second token request (wallet retry, or anyone with the offer
        # QR) must not turn an issued grant into a reclaimable reservation
        # (#313).
        conf, offer = self._offered(tmp_path, store)
        handle_token_request(conf, code=offer.pre_authorized_code, store=store,
                             now=NOW)
        from openbadgeslib.oid4vci.store import issuance_fingerprint
        store.claim_issuance(offer.grant_id,
                             issuance_fingerprint('badge_1_jwt_vc_json',
                                                  ['thumb']), now=NOW)
        # Replay the pre-authorized code — the token endpoint's reuse path.
        from openbadgeslib.oid4vci.errors import OID4VCIError
        with pytest.raises(OID4VCIError):
            handle_token_request(conf, code=offer.pre_authorized_code,
                                 store=store, now=NOW)
        assert store.find_grant(offer.grant_id).state == STATE_ISSUED

        later = NOW + timedelta(hours=2)
        result = reconcile_reservations(conf, 'badge_1', store=store,
                                        reclaim=True, now=later)
        credential_id = store.find_grant(offer.grant_id).credential_id
        assert result.delivered == [credential_id]
        assert result.reclaimed == []

    def test_a_badge_without_status_lists_is_a_no_op(self, tmp_path, store):
        conf = _conf(tmp_path)
        del conf['badge_1']['status_lists']
        result = reconcile_reservations(conf, 'badge_1', store=store, now=NOW)
        assert result.pending_total == 0
        assert not result.changed

    def test_freed_indices_become_available_again(self, tmp_path, store):
        conf, offer = self._offered(tmp_path, store)
        later = NOW + timedelta(hours=2)
        reconcile_reservations(conf, 'badge_1', store=store, reclaim=True,
                               now=later)
        from openbadgeslib.issue import issue_credential_from_conf
        result = issue_credential_from_conf(conf, 'badge_1', 'other@example.org')
        assert result.status_index is not None
