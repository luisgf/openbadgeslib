"""Tests for the OID4VCI state store.

The store is where the flow's security properties actually live: a nonce spent
exactly once, a pre-authorized code redeemed exactly once, a tx_code counter
that cannot be raced, and one issuance per grant. Every test here runs against
BOTH implementations, because a backend that satisfies the Protocol in a
single-threaded test and loses atomicity under load is precisely the failure
this design exists to prevent.
"""
import os
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from openbadgeslib.oid4vci.codes import (TX_CODE_KDF, hash_tx_code, new_id,
                                         new_secret, new_tx_code, secret_id,
                                         verify_tx_code)
from openbadgeslib.oid4vci.memory_store import InMemoryOID4VCIStore
from openbadgeslib.oid4vci.nonce import NonceIssuer
from openbadgeslib.oid4vci.sqlite_store import SqliteOID4VCIStore
from openbadgeslib.oid4vci.store import (CLAIM_CONFLICT, CLAIM_GONE, CLAIM_OK,
                                         OID4VCIStoreError,
                                         PreAuthorizedGrant, STATE_INVALIDATED,
                                         STATE_ISSUED, STATE_OFFERED,
                                         STATE_REDEEMED, issuance_fingerprint)

NOW = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)


def _sqlite(path):
    """A SQLite store whose opportunistic GC runs on this module's frozen clock.

    Every query takes an explicit ``now=``, but the store also garbage-collects
    on write. Left on wall-clock time that GC collects the very rows a test just
    created — the fixtures date everything from NOW, so once NOW is in the past
    a save is undone by the purge that follows it, and the test fails on a
    calendar date rather than on a code change.
    """
    return SqliteOID4VCIStore(path, clock=lambda: NOW)


def _suppress_opportunistic_gc(store):
    """Hold off the SQLite store's once-a-minute GC for this test.

    For a test that drives ``purge_expired()`` itself, the opportunistic GC is
    not the subject: firing on the first write, it collects the expired rows the
    test staged and the explicit call then reports nothing to do. The in-memory
    store has no such GC, which is why only the sqlite parameter needs this.
    """
    if hasattr(store, '_last_gc'):
        store._last_gc = time.monotonic()


def _burn_in_subprocess(path):
    """Open the store fresh and try to spend the contested nonce.

    Module level and argument-only so it survives pickling under the 'spawn'
    start method, which is the default on macOS and Windows — the platforms
    this test most needs to run on.
    """
    store = SqliteOID4VCIStore(path)
    try:
        return store.burn_nonce(
            'contested-across-processes',
            expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=5),
            now=datetime.now(tz=timezone.utc))
    finally:
        store.close()


@pytest.fixture(params=['sqlite', 'memory'])
def store(request, tmp_path):
    if request.param == 'sqlite':
        made = _sqlite(str(tmp_path / 'state' / 'oid4vci.sqlite3'))
    else:
        made = InMemoryOID4VCIStore()
    yield made
    made.close()


@pytest.fixture
def sqlite_store(tmp_path):
    made = _sqlite(str(tmp_path / 'state' / 'oid4vci.sqlite3'))
    yield made
    made.close()


def _grant(*, code=None, expires_at=None, tx_code=None, **kw):
    code = code or new_secret()
    grant = PreAuthorizedGrant(
        grant_id=new_id(), code_id=secret_id(code), badge='badge_1',
        credential_configuration_id='badge_1_jwt_vc_json',
        credential_format='jwt_vc_json', recipient='r@example.com',
        expires_at=expires_at or (NOW + timedelta(minutes=10)),
        created_at=NOW, **kw)
    if tx_code is not None:
        kdf, salt, digest = hash_tx_code(tx_code)
        grant.tx_code_kdf, grant.tx_code_salt, grant.tx_code_digest = \
            kdf, salt, digest
        grant.tx_code_length = len(tx_code)
        grant.tx_code_input_mode = 'numeric'
    return code, grant


class TestGrantLifecycle:
    def test_save_and_find_by_code(self, store):
        code, grant = _grant()
        store.save_grant(grant)
        found = store.find_grant_by_code(secret_id(code), now=NOW)
        assert found is not None
        assert found.grant_id == grant.grant_id
        assert found.recipient == 'r@example.com'
        assert found.state == STATE_OFFERED

    def test_unknown_code_is_none(self, store):
        assert store.find_grant_by_code(secret_id('nope'), now=NOW) is None

    def test_expired_grant_is_not_found(self, store):
        code, grant = _grant(expires_at=NOW - timedelta(seconds=1))
        store.save_grant(grant)
        assert store.find_grant_by_code(secret_id(code), now=NOW) is None

    def test_duplicate_code_is_refused(self, store):
        code, grant = _grant()
        store.save_grant(grant)
        _, twin = _grant(code=code)
        with pytest.raises((OID4VCIStoreError, ValueError)):
            store.save_grant(twin)

    def test_redeem_is_single_use(self, store):
        code, grant = _grant()
        store.save_grant(grant)
        assert store.redeem_grant(grant.grant_id, now=NOW) is True
        assert store.redeem_grant(grant.grant_id, now=NOW) is False
        assert store.find_grant(grant.grant_id).state == STATE_REDEEMED

    def test_a_spent_code_is_still_findable(self, store):
        # The lookup must NOT hide a spent code behind None: the token endpoint
        # has to tell "unknown" from "already used", because the second means
        # the offer leaked and its tokens must be revoked.
        code, grant = _grant()
        store.save_grant(grant)
        store.redeem_grant(grant.grant_id, now=NOW)
        found = store.find_grant_by_code(secret_id(code), now=NOW)
        assert found is not None
        assert found.state == STATE_REDEEMED

    def test_redeem_refuses_an_expired_grant(self, store):
        _, grant = _grant(expires_at=NOW - timedelta(seconds=1))
        store.save_grant(grant)
        assert store.redeem_grant(grant.grant_id, now=NOW) is False

    def test_invalidate_kills_the_grant_and_its_tokens(self, store):
        _, grant = _grant()
        store.save_grant(grant)
        store.redeem_grant(grant.grant_id, now=NOW)
        token = new_secret()
        store.mint_token(secret_id(token), grant.grant_id,
                         expires_at=NOW + timedelta(minutes=5))
        store.invalidate_grant(grant.grant_id)
        assert store.find_grant(grant.grant_id).state == STATE_INVALIDATED
        assert store.grant_for_token(secret_id(token), now=NOW) is None

    def test_invalidate_does_not_demote_an_issued_grant(self, store):
        # Code reuse after a wallet claimed must revoke tokens, not erase
        # the delivery evidence reclaim uses to keep the status index (#313).
        _, grant = _grant()
        store.save_grant(grant)
        store.redeem_grant(grant.grant_id, now=NOW)
        fp = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb'])
        assert store.claim_issuance(grant.grant_id, fp, now=NOW) == CLAIM_OK
        token = new_secret()
        store.mint_token(secret_id(token), grant.grant_id,
                         expires_at=NOW + timedelta(minutes=5))
        store.invalidate_grant(grant.grant_id)
        kept = store.find_grant(grant.grant_id)
        assert kept.state == STATE_ISSUED
        assert kept.issuance_fingerprint == fp
        assert store.grant_for_token(secret_id(token), now=NOW) is None

    def test_status_index_round_trips(self, store):
        _, grant = _grant(status_index=4242)
        store.save_grant(grant)
        assert store.find_grant(grant.grant_id).status_index == 4242

    def test_status_index_none_round_trips(self, store):
        _, grant = _grant()
        store.save_grant(grant)
        assert store.find_grant(grant.grant_id).status_index is None


class TestTxCode:
    def test_attempts_increment_and_cap_invalidates(self, store):
        _, grant = _grant(tx_code='123456', tx_code_max_attempts=3)
        store.save_grant(grant)
        assert store.record_tx_failure(grant.grant_id) == 1
        assert store.find_grant(grant.grant_id).state == STATE_OFFERED
        assert store.record_tx_failure(grant.grant_id) == 2
        assert store.record_tx_failure(grant.grant_id) == 3
        # The third wrong guess burns the grant, so a fourth try has nothing
        # left to guess against.
        assert store.find_grant(grant.grant_id).state == STATE_INVALIDATED

    def test_digest_round_trips_and_rejects_a_wrong_code(self, store):
        _, grant = _grant(tx_code='042190')
        store.save_grant(grant)
        stored = store.find_grant(grant.grant_id)
        assert verify_tx_code('042190', stored.tx_code_kdf,
                              stored.tx_code_salt, stored.tx_code_digest)
        assert not verify_tx_code('042191', stored.tx_code_kdf,
                                  stored.tx_code_salt, stored.tx_code_digest)

    def test_concurrent_failures_are_all_counted(self, store):
        # A read-modify-write counter would lose increments here, and losing
        # increments means the cap never trips on a 20-bit secret.
        _, grant = _grant(tx_code='123456', tx_code_max_attempts=50)
        store.save_grant(grant)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: store.record_tx_failure(grant.grant_id),
                          range(40)))
        assert store.find_grant(grant.grant_id).tx_code_attempts == 40


class TestAccessTokens:
    def test_token_resolves_to_its_grant(self, store):
        _, grant = _grant()
        store.save_grant(grant)
        store.redeem_grant(grant.grant_id, now=NOW)
        token = new_secret()
        store.mint_token(secret_id(token), grant.grant_id,
                         expires_at=NOW + timedelta(minutes=5))
        found = store.grant_for_token(secret_id(token), now=NOW)
        assert found is not None and found.grant_id == grant.grant_id

    def test_expired_token_resolves_to_nothing(self, store):
        _, grant = _grant()
        store.save_grant(grant)
        store.redeem_grant(grant.grant_id, now=NOW)
        token = new_secret()
        store.mint_token(secret_id(token), grant.grant_id,
                         expires_at=NOW - timedelta(seconds=1))
        assert store.grant_for_token(secret_id(token), now=NOW) is None

    def test_unknown_token_resolves_to_nothing(self, store):
        assert store.grant_for_token(secret_id('nope'), now=NOW) is None

    def test_token_on_an_unredeemed_grant_resolves_to_nothing(self, store):
        _, grant = _grant()
        store.save_grant(grant)
        token = new_secret()
        store.mint_token(secret_id(token), grant.grant_id,
                         expires_at=NOW + timedelta(minutes=5))
        assert store.grant_for_token(secret_id(token), now=NOW) is None


class TestBurnNonce:
    def test_first_burn_wins_and_the_second_loses(self, store):
        expires = NOW + timedelta(minutes=2)
        assert store.burn_nonce('abc', expires_at=expires, now=NOW) is True
        assert store.burn_nonce('abc', expires_at=expires, now=NOW) is False

    def test_distinct_nonces_are_independent(self, store):
        expires = NOW + timedelta(minutes=2)
        assert store.burn_nonce('a', expires_at=expires, now=NOW) is True
        assert store.burn_nonce('b', expires_at=expires, now=NOW) is True

    def test_exactly_one_thread_wins(self, store):
        # The core property. Sixteen threads race for one nonce; if more than
        # one sees True, that is a credential issued twice.
        expires = NOW + timedelta(minutes=2)
        barrier = threading.Barrier(16)

        def _race(_):
            barrier.wait()
            return store.burn_nonce('contested', expires_at=expires, now=NOW)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(_race, range(16)))
        assert results.count(True) == 1
        assert results.count(False) == 15


class TestSqliteConnectionLifecycle:
    def test_close_closes_connections_from_every_thread(self, tmp_path):
        # #301: close() used to only close the calling thread's connection, so
        # other threads' handles leaked as ResourceWarning under --cov.
        path = str(tmp_path / 'state' / 'oid4vci.sqlite3')
        store = _sqlite(path)
        barrier = threading.Barrier(4)

        def _open(_):
            barrier.wait()
            store._conn()                      # open a connection on this thread

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(_open, range(4)))
        # __init__ opens one on the main thread + one per worker.
        assert len(store._conns) >= 4
        opened = list(store._conns)
        store.close()
        assert store._conns == set()
        # Every previously-open connection must refuse further use.
        for conn in opened:
            with pytest.raises(sqlite3.ProgrammingError):
                conn.execute('SELECT 1')

    def test_exactly_one_process_wins(self, tmp_path):
        # The real target. Threads share a GIL and a Python-level lock; only
        # separate processes exercise SQLite's own writer lock, which is the
        # thing standing between a multi-worker deployment and a nonce spent
        # twice. This is also the test that would fail on the JSON+flock
        # pattern, and would fail SILENTLY on a platform without fcntl.
        import multiprocessing
        path = str(tmp_path / 'state' / 'oid4vci.sqlite3')
        SqliteOID4VCIStore(path).close()      # create the schema up front
        context = multiprocessing.get_context('spawn')
        with context.Pool(4) as pool:
            results = pool.map(_burn_in_subprocess, [path] * 4)
        assert results.count(True) == 1
        assert results.count(False) == 3

    def test_exactly_one_connection_wins(self, sqlite_store, tmp_path):
        # Two SQLite connections to the same file is the in-process stand-in
        # for two workers: it exercises the real writer lock, not a Python one.
        other = _sqlite(str(tmp_path / 'state' / 'oid4vci.sqlite3'))
        try:
            expires = NOW + timedelta(minutes=2)
            first = sqlite_store.burn_nonce('shared', expires_at=expires,
                                            now=NOW)
            second = other.burn_nonce('shared', expires_at=expires, now=NOW)
            assert [first, second] == [True, False]
        finally:
            other.close()


class TestClaimIssuance:
    def _redeemed(self, store):
        _, grant = _grant()
        store.save_grant(grant)
        store.redeem_grant(grant.grant_id, now=NOW)
        return grant

    def test_first_claim_succeeds(self, store):
        grant = self._redeemed(store)
        fp = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb-a'])
        assert store.claim_issuance(grant.grant_id, fp, now=NOW) == CLAIM_OK
        assert store.find_grant(grant.grant_id).state == STATE_ISSUED

    def test_same_keys_may_retry(self, store):
        # A dropped response must not cost the wallet its credential.
        grant = self._redeemed(store)
        fp = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb-a'])
        assert store.claim_issuance(grant.grant_id, fp, now=NOW) == CLAIM_OK
        assert store.claim_issuance(grant.grant_id, fp, now=NOW) == CLAIM_OK

    def test_different_keys_conflict(self, store):
        # A second holder claiming the same grant is the wrong-issue case.
        grant = self._redeemed(store)
        first = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb-a'])
        second = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb-b'])
        assert store.claim_issuance(grant.grant_id, first, now=NOW) == CLAIM_OK
        assert store.claim_issuance(grant.grant_id, second,
                                    now=NOW) == CLAIM_CONFLICT

    def test_unknown_grant_is_gone(self, store):
        fp = issuance_fingerprint('x', ['t'])
        assert store.claim_issuance('nope', fp, now=NOW) == CLAIM_GONE

    def test_unredeemed_grant_is_gone(self, store):
        _, grant = _grant()
        store.save_grant(grant)
        fp = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb-a'])
        assert store.claim_issuance(grant.grant_id, fp, now=NOW) == CLAIM_GONE

    def test_expired_grant_is_gone(self, store):
        grant = self._redeemed(store)
        fp = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb-a'])
        later = NOW + timedelta(hours=1)
        assert store.claim_issuance(grant.grant_id, fp, now=later) == CLAIM_GONE

    def test_invalidated_grant_is_gone(self, store):
        grant = self._redeemed(store)
        store.invalidate_grant(grant.grant_id)
        fp = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb-a'])
        assert store.claim_issuance(grant.grant_id, fp, now=NOW) == CLAIM_GONE

    def test_exactly_one_of_two_racing_holders_wins(self, store):
        grant = self._redeemed(store)
        barrier = threading.Barrier(8)

        def _race(index):
            fp = issuance_fingerprint('badge_1_jwt_vc_json',
                                      ['thumb-%d' % index])
            barrier.wait()
            return store.claim_issuance(grant.grant_id, fp, now=NOW)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(_race, range(8)))
        assert results.count(CLAIM_OK) == 1


class TestFingerprint:
    def test_proof_order_does_not_change_it(self):
        a = issuance_fingerprint('cfg', ['t1', 't2'])
        b = issuance_fingerprint('cfg', ['t2', 't1'])
        assert a == b

    def test_configuration_is_part_of_it(self):
        assert issuance_fingerprint('cfg-a', ['t']) != \
            issuance_fingerprint('cfg-b', ['t'])

    def test_keys_are_part_of_it(self):
        assert issuance_fingerprint('cfg', ['t1']) != \
            issuance_fingerprint('cfg', ['t2'])


class TestPurge:
    def test_expired_rows_are_removed_and_live_ones_kept(self, store):
        _suppress_opportunistic_gc(store)
        _, dead = _grant(expires_at=NOW - timedelta(minutes=1))
        _, live = _grant()
        store.save_grant(dead)
        store.save_grant(live)
        store.burn_nonce('old', expires_at=NOW - timedelta(seconds=1), now=NOW)
        store.burn_nonce('new', expires_at=NOW + timedelta(minutes=5), now=NOW)

        stats = store.purge_expired(now=NOW)
        assert stats.grants == 1
        assert stats.nonces == 1
        assert stats.total >= 2
        assert store.find_grant(dead.grant_id) is None
        assert store.find_grant(live.grant_id) is not None

    def test_an_issued_grant_is_not_collected_after_expiry(self, store):
        # Delivery evidence must outlive the offer TTL: reconcile reads
        # STATE_ISSUED to mark the status-list reservation delivered, and
        # a collected row would look like "never claimed" (#303).
        _suppress_opportunistic_gc(store)
        _, grant = _grant()
        store.save_grant(grant)
        assert store.redeem_grant(grant.grant_id, now=NOW) is True
        fp = issuance_fingerprint('badge_1_jwt_vc_json', ['thumb'])
        assert store.claim_issuance(grant.grant_id, fp, now=NOW) == CLAIM_OK
        later = NOW + timedelta(hours=2)
        stats = store.purge_expired(now=later)
        assert stats.grants == 0
        kept = store.find_grant(grant.grant_id)
        assert kept is not None
        assert kept.state == STATE_ISSUED

    def test_a_live_nonce_is_never_collected(self, store):
        # If GC could remove a live burn, a spent nonce would become spendable
        # again — the exact replay the burn list prevents.
        expires = NOW + timedelta(minutes=5)
        store.burn_nonce('live', expires_at=expires, now=NOW)
        store.purge_expired(now=NOW)
        assert store.burn_nonce('live', expires_at=expires, now=NOW) is False

    def test_more_is_reported_when_the_limit_is_hit(self, store):
        for index in range(5):
            store.burn_nonce('n%d' % index,
                             expires_at=NOW - timedelta(seconds=1), now=NOW)
        stats = store.purge_expired(now=NOW, limit=2)
        assert stats.nonces == 2
        assert stats.more is True


class TestNonceIssuer:
    def test_mint_and_consume_once(self, store):
        issuer = NonceIssuer(store, ttl_s=120)
        nonce = issuer.mint()
        assert issuer.consume(nonce) is True
        assert issuer.consume(nonce) is False

    def test_minting_writes_nothing(self, store):
        # The nonce endpoint is unauthenticated: minting must not let a
        # stranger drive writes into the issuer's store.
        issuer = NonceIssuer(store, ttl_s=120)
        for _ in range(50):
            issuer.mint()
        assert store.purge_expired(now=NOW + timedelta(days=1)).nonces == 0

    def test_forged_nonce_is_rejected(self, store):
        import base64
        issuer = NonceIssuer(store, ttl_s=120)
        forged = base64.urlsafe_b64encode(b'\x00' * 40).decode().rstrip('=')
        assert issuer.consume(forged) is False

    def test_tampered_nonce_is_rejected(self, store):
        import base64
        issuer = NonceIssuer(store, ttl_s=120)
        raw = bytearray(base64.urlsafe_b64decode(
            issuer.mint() + '=' * 2)[:40])
        raw[-1] ^= 0xFF                       # flip a bit of the MAC tag
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip('=')
        assert issuer.consume(tampered) is False

    def test_expired_nonce_is_rejected_without_burning_a_row(self, store):
        issuer = NonceIssuer(store, ttl_s=1)
        past = datetime.now(tz=timezone.utc) - timedelta(seconds=10)
        nonce = issuer.mint(now=past)
        assert issuer.consume(nonce) is False
        assert store.purge_expired(now=datetime.now(tz=timezone.utc)
                                   + timedelta(days=1)).nonces == 0

    @pytest.mark.parametrize('bogus', ['', 'not base64 !!', 'aGk',
                                       'x' * 200, None])
    def test_malformed_input_is_rejected(self, store, bogus):
        issuer = NonceIssuer(store, ttl_s=120)
        assert issuer.consume(bogus) is False

    def test_a_nonce_from_another_issuer_is_rejected(self, store, tmp_path):
        # Different store, different HMAC key: nonces do not transfer.
        other_store = InMemoryOID4VCIStore()
        foreign = NonceIssuer(other_store, ttl_s=120).mint()
        assert NonceIssuer(store, ttl_s=120).consume(foreign) is False

    def test_secret_survives_reopening_a_sqlite_store(self, tmp_path):
        # A restart must not invalidate the nonces already in wallets.
        path = str(tmp_path / 'state' / 'oid4vci.sqlite3')
        first = SqliteOID4VCIStore(path)
        nonce = NonceIssuer(first, ttl_s=300).mint()
        first.close()
        second = SqliteOID4VCIStore(path)
        try:
            assert NonceIssuer(second, ttl_s=300).consume(nonce) is True
        finally:
            second.close()

    def test_exactly_one_thread_consumes(self, store):
        issuer = NonceIssuer(store, ttl_s=300)
        nonce = issuer.mint()
        barrier = threading.Barrier(12)

        def _race(_):
            barrier.wait()
            return issuer.consume(nonce)

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(_race, range(12)))
        assert results.count(True) == 1

    def test_zero_ttl_is_refused(self, store):
        with pytest.raises(ValueError):
            NonceIssuer(store, ttl_s=0)


class TestCodes:
    def test_secrets_are_distinct_and_long(self):
        values = {new_secret() for _ in range(100)}
        assert len(values) == 100
        assert all(len(v) >= 43 for v in values)

    def test_secret_id_is_stable_and_hides_the_secret(self):
        secret = new_secret()
        assert secret_id(secret) == secret_id(secret)
        assert secret not in secret_id(secret)
        assert len(secret_id(secret)) == 64

    def test_numeric_tx_code_keeps_leading_zeros(self):
        codes = {new_tx_code(6) for _ in range(400)}
        assert all(len(c) == 6 and c.isdigit() for c in codes)
        # The whole 0..999999 range must be reachable, which the common
        # randbelow(900000)+100000 mistake would silently prevent.
        assert any(c.startswith('0') for c in codes)

    def test_text_tx_code_avoids_ambiguous_characters(self):
        code = new_tx_code(8, 'text')
        assert len(code) == 8
        assert not (set(code) & set('ILOU'))

    def test_unknown_input_mode_is_refused(self):
        with pytest.raises(ValueError):
            new_tx_code(6, 'morse')

    def test_zero_length_is_refused(self):
        with pytest.raises(ValueError):
            new_tx_code(0)

    def test_tx_code_verification_round_trips(self):
        kdf, salt, digest = hash_tx_code('123456')
        assert kdf == TX_CODE_KDF
        assert verify_tx_code('123456', kdf, salt, digest) is True
        assert verify_tx_code('654321', kdf, salt, digest) is False

    def test_unknown_kdf_fails_closed(self):
        _, salt, digest = hash_tx_code('123456')
        assert verify_tx_code('123456', 'scrypt-from-the-future', salt,
                              digest) is False

    def test_salt_makes_identical_codes_differ(self):
        _, _, first = hash_tx_code('123456')
        _, _, second = hash_tx_code('123456')
        assert first != second


class TestSqliteSpecifics:
    def test_schema_version_is_recorded(self, sqlite_store):
        conn = sqlite3.connect(sqlite_store.path)
        try:
            assert conn.execute('PRAGMA user_version').fetchone()[0] == 1
        finally:
            conn.close()

    def test_an_unknown_schema_version_is_refused(self, tmp_path):
        path = str(tmp_path / 'state' / 'oid4vci.sqlite3')
        store = SqliteOID4VCIStore(path)
        store.close()
        conn = sqlite3.connect(path)
        conn.execute('PRAGMA user_version = 99')
        conn.close()
        with pytest.raises(OID4VCIStoreError, match='schema version'):
            SqliteOID4VCIStore(path)

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason='POSIX file modes')
    def test_directory_and_file_are_private(self, tmp_path):
        path = str(tmp_path / 'state' / 'oid4vci.sqlite3')
        store = SqliteOID4VCIStore(path)
        try:
            _, grant = _grant()
            store.save_grant(grant)      # force the file into existence
            assert os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
            assert os.stat(path).st_mode & 0o777 == 0o600
        finally:
            store.close()

    def test_recipient_pii_is_stored_but_secrets_are_not(self, sqlite_store):
        code, grant = _grant(tx_code='123456')
        sqlite_store.save_grant(grant)
        # In WAL mode a fresh write lives in the -wal sidecar until a
        # checkpoint, so both files must be searched — which is also why the
        # store chmods the sidecars and relies on a 0700 directory.
        blob = b''
        for suffix in ('', '-wal'):
            try:
                blob += open(sqlite_store.path + suffix, 'rb').read()
            except FileNotFoundError:
                pass
        # The issuer must know who it issues to, so the address is there...
        assert b'r@example.com' in blob
        # ...but nothing that would let a reader redeem the offer is.
        assert code.encode() not in blob
        assert b'123456' not in blob

    def test_survives_reopening(self, tmp_path):
        path = str(tmp_path / 'state' / 'oid4vci.sqlite3')
        first = _sqlite(path)
        code, grant = _grant()
        first.save_grant(grant)
        first.close()
        second = _sqlite(path)
        try:
            found = second.find_grant_by_code(secret_id(code), now=NOW)
            assert found is not None and found.grant_id == grant.grant_id
        finally:
            second.close()

    def test_reports_multiprocess_safety(self, sqlite_store):
        assert sqlite_store.multiprocess_safe is True
        assert InMemoryOID4VCIStore().multiprocess_safe is False
