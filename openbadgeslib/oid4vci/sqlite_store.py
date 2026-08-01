"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es

        All rights reserved.

        This library is free software; you can redistribute it and/or
        modify it under the terms of the GNU Lesser General Public
        License as published by the Free Software Foundation; either
        version 3.0 of the License, or (at your option) any later version.

        This library is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
        Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public
        License along with this library.
"""

# The reference OID4VCI state store, on stdlib sqlite3.
#
# WHY SQLITE AND NOT THE JSON+flock PATTERN THIS REPO USES ELSEWHERE.
# StatusRegistry stores JSON under an fcntl.flock and rewrites the whole file
# per operation. That is right for what it holds: append-only records, written
# at human pace by a CLI, whose indices are never reused. It is wrong here, and
# not marginally:
#
#   1. `_exclusive_file_lock` degrades to a NO-OP where fcntl is missing
#      (status_registry.py documents this). For a revocation registry that is a
#      bounded, documented flaw. For burn_nonce it is a replay vulnerability:
#      two processes both load the file, both delete the nonce, both write, and
#      both return True — two credentials issued to two different holder keys
#      off one nonce. Worse, CI runs a Windows job, so the platform where the
#      flaw exists is the one that would report the tests green.
#   2. os.replace gives an atomic *write*. What this needs is an atomic
#      *decision plus write*: "insert if absent, and tell me whether I was the
#      one who inserted". That is a transaction, not a file swap.
#   3. Nonces churn at machine pace. Rewriting every live row per burn is O(n)
#      inside an HTTP request, under a global exclusive lock.
#   4. The registry deliberately has no expiry. Everything here expires.
#
# sqlite3 is stdlib on every supported platform, so this costs no dependency,
# and it locks correctly on Windows — where the tests are therefore meaningful.
#
# THE PROOF THAT burn_nonce IS CORRECT. Let N be a live nonce, id = sha256(N),
# and let two processes call burn_nonce(id) at once.
#   * BEGIN IMMEDIATE takes SQLite's writer lock BEFORE executing any
#     statement, so the two transactions are totally ordered; call the first to
#     commit T1. (A deferred BEGIN that read first and wrote later would have
#     to promote its snapshot, and SQLITE_BUSY_SNAPSHOT is not retried by
#     busy_timeout — which is why IMMEDIATE is not optional here.)
#   * INSERT OR IGNORE inserts if and only if the primary key was absent,
#     evaluated inside the transaction. T1 therefore sees rowcount 1 and
#     returns True only after its COMMIT returns.
#   * T2 begins after T1 committed and so sees the row: rowcount 0, False.
#   * No GC can remove the row in between: purge_expired only deletes rows with
#     expires_at <= now, and consume rejected expired nonces before reaching
#     the store. A live nonce is never collectable.
#   * If T1's commit fails it rolls back and returns nothing — the exception
#     propagates, the request is rejected, and no credential was issued.
# Hence exactly one caller observes True. With synchronous=FULL the commit has
# fsynced before that True is returned, so a crash cannot resurrect the nonce.
#
# NOT FOR NFS OR SMB: SQLite's locking is broken on network filesystems, and
# this module cannot detect that it is on one.

import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .store import (CLAIM_CONFLICT, CLAIM_GONE, CLAIM_OK, OID4VCIStoreError,
                    PreAuthorizedGrant, PurgeStats, STATE_INVALIDATED,
                    STATE_ISSUED, STATE_OFFERED, STATE_REDEEMED)

#: Bumped when the schema changes shape. An unknown version is refused rather
#: than migrated blind — the same discipline as StatusRegistry._SCHEMA_VERSION.
_SCHEMA_VERSION = 1

#: `PRAGMA application_id`, so `file` and sqlite3 can tell what this database
#: is. Arbitrary but fixed: 'OB4V' as big-endian ASCII.
_APPLICATION_ID = 0x4F423456

#: How often one process bothers to garbage-collect, at most.
_GC_INTERVAL_S = 60.0
#: Rows per table per opportunistic pass, so GC never stalls a request.
_GC_LIMIT = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS issuer_secret (
  name       TEXT PRIMARY KEY,
  value      BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS grant_record (
  grant_id            TEXT    PRIMARY KEY,
  code_id             TEXT    NOT NULL UNIQUE,
  state               TEXT    NOT NULL,
  badge               TEXT    NOT NULL,
  cfg_id              TEXT    NOT NULL,
  fmt                 TEXT    NOT NULL,
  recipient           TEXT    NOT NULL,
  status_index        INTEGER,
  credential_id       TEXT,
  max_proofs          INTEGER NOT NULL DEFAULT 1,
  txc_kdf             TEXT,
  txc_salt            BLOB,
  txc_digest          BLOB,
  txc_attempts        INTEGER NOT NULL DEFAULT 0,
  txc_max             INTEGER NOT NULL DEFAULT 3,
  txc_length          INTEGER,
  txc_input_mode      TEXT,
  fingerprint         TEXT,
  created_at          INTEGER NOT NULL,
  expires_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS grant_expiry ON grant_record(expires_at);

CREATE TABLE IF NOT EXISTS access_token (
  token_id   TEXT    PRIMARY KEY,
  grant_id   TEXT    NOT NULL REFERENCES grant_record(grant_id)
             ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS token_expiry ON access_token(expires_at);
CREATE INDEX IF NOT EXISTS token_grant ON access_token(grant_id);

CREATE TABLE IF NOT EXISTS nonce_burn (
  nonce_id   TEXT    PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nonce_expiry ON nonce_burn(expires_at);
"""

#: The schema as individual statements. sqlite3's executescript() issues an
#: implicit COMMIT before it runs, which would silently end the BEGIN IMMEDIATE
#: the migration opened and leave schema creation outside its transaction.
_SCHEMA_STATEMENTS = tuple(
    statement.strip() for statement in _SCHEMA.split(';') if statement.strip())

#: The grant_record columns, in the order _row_to_grant unpacks them. Kept as a
#: tuple so the SELECT lists and the INSERT placeholder count derive from one
#: definition instead of three hand-synchronised strings.
_GRANT_FIELDS = (
    'grant_id', 'code_id', 'state', 'badge', 'cfg_id', 'fmt', 'recipient',
    'status_index', 'credential_id', 'max_proofs', 'txc_kdf', 'txc_salt',
    'txc_digest', 'txc_attempts', 'txc_max', 'txc_length', 'txc_input_mode',
    'fingerprint', 'created_at', 'expires_at')

_GRANT_COLUMNS = ', '.join(_GRANT_FIELDS)
#: Same list qualified for a join, where a bare `grant_id` is ambiguous.
_GRANT_COLUMNS_G = ', '.join('g.' + name for name in _GRANT_FIELDS)


def _epoch(moment: datetime) -> int:
    """A datetime as integer epoch seconds, so SQL can compare it.

    A naive datetime is read as UTC rather than local time: every timestamp in
    this package is UTC by construction, and silently applying the host's
    timezone would shift every TTL by the offset.
    """
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp())


def _moment(value: Optional[int]) -> Optional[datetime]:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


class SqliteOID4VCIStore:
    """An OID4VCI state store in a single SQLite file.

    Correct for any number of processes and threads on ONE host. For several
    hosts, implement :class:`~openbadgeslib.oid4vci.store.OID4VCIStore` over a
    shared backend instead — this class cannot detect that its file is on a
    network filesystem, where SQLite's locking does not work.

    The file holds live bearer secrets (as digests) and recipient addresses (in
    the clear, since the issuer must know who it is issuing to). Its directory
    is created 0700 and the database 0600, and it should not be backed up:
    doing so preserves secrets and personal data past the lifetimes that are
    the whole point of them.
    """

    multiprocess_safe = True

    def __init__(self, path: str, *, timeout: float = 5.0,
                 clock: Optional[Callable[[], datetime]] = None) -> None:
        self.path = path
        self._timeout = timeout
        self._local = threading.local()
        self._last_gc = 0.0
        # Every query takes its cutoff as an explicit ``now=``; the opportunistic
        # GC is the one place that needs a clock of its own. Injecting it (rather
        # than calling datetime.now() inside _maybe_purge) keeps the store
        # deterministic under test: with a frozen clock a write no longer
        # collects the very rows the test just created against that same instant.
        self._clock: Callable[[], datetime] = (
            clock if clock is not None else (lambda: datetime.now(tz=timezone.utc)))
        self._prepare_directory()
        # Open once eagerly so a broken path or an incompatible schema fails
        # when the store is constructed, not on the first wallet request.
        self._conn()

    # ── connection handling ──────────────────────────────────────────────────

    def _prepare_directory(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise OID4VCIStoreError(
                'could not create the OID4VCI store directory %s: %s'
                % (directory, exc)) from exc

    def _conn(self) -> sqlite3.Connection:
        """This thread's connection, opened and configured on first use.

        One connection per thread, never a shared one with
        check_same_thread=False: two threads issuing BEGIN on the same
        connection interleave their transactions into each other.
        """
        cached: Optional[sqlite3.Connection] = getattr(self._local, 'conn', None)
        if cached is not None:
            return cached
        try:
            conn = sqlite3.connect(self.path, timeout=self._timeout,
                                   isolation_level=None)
            self._configure(conn)
            self._migrate(conn)
        except sqlite3.Error as exc:
            raise OID4VCIStoreError(
                'could not open the OID4VCI store at %s: %s'
                % (self.path, exc)) from exc
        self._local.conn = conn
        self._restrict_permissions()
        return conn

    def _configure(self, conn: sqlite3.Connection) -> None:
        # auto_vacuum must be set before the first table exists, so it leads.
        conn.execute('PRAGMA auto_vacuum = INCREMENTAL')
        conn.execute('PRAGMA journal_mode = WAL')
        # A nonce burn that survives the response but not a power cut is a
        # replay window, so durability beats throughput here.
        conn.execute('PRAGMA synchronous = FULL')
        conn.execute('PRAGMA foreign_keys = ON')
        # A tampered database file must not be able to run triggers or views.
        conn.execute('PRAGMA trusted_schema = OFF')
        # Zero freed pages: a deleted secret should not stay readable in the
        # file's slack space.
        conn.execute('PRAGMA secure_delete = ON')
        conn.execute('PRAGMA busy_timeout = %d' % int(self._timeout * 1000))

    def _migrate(self, conn: sqlite3.Connection) -> None:
        version = int(conn.execute('PRAGMA user_version').fetchone()[0])
        if version == 0:
            # Two processes opening a fresh store both see version 0; the
            # second blocks on BEGIN IMMEDIATE, then re-runs statements that
            # are all IF NOT EXISTS and rewrites the same version. Idempotent.
            conn.execute('BEGIN IMMEDIATE')
            try:
                for statement in _SCHEMA_STATEMENTS:
                    conn.execute(statement)
                conn.execute('PRAGMA application_id = %d' % _APPLICATION_ID)
                conn.execute('PRAGMA user_version = %d' % _SCHEMA_VERSION)
                conn.execute('COMMIT')
            except BaseException:
                self._rollback(conn)
                raise
        elif version != _SCHEMA_VERSION:
            raise OID4VCIStoreError(
                'the OID4VCI store at %s has schema version %d, but this '
                'version of openbadgeslib understands %d — refusing to use it '
                'rather than migrate blindly'
                % (self.path, version, _SCHEMA_VERSION))

    def _restrict_permissions(self) -> None:
        """Tighten the database and its WAL sidecars to 0600.

        The directory mode is the real control: sqlite3 creates ``-wal`` and
        ``-shm`` lazily on the first write, outside any umask this code could
        wrap around connect(). Chmod-ing them here closes the window for the
        common case, and a 0700 directory covers it regardless.
        """
        for suffix in ('', '-wal', '-shm'):
            try:
                os.chmod(self.path + suffix, 0o600)
            except OSError:
                pass    # not created yet, or a platform without POSIX modes

    def close(self) -> None:
        conn = getattr(self._local, 'conn', None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # ── transactions ─────────────────────────────────────────────────────────

    def _write(self, statements: Any) -> Any:
        """Run *statements(conn)* inside one immediate write transaction.

        BEGIN IMMEDIATE rather than a bare BEGIN: taking the writer lock up
        front gives a total order over writers and a snapshot that already
        includes every prior commit, so no transaction here can hit
        SQLITE_BUSY_SNAPSHOT — which busy_timeout would not retry.
        """
        conn = self._conn()
        try:
            conn.execute('BEGIN IMMEDIATE')
        except sqlite3.Error as exc:
            raise OID4VCIStoreError(
                'could not begin an OID4VCI store transaction: %s' % exc) from exc
        try:
            result = statements(conn)
            conn.execute('COMMIT')
        except sqlite3.Error as exc:
            self._rollback(conn)
            raise OID4VCIStoreError('OID4VCI store write failed: %s' % exc) from exc
        except BaseException:
            self._rollback(conn)
            raise
        return result

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        try:
            conn.execute('ROLLBACK')
        except sqlite3.Error:
            pass

    def _read(self, sql: str, params: Any = ()) -> Any:
        try:
            return self._conn().execute(sql, params).fetchone()
        except sqlite3.Error as exc:
            raise OID4VCIStoreError('OID4VCI store read failed: %s' % exc) from exc

    # ── the issuer's nonce key ───────────────────────────────────────────────

    def nonce_secret(self) -> bytes:
        """The HMAC key stateless nonces are authenticated with.

        Minted on first use and shared by every worker on this store, so a
        nonce handed out by one process is accepted by another and a restart
        does not invalidate the ones already in wallets. INSERT OR IGNORE plus
        a re-read makes two workers racing to create it converge on whichever
        one won, rather than one of them overwriting the other's key.
        """
        row = self._read("SELECT value FROM issuer_secret WHERE name = 'nonce'")
        if row is not None:
            return bytes(row[0])
        candidate = os.urandom(32)

        def _insert(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT OR IGNORE INTO issuer_secret (name, value) "
                "VALUES ('nonce', ?)", (candidate,))
        self._write(_insert)
        row = self._read("SELECT value FROM issuer_secret WHERE name = 'nonce'")
        if row is None:      # pragma: no cover - the insert above guarantees it
            raise OID4VCIStoreError('could not persist the OID4VCI nonce key')
        return bytes(row[0])

    # ── grants ───────────────────────────────────────────────────────────────

    def save_grant(self, grant: PreAuthorizedGrant) -> None:
        created = grant.created_at or datetime.now(tz=timezone.utc)

        def _insert(conn: sqlite3.Connection) -> None:
            conn.execute(
                'INSERT INTO grant_record (%s) VALUES (%s)'
                % (_GRANT_COLUMNS, ', '.join(['?'] * len(_GRANT_FIELDS))),
                (grant.grant_id, grant.code_id, grant.state, grant.badge,
                 grant.credential_configuration_id, grant.credential_format,
                 grant.recipient, grant.status_index, grant.credential_id,
                 grant.max_proofs,
                 grant.tx_code_kdf, grant.tx_code_salt, grant.tx_code_digest,
                 grant.tx_code_attempts, grant.tx_code_max_attempts,
                 grant.tx_code_length, grant.tx_code_input_mode,
                 grant.issuance_fingerprint, _epoch(created),
                 _epoch(grant.expires_at)))
        self._write(_insert)
        self._maybe_purge()

    def find_grant_by_code(self, code_id: str, *,
                           now: datetime) -> Optional[PreAuthorizedGrant]:
        row = self._read(
            'SELECT %s FROM grant_record WHERE code_id = ? AND expires_at > ?'
            % _GRANT_COLUMNS, (code_id, _epoch(now)))
        return _row_to_grant(row) if row is not None else None

    def find_grant(self, grant_id: str) -> Optional[PreAuthorizedGrant]:
        """The grant with this id whatever its state — for inspection and
        tests. The request paths use the state-filtered lookups instead."""
        row = self._read('SELECT %s FROM grant_record WHERE grant_id = ?'
                         % _GRANT_COLUMNS, (grant_id,))
        return _row_to_grant(row) if row is not None else None

    def find_grant_by_credential_id(self, credential_id: str
                                    ) -> Optional[PreAuthorizedGrant]:
        row = self._read('SELECT %s FROM grant_record WHERE credential_id = ?'
                         % _GRANT_COLUMNS, (credential_id,))
        return _row_to_grant(row) if row is not None else None

    def record_tx_failure(self, grant_id: str) -> int:
        """Increment the attempt counter, invalidating the grant at the cap.

        Both effects in one UPDATE. Read-modify-write here would let two
        simultaneous wrong guesses each read the same count and each write the
        same increment, so the cap would never be reached and a 20-bit PIN
        would be open to unlimited guessing.
        """
        def _bump(conn: sqlite3.Connection) -> int:
            conn.execute(
                'UPDATE grant_record SET txc_attempts = txc_attempts + 1, '
                'state = CASE WHEN txc_attempts + 1 >= txc_max THEN ? '
                'ELSE state END WHERE grant_id = ?',
                (STATE_INVALIDATED, grant_id))
            row = conn.execute(
                'SELECT txc_attempts FROM grant_record WHERE grant_id = ?',
                (grant_id,)).fetchone()
            return int(row[0]) if row is not None else 0
        return int(self._write(_bump))

    def redeem_grant(self, grant_id: str, *, now: datetime) -> bool:
        def _cas(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                'UPDATE grant_record SET state = ? '
                'WHERE grant_id = ? AND state = ? AND expires_at > ?',
                (STATE_REDEEMED, grant_id, STATE_OFFERED, _epoch(now)))
            return bool(cur.rowcount == 1)
        return bool(self._write(_cas))

    def invalidate_grant(self, grant_id: str) -> None:
        def _kill(conn: sqlite3.Connection) -> None:
            conn.execute('UPDATE grant_record SET state = ? WHERE grant_id = ?',
                         (STATE_INVALIDATED, grant_id))
            conn.execute('DELETE FROM access_token WHERE grant_id = ?',
                         (grant_id,))
        self._write(_kill)

    # ── access tokens ────────────────────────────────────────────────────────

    def mint_token(self, token_id: str, grant_id: str, *,
                   expires_at: datetime) -> None:
        def _insert(conn: sqlite3.Connection) -> None:
            conn.execute(
                'INSERT INTO access_token (token_id, grant_id, expires_at) '
                'VALUES (?, ?, ?)', (token_id, grant_id, _epoch(expires_at)))
        self._write(_insert)

    def grant_for_token(self, token_id: str, *,
                        now: datetime) -> Optional[PreAuthorizedGrant]:
        row = self._read(
            'SELECT %s FROM grant_record g JOIN access_token t '
            'ON t.grant_id = g.grant_id '
            'WHERE t.token_id = ? AND t.expires_at > ? AND g.expires_at > ? '
            'AND g.state IN (?, ?)' % _GRANT_COLUMNS_G,
            (token_id, _epoch(now), _epoch(now), STATE_REDEEMED, STATE_ISSUED))
        return _row_to_grant(row) if row is not None else None

    # ── nonces ───────────────────────────────────────────────────────────────

    def burn_nonce(self, nonce_id: str, *, expires_at: datetime,
                   now: datetime) -> bool:
        """True if and only if this call was the one that spent *nonce_id*.

        See the module docstring for why INSERT OR IGNORE inside BEGIN
        IMMEDIATE is exactly right, and why nothing weaker is.
        """
        def _burn(conn: sqlite3.Connection) -> bool:
            cur = conn.execute(
                'INSERT OR IGNORE INTO nonce_burn (nonce_id, expires_at) '
                'VALUES (?, ?)', (nonce_id, _epoch(expires_at)))
            return bool(cur.rowcount == 1)
        won = bool(self._write(_burn))
        self._maybe_purge()
        return won

    # ── issuance ─────────────────────────────────────────────────────────────

    def claim_issuance(self, grant_id: str, fingerprint: str, *,
                       now: datetime) -> str:
        def _claim(conn: sqlite3.Connection) -> str:
            row = conn.execute(
                'SELECT state, fingerprint, expires_at FROM grant_record '
                'WHERE grant_id = ?', (grant_id,)).fetchone()
            if row is None:
                return CLAIM_GONE
            state, stored, expires_at = row[0], row[1], int(row[2])
            if state == STATE_INVALIDATED or expires_at <= _epoch(now):
                return CLAIM_GONE
            if stored is not None:
                # A retry with the same holder keys is the wallet asking again
                # for a credential it never received; a different set is
                # someone else claiming this grant.
                return CLAIM_OK if stored == fingerprint else CLAIM_CONFLICT
            if state != STATE_REDEEMED:
                return CLAIM_GONE
            conn.execute(
                'UPDATE grant_record SET state = ?, fingerprint = ? '
                'WHERE grant_id = ? AND fingerprint IS NULL',
                (STATE_ISSUED, fingerprint, grant_id))
            return CLAIM_OK
        return str(self._write(_claim))

    # ── garbage collection ───────────────────────────────────────────────────

    def purge_expired(self, *, now: datetime, limit: int = _GC_LIMIT
                      ) -> PurgeStats:
        cutoff = _epoch(now)

        def _purge(conn: sqlite3.Connection) -> PurgeStats:
            stats = PurgeStats()
            # DELETE ... LIMIT needs a compile-time option that is not always
            # present, so bound it through a rowid subquery instead.
            for table, attr in (('grant_record', 'grants'),
                                ('access_token', 'tokens'),
                                ('nonce_burn', 'nonces')):
                cur = conn.execute(
                    'DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s '
                    'WHERE expires_at <= ? LIMIT ?)' % (table, table),
                    (cutoff, limit))
                removed = max(cur.rowcount, 0)
                setattr(stats, attr, removed)
                if removed >= limit:
                    stats.more = True
            return stats
        return PurgeStats(**vars(self._write(_purge)))

    def _maybe_purge(self) -> None:
        """Collect garbage at most once a minute per process, best effort.

        A failure here is logged by being swallowed, not propagated: expiry is
        enforced by every query's predicate, so a GC that never runs makes the
        file bigger and nothing else. Letting a GC error fail a wallet's
        request would trade a real outage for a housekeeping problem.
        """
        elapsed = time.monotonic() - self._last_gc
        if elapsed < _GC_INTERVAL_S:
            return
        self._last_gc = time.monotonic()
        try:
            self.purge_expired(now=self._clock())
        except OID4VCIStoreError:
            pass


def _row_to_grant(row: Any) -> PreAuthorizedGrant:
    """Rebuild a grant from a SELECT over _GRANT_FIELDS.

    Zipped against the field names rather than indexed positionally: adding a
    column would otherwise shift every index after it, and the resulting
    mis-assignment (a status index read as a max_proofs, say) is the kind of
    bug that type-checks, runs, and issues wrong credentials.
    """
    data = dict(zip(_GRANT_FIELDS, row))
    expires_at = _moment(int(data['expires_at']))
    assert expires_at is not None

    def _opt_int(name: str) -> Optional[int]:
        value = data[name]
        return None if value is None else int(value)

    def _opt_bytes(name: str) -> Optional[bytes]:
        value = data[name]
        return None if value is None else bytes(value)

    return PreAuthorizedGrant(
        grant_id=data['grant_id'], code_id=data['code_id'],
        state=data['state'], badge=data['badge'],
        credential_configuration_id=data['cfg_id'],
        credential_format=data['fmt'], recipient=data['recipient'],
        status_index=_opt_int('status_index'),
        credential_id=data['credential_id'],
        max_proofs=int(data['max_proofs']),
        tx_code_kdf=data['txc_kdf'],
        tx_code_salt=_opt_bytes('txc_salt'),
        tx_code_digest=_opt_bytes('txc_digest'),
        tx_code_attempts=int(data['txc_attempts']),
        tx_code_max_attempts=int(data['txc_max']),
        tx_code_length=_opt_int('txc_length'),
        tx_code_input_mode=data['txc_input_mode'],
        issuance_fingerprint=data['fingerprint'],
        created_at=_moment(int(data['created_at'])),
        expires_at=expires_at,
    )


__all__ = ['SqliteOID4VCIStore']
