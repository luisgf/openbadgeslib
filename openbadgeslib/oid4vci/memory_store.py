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

# An in-process OID4VCI store, for tests, examples and single-process demos.
#
# It is correct across THREADS — every decision runs under one lock — and
# wrong across PROCESSES, which is why `multiprocess_safe` is False and why the
# issuer refuses it unless the caller opts in by name. Under gunicorn or
# uvicorn with more than one worker, each worker gets its own dictionaries, so
# the same nonce is accepted once per worker and a pre-authorized code can be
# redeemed as many times as there are workers. Nothing logs that; the only
# symptom is duplicate credentials.
#
# The class exists anyway because the alternative is worse: without a store
# that runs with no filesystem at all, every example and every doctest would
# either touch disk or invent its own dict-based store — and an ad-hoc one
# written in a hurry is exactly where read-then-write creeps back in.

import copy
import os
import threading
from datetime import datetime
from typing import Dict, Optional

from .store import (CLAIM_CONFLICT, CLAIM_GONE, CLAIM_OK, PreAuthorizedGrant,
                    PurgeStats, STATE_INVALIDATED, STATE_ISSUED, STATE_OFFERED,
                    STATE_REDEEMED)


class InMemoryOID4VCIStore:
    """A single-process OID4VCI state store.

    NOT for production: see the module docstring. Thread-safe, process-local,
    and gone when the process is.
    """

    multiprocess_safe = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: Dict[str, PreAuthorizedGrant] = {}
        self._codes: Dict[str, str] = {}            # code_id -> grant_id
        self._tokens: Dict[str, tuple[str, datetime]] = {}
        self._nonces: Dict[str, datetime] = {}
        self._secret = os.urandom(32)

    def nonce_secret(self) -> bytes:
        return self._secret

    # ── grants ───────────────────────────────────────────────────────────────

    def save_grant(self, grant: PreAuthorizedGrant) -> None:
        with self._lock:
            if grant.code_id in self._codes:
                raise ValueError('duplicate pre-authorized code')
            self._grants[grant.grant_id] = copy.deepcopy(grant)
            self._codes[grant.code_id] = grant.grant_id

    def find_grant_by_code(self, code_id: str, *,
                           now: datetime) -> Optional[PreAuthorizedGrant]:
        with self._lock:
            grant_id = self._codes.get(code_id)
            grant = self._grants.get(grant_id) if grant_id else None
            if grant is None or grant.is_expired(now):
                return None
            return copy.deepcopy(grant)

    def find_grant(self, grant_id: str) -> Optional[PreAuthorizedGrant]:
        with self._lock:
            grant = self._grants.get(grant_id)
            return copy.deepcopy(grant) if grant is not None else None

    def find_grant_by_credential_id(self, credential_id: str
                                    ) -> Optional[PreAuthorizedGrant]:
        with self._lock:
            for grant in self._grants.values():
                if grant.credential_id == credential_id:
                    return copy.deepcopy(grant)
            return None

    def record_tx_failure(self, grant_id: str) -> int:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None:
                return 0
            grant.tx_code_attempts += 1
            if grant.tx_code_attempts >= grant.tx_code_max_attempts:
                grant.state = STATE_INVALIDATED
            return grant.tx_code_attempts

    def redeem_grant(self, grant_id: str, *, now: datetime) -> bool:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None or grant.state != STATE_OFFERED \
                    or grant.is_expired(now):
                return False
            grant.state = STATE_REDEEMED
            return True

    def invalidate_grant(self, grant_id: str) -> None:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is not None:
                grant.state = STATE_INVALIDATED
            self._tokens = {tid: entry for tid, entry in self._tokens.items()
                            if entry[0] != grant_id}

    # ── access tokens ────────────────────────────────────────────────────────

    def mint_token(self, token_id: str, grant_id: str, *,
                   expires_at: datetime) -> None:
        with self._lock:
            self._tokens[token_id] = (grant_id, expires_at)

    def grant_for_token(self, token_id: str, *,
                        now: datetime) -> Optional[PreAuthorizedGrant]:
        with self._lock:
            entry = self._tokens.get(token_id)
            if entry is None or entry[1] <= now:
                return None
            grant = self._grants.get(entry[0])
            if grant is None or grant.is_expired(now) \
                    or grant.state not in (STATE_REDEEMED, STATE_ISSUED):
                return None
            return copy.deepcopy(grant)

    # ── nonces ───────────────────────────────────────────────────────────────

    def burn_nonce(self, nonce_id: str, *, expires_at: datetime,
                   now: datetime) -> bool:
        with self._lock:
            # The check and the write are one critical section, so no other
            # thread can slip between them. This is the whole reason the lock
            # exists — the same read-then-write shape without it is the replay
            # bug the Protocol warns about.
            if nonce_id in self._nonces:
                return False
            self._nonces[nonce_id] = expires_at
            return True

    # ── issuance ─────────────────────────────────────────────────────────────

    def claim_issuance(self, grant_id: str, fingerprint: str, *,
                       now: datetime) -> str:
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None or grant.state == STATE_INVALIDATED \
                    or grant.is_expired(now):
                return CLAIM_GONE
            if grant.issuance_fingerprint is not None:
                return CLAIM_OK if grant.issuance_fingerprint == fingerprint \
                    else CLAIM_CONFLICT
            if grant.state != STATE_REDEEMED:
                return CLAIM_GONE
            grant.issuance_fingerprint = fingerprint
            grant.state = STATE_ISSUED
            return CLAIM_OK

    # ── garbage collection ───────────────────────────────────────────────────

    def purge_expired(self, *, now: datetime, limit: int = 500) -> PurgeStats:
        with self._lock:
            stats = PurgeStats()
            # Keep STATE_ISSUED grants past expiry: they are the only proof
            # a wallet claimed the offer, and reconcile needs them so it
            # does not free a delivered credential's status-list index (#303).
            dead_grants = [gid for gid, g in self._grants.items()
                           if g.is_expired(now)
                           and g.state != STATE_ISSUED][:limit]
            for gid in dead_grants:
                grant = self._grants.pop(gid)
                self._codes.pop(grant.code_id, None)
            stats.grants = len(dead_grants)

            dead_tokens = [tid for tid, entry in self._tokens.items()
                           if entry[1] <= now][:limit]
            for tid in dead_tokens:
                self._tokens.pop(tid, None)
            stats.tokens = len(dead_tokens)

            dead_nonces = [nid for nid, exp in self._nonces.items()
                           if exp <= now][:limit]
            for nid in dead_nonces:
                self._nonces.pop(nid, None)
            stats.nonces = len(dead_nonces)

            stats.more = any(n >= limit for n in
                             (stats.grants, stats.tokens, stats.nonces))
            return stats

    def close(self) -> None:
        """Nothing to release; present so the Protocol is satisfied."""


__all__ = ['InMemoryOID4VCIStore']
