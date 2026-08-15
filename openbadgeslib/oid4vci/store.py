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

# The state seam for OID4VCI issuance.
#
# openvc verifies the wallet's key proof but refuses to hold anything with a
# lifetime, so the codes, tokens, nonces and grants are this library's problem
# — and with them the property that no credential is ever issued twice, or to a
# key that did not prove possession of itself.
#
# WHY THIS IS A PROTOCOL AND NOT A PILE OF CALLABLES. Elsewhere this codebase
# injects single functions (`download` in ob3.status, ob3.publish). Those seams
# are stateless and one-shot. This one is the same category as StatusRegistry:
# a thing that owns persistence, atomicity and a documented failure contract,
# whose operations must share one transactional backend. Splitting it into six
# callables would make "these all hit the same database" unstateable, and would
# let a caller pass a consistent nonce store with an inconsistent grant store.
#
# EVERY METHOD IS ONE ATOMIC OPERATION OR ONE PURE READ. There is deliberately
# no `get` + `put` pair anywhere in this interface, because the moment an
# implementer can express read-then-write they will, and a read-then-write
# nonce check is a replay window that looks correct in every single-threaded
# test. Where a decision depends on prior state — burning a nonce, redeeming a
# code, claiming an issuance — the decision and the write are the same call and
# the return value says who won.

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol, Sequence

from ..errors import LibOpenBadgesException


class OID4VCIStoreError(LibOpenBadgesException):
    """The state store could not be read or written.

    Distinct from a protocol-level rejection: this is the issuer's own
    infrastructure failing, so it must surface as a server error rather than
    being folded into an ``invalid_grant`` that tells the wallet to retry
    forever. Never raised to mean "not found" — that is a None or a False.
    """


#: A grant that has been offered but not yet redeemed at the token endpoint.
STATE_OFFERED = 'offered'
#: The code was redeemed; an access token exists and the credential is claimable.
STATE_REDEEMED = 'redeemed'
#: A credential was issued against this grant. Terminal.
STATE_ISSUED = 'issued'
#: Killed before use — a replayed code, or too many tx_code attempts. Terminal.
STATE_INVALIDATED = 'invalidated'

GRANT_STATES = (STATE_OFFERED, STATE_REDEEMED, STATE_ISSUED, STATE_INVALIDATED)

#: Results of :meth:`OID4VCIStore.claim_issuance`.
CLAIM_OK = 'ok'                  # this caller may issue
CLAIM_CONFLICT = 'conflict'      # already issued, and not to these keys
CLAIM_GONE = 'gone'              # no such grant, expired, or invalidated


@dataclass
class PreAuthorizedGrant:
    """What one pre-authorized code entitles its bearer to.

    Created when an offer is built, consumed at the token endpoint, and read
    (never re-decided) at the credential endpoint. The credential's content is
    fixed here, at offer time, by the issuer: the wallet's request can only
    match it or be refused, never widen it. That is what makes "no wrong-issue"
    checkable — the request has no say in who the badge is for.

    ``tx_code_*`` hold the KDF digest of the out-of-band PIN, never the PIN.
    ``status_index`` is the status-list slot reserved for this credential, or
    None for a badge without status lists (or an irrevocable format).
    """

    grant_id: str
    code_id: str                       # sha256 of the pre-authorized code
    badge: str                         # config section, e.g. 'badge_1'
    credential_configuration_id: str
    credential_format: str
    recipient: str
    expires_at: datetime
    state: str = STATE_OFFERED
    status_index: Optional[int] = None
    # The credential's `id` (jti), decided HERE rather than at signing time.
    # A revocable badge's status-list slot is reserved when the offer is made,
    # and the registry indexes it by jti — so if signing minted a fresh id the
    # registry would name a credential that never existed and the delivered one
    # could never be revoked.
    credential_id: Optional[str] = None
    max_proofs: int = 1
    tx_code_kdf: Optional[str] = None
    tx_code_salt: Optional[bytes] = None
    tx_code_digest: Optional[bytes] = None
    tx_code_attempts: int = 0
    tx_code_max_attempts: int = 3
    tx_code_length: Optional[int] = None
    tx_code_input_mode: Optional[str] = None
    issuance_fingerprint: Optional[str] = None
    created_at: Optional[datetime] = None

    @property
    def requires_tx_code(self) -> bool:
        return self.tx_code_digest is not None

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at <= now


@dataclass
class PurgeStats:
    """What one garbage-collection pass removed.

    ``more`` is True when the pass hit its row limit, so a caller draining the
    store on a schedule knows to go round again rather than assume it is clean.
    """

    grants: int = 0
    tokens: int = 0
    nonces: int = 0
    more: bool = False

    @property
    def total(self) -> int:
        return self.grants + self.tokens + self.nonces


def issuance_fingerprint(credential_configuration_id: str,
                         thumbprints: Sequence[str]) -> str:
    """Identify one issuance attempt by what it would produce.

    A retry after a dropped response repeats the same configuration and the
    same holder keys, and must be allowed to succeed — the wallet never got its
    credential. A *different* set of keys against the same grant is a second
    holder trying to claim someone else's badge, and must not. Hashing the pair
    lets :meth:`OID4VCIStore.claim_issuance` tell those apart without storing
    the keys themselves.

    Thumbprints are sorted, so proof order in the request cannot change the
    identity of the attempt.
    """
    material = '\x1f'.join([credential_configuration_id] + sorted(thumbprints))
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


class OID4VCIStore(Protocol):
    """The state an OID4VCI issuer must keep, as a pluggable backend.

    :class:`~openbadgeslib.oid4vci.sqlite_store.SqliteOID4VCIStore` is the
    reference implementation and is what a single-host deployment should use.
    Implement this yourself to put the state in Redis or a shared SQL database,
    which is what a multi-host deployment needs.

    IF YOU IMPLEMENT THIS, the contract that matters is atomicity.
    :meth:`burn_nonce`, :meth:`redeem_grant`, :meth:`record_tx_failure` and
    :meth:`claim_issuance` each decide something *and* record it, and each must
    do so as one indivisible operation — a `SET NX`, an `INSERT ... ON
    CONFLICT`, a `DELETE ... RETURNING`, or a transaction. Implementing any of
    them as a read followed by a write reopens the replay window that the key
    proof exists to close, and no test that runs one request at a time will
    notice.
    """

    #: False for a backend that cannot coordinate across processes. The issuer
    #: refuses such a store unless the caller opts in explicitly, because a
    #: multi-worker deployment on a single-process store loses atomicity
    #: silently — the failure mode is a credential issued twice, with nothing
    #: in the logs to say so.
    multiprocess_safe: bool

    def nonce_secret(self) -> bytes:
        """The HMAC key that authenticates stateless nonces.

        Created once and returned unchanged afterwards, so every worker sharing
        this store mints nonces the others accept, and a restart does not
        invalidate the ones already in flight.
        """
        ...

    def save_grant(self, grant: PreAuthorizedGrant) -> None:
        """Persist a newly created grant. Raises on a duplicate code."""
        ...

    def find_grant_by_code(self, code_id: str, *,
                           now: datetime) -> Optional[PreAuthorizedGrant]:
        """The unexpired grant for a code, WHATEVER its state, or None.

        A pure read. It deliberately does not filter on state: the caller has
        to be able to tell "no such code" from "this code was already spent",
        because the second means the offer leaked and every token issued
        against it must be revoked. Filtering here would make that case
        indistinguishable from an unknown code and the revocation unreachable.

        Expired grants ARE excluded — an expiry is routine, not evidence of a
        leak. The token endpoint must still answer all of these identically on
        the wire; the distinction is for what it does, not what it says.
        """
        ...

    def find_grant(self, grant_id: str) -> Optional[PreAuthorizedGrant]:
        """The grant with this id, whatever its state. A pure read, for
        inspection and reconciliation; request paths use the lookups above."""
        ...

    def find_grant_by_credential_id(self, credential_id: str
                                    ) -> Optional[PreAuthorizedGrant]:
        """The grant that reserved this credential id, whatever its state.

        Used only by the offline reconciliation that decides whether an
        unclaimed status-list reservation can be freed. Not on any request
        path.
        """
        ...

    def record_tx_failure(self, grant_id: str) -> int:
        """Count one wrong tx_code attempt; return the new total.

        Must increment and (on reaching the grant's maximum) invalidate in a
        single operation. Two concurrent wrong guesses that both read "2
        attempts used" and both write "3" would hand an attacker unlimited
        tries at a 20-bit secret.
        """
        ...

    def redeem_grant(self, grant_id: str, *, now: datetime) -> bool:
        """Move a grant from offered to redeemed; True if this call did it.

        The single-use property of the pre-authorized code. A second redemption
        returns False, and the caller must then invalidate the grant and revoke
        its tokens: a replayed code means the offer leaked.
        """
        ...

    def invalidate_grant(self, grant_id: str) -> None:
        """Kill a grant and every access token issued against it."""
        ...

    def mint_token(self, token_id: str, grant_id: str, *,
                   expires_at: datetime) -> None:
        """Bind an access token to a grant.

        The grant's own expiry is stretched to at least *expires_at* so
        ``grant_for_token`` does not reject a token the issuer just advertised
        as live (#320).
        """
        ...

    def grant_for_token(self, token_id: str, *,
                        now: datetime) -> Optional[PreAuthorizedGrant]:
        """The grant a live access token authorises, or None.

        A pure read, and the ONLY way the credential endpoint decides what to
        issue. Nothing in the wallet's request selects a credential; the
        request can only be checked against what this returns.
        """
        ...

    def burn_nonce(self, nonce_id: str, *, expires_at: datetime,
                   now: datetime) -> bool:
        """Mark a nonce used; True if and only if THIS call marked it.

        This is the whole replay defence, and the one method where a
        read-then-write implementation is a vulnerability rather than a race.
        See the module docstring of ``sqlite_store`` for the proof that its
        implementation holds under concurrency.
        """
        ...

    def claim_issuance(self, grant_id: str, fingerprint: str, *,
                       now: datetime) -> str:
        """Reserve the right to issue against a grant.

        Returns :data:`CLAIM_OK` for the caller that may proceed,
        :data:`CLAIM_CONFLICT` when this grant already issued to a different
        set of holder keys, and :data:`CLAIM_GONE` when the grant is missing,
        expired or invalidated. A repeat of the same fingerprint returns
        CLAIM_OK, so a wallet retrying after a dropped response gets its
        credential rather than a permanent failure.
        """
        ...

    def purge_expired(self, *, now: datetime,
                      limit: int = 500) -> PurgeStats:
        """Delete expired rows, at most *limit* per table.

        Never the mechanism by which anything expires — every query already
        excludes expired rows — so a store whose GC never runs is safe, merely
        large. That asymmetry is deliberate: a GC bug must not be able to
        shorten a lifetime or resurrect a spent nonce.
        """
        ...

    def close(self) -> None:
        """Release the backend's resources."""
        ...


__all__ = [
    'CLAIM_CONFLICT', 'CLAIM_GONE', 'CLAIM_OK',
    'GRANT_STATES', 'OID4VCIStore', 'OID4VCIStoreError',
    'PreAuthorizedGrant', 'PurgeStats',
    'STATE_INVALIDATED', 'STATE_ISSUED', 'STATE_OFFERED', 'STATE_REDEEMED',
    'issuance_fingerprint',
]
