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

# Reconciling status-list reservations against what actually got issued.
#
# An OID4VCI offer reserves a revocation slot before it knows whether a wallet
# will ever claim it. Most do; some do not, and their slots sit used forever.
# That is a capacity cost, not a correctness one, and the cure must never be
# worse than the disease: freeing a slot whose credential IS out there would
# tie two credentials to one revocation bit, so revoking either would revoke
# both.
#
# Hence this runs OFFLINE, from an explicit operator command, and never from a
# request path — and it frees a slot only when BOTH sources agree there is
# nothing to protect: the registry says the reservation was never claimed, and
# the OID4VCI store still holds a grant that never reached an issued state.
# Either source alone is not enough. A missing grant is not "unclaimed":
# STATE_ISSUED rows are kept past expiry so this pass can see them, and a
# row that is already gone is left alone rather than reclaimed (#303).
#
# The credential endpoint deliberately does NOT clear `pending` when it issues.
# Doing so would put a registry load-lock-rewrite into a concurrent HTTP path,
# on a lock that is a no-op where fcntl is missing — the very thing reserving
# early was meant to avoid. Instead, this pass clears it later, in the one
# place that already holds both halves of the picture.

import configparser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional

from ..errors import StatusError
from ..ob3.status_registry import StatusRegistry
from .store import STATE_ISSUED


@dataclass
class ReconcileResult:
    """What one reconciliation pass found and, if asked, changed.

    ``delivered`` are reservations confirmed claimed (their pending flag was
    cleared); ``reclaimed`` are indices freed; ``undecided`` are reservations
    whose offer has not lapsed yet, or whose grant is still live — left alone.
    """

    badge: str
    delivered: List[str] = field(default_factory=list)
    reclaimed: List[int] = field(default_factory=list)
    undecided: List[str] = field(default_factory=list)
    pending_total: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.delivered or self.reclaimed)


def reconcile_reservations(conf: configparser.ConfigParser, badge: str, *,
                           store: Any, reclaim: bool = False,
                           now: Optional[datetime] = None) -> ReconcileResult:
    """Reconcile *badge*'s status reservations against the OID4VCI store.

    Read-only by default: it reports what it would do. Pass ``reclaim=True`` to
    actually clear delivered reservations and free the indices of offers that
    lapsed unclaimed.

    An index is freed only when the registry says the reservation is still
    pending AND the store still holds a grant that never reached ``issued``
    AND the offer's expiry has passed. A reservation whose grant reached
    ``issued`` is marked delivered instead — its index stays assigned for
    good. A missing grant is left alone (the store no longer forgets an
    issued row, so "gone" is not proof of "never claimed").
    """
    from ..confparser import ob3_status_config

    moment = now or datetime.now(tz=timezone.utc)
    result = ReconcileResult(badge=badge)
    status_conf = ob3_status_config(conf, badge)
    if status_conf is None:
        return result

    try:
        with StatusRegistry.locked(status_conf.registry_path,
                                   status_conf.size_bits) as registry:
            pending = registry.pending_entries()
            result.pending_total = len(pending)
            lapsed = {entry.jti for entry in registry.reclaimable(moment)}

            for entry in pending:
                grant = store.find_grant_by_credential_id(entry.jti)
                issued = (grant is not None and (
                    grant.state == STATE_ISSUED
                    or grant.issuance_fingerprint is not None))
                if issued:
                    # The wallet claimed it. The index is permanently assigned.
                    # A fingerprint is enough even if a later code-reuse path
                    # tried to demote the row (#313).
                    result.delivered.append(entry.jti)
                    if reclaim:
                        registry.mark_delivered(entry.jti)
                    continue
                if entry.jti not in lapsed:
                    # Still claimable: the offer has not expired, or it carries
                    # no recorded expiry to judge it by.
                    result.undecided.append(entry.jti)
                    continue
                if grant is None:
                    # A missing row is not "the store says this never issued".
                    # STATE_ISSUED grants are no longer purged (#303), so a
                    # missing grant here is either an unclaimed offer the GC
                    # already collected or a pre-fix issued grant whose
                    # evidence is gone. Either source alone is not enough:
                    # leave it alone rather than free an index that may
                    # already belong to a wallet.
                    result.undecided.append(entry.jti)
                    continue
                if grant.state != STATE_ISSUED and not grant.is_expired(moment):
                    # The registry thinks the offer lapsed but the store does
                    # not. Disagreement is not a licence to free anything.
                    result.undecided.append(entry.jti)
                    continue
                result.reclaimed.append(entry.index)
                if reclaim:
                    registry.reclaim(entry.jti)

            if reclaim and result.changed:
                registry.save()
    except (StatusError, OSError) as exc:
        raise StatusError('could not reconcile [%s] reservations: %s'
                          % (badge, exc)) from exc
    return result


__all__ = ['ReconcileResult', 'reconcile_reservations']
