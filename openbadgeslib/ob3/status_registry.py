"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014-2026, Jesús Cea Avión, jcea@jcea.es

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

# Persistent issuer-side registry of status list index assignments.
#
# One JSON file per badge maps every issued credential (by its jti) to the
# bitstring index it occupies and to its revocation/suspension state. The
# signer allocates here at issue time; openbadges-publish reads it back to
# regenerate the published Bitstring Status Lists.
#
# The file is private issuer state (it names recipients), so it is written
# under a restrictive umask and atomically — a crash mid-write must never
# leave a truncated registry behind, because a lost registry makes every
# outstanding credential unrevocable.

import contextlib
import json
import os
import secrets
import tempfile

try:
    import fcntl                    # POSIX advisory file locking
except ImportError:                 # pragma: no cover - non-POSIX (e.g. Windows)
    fcntl = None                    # type: ignore[assignment]

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Set

from ..errors import (
    AlreadyRevoked,
    AlreadySuspended,
    NotSuspended,
    RegistryCorrupt,
    StatusListFull,
    UnknownCredential,
)
from ..util import normalize_recipient_id, recipient_ids_match
from .status_list import DEFAULT_SIZE_BITS

_SCHEMA_VERSION = 1

#: Random allocation attempts before falling back to a linear scan. With the
#: spec-minimum 131072-bit list this only triggers past ~99.9% occupancy.
_MAX_RANDOM_TRIES = 1000


@contextlib.contextmanager
def _exclusive_file_lock(lock_path: str) -> Iterator[None]:
    """Hold an exclusive inter-process lock for the duration of the block.

    Backed by POSIX ``fcntl.flock`` on a dedicated lock file. Where ``fcntl``
    is unavailable (non-POSIX platforms) it degrades to no locking — the same
    behaviour as before this guard existed — so single-process use is
    unaffected and nothing regresses; concurrent writers are simply not
    serialised there.
    """
    directory = os.path.dirname(lock_path) or '.'
    umask = os.umask(0o077)
    try:
        os.makedirs(directory, exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    finally:
        os.umask(umask)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)        # blocks until the lock frees
        yield
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


@dataclass
class StatusEvent:
    """A revocation or suspension, with when and (optionally) why."""
    date: str
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        data: dict = {'date': self.date}
        if self.reason is not None:
            data['reason'] = self.reason
        return data


@dataclass
class StatusEntry:
    """The registry record of one issued credential."""
    jti: str
    index: int
    recipient: str
    issued_on: str
    revoked: Optional[StatusEvent] = None
    suspended: Optional[StatusEvent] = None


class StatusRegistry:
    """Index assignments and status state for one badge's status lists.

    Load with :meth:`load`, mutate through :meth:`allocate` /
    :meth:`revoke` / :meth:`suspend` / :meth:`unsuspend`, then persist with
    :meth:`save`. Indices are allocated randomly (a W3C Bitstring Status
    List privacy recommendation: sequential indices leak issuance order and
    volume) and are never reused.
    """

    def __init__(self, path: str, size_bits: int = DEFAULT_SIZE_BITS) -> None:
        self.path = path
        self.size_bits = size_bits
        self.entries: Dict[str, StatusEntry] = {}
        self._used_indices: Set[int] = set()

    # ── persistence ──────────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: str,
             size_bits: int = DEFAULT_SIZE_BITS) -> 'StatusRegistry':
        """Read a registry file; a missing file yields an empty registry.

        The effective size is ``max(size_bits, stored size)``: growing a
        list keeps every assigned index valid, while shrinking would orphan
        indices past the new end, so it is rejected as corruption-in-waiting.
        """
        registry = cls(path, size_bits)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except FileNotFoundError:
            return registry
        except (OSError, ValueError) as exc:
            raise RegistryCorrupt('%s: %s' % (path, exc)) from exc

        try:
            stored_bits = int(data['size_bits'])
            if int(data['version']) != _SCHEMA_VERSION:
                raise ValueError('unsupported version %r' % (data['version'],))
            if size_bits < stored_bits:
                raise ValueError(
                    'size_bits %d is smaller than the stored %d — shrinking '
                    'a list would invalidate assigned indices'
                    % (size_bits, stored_bits))
            registry.size_bits = max(size_bits, stored_bits)
            for jti, raw in data['entries'].items():
                entry = StatusEntry(
                    jti=jti,
                    index=int(raw['index']),
                    recipient=raw['recipient'],
                    issued_on=raw['issued_on'],
                    revoked=_event_from(raw.get('revoked')),
                    suspended=_event_from(raw.get('suspended')),
                )
                if not 0 <= entry.index < registry.size_bits \
                        or entry.index in registry._used_indices:
                    raise ValueError('invalid or duplicate index %d for %s'
                                     % (entry.index, jti))
                registry.entries[jti] = entry
                registry._used_indices.add(entry.index)
        except (KeyError, TypeError, ValueError) as exc:
            raise RegistryCorrupt('%s: %s' % (path, exc)) from exc
        return registry

    @classmethod
    @contextlib.contextmanager
    def locked(cls, path: str,
               size_bits: int = DEFAULT_SIZE_BITS) -> Iterator['StatusRegistry']:
        """Load the registry under an exclusive inter-process lock, yield it.

        The lock (a sibling ``<path>.lock`` file) is held for the whole block,
        so a ``load → allocate/revoke/… → save()`` sequence inside it is
        atomic against other processes. This closes the race where two
        concurrent writers both load, and the second :meth:`save` clobbers the
        first's new entry — leaving a delivered credential unrevocable. Call
        :meth:`save` inside the block; the lock releases on exit.

        A dedicated lock file (not the registry JSON) is used on purpose:
        :meth:`save` replaces the JSON via ``os.rename``, so a lock held on the
        JSON inode would be orphaned by the first write.
        """
        with _exclusive_file_lock(path + '.lock'):
            yield cls.load(path, size_bits)

    def save(self) -> None:
        """Write the registry atomically (temp file + rename) under a
        restrictive umask; the file names recipients and is issuer-private."""
        payload = {
            'version': _SCHEMA_VERSION,
            'size_bits': self.size_bits,
            'entries': {
                entry.jti: _entry_to_dict(entry)
                for entry in self.entries.values()
            },
        }
        directory = os.path.dirname(self.path) or '.'
        umask = os.umask(0o077)
        try:
            os.makedirs(directory, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=directory, suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    json.dump(payload, f, sort_keys=True, indent=1)
                os.replace(tmp_path, self.path)
            except BaseException:
                os.unlink(tmp_path)
                raise
        finally:
            os.umask(umask)

    # ── issuance ─────────────────────────────────────────────────────────────

    def allocate(self, jti: str, recipient: str,
                 issued_on: datetime) -> int:
        """Assign a free random index to a newly issued credential and record
        it. Raises StatusListFull when every index is taken."""
        if jti in self.entries:
            raise ValueError('jti %r already has index %d'
                             % (jti, self.entries[jti].index))
        index = self._free_index()
        self.entries[jti] = StatusEntry(
            jti=jti,
            index=index,
            recipient=normalize_recipient_id(recipient),
            issued_on=_iso_z(issued_on),
        )
        self._used_indices.add(index)
        return index

    def _free_index(self) -> int:
        if len(self._used_indices) >= self.size_bits:
            raise StatusListFull(
                'all %d status list indices are assigned — raise '
                'status_size_bits in the badge config section'
                % self.size_bits)
        for _ in range(_MAX_RANDOM_TRIES):
            index = secrets.randbelow(self.size_bits)
            if index not in self._used_indices:
                return index
        # Nearly full: scan from a random offset so the fallback stays
        # unpredictable while guaranteeing termination.
        start = secrets.randbelow(self.size_bits)
        for offset in range(self.size_bits):
            index = (start + offset) % self.size_bits
            if index not in self._used_indices:
                return index
        raise StatusListFull('all %d status list indices are assigned'
                             % self.size_bits)

    # ── state transitions ────────────────────────────────────────────────────

    def revoke(self, jti: str, when: datetime,
               reason: Optional[str] = None) -> StatusEntry:
        """Permanently revoke a credential. There is no unrevoke: consumers
        may have already acted on the revocation."""
        entry = self._entry(jti)
        if entry.revoked is not None:
            raise AlreadyRevoked('%s was already revoked on %s'
                                 % (jti, entry.revoked.date))
        entry.revoked = StatusEvent(date=_iso_z(when), reason=reason)
        return entry

    def suspend(self, jti: str, when: datetime,
                reason: Optional[str] = None) -> StatusEntry:
        entry = self._entry(jti)
        if entry.revoked is not None:
            raise AlreadyRevoked(
                '%s was revoked on %s — revocation is permanent, suspension '
                'is pointless' % (jti, entry.revoked.date))
        if entry.suspended is not None:
            raise AlreadySuspended('%s was already suspended on %s'
                                   % (jti, entry.suspended.date))
        entry.suspended = StatusEvent(date=_iso_z(when), reason=reason)
        return entry

    def unsuspend(self, jti: str) -> StatusEntry:
        entry = self._entry(jti)
        if entry.suspended is None:
            raise NotSuspended('%s is not suspended' % jti)
        entry.suspended = None
        return entry

    # ── queries ──────────────────────────────────────────────────────────────

    def find(self, query: str) -> List[StatusEntry]:
        """Locate entries by exact jti or by recipient identifier (a bare
        email matches its ``mailto:`` form, case-insensitively)."""
        if query in self.entries:
            return [self.entries[query]]
        wanted = normalize_recipient_id(query)
        return [entry for entry in self.entries.values()
                if recipient_ids_match(entry.recipient, wanted)]

    def revoked_indices(self) -> List[int]:
        return sorted(e.index for e in self.entries.values()
                      if e.revoked is not None)

    def suspended_indices(self) -> List[int]:
        return sorted(e.index for e in self.entries.values()
                      if e.suspended is not None)

    def _entry(self, jti: str) -> StatusEntry:
        try:
            return self.entries[jti]
        except KeyError:
            raise UnknownCredential(
                'no credential %r in %s' % (jti, self.path)) from None


def _entry_to_dict(entry: StatusEntry) -> dict:
    data: dict = {
        'index': entry.index,
        'recipient': entry.recipient,
        'issued_on': entry.issued_on,
    }
    if entry.revoked is not None:
        data['revoked'] = entry.revoked.to_dict()
    if entry.suspended is not None:
        data['suspended'] = entry.suspended.to_dict()
    return data


def _event_from(raw: Optional[dict]) -> Optional[StatusEvent]:
    if raw is None:
        return None
    return StatusEvent(date=raw['date'], reason=raw.get('reason'))


def _iso_z(dt: datetime) -> str:
    """Render *dt* as a UTC ``Z``-suffixed ISO 8601 timestamp.

    Normalises to UTC first (mirroring ob3.credential._iso), so a naive or
    non-UTC datetime still yields the ``...Z`` form the registry and W3C
    status lists expect rather than an offset-less or ``+02:00`` string. A
    naive datetime is assumed to be UTC.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec='seconds').replace(
        '+00:00', 'Z')
