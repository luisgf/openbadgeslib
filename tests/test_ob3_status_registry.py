"""Tests for the issuer-side status index registry — ob3.status_registry."""
import json
import os

from datetime import datetime, timezone

import pytest

from openbadgeslib.errors import (
    AlreadyRevoked,
    AlreadySuspended,
    NotSuspended,
    RegistryCorrupt,
    StatusListFull,
    UnknownCredential,
)
from openbadgeslib.ob3.status_registry import StatusRegistry, _iso_z

NOW = datetime(2026, 7, 2, 10, 0, 0, tzinfo=timezone.utc)
JTI = 'urn:uuid:00000000-0000-0000-0000-0000000000cc'


class TestIsoZ:
    def test_utc_aware(self):
        assert _iso_z(NOW) == '2026-07-02T10:00:00Z'

    def test_naive_assumed_utc(self):
        assert _iso_z(datetime(2026, 7, 2, 10, 0, 0)) == '2026-07-02T10:00:00Z'

    def test_non_utc_offset_normalized(self):
        from datetime import timedelta
        tz2 = timezone(timedelta(hours=2))
        assert _iso_z(datetime(2026, 7, 2, 12, 0, 0, tzinfo=tz2)) == \
            '2026-07-02T10:00:00Z'


def _registry(tmp_path, size_bits=131072):
    return StatusRegistry.load(str(tmp_path / 'badge_1.json'), size_bits)


# ── inter-process locking ────────────────────────────────────────────────────

def _alloc_worker(path, size_bits, jti, recipient, when):
    # Module-level so it is importable under the 'spawn' start method. Each
    # call is a separate process doing the full locked load→allocate→save.
    from openbadgeslib.ob3.status_registry import StatusRegistry
    with StatusRegistry.locked(path, size_bits) as registry:
        registry.allocate(jti, recipient, when)
        registry.save()


class TestLocked:
    def test_yields_loaded_registry_and_creates_lock_file(self, tmp_path):
        path = str(tmp_path / 'badge_1.json')
        with StatusRegistry.locked(path, 131072) as registry:
            assert registry.path == path
            registry.allocate(JTI, 'mailto:a@example.org', NOW)
            registry.save()
        assert os.path.exists(path + '.lock')          # dedicated lock file
        assert JTI in StatusRegistry.load(path, 131072).entries

    def test_concurrent_allocations_are_never_lost(self, tmp_path):
        # Without the lock, N processes each load→allocate→save would clobber
        # one another and only the last save() would survive. With it, every
        # allocation must be present.
        pytest.importorskip('fcntl')                   # POSIX-only guarantee
        import multiprocessing as mp
        path = str(tmp_path / 'badge_1.json')
        bits = 131072
        n = 6
        ctx = mp.get_context('spawn')                  # deterministic on macOS
        procs = [
            ctx.Process(target=_alloc_worker,
                        args=(path, bits, 'urn:jti:%d' % i,
                              'mailto:u%d@example.org' % i, NOW))
            for i in range(n)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
            assert p.exitcode == 0

        registry = StatusRegistry.load(path, bits)
        assert {e.jti for e in registry.entries.values()} == \
            {'urn:jti:%d' % i for i in range(n)}
        assert len({e.index for e in registry.entries.values()}) == n


class TestNoFcntlFallback:
    """Where fcntl is unavailable (Windows, the "OS Independent" classifier's
    other side) the advisory lock degrades to a no-op — load/allocate/save must
    still work. Monkeypatch fcntl=None so the fallback is exercised on POSIX too,
    the path only a windows-latest CI leg would otherwise reach (#230)."""

    def test_exclusive_file_lock_is_a_noop_without_fcntl(self, tmp_path, monkeypatch):
        from openbadgeslib.ob3 import status_registry
        monkeypatch.setattr(status_registry, 'fcntl', None)
        lock_path = str(tmp_path / 'badge_1.json.lock')
        # No flock is called, but the block still runs and the fd is created and
        # closed cleanly (no leak, no raise).
        with status_registry._exclusive_file_lock(lock_path):
            pass
        assert os.path.exists(lock_path)

    def test_locked_registry_roundtrip_without_fcntl(self, tmp_path, monkeypatch):
        from openbadgeslib.ob3 import status_registry
        monkeypatch.setattr(status_registry, 'fcntl', None)
        path = str(tmp_path / 'badge_1.json')
        with status_registry.StatusRegistry.locked(path, 131072) as registry:
            registry.allocate(JTI, 'mailto:a@example.org', NOW)
            registry.save()
        assert os.path.exists(path + '.lock')
        assert JTI in StatusRegistry.load(path, 131072).entries


# ── allocation ───────────────────────────────────────────────────────────────

class TestAllocate:
    def test_allocates_within_bounds_and_records(self, tmp_path):
        reg = _registry(tmp_path)
        index = reg.allocate(JTI, 'r@example.com', NOW)
        assert 0 <= index < reg.size_bits
        entry = reg.entries[JTI]
        assert entry.index == index
        assert entry.recipient == 'mailto:r@example.com'   # normalized
        assert entry.issued_on == '2026-07-02T10:00:00Z'
        assert entry.revoked is None and entry.suspended is None

    def test_duplicate_jti_rejected(self, tmp_path):
        reg = _registry(tmp_path)
        reg.allocate(JTI, 'r@example.com', NOW)
        with pytest.raises(ValueError):
            reg.allocate(JTI, 'r@example.com', NOW)

    def test_collision_retries(self, tmp_path, monkeypatch):
        reg = _registry(tmp_path, size_bits=16)
        first = reg.allocate(JTI + '1', 'a@example.com', NOW)
        # Force the RNG to return the taken index once, then a free one.
        wanted = [first, (first + 1) % 16]
        calls = iter(wanted)
        monkeypatch.setattr('openbadgeslib.ob3.status_registry.secrets.randbelow',
                            lambda n: next(calls))
        second = reg.allocate(JTI + '2', 'b@example.com', NOW)
        assert second == wanted[1]

    def test_exhausted_random_falls_back_to_scan(self, tmp_path, monkeypatch):
        reg = _registry(tmp_path, size_bits=8)
        taken = [reg.allocate('urn:uuid:%d' % i, 'a@example.com', NOW)
                 for i in range(7)]
        free = ({0, 1, 2, 3, 4, 5, 6, 7} - set(taken)).pop()
        # RNG always collides: the linear-scan fallback must find the hole.
        monkeypatch.setattr('openbadgeslib.ob3.status_registry.secrets.randbelow',
                            lambda n: taken[0])
        assert reg.allocate('urn:uuid:last', 'z@example.com', NOW) == free

    def test_full_registry_raises(self, tmp_path):
        reg = _registry(tmp_path, size_bits=8)
        for i in range(8):
            reg.allocate('urn:uuid:%d' % i, 'a@example.com', NOW)
        with pytest.raises(StatusListFull, match='status_size_bits'):
            reg.allocate('urn:uuid:overflow', 'a@example.com', NOW)


# ── persistence ──────────────────────────────────────────────────────────────

class TestPersistence:
    def test_round_trip(self, tmp_path):
        reg = _registry(tmp_path)
        index = reg.allocate(JTI, 'r@example.com', NOW)
        reg.revoke(JTI, NOW, reason='cheating')
        reg.save()

        loaded = _registry(tmp_path)
        entry = loaded.entries[JTI]
        assert entry.index == index
        assert entry.revoked is not None
        assert entry.revoked.reason == 'cheating'
        assert entry.suspended is None
        assert loaded.revoked_indices() == [index]

    def test_missing_file_is_empty(self, tmp_path):
        reg = _registry(tmp_path)
        assert reg.entries == {}

    def test_save_creates_directory_and_no_tmp_left(self, tmp_path):
        path = tmp_path / 'deep' / 'badge_1.json'
        reg = StatusRegistry.load(str(path))
        reg.allocate(JTI, 'r@example.com', NOW)
        reg.save()
        assert path.exists()
        assert [p.name for p in path.parent.iterdir()] == ['badge_1.json']

    def test_save_is_private(self, tmp_path):
        reg = _registry(tmp_path)
        reg.save()
        mode = os.stat(tmp_path / 'badge_1.json').st_mode & 0o777
        assert mode == 0o600

    def test_corrupt_json_raises_and_survives(self, tmp_path):
        path = tmp_path / 'badge_1.json'
        path.write_text('{not json')
        with pytest.raises(RegistryCorrupt):
            StatusRegistry.load(str(path))
        assert path.read_text() == '{not json'   # untouched

    def test_bad_schema_raises(self, tmp_path):
        path = tmp_path / 'badge_1.json'
        path.write_text(json.dumps({'version': 99, 'size_bits': 8, 'entries': {}}))
        with pytest.raises(RegistryCorrupt):
            StatusRegistry.load(str(path))

    def test_duplicate_index_raises(self, tmp_path):
        path = tmp_path / 'badge_1.json'
        entry = {'index': 3, 'recipient': 'mailto:a@example.com',
                 'issued_on': '2026-07-02T10:00:00Z'}
        path.write_text(json.dumps({'version': 1, 'size_bits': 131072,
                                    'entries': {'urn:uuid:1': entry,
                                                'urn:uuid:2': entry}}))
        with pytest.raises(RegistryCorrupt):
            StatusRegistry.load(str(path))

    def test_growing_size_is_allowed(self, tmp_path):
        reg = _registry(tmp_path, size_bits=131072)
        reg.save()
        grown = StatusRegistry.load(str(tmp_path / 'badge_1.json'),
                                    size_bits=262144)
        assert grown.size_bits == 262144

    def test_shrinking_size_is_rejected(self, tmp_path):
        reg = _registry(tmp_path, size_bits=131072)
        reg.save()
        with pytest.raises(RegistryCorrupt, match='shrink'):
            StatusRegistry.load(str(tmp_path / 'badge_1.json'), size_bits=8)


# ── state transitions ────────────────────────────────────────────────────────

class TestTransitions:
    def _issued(self, tmp_path):
        reg = _registry(tmp_path)
        reg.allocate(JTI, 'r@example.com', NOW)
        return reg

    def test_revoke_then_again_fails(self, tmp_path):
        reg = self._issued(tmp_path)
        reg.revoke(JTI, NOW)
        with pytest.raises(AlreadyRevoked, match='2026-07-02'):
            reg.revoke(JTI, NOW)

    def test_no_unrevoke_api_exists(self):
        assert not hasattr(StatusRegistry, 'unrevoke')

    def test_suspend_unsuspend_cycle(self, tmp_path):
        reg = self._issued(tmp_path)
        reg.suspend(JTI, NOW, reason='pending review')
        assert reg.suspended_indices() == [reg.entries[JTI].index]
        with pytest.raises(AlreadySuspended):
            reg.suspend(JTI, NOW)
        reg.unsuspend(JTI)
        assert reg.suspended_indices() == []
        with pytest.raises(NotSuspended):
            reg.unsuspend(JTI)

    def test_suspend_revoked_rejected(self, tmp_path):
        reg = self._issued(tmp_path)
        reg.revoke(JTI, NOW)
        with pytest.raises(AlreadyRevoked, match='permanent'):
            reg.suspend(JTI, NOW)

    def test_unknown_jti(self, tmp_path):
        reg = _registry(tmp_path)
        for action in (lambda: reg.revoke('urn:uuid:nope', NOW),
                       lambda: reg.suspend('urn:uuid:nope', NOW),
                       lambda: reg.unsuspend('urn:uuid:nope')):
            with pytest.raises(UnknownCredential):
                action()


# ── queries ──────────────────────────────────────────────────────────────────

class TestFind:
    def test_find_by_jti_and_by_email(self, tmp_path):
        reg = _registry(tmp_path)
        reg.allocate(JTI, 'R@Example.COM', NOW)
        assert [e.jti for e in reg.find(JTI)] == [JTI]
        assert [e.jti for e in reg.find('r@example.com')] == [JTI]
        assert [e.jti for e in reg.find('mailto:r@example.com')] == [JTI]
        assert reg.find('other@example.com') == []

    def test_find_multiple_issuances(self, tmp_path):
        reg = _registry(tmp_path)
        reg.allocate(JTI + '1', 'r@example.com', NOW)
        reg.allocate(JTI + '2', 'r@example.com', NOW)
        assert len(reg.find('r@example.com')) == 2
