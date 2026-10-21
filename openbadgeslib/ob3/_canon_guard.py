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

# Bounded RDF Dataset Canonicalization (URDNA2015 / RDFC-1.0) for untrusted
# input.
#
# A Data Integrity proof signs the *canonical* form of the RDF dataset a
# JSON-LD document expands to, so the verifier has to canonicalize the document
# BEFORE it can tell whether the signature is any good: the cost is paid on
# input nobody has authenticated yet. RDFC-1.0 is cheap on every real
# credential and factorial on a "poison graph": groups of blank nodes the
# first-degree hash cannot tell apart (identical siblings, a clique, a
# symmetric tree, a ring) are resolved by trying their permutations,
# recursively. A 2.6 KB document that passes context validation (an ``evidence``
# clique of eight labelled blank nodes) keeps a worker busy for 20 to 25 s on
# an unpatched pyld 3.3.0, and one more node means minutes; pyld has no work
# cap (digitalbazaar/pyld#336 adds one to the unreleased, breaking 4.0).
#
# This module bounds that work without touching pyld. canonize() does what
# ``jsonld.normalize`` does (``to_rdf``, then ``URDNA2015.main``) but runs the
# second half with a per-call subclass of pyld's own ``URDNA2015`` that meters
# the one place the cost comes from. Every ``hash_n_degree_quads`` call, the
# recursive ones included, opens with ``create_hash_to_related``; the subclass
# charges the call there and returns each group of equivalent blank nodes
# wrapped in a list that charges one permutation step each time pyld's
# permutation generator rearranges it. Charging is cumulative over the whole
# check (see WorkBudget), which is what catches the shapes made of many small
# groups (a ring has none larger than one node), and exhausting the budget
# raises before the next step runs. A group of all-distinct nodes is refused
# at once when its ``size!`` permutations cannot fit what is left, so the
# obvious shapes are rejected in microseconds, not after the budget has been
# spent.
#
# THE TIME BOUND IS CPU TIME, NOT THE UNIT BUDGET. The unit budget is a model
# of pyld's cost, fitted on one implementation, and it cannot be an
# interpreter-independent bound: CPython 3.11 and 3.12 pay 5 to 10 times more
# per unit for a window of document sizes (a circulant graph of 80 to 160
# nodes, 8 to 15 KB, is the one that was found) that moves with the absolute
# depth of the call stack the canonicalization runs at; 3.10 and 3.13 to 3.15
# do not have it. So the budget also carries a CPU-time allowance for the
# canonicalization proper, read from time.thread_time (this thread's CPU: it
# does not advance while the thread waits for the pyld lock or the GIL, so a
# legitimate request queued behind a hostile one is not charged for the wait,
# and neither is a loaded or paused host, whose legitimate canonicalizations
# cost milliseconds), checked at every Hash N-Degree Quads call and every 64th
# charge, i.e. at least every few hundred microseconds of pyld work. The
# allowance covers only the URDNA2015 phase: the JSON-LD expansion and RDF
# conversion before it are linear in the document, bounded by the document
# size cap and by the duplicate-check allowance below, and a large legitimate
# document must not lose its allowance there.
#
# Why this and not the alternatives:
#
# * a process-global patch of ``pyld.canon`` (the module-level
#   ``permutations``, or ``URDNA2015`` itself) would be visible to every thread
#   and to every other library using pyld, including openvc-core: rejected.
#   Everything metered here is instance state, so concurrent verifications
#   cannot see each other's budget.
# * a static pre-pass over the dataset (largest group of equal first-degree
#   hashes, node count) cannot bound the cost: a ring has no group larger than
#   one and costs ~n^3, and a tree of groups of three costs (3!)^depth.
# * a deadline in a worker thread cannot stop pure-Python code, and a worker
#   process costs ~50 ms per call and fails in frozen / restricted
#   environments. The CPU deadline here is checked from the metering hooks of
#   the very thread that does the work.
# * relying on pyld 4: unreleased and breaking (rdflib), and its cap counts
#   permutations only, not their cost (each copies an issuer as large as the
#   component it is hashing), and counts a repeated element as if it were
#   distinct, where 3.x enumerates it once.
#
# The unit model is empirical (see MAX_CANON_WORK for the measurements). It
# describes pyld 3.3.0's implementation, so the guard fails CLOSED when that
# implementation is not the one it was fitted to: an unsupported pyld major
# version, a missing hook, or a canary canonicalization that does not
# reproduce the known output, does not spend work in the calibrated range or
# does not step through its permutation groups the way pyld 3.3.0 does, all
# raise CanonicalizationGuardUnavailable (surfaced as ``OB3GuardUnavailable``,
# a subclass of ``OB3VerificationError``, by ``ldp._canonize``, so a
# deployment can alert on "the guard is down" apart from "this credential is
# bad"). The message names the pyld it found, what it expected and the
# remedy. It never falls back to an unmetered ``jsonld.normalize``.
#
# The JSON-LD to RDF conversion that precedes canonicalization has a cost of
# its own that no hook can meter: pyld builds each node's property array with
# a linear duplicate check per value, so a node property holding N distinct
# values costs N^2/2 comparisons (8,000 distinct ``tag`` values, 57 KB, spend
# 12 s), N values spread over many occurrences of the same ``@id`` cost the
# same, and so do N node objects that all reverse into one node (``@reverse``:
# 6,000 children spread over 80 parents, about 240 KB, 18 million comparisons
# and 6 to 11 s). node_map_pairs() counts those comparisons on the expanded
# document first, the way pyld makes them, and canonize() refuses a document
# whose count is over the allowance of MAX_NODE_MAP_PAIRS, which is shared by
# the document and the proof options of one signature check and is a SUM over
# every property of every node, because pyld's cost is the sum of those
# quadratics. A value repeated is compared once (pyld stops at the first
# match), so only distinct values count towards the square.
#
# THREADS. pyld's JSON-LD processor keeps two caches for the whole process,
# resolved contexts and inverse contexts, in plain LRU caches that are not
# thread-safe: concurrent expand / compact / to_rdf calls corrupt them, and a
# corrupted cache fails every later call in the process, signing included
# (4.6.2, which shares them, failed 459 of 480 verifications run by 8 threads
# on CPython 3.14 and 182 of 480 on 3.10).
# Putting every pyld call behind one lock cured that, and was this module's
# first answer, but a document that passes every screen spends about a second
# of CPU, 98% of it in pyld's linear JSON-LD phase, so a request holding the
# lock for that second held every other thread up with it: with one such
# request in flight (42 KB, 1,200 typed nodes) a legitimate verification that
# takes 5 ms alone waited 1.1 s (p50, CPython 3.14), 4.4 s behind four and 17 s
# behind sixteen. So the caches are kept apart instead of the calls serialized:
#
# * resolved contexts: every call is handed a ContextResolver (the
#   ``contextResolver`` option pyld documents as internal use) over a cache
#   that belongs to the calling thread. Bounded like pyld's own (100 entries;
#   about 1 to 2 MiB once a credential has gone through, per thread: N worker
#   threads hold N times that, where pyld's cache held it once) and dropped by
#   any call that raises, an interrupted one included, so a half-updated cache
#   is never reused. A thread's first call, or the first after a refusal,
#   builds it again: 6.2 ms instead of 4.4 for a small credential. The output
#   is the same: these caches only remember work. The low-level functions
#   admit inline @context objects, which pyld keys by their text, so a
#   document can fill a thread's 100 entries with contexts of its own (each as
#   large as the document: 256 KiB); the verifier refuses inline contexts
#   before pyld sees them.
# * inverse contexts (compaction only): derived per compaction and remembered
#   by it. pyld stores each one in its process-wide cache as well, with no
#   option to say otherwise, so deriving one takes PYLD_LOCK, for about 50
#   microseconds (8 times per legitimate verification, 1,300 times per hostile
#   typed-flood request, which holds the lock 8% of its second). This is the
#   one lock left on the path and it is what remains of the convoy. A thread
#   that finds it taken blocks, and a blocked thread has to win the GIL back
#   from the CPU-bound ones, which costs it up to 60 ms each time. Measured
#   (CPython 3.14, one legitimate verification every 20 ms, hostile requests of
#   the kind above in a loop, best of three runs): p50 / p99 of the legitimate
#   one with 1, 4 and 16 hostile requests in flight is 13 / 21, 29 / 517 and
#   43 / 442 ms (1.0 s at the worst), against 13 / 23, 35 / 95 and 92 / 721 ms
#   with the lock taken out (not safe: the cache then corrupts) and 4.4 s and
#   17 s at the median behind the old lock. 3.10 and 3.12 measure the same
#   within noise. Only a copy of pyld's inverse-context code that does not
#   write its cache would remove it, and a copy would put the compacted form
#   context validation compares against in this library's hands.
#
# Nothing else the path does touches pyld's caches (INITIAL_CONTEXTS, written
# once per processing mode with an immutable value, apart), and the
# document loader hands out the same pinned documents to every thread.
#
# ASYNCHRONOUS EXCEPTIONS. A signal handler that raises (a timeout, Celery's
# soft limit, KeyboardInterrupt) can land between two statements of pyld's
# cache code and leave an LRU with a stale key at its head, after which every
# call that must evict fails with a KeyError for as long as the process lives
# (reproduced on CPython 3.10, and in pyld alone on 3.14 and 3.15). A thread's
# cache is dropped by any exception, and the shared inverse-context cache,
# which this module touches only under PYLD_LOCK, is emptied in place if the
# exception comes out of its derivation. What this does not cover: a handler
# that verifies a credential itself, on the thread it interrupted (the nested
# call sees the interrupted one's cache as it was left; unsupported, as
# before), and CPython 3.14.8, where ANY ``with lock:`` can leak the lock when
# the exception arrives between taking it and entering the block (a Lock, an
# RLock and acquire/try/finally leak alike; 3.10 to 3.13 and 3.15 do not). That
# is an interpreter defect. PYLD_LOCK is held for tens of microseconds per
# derivation instead of for a whole verification, so the window is far smaller
# than it was; a leaked one blocks the next derivation of every other thread.
#
# FORK. A child inherits whatever state a thread of the parent left the shared
# inverse-context cache in, so fork() waits for PYLD_LOCK (as the standard
# logging module does for its own) and releases it on both sides. A thread's
# private cache is not inherited by anyone but the thread that forks.
#
# What PYLD_LOCK does not cover: other libraries that call pyld in the same
# process share pyld's own caches. The one call this library makes that way is
# the ecdsa-sd-2023 suite delegated to openvc-core, which calls pyld on its own
# and without a work bound. Its calls are as safe as the lock held around them:
# PYLD_LOCK is exported for ldp to hold around the delegate, and a call made
# without it (that one, or any other user of pyld in the process) can tear the
# shared inverse-context cache. That no longer outlives the next derivation
# here: it finds the stale key, fails once and empties the cache (before, every
# later call failed until the process restarted). The delegated path is also
# screened here, before the delegate runs (poison-graph work and the statement
# count, ldp._prescreen_canonicalization); the statements the lifecycle check
# indexes after the signature are canonicalized under the guard.
import functools
import math
import os
import threading
import time

from typing import Any, Callable, Dict, List, Optional, Tuple

#: Serializes whatever still uses pyld's own process-wide caches (resolved
#: contexts, inverse contexts: plain LRU caches, not thread-safe) across the
#: threads of one process: the derivation of an inverse context in a
#: compaction here (tens of microseconds), the build of the guard (once) and a
#: fork, and, where this library takes it around them, calls into pyld made by
#: another library (the openvc-core delegate of ecdsa-sd-2023). Nothing else
#: on the Data Integrity path takes it: see THREADS in the module comment.
#: Reentrant, because a caller already holding it may call canonize().
PYLD_LOCK = threading.RLock()

#: Work one signature check may spend canonicalizing (the proof options and
#: the document share it), in model units. About 100 times the most a real
#: credential spends (the repo's modelled copy of 1EdTech's "Complete
#: OpenBadgeCredential" spends 1,124; the review of this guard measured 1,828
#: for the real example and at most ~2,400 over 53 real documents), and 1.5
#: times the largest legitimate shape known: an identifier-only subject with
#: 1,400 first-degree-identical blank Results, which is where the node-map
#: allowance below stops it anyway (161,000 units; 700 spend 80,500).
#:
#: Measured, CPython 3.10 to 3.15rc3 on an Apple-silicon laptop: a unit costs
#: 0.15 to 0.4 microseconds on the poison graphs (cliques, trees, rings,
#: grids, bipartite graphs, ladders, twins, random digraphs, circulants), so a
#: document that exhausts the budget is refused after 0.05 to 0.22 s of CPU
#: in all, expansion included (0.16 to 0.22 s at most, per interpreter);
#: inside the CPython 3.11/3.12 window of the module comment a unit costs up
#: to 3.4 microseconds and the same refusal took up to 0.9 s in our sweeps,
#: which is what MAX_CANON_SECONDS bounds (1.1 s in all, whatever the model
#: says).
MAX_CANON_WORK = 250_000

#: CPU seconds one signature check may spend inside URDNA2015 (the proof
#: options and the document share it): the bound that holds on every
#: interpreter whatever the unit model says. A legitimate canonicalization
#: takes milliseconds (a real credential: 1 ms; the 161,000 units above:
#: 0.05 s on 3.14, 0.075 s on 3.10). With the unit budget out of the way, a
#: poison graph that is the whole document (148 blank nodes, 19 KB) is refused
#: after 1.04 to 1.11 s of CPU in all on CPython 3.10 to 3.15.
#:
#: That is the allowance, not what a verification costs: it comes on top of
#: whatever pyld spent before URDNA2015 started, which this clock does not
#: meter (expansion, RDF conversion and context validation: 1.0 to 1.4 s for
#: the most the structure screen and MAX_NODE_MAP_PAIRS admit). A document
#: that carries a flood of typed nodes AND a poison graph pays both, measured
#: through ``OB3LdpVerifier.verify`` (1,260 typed nodes and a 148-node
#: circulant, 102 KB, unit budget out of the way): 2.1 to 2.3 s of CPU on
#: CPython 3.11 to 3.15 and 2.4 to 2.5 s on 3.10. With the unit budget in
#: force the graph is refused after 0.1 to 0.25 s and the same document costs
#: 1.2 to 1.6 s, except in the 3.11/3.12 window of the module comment, where a
#: review reached the deadline with it in force and measured up to 2.24 s.
MAX_CANON_SECONDS = 1.0

#: Cap on the duplicate-check comparisons pyld's JSON-LD to RDF conversion
#: makes building the node map (see :func:`node_map_pairs`), summed over every
#: node property of the document AND the proof options of one signature check.
#: pyld spends 0.35 to 0.5 microseconds per comparison (CPython 3.10 to 3.15),
#: so a document at the cap (one property of 1,414 distinct values, or two of
#: about 1,000) takes 0.35 to 0.5 s of CPU to convert, and a refusal costs the
#: expansion only.
MAX_NODE_MAP_PAIRS = 1_000_000

# Cost model, in units. A hash_n_degree_quads call: fixed overhead plus a unit
# per quad of the node it hashes. A permutation: fixed overhead, plus one unit
# per element of the group (the permutation generator reorders it) and one per
# identifier the issuer can hold (the issuer is copied for every permutation;
# it holds at most the blank nodes the algorithm can still reach from the
# start node: its component among blank nodes that have no canonical
# identifier yet).
_CALL_UNITS = 9
_QUAD_UNITS = 14
_PERM_UNITS = 6

#: An all-distinct group this large has size! permutations: more than any
#: budget (13! = 6.2 billion) without computing the factorial.
_MAX_GROUP = 12

#: The only pyld major version the cost model describes. pyproject.toml's
#: ``pyld>=3.3.0,<4`` (both extras) must say the same; pip does not enforce a
#: dependency range after install, this check does at run time.
_SUPPORTED_PYLD_MAJOR = 3

#: The deadline is read every this many charges (a clock read is a system
#: call on some platforms).
_TICK_MASK = 63


def _cpu_seconds() -> float:
    """CPU time of the calling thread (process CPU where the platform has no
    per-thread clock)."""
    return _CLOCK()


def _pick_clock() -> Callable[[], float]:
    clock = getattr(time, 'thread_time', None)
    if clock is not None:
        try:
            clock()
            return clock                            # type: ignore[no-any-return]
        except (OSError, NotImplementedError):      # pragma: no cover
            pass
    return time.process_time                        # pragma: no cover


_CLOCK = _pick_clock()


class CanonicalizationWorkExceeded(Exception):
    """The canonicalization needs more work than the budget allows."""


class CanonicalizationGuardUnavailable(Exception):
    """The installed pyld is not one the guard can meter: fail closed."""


class WorkBudget:
    """Allowance of one signature check, shared by every canonicalization it
    performs (and used by one thread, whose CPU clock it reads).

    * ``limit``: model units (:data:`MAX_CANON_WORK`);
    * ``seconds``: CPU seconds spent inside URDNA2015
      (:data:`MAX_CANON_SECONDS`), accumulated over the canonicalizations
      that share the budget;
    * ``pairs``: JSON-LD to RDF duplicate checks
      (:data:`MAX_NODE_MAP_PAIRS`), shared in the same way.

    ``None`` means the module constant, read at construction."""

    __slots__ = ('limit', 'spent', 'swaps', 'seconds', 'pairs_left',
                 '_cpu_used', '_cpu_mark', '_ticks')

    def __init__(self, limit: Optional[int] = None,
                 seconds: Optional[float] = None,
                 pairs: Optional[int] = None) -> None:
        self.limit = MAX_CANON_WORK if limit is None else limit
        self.spent = 0
        #: permutation steps charged (the canary proves the meter is wired)
        self.swaps = 0
        self.seconds = MAX_CANON_SECONDS if seconds is None else seconds
        self.pairs_left = MAX_NODE_MAP_PAIRS if pairs is None else pairs
        self._cpu_used = 0.0
        self._cpu_mark: Optional[float] = None
        self._ticks = 0

    def charge(self, units: int) -> None:
        self.spent += units
        if self.spent > self.limit:
            raise CanonicalizationWorkExceeded(
                "RDF canonicalization needs more than %d work units (the "
                "document contains blank nodes the algorithm cannot tell "
                "apart cheaply)" % self.limit)
        self._ticks += 1
        if not self._ticks & _TICK_MASK:
            self.check_time()

    def begin(self) -> None:
        """Start the CPU clock of a URDNA2015 run."""
        self._cpu_mark = _cpu_seconds()

    def end(self) -> None:
        """Stop it, keeping the time spent against the allowance."""
        if self._cpu_mark is not None:
            self._cpu_used += max(0.0, _cpu_seconds() - self._cpu_mark)
            self._cpu_mark = None

    def check_time(self) -> None:
        used = self._cpu_used
        if self._cpu_mark is not None:
            used += max(0.0, _cpu_seconds() - self._cpu_mark)
        if used > self.seconds:
            raise CanonicalizationWorkExceeded(
                "RDF canonicalization exceeded its CPU time limit (%.2f s)"
                % self.seconds)

    def take_pairs(self, pairs: int, detail: str = '') -> None:
        """Charge the duplicate checks of one JSON-LD to RDF conversion."""
        if pairs > self.pairs_left:
            raise CanonicalizationWorkExceeded(
                "the document puts too many values on its node properties "
                "for RDF conversion (%d duplicate checks, %d allowed%s)"
                % (pairs, self.pairs_left, detail))
        self.pairs_left -= pairs


class _MeteredGroup(List[str]):
    """A group of equivalent blank nodes whose permutation is metered.

    pyld's generator steps through the permutations by swapping two elements
    in place (``elements[i], elements[j] = elements[j], elements[i]``): two
    item assignments per step, so each one pays half a permutation."""

    __slots__ = ('_budget', '_half')

    def __init__(self, items: List[str], budget: WorkBudget,
                 permutation_units: int) -> None:
        super().__init__(items)
        self._budget = budget
        self._half = permutation_units // 2 + 1

    def __setitem__(self, index: Any, value: Any) -> None:
        self._budget.swaps += 1
        self._budget.charge(self._half)
        super().__setitem__(index, value)


# ── pyld's process-wide caches, kept out of reach ─────────────────────────────
# See the module comment. pyld gives every JSON-LD call the same two plain LRU
# caches. Here each thread keeps its own resolved contexts, each compaction its
# own inverse contexts, and only the derivation of an inverse context, which
# pyld insists on storing in its own cache, takes PYLD_LOCK.

#: Resolved contexts a thread keeps (the size of pyld's own shared cache): the
#: pinned documents and the scoped contexts they define inline, about thirty
#: for a complete credential.
_MAX_RESOLVED_CONTEXTS = 100

#: Inverse contexts one compaction remembers (pyld's own cache holds 20).
_MAX_INVERSE_CONTEXTS = 20


class _Cache(Dict[str, Any]):
    """A bounded map (the oldest entry makes room) in the shape pyld expects
    of a context cache: ``get`` and item assignment. Used by one thread at a
    time, so it takes no lock."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self._limit = limit

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self and len(self) >= self._limit:
            del self[next(iter(self))]
        super().__setitem__(key, value)


_LOCAL = threading.local()


def _thread_contexts() -> _Cache:
    """The calling thread's resolved contexts."""
    cache: Optional[_Cache] = getattr(_LOCAL, 'contexts', None)
    if cache is None:
        cache = _LOCAL.contexts = _Cache(_MAX_RESOLVED_CONTEXTS)
    return cache


def _discard_thread_contexts() -> None:
    _LOCAL.contexts = None


def _reset(cache: Any) -> None:
    """Empty a cachetools cache in place, whatever state an exception left it
    in: its constructor is its reset (``clear`` stops at the first stale key)."""
    try:
        type(cache).__init__(cache, cache.maxsize)
    except Exception:                               # pragma: no cover
        pass


@functools.lru_cache(maxsize=None)
def _processor_class(jsonld: Any) -> Any:
    """pyld's ``JsonLdProcessor`` with the inverse contexts of one compaction
    kept by that compaction. A miss takes :data:`PYLD_LOCK` for as long as
    pyld takes to derive one inverse context (tens of microseconds on a
    pinned context) because pyld stores the result in a cache of its own,
    shared by the whole process; if the derivation is interrupted, that cache
    is emptied rather than left half updated."""
    base: Any = jsonld.JsonLdProcessor
    if not callable(getattr(base, '_get_inverse_context', None)):
        raise CanonicalizationGuardUnavailable(
            "pyld's JsonLdProcessor has no _get_inverse_context(): the "
            "guard cannot keep the caches of a compaction apart")

    class PrivateProcessor(base):                   # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            self._inverse = _Cache(_MAX_INVERSE_CONTEXTS)

        def _get_inverse_context(self, active_ctx: Any) -> Any:
            key = active_ctx['_uuid']
            inverse = self._inverse.get(key)
            if inverse is None:
                with PYLD_LOCK:
                    try:
                        inverse = super()._get_inverse_context(active_ctx)
                    except BaseException:
                        shared = getattr(jsonld, '_inverse_context_cache', None)
                        if shared is not None:
                            _reset(shared)
                        raise
                self._inverse[key] = inverse
            return inverse

    return PrivateProcessor


class _Isolated:
    """``expand`` / ``compact`` / ``to_rdf`` of the pyld ``jsonld`` module, each
    run on this thread's own resolved-context cache (*contexts*, for a probe)
    instead of pyld's process-wide one. The output is the same: the caches
    only remember work. A call that raises discards the thread's cache, so
    whatever an exception (an asynchronous one included) interrupted is
    rebuilt, never reused."""

    __slots__ = ('_jsonld', '_contexts')

    def __init__(self, jsonld: Any, contexts: Optional[_Cache] = None) -> None:
        self._jsonld = jsonld
        self._contexts = contexts

    def _options(self, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        options = dict(options or {})
        loader = options.get('documentLoader')
        if loader is None:
            loader = options['documentLoader'] = \
                self._jsonld.get_document_loader()
        contexts = (_thread_contexts() if self._contexts is None
                    else self._contexts)
        options['contextResolver'] = self._jsonld.ContextResolver(
            contexts, loader)
        return options

    def _call(self, function: Callable[[Dict[str, Any]], Any],
              options: Optional[Dict[str, Any]]) -> Any:
        try:
            return function(self._options(options))
        except BaseException:
            if self._contexts is None:
                _discard_thread_contexts()
            raise

    def expand(self, document: Any,
               options: Optional[Dict[str, Any]] = None) -> Any:
        return self._call(lambda o: self._jsonld.expand(document, o), options)

    def to_rdf(self, document: Any,
               options: Optional[Dict[str, Any]] = None) -> Any:
        return self._call(lambda o: self._jsonld.to_rdf(document, o), options)

    def compact(self, document: Any, context: Any,
                options: Optional[Dict[str, Any]] = None) -> Any:
        return self._call(
            lambda o: _processor_class(self._jsonld)().compact(
                document, context, o), options)


def isolate(jsonld: Any) -> Any:
    """*jsonld* (the pyld module) as :class:`_Isolated`; one already isolated
    is returned as it is."""
    return jsonld if isinstance(jsonld, _Isolated) else _Isolated(jsonld)


# ── the canary ───────────────────────────────────────────────────────────────
# Two tiny documents canonicalized, on first use, with the metered class. Their
# output is what stock pyld 3.3.0 produces; their metering is what this cost
# model expects of it.
#
# * identical parents with groups of FOUR distinct blank nodes: the in-place
#   permutation generator (a group of four takes 23 steps, so a pyld that
#   stopped swapping in place for groups of three or more, as pyld 4's
#   itertools.permutations, would charge none of them);
# * two blank graphs, each holding a node whose four statements all name that
#   graph: a group of four entries that are ONE node, which pyld 3.3.0
#   enumerates once, not 4! times (an embedded proof does this).

_CANARY_VOCAB = {'@vocab': 'https://example.org/c#'}

_CANARY_DISTINCT: Dict[str, Any] = {
    '@context': _CANARY_VOCAB,
    '@id': 'https://example.org/c/root',
    'p': [{'q': [{'s': 'x'} for _ in range(4)]} for _ in range(2)],
}

_CANARY_REPEATED: Dict[str, Any] = {
    '@context': _CANARY_VOCAB,
    '@graph': [{'@id': '_:g%d' % i,
                '@graph': [{'@id': '_:a%d' % i, 'q': ['1', '2', '3', '4']}]}
               for i in range(2)],
}

_CANARY_NQUADS_DISTINCT = (
    '<https://example.org/c/root> <https://example.org/c#p> _:c14n0 .\n'
    '<https://example.org/c/root> <https://example.org/c#p> _:c14n5 .\n'
    '_:c14n0 <https://example.org/c#q> _:c14n1 .\n'
    '_:c14n0 <https://example.org/c#q> _:c14n2 .\n'
    '_:c14n0 <https://example.org/c#q> _:c14n3 .\n'
    '_:c14n0 <https://example.org/c#q> _:c14n4 .\n'
    '_:c14n1 <https://example.org/c#s> "x" .\n'
    '_:c14n2 <https://example.org/c#s> "x" .\n'
    '_:c14n3 <https://example.org/c#s> "x" .\n'
    '_:c14n4 <https://example.org/c#s> "x" .\n'
    '_:c14n5 <https://example.org/c#q> _:c14n6 .\n'
    '_:c14n5 <https://example.org/c#q> _:c14n7 .\n'
    '_:c14n5 <https://example.org/c#q> _:c14n8 .\n'
    '_:c14n5 <https://example.org/c#q> _:c14n9 .\n'
    '_:c14n6 <https://example.org/c#s> "x" .\n'
    '_:c14n7 <https://example.org/c#s> "x" .\n'
    '_:c14n8 <https://example.org/c#s> "x" .\n'
    '_:c14n9 <https://example.org/c#s> "x" .\n')

_CANARY_NQUADS_REPEATED = (
    '_:c14n1 <https://example.org/c#q> "1" _:c14n0 .\n'
    '_:c14n1 <https://example.org/c#q> "2" _:c14n0 .\n'
    '_:c14n1 <https://example.org/c#q> "3" _:c14n0 .\n'
    '_:c14n1 <https://example.org/c#q> "4" _:c14n0 .\n'
    '_:c14n3 <https://example.org/c#q> "1" _:c14n2 .\n'
    '_:c14n3 <https://example.org/c#q> "2" _:c14n2 .\n'
    '_:c14n3 <https://example.org/c#q> "3" _:c14n2 .\n'
    '_:c14n3 <https://example.org/c#q> "4" _:c14n2 .\n')

#: (document, canonical N-Quads, permutation steps, (min, max) units). Measured
#: on pyld 3.3.0: 10,332 units and 92 steps (two groups of four: 23 steps of
#: two item assignments each), 308 units and no step. The step counts are
#: exact for pyld's Steinhaus-Johnson-Trotter generator and are a hard
#: requirement: they are what proves the per-step meter is wired. The unit
#: range (0.5x to 4x) tolerates a pyld that does more or less work elsewhere
#: (more work only makes the guard refuse sooner).
_CANARIES: Tuple[Tuple[Dict[str, Any], str, int, Tuple[int, int]], ...] = (
    (_CANARY_DISTINCT, _CANARY_NQUADS_DISTINCT, 92, (5_166, 41_328)),
    (_CANARY_REPEATED, _CANARY_NQUADS_REPEATED, 0, (154, 1_232)),
)


def _remedy(pyld_version: str) -> str:
    return ("openbadgeslib's RDF canonicalization guard is fitted to pyld "
            "3.3.0 (found %s): pin pyld==3.3.0, or upgrade openbadgeslib to "
            "a release that supports this pyld" % pyld_version)


# ── the metered class, built once per process ────────────────────────────────

def _build_bounded_class() -> Any:
    """Build the metered URDNA2015 subclass, after proving the installed pyld
    is the implementation the cost model describes."""
    try:
        from pyld import jsonld
        from pyld.__about__ import __version__ as pyld_version
        from pyld.canon import URDNA2015
    except ImportError as exc:
        raise CanonicalizationGuardUnavailable(
            "pyld's canonicalizer is not importable: %s" % exc) from exc
    pyld_version = str(pyld_version)
    if pyld_version.split('.')[0] != str(_SUPPORTED_PYLD_MAJOR):
        raise CanonicalizationGuardUnavailable(
            "pyld %s is not supported by the canonicalization guard "
            "(it meters pyld %d.x; install pyld>=3.3.0,<%d)"
            % (pyld_version, _SUPPORTED_PYLD_MAJOR, _SUPPORTED_PYLD_MAJOR + 1))
    for name in ('main', 'create_hash_to_related', 'hash_n_degree_quads'):
        if not callable(getattr(URDNA2015, name, None)):
            raise CanonicalizationGuardUnavailable(
                "pyld.canon.URDNA2015 has no %s(): the canonicalization "
                "guard cannot meter this pyld. %s"
                % (name, _remedy(pyld_version)))

    class BoundedURDNA2015(URDNA2015):          # type: ignore[misc]
        """URDNA2015 that charges a :class:`WorkBudget` for the work each
        Hash N-Degree Quads call does."""

        def __init__(self, budget: WorkBudget) -> None:
            super().__init__()
            self._budget = budget
            self._component: Dict[str, int] = {}

        def _component_size(self, id_: str) -> int:
            """Blank nodes the algorithm can still reach from *id_*: its
            component among the blank nodes that have no canonical
            identifier. An identifier issuer holds only such nodes (a node
            with a canonical identifier is written into a path as that
            identifier and never recursed into), so this bounds what each
            permutation step copies. Computed once per component, when it is
            first needed; canonical identifiers are only ever added, so a
            later component can only be smaller than the cached one."""
            size = self._component.get(id_)
            if size is None:
                canonical = self.canonical_issuer.existing
                seen = {id_}
                todo = [id_]
                while todo:
                    for quad in self.blank_node_info[todo.pop()]['quads']:
                        for key, term in quad.items():
                            if key != 'predicate' and (
                                    term['type'] == 'blank node'):
                                value = term['value']
                                if value not in seen and value not in canonical:
                                    seen.add(value)
                                    todo.append(value)
                size = len(seen)
                for member in seen:
                    self._component[member] = size
            return size

        def create_hash_to_related(self, id_: str, issuer: Any) -> Any:
            budget = self._budget
            budget.check_time()
            budget.charge(_CALL_UNITS + _QUAD_UNITS
                          * len(self.blank_node_info[id_]['quads']))
            related = super().create_hash_to_related(id_, issuer)
            issued = self._component_size(id_)
            metered = {}
            for key, group in related.items():
                size = len(group)
                step = _PERM_UNITS + size + issued
                budget.charge(step)                     # the first permutation
                if (size > 1 and len(set(group)) == size and (
                        size > _MAX_GROUP or math.factorial(size) * step
                        > budget.limit - budget.spent)):
                    # size! permutations, none of them avoidable, cannot fit.
                    budget.charge(budget.limit)
                metered[key] = _MeteredGroup(group, budget, step)
            return metered

    _selftest(jsonld, BoundedURDNA2015, pyld_version)
    return BoundedURDNA2015


class _Once:
    """The metered class, built (and proven) once per process.

    Race-free: the first callers queue on :data:`PYLD_LOCK` and only one of
    them runs the canary. A failed build is not remembered, so a transient
    error (memory, recursion depth) is retried by the next call."""

    def __init__(self) -> None:
        self._value: Any = None

    def __call__(self) -> Any:
        value = self._value
        if value is None:
            with PYLD_LOCK:
                value = self._value
                if value is None:
                    value = self._value = _build_bounded_class()
        return value

    def cache_clear(self) -> None:
        with PYLD_LOCK:
            self._value = None


_bounded_class = _Once()


def require_guard() -> None:
    """Build and prove the guard if that has not been done: raises
    :class:`CanonicalizationGuardUnavailable` when the installed pyld is not
    one it can meter or keep apart (see the module comment)."""
    _bounded_class()


def _selftest(jsonld: Any, bounded: Any, pyld_version: str) -> None:
    """Prove, on documents with permutation groups, that the guard (a)
    reproduces stock pyld's output, (b) meters the work this cost model
    expects of pyld 3.3.0, step by step, and (c) is enforced."""
    try:
        for index, (document, nquads, swaps, units) in enumerate(_CANARIES):
            # A generous budget: the canary measures, it is not itself limited.
            budget = WorkBudget(limit=10 ** 8, seconds=60.0)
            out = _run(jsonld, bounded, document, None, budget)
            where = "canary %d of %d" % (index + 1, len(_CANARIES))
            if out != nquads:
                raise CanonicalizationGuardUnavailable(
                    "%s: pyld %s no longer canonicalizes the canary document "
                    "to the known output. %s"
                    % (where, pyld_version, _remedy(pyld_version)))
            if budget.swaps != swaps:
                raise CanonicalizationGuardUnavailable(
                    "%s: pyld %s steps through %d permutations where the "
                    "guard expects %d: its permutation generator no longer "
                    "reorders the groups it is given in place, so the "
                    "per-step meter would see nothing. %s"
                    % (where, pyld_version, budget.swaps, swaps,
                       _remedy(pyld_version)))
            if not units[0] <= budget.spent <= units[1]:
                raise CanonicalizationGuardUnavailable(
                    "%s: pyld %s costs %d work units where the guard was "
                    "calibrated on %d to %d. %s"
                    % (where, pyld_version, budget.spent, units[0], units[1],
                       _remedy(pyld_version)))
            try:
                _run(jsonld, bounded, document, None,
                     WorkBudget(limit=budget.spent // 2, seconds=60.0))
            except CanonicalizationWorkExceeded:
                continue
            raise CanonicalizationGuardUnavailable(
                "the canonicalization budget is not enforced")
        _probe_isolation(jsonld, pyld_version)
    except CanonicalizationGuardUnavailable:
        raise
    except (MemoryError, RecursionError):
        raise                           # transient: not a verdict on pyld
    except Exception as exc:
        raise CanonicalizationGuardUnavailable(
            "the canonicalization self-test failed on pyld %s: %r. %s"
            % (pyld_version, exc, _remedy(pyld_version))) from exc


def _probe_isolation(jsonld: Any, pyld_version: str) -> None:
    """Prove that pyld answers from the caches handed to it, not from its
    process-wide ones: a pinned context lands in the private cache, and a
    compaction reaches the inverse-context hook."""
    from .contexts import document_loader
    context = 'https://www.w3.org/ns/credentials/v2'
    document = {'@context': context, 'id': 'urn:example:probe',
                'type': 'VerifiableCredential'}
    contexts = _Cache(_MAX_RESOLVED_CONTEXTS)
    isolated = _Isolated(jsonld, contexts)
    options = {'documentLoader': document_loader()}
    expanded = isolated.expand(document, options)
    if context not in contexts:
        raise CanonicalizationGuardUnavailable(
            "pyld %s resolved a context without using the cache the guard "
            "handed it, so its process-wide cache cannot be kept out of reach. "
            "%s" % (pyld_version, _remedy(pyld_version)))
    processor = _processor_class(jsonld)()
    processor.compact(expanded, context, isolated._options(options))
    if not processor._inverse:
        raise CanonicalizationGuardUnavailable(
            "pyld %s compacted without asking for an inverse context, so its "
            "process-wide cache cannot be kept out of reach. %s"
            % (pyld_version, _remedy(pyld_version)))


def _to_dataset(jsonld: Any, document: Any, loader: Any) -> Any:
    options: Dict[str, Any] = {'produceGeneralizedRdf': False}
    if loader is not None:
        options['documentLoader'] = loader
    # What jsonld.normalize does for URDNA2015: to_rdf without a format, then
    # the algorithm on the resulting dataset.
    return isolate(jsonld).to_rdf(document, options)


def _canonicalize(bounded: Any, dataset: Any, budget: WorkBudget) -> str:
    """URDNA2015 on *dataset*: pure Python on plain dicts, touching no pyld
    cache."""
    budget.begin()
    try:
        return str(bounded(budget).main(
            dataset, {'format': 'application/n-quads'}))
    finally:
        budget.end()


def _run(jsonld: Any, bounded: Any, document: Any, loader: Any,
         budget: WorkBudget) -> str:
    return _canonicalize(bounded, _to_dataset(jsonld, document, loader),
                         budget)


# ── the duplicate checks of the JSON-LD to RDF conversion ────────────────────

def _node_key(node: Dict[str, Any]) -> Tuple[str, Any]:
    """Identity of a node object in pyld's node map: its ``@id`` (a blank node
    label included), else a node of its own."""
    ident = node.get('@id')
    return ('i', ident) if isinstance(ident, str) else ('u', id(node))


def _value_key(item: Any) -> Any:
    """What ``compare_values`` compares in pyld: two values with an equal key
    are one entry of a node property. Finer than pyld's equality is safe (the
    count only grows), coarser is not."""
    if not isinstance(item, dict):
        return ('p', item) if isinstance(item, (str, int, float)) else (
            'u', id(item))
    if '@value' in item:
        try:
            key = ('v', item['@value'], item.get('@type'),
                   item.get('@language'), item.get('@index'))
            hash(key)
            return key
        except TypeError:                           # an @json object or array
            pass
        try:
            return ('j', _dumps(item), None)
        except Exception:
            return ('u', id(item))
    if '@list' in item:
        return ('u', id(item))                      # appended, never compared
    return _node_key(item)                          # a reference: its @id


def _dumps(value: Any) -> str:
    import json
    return json.dumps(value, sort_keys=True)


def _tally(cells: Dict[Any, List[Any]], cell: Any, keys: List[Any]) -> None:
    slot = cells.get(cell)
    if slot is None:
        slot = cells[cell] = [0, set()]
    slot[0] += len(keys)
    slot[1].update(keys)


def _scan_node_map(expanded: Any) -> Tuple[int, int, str]:
    """(pairs, the largest property's value count, its name) for an
    *expanded* JSON-LD document; see :func:`node_map_pairs`."""
    cells: Dict[Any, List[Any]] = {}
    todo = [expanded]
    while todo:
        item = todo.pop()
        if isinstance(item, list):
            todo.extend(item)
        elif not isinstance(item, dict) or '@value' in item:
            continue
        elif '@list' in item:
            todo.extend(item['@list'])              # a list keeps duplicates
        else:
            node = _node_key(item)
            for key, value in item.items():
                if key == '@id':
                    continue
                if key == '@reverse':
                    # Each reverse entry adds a reference to THIS node to the
                    # property of the node that reverses into it.
                    if isinstance(value, dict):
                        for prop, targets in value.items():
                            if not isinstance(targets, list):
                                continue
                            for target in targets:
                                if isinstance(target, dict) and (
                                        '@value' not in target
                                        and '@list' not in target):
                                    _tally(cells, (_node_key(target), prop),
                                           [node])
                            todo.extend(targets)
                    continue
                if isinstance(value, list):
                    if key not in ('@graph', '@included'):
                        _tally(cells, (node, key),
                               [_value_key(v) for v in value])
                    todo.extend(value)
                else:
                    todo.append(value)
    pairs = 0
    widest = (0, '')
    for (node, key), (total, distinct) in cells.items():
        d = len(distinct)
        # The d-th distinct value is compared with the d-1 before it, a value
        # already there with at most d (pyld stops at the first match): an
        # upper bound whatever order pyld meets the values in.
        pairs += d * (d - 1) // 2 + (total - d) * d
        if total > widest[0]:
            widest = (total, '%s of %s' % (str(key)[:60], str(node[1])[:60]))
    return pairs, widest[0], widest[1]


def node_map_pairs(expanded: Any) -> int:
    """Duplicate-check comparisons pyld makes building the node map of an
    *expanded* JSON-LD document. For every node (nodes sharing an ``@id`` are
    one) and property, with ``n`` occurrences of ``d`` distinct values:
    ``d(d-1)/2 + (n-d)d``, i.e. n(n-1)/2 for distinct values and only n-1 for
    one value repeated. Counted the way pyld does it: a ``@reverse`` entry
    adds a reference to the *reversed-into* node's property, ``@graph`` and
    ``@included`` entries are not compared at all, and a ``@list`` keeps its
    duplicates (8,000 entries convert in 26 ms)."""
    return _scan_node_map(expanded)[0]


def canonize(jsonld: Any, document: Any, loader: Any,
             budget: Optional[WorkBudget] = None) -> str:
    """RDFC-1.0-canonicalize *document* to N-Quads, byte-identical to
    ``jsonld.normalize(document, {'algorithm': 'URDNA2015', 'format':
    'application/n-quads', 'documentLoader': loader})`` but bounded by
    *budget* (a fresh :class:`WorkBudget` by default): its work units, its
    CPU time inside URDNA2015 and its allowance of JSON-LD to RDF duplicate
    checks.

    Raises :class:`CanonicalizationWorkExceeded` over any bound and
    :class:`CanonicalizationGuardUnavailable` when the guard cannot meter the
    installed pyld; anything else is pyld's own error."""
    bounded = _bounded_class()
    if budget is None:
        budget = WorkBudget()
    options = {} if loader is None else {'documentLoader': loader}
    pairs, widest, where = _scan_node_map(
        isolate(jsonld).expand(document, options))
    budget.take_pairs(pairs, "; the largest property holds %d values: %s"
                      % (widest, where))
    dataset = _to_dataset(jsonld, document, loader)
    return _canonicalize(bounded, dataset, budget)


def canonize_dataset(dataset: Any, budget: Optional[WorkBudget] = None) -> str:
    """RDFC-1.0-canonicalize an RDF *dataset* that is already in memory (the
    dict of ``jsonld.to_rdf`` or ``JsonLdProcessor.parse_nquads``) to N-Quads,
    bounded by *budget* exactly as :func:`canonize` is, for the caller that
    builds the dataset itself. The caller owns what happens before this (the
    JSON-LD to RDF conversion and its duplicate checks, see
    :func:`node_map_pairs`) and holds :data:`PYLD_LOCK` for it; this runs the
    algorithm only, which touches no pyld cache. Like pyld's own
    ``URDNA2015.main`` it rewrites the dataset's blank node labels in place.

    Raises :class:`CanonicalizationWorkExceeded` over any bound and
    :class:`CanonicalizationGuardUnavailable` when the guard cannot meter the
    installed pyld."""
    bounded = _bounded_class()
    if budget is None:
        budget = WorkBudget()
    return _canonicalize(bounded, dataset, budget)


def _reinit_after_fork(lock: Any) -> None:
    """Give a forked child a lock nobody holds, whatever state some thread of
    the parent left it in (that thread does not exist there)."""
    reinit = getattr(lock, '_at_fork_reinit', None)
    if reinit is not None:
        reinit()


def _before_fork() -> None:
    """Wait for whoever is inside pyld's process-wide caches (an inverse
    context being derived, the delegated ecdsa-sd-2023 verification), so the
    child is not born with one half written."""
    PYLD_LOCK.acquire()


def _after_fork_in_parent() -> None:
    PYLD_LOCK.release()


def _after_fork_in_child() -> None:
    """The forking thread is all that is left, and holds the lock
    :func:`_before_fork` took: give it back."""
    try:
        PYLD_LOCK.release()
    except RuntimeError:                            # pragma: no cover
        _reinit_after_fork(PYLD_LOCK)


if hasattr(os, 'register_at_fork'):                 # pragma: no branch
    os.register_at_fork(before=_before_fork,
                        after_in_parent=_after_fork_in_parent,
                        after_in_child=_after_fork_in_child)
