"""Bounded RDF Dataset Canonicalization (URDNA2015 / RDFC-1.0) for untrusted input.

A Data Integrity proof signs the *canonical* form of the RDF dataset a JSON-LD
document expands to, so the verifier has to canonicalize the document BEFORE it
can tell whether the signature is any good: the cost is paid on input nobody
has authenticated yet. RDFC-1.0 is cheap on every real credential and
factorial on a "poison graph": groups of blank nodes the first-degree hash
cannot tell apart (identical siblings, a clique, a symmetric tree, a ring) are
resolved by trying their permutations, recursively. A 2.6 KB document that
passes context validation is enough to keep a worker busy for minutes
(pyld 3.3.0 has no work cap; digitalbazaar/pyld#336 adds one to the unreleased,
breaking 4.0).

This module bounds that work without touching pyld. :func:`canonize` does what
``jsonld.normalize`` does (``to_rdf``, then ``URDNA2015.main``) but runs the
second half with a per-call subclass of pyld's own ``URDNA2015`` that meters
the one place the cost comes from. Every ``hash_n_degree_quads`` call, the
recursive ones included, opens with ``create_hash_to_related``; the subclass
charges the call there and returns each group of equivalent blank nodes wrapped
in a list that charges one permutation step each time pyld's permutation
generator rearranges it. Charging is cumulative over the whole check (see
:class:`WorkBudget`), which is what catches the shapes made of many small
groups (a ring has none larger than one node), and exhausting the budget raises
before the next step runs. A group of all-distinct nodes is refused at once
when its ``size!`` permutations cannot fit what is left, so the obvious shapes
are rejected in microseconds, not after the budget has been spent.

Why this and not the alternatives:

* a process-global patch of ``pyld.canon`` (the module-level ``permutations``,
  or ``URDNA2015`` itself) would be visible to every thread and to every other
  library using pyld, including openvc-core: rejected. Everything here is
  instance state, so concurrent verifications cannot see each other's budget.
* a static pre-pass over the dataset (largest group of equal first-degree
  hashes, node count) cannot bound the cost: a ring has no group larger than
  one and costs ~n^3, and a tree of groups of three costs (3!)^depth.
* a deadline in a worker thread cannot stop pure-Python code, and a worker
  process costs ~50 ms per call and fails in frozen / restricted environments.
  A monotonic deadline IS checked from the same hook, as a backstop for a cost
  model that is wrong on some interpreter, but it is not the bound.
* relying on pyld 4: unreleased and breaking (rdflib), and its cap counts
  permutations only, not their cost (each copies an issuer as large as the
  component it is hashing), and counts a repeated element as if it were
  distinct, where 3.x enumerates it once.

The cost model is empirical: one unit is ~0.2 microseconds of CPython time. It
was checked on sixteen families of hostile graphs (cliques, trees, rings,
chains, grids, bipartite graphs, ladders, hubs, twins and random digraphs, up
to ~11 million units each) and ~1,300 random ones: 0.03 to 0.21 microseconds
per unit on CPython 3.14, up to 0.25 on 3.13, never more, so the budget can
only over-charge. It describes pyld 3.3.0's implementation, so the guard fails
CLOSED when that implementation is not the one it was fitted to: an
unsupported pyld major version, a missing hook, or a canary canonicalization
that does not reproduce the known output AND the known work total all raise
:class:`CanonicalizationGuardUnavailable` (surfaced as ``OB3VerificationError``
by ``ldp._canonize``). It never falls back to an unmetered
``jsonld.normalize``. A pyld 3.x release that changes ``create_hash_to_related``
or how it permutes therefore stops verification until this module is
recalibrated (``_CANARY_SPENT``): that is the intended failure mode.

The JSON-LD to RDF conversion that precedes canonicalization has a cost of
its own that no hook can meter: pyld builds each node's property array with a
linear duplicate check per value, so a node property holding N distinct values
costs N^2/2 comparisons (8,000 distinct ``tag`` values, 57 KB, spend 12 s),
N values spread over many occurrences of the same ``@id`` cost the same, and so
do N node objects that all reverse into one node (``@reverse``: 6,000 children
spread over 80 parents, about 240 KB, 18 million comparisons and 6 to 11 s).
:func:`node_map_pairs` counts those comparisons on the expanded document first,
the way pyld makes them, and :func:`canonize` refuses a document whose count is
over the allowance of ``MAX_NODE_MAP_PAIRS``, which is shared by the document
and the proof options of one signature check and is a SUM over every property
of every node, because pyld's cost is the sum of those quadratics. A value
repeated is compared once (pyld stops at the first match), so only distinct
values count towards the square.

What it does not cover: canonicalization performed by other libraries on the
same document, notably the ecdsa-sd-2023 suite delegated to openvc-core, which
calls pyld on its own.
"""
import functools
import math
import time

from typing import Any, Dict, List, Optional, Tuple

#: Work one signature check may spend canonicalizing (the proof options and
#: the document share it). ~0.2 us per unit on CPython 3.13-3.15 on an
#: Apple-silicon laptop, so about 0.4 s there and a few seconds on a slow
#: CI runner. A real credential spends 0 to a few thousand.
MAX_CANON_WORK = 2_000_000

#: Backstop wall-clock limit for the same check, in seconds. Not the bound:
#: the unit budget takes ~0.4 s here, so this is reached first only on
#: hardware or an interpreter ~25x slower than the one the model was fitted
#: on, or where the model is wrong.
MAX_CANON_SECONDS = 10.0

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
# identifier the issuer already holds (the issuer is copied for every
# permutation; it can hold at most the blank nodes of the start node's
# connected component).
_CALL_UNITS = 9
_QUAD_UNITS = 14
_PERM_UNITS = 6

#: An all-distinct group this large has size! permutations: more than any
#: budget (13! = 6.2 billion) without computing the factorial.
_MAX_GROUP = 12

# Output of the canary document below, produced by stock pyld 3.3.0, and the
# exact work it costs under the model above. Changing a constant or the
# metering changes _CANARY_SPENT; so does pyld changing how it permutes.
_CANARY_DOCUMENT = {
    '@context': {'@vocab': 'https://example.org/c#'},
    '@id': 'https://example.org/c/root',
    'p': [{'q': [{'s': 'x'}, {'s': 'x'}]}, {'q': [{'s': 'x'}, {'s': 'x'}]}],
}
_CANARY_NQUADS = (
    '<https://example.org/c/root> <https://example.org/c#p> _:c14n0 .\n'
    '<https://example.org/c/root> <https://example.org/c#p> _:c14n3 .\n'
    '_:c14n0 <https://example.org/c#q> _:c14n1 .\n'
    '_:c14n0 <https://example.org/c#q> _:c14n2 .\n'
    '_:c14n1 <https://example.org/c#s> "x" .\n'
    '_:c14n2 <https://example.org/c#s> "x" .\n'
    '_:c14n3 <https://example.org/c#q> _:c14n4 .\n'
    '_:c14n3 <https://example.org/c#q> _:c14n5 .\n'
    '_:c14n4 <https://example.org/c#s> "x" .\n'
    '_:c14n5 <https://example.org/c#s> "x" .\n')
_CANARY_SPENT = 524


class CanonicalizationWorkExceeded(Exception):
    """The canonicalization needs more work than the budget allows."""


class CanonicalizationGuardUnavailable(Exception):
    """The installed pyld is not one the guard can meter: fail closed."""


class WorkBudget:
    """Work allowance of one signature check, shared by every canonicalization
    it performs. ``limit`` and ``seconds`` default to the module constants,
    read at construction; so does ``pairs``, the allowance of JSON-LD to RDF
    duplicate checks (:data:`MAX_NODE_MAP_PAIRS`), shared in the same way."""

    __slots__ = ('limit', 'spent', 'deadline', 'pairs_left')

    def __init__(self, limit: Optional[int] = None,
                 seconds: Optional[float] = None,
                 pairs: Optional[int] = None) -> None:
        self.limit = MAX_CANON_WORK if limit is None else limit
        self.spent = 0
        self.pairs_left = MAX_NODE_MAP_PAIRS if pairs is None else pairs
        self.deadline = time.monotonic() + (
            MAX_CANON_SECONDS if seconds is None else seconds)

    def charge(self, units: int) -> None:
        self.spent += units
        if self.spent > self.limit:
            raise CanonicalizationWorkExceeded(
                "RDF canonicalization needs more than %d work units (the "
                "document contains blank nodes the algorithm cannot tell "
                "apart cheaply)" % self.limit)

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise CanonicalizationWorkExceeded(
                "RDF canonicalization exceeded its time limit")

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
        self._budget.charge(self._half)
        super().__setitem__(index, value)


@functools.lru_cache(maxsize=1)
def _bounded_class() -> Any:
    """Build (once per process) the metered URDNA2015 subclass, after proving
    the installed pyld is the implementation the cost model describes."""
    try:
        from pyld import jsonld
        from pyld.__about__ import __version__ as pyld_version
        from pyld.canon import URDNA2015
    except ImportError as exc:
        raise CanonicalizationGuardUnavailable(
            "pyld's canonicalizer is not importable: %s" % exc) from exc
    if str(pyld_version).split('.')[0] != '3':
        raise CanonicalizationGuardUnavailable(
            "pyld %s is not supported by the canonicalization guard "
            "(it meters pyld 3.x; install pyld>=3.3.0,<4)" % pyld_version)
    for name in ('main', 'create_hash_to_related', 'hash_n_degree_quads'):
        if not callable(getattr(URDNA2015, name, None)):
            raise CanonicalizationGuardUnavailable(
                "pyld.canon.URDNA2015 has no %s(): the canonicalization "
                "guard cannot meter this pyld" % name)

    class BoundedURDNA2015(URDNA2015):          # type: ignore[misc]
        """URDNA2015 that charges a :class:`WorkBudget` for the work each
        Hash N-Degree Quads call does."""

        def __init__(self, budget: WorkBudget) -> None:
            super().__init__()
            self._budget = budget
            self._component: Dict[str, int] = {}

        def _component_size(self, id_: str) -> int:
            """Blank nodes connected to *id_* through quads: an upper bound
            on the identifiers an issuer can hold while hashing *id_*."""
            size = self._component.get(id_)
            if size is None:
                seen = {id_}
                todo = [id_]
                while todo:
                    for quad in self.blank_node_info[todo.pop()]['quads']:
                        for key, term in quad.items():
                            if (key != 'predicate'
                                    and term['type'] == 'blank node'
                                    and term['value'] not in seen):
                                seen.add(term['value'])
                                todo.append(term['value'])
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

    _selftest(jsonld, BoundedURDNA2015)
    return BoundedURDNA2015


def _selftest(jsonld: Any, bounded: Any) -> None:
    """Prove, on a document with a permutation group, that the guard (a)
    reproduces stock pyld's output, (b) meters exactly the work this cost
    model expects of pyld 3.3.0, and (c) is enforced."""
    try:
        budget = WorkBudget()
        out = _run(jsonld, bounded, _CANARY_DOCUMENT, None, budget)
        if out != _CANARY_NQUADS:
            raise CanonicalizationGuardUnavailable(
                "the canary document no longer canonicalizes to the known "
                "output")
        if budget.spent != _CANARY_SPENT:
            raise CanonicalizationGuardUnavailable(
                "the canonicalization work of the canary document is %d, "
                "not the %d this guard was calibrated on"
                % (budget.spent, _CANARY_SPENT))
        try:
            _run(jsonld, bounded, _CANARY_DOCUMENT, None,
                 WorkBudget(limit=_CANARY_SPENT // 2))
        except CanonicalizationWorkExceeded:
            return
        raise CanonicalizationGuardUnavailable(
            "the canonicalization budget is not enforced")
    except CanonicalizationGuardUnavailable:
        raise
    except Exception as exc:
        raise CanonicalizationGuardUnavailable(
            "the canonicalization self-test failed: %s" % exc) from exc


def _run(jsonld: Any, bounded: Any, document: Any, loader: Any,
         budget: WorkBudget) -> str:
    options: Dict[str, Any] = {'produceGeneralizedRdf': False}
    if loader is not None:
        options['documentLoader'] = loader
    # What jsonld.normalize does for URDNA2015: to_rdf without a format, then
    # the algorithm on the resulting dataset.
    dataset = jsonld.to_rdf(document, options)
    return str(bounded(budget).main(
        dataset, {'format': 'application/n-quads'}))


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
    *budget* (a fresh :class:`WorkBudget` by default): its work units and its
    allowance of JSON-LD to RDF duplicate checks.

    Raises :class:`CanonicalizationWorkExceeded` over either bound and
    :class:`CanonicalizationGuardUnavailable` when the guard cannot meter the
    installed pyld; anything else is pyld's own error."""
    bounded = _bounded_class()
    if budget is None:
        budget = WorkBudget()
    options = {} if loader is None else {'documentLoader': loader}
    pairs, widest, where = _scan_node_map(jsonld.expand(document, options))
    budget.take_pairs(pairs, "; the largest property holds %d values: %s"
                      % (widest, where))
    return _run(jsonld, bounded, document, loader, budget)
