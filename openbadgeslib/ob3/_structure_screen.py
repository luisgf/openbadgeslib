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

# Structural limits on an untrusted JSON-LD document, checked BEFORE any
# JSON-LD processor sees it.
#
# A Data Integrity credential is processed (expanded, compacted, converted to
# RDF) before its signature can be looked at, so every unit of work the
# processor does is paid on input nobody has authenticated. The document-size
# cap bounds the BYTES, not that work: pyld applies a type-scoped @context once
# per entry of every node's ``type`` array (duplicates included) and once per
# typed node, in expansion and again in compaction, and it applies the
# entries of an ``@context`` array one by one. That costs ~0.3 to 0.6 ms per
# type entry through OB3LdpVerifier.verify, ~40 microseconds per byte of a
# short typed node against ~2 for ordinary text: a 258 KB credential whose
# nodes repeat ``"type": ["Profile", "Profile", ...]`` cost 9 to 11 s of CPU,
# the same credential inside one embedded endorsement 12 to 15 s, a flood of
# ~7,000 distinct typed nodes 6 to 7 s, and a list of one pinned context
# repeated 1,000 times (62 KB) 3.4 s in verify_data_integrity_proof, every one
# of them ending in "signature mismatch". The canonicalization guard
# (_canon_guard.py) meters what the canonicalizer does after that; it does not
# see these costs.
#
# screen() is one iterative pass over the PARSED JSON (no JSON-LD processing,
# no recursion, so no nesting can exhaust the stack) that counts what the
# processor pays per unit and refuses a document over a limit:
#
# * a ``type`` / ``@type`` array that repeats an entry, or lists more than
#   MAX_TYPES_PER_NODE of them (a real node has one to three);
# * more than MAX_TYPED_NODES typed objects, MAX_TYPE_ENTRIES type entries
#   (a value of a property named like a term that has an @context of its own
#   counts as one, see scoped_terms) or MAX_NODES objects in all;
# * an ``@context`` array longer than MAX_CONTEXT_ENTRIES (pyld finds up to
#   ten entries already processed and re-resolves each one past that), or more
#   than MAX_CONTEXT_ENTRIES_TOTAL entries in all.
#
# Where context validation (_context_validation.py) runs, it expands and
# compacts every embedded EndorsementCredential again on its own, so a node k
# endorsements deep is processed k + 1 times: the three totals count it k + 1
# times (its weight). Where it does not run (the low-level functions) a node
# takes about half the passes, and the totals double (scale). The numbers
# were fixed by building the most expensive document each limit admits (the
# costliest type pairs, with and without IRIs, flat, nested and inside
# endorsements, plus untyped objects up to the object limit) and timing it
# through OB3LdpVerifier.verify on CPython 3.10 to 3.15: wiki/Security-Model.md
# has the table. They are measured, not derived from a model of pyld.
#
# What it does not do: it knows no context beyond the set of terms that have an
# @context of their own (the bundled ones, and those of the extra_contexts a
# low-level function is given), so a ``type`` alias other than ``type`` and
# ``@type`` (only an extra_contexts entry of the low-level functions could
# define one) is not counted; it does not bound RDF canonicalization (see
# _canon_guard.py), the ecdsa-sd-2023 suite openvc-core runs on its own, or the
# bytes of a document the caller does not cap.

import functools

from typing import (AbstractSet, Any, FrozenSet, Iterable, List, NamedTuple,
                    Optional, Tuple)

from .contexts import bundled_contexts

#: Most entries one node's ``type`` may list. A real node has one to three
#: (``["VerifiableCredential", "OpenBadgeCredential"]``, ``["Profile"]``,
#: ``["Extension", "extensions:ApplicationProfile"]``).
MAX_TYPES_PER_NODE = 8

#: Most typed nodes (an object with a ``type`` or ``@type``) in a document,
#: embedded credentials counted once more per level of nesting.
MAX_TYPED_NODES = 1_600

#: Most ``type`` entries in a document (and values of the properties named
#: like a term that has a scoped context, see scoped_terms), counted like the
#: typed nodes.
MAX_TYPE_ENTRIES = 2_000

#: Most objects in a document, counted like the typed nodes.
MAX_NODES = 8_000

#: Most containers (objects and arrays) one inside another, the document
#: itself being the first (``@context`` values are not entered). The deepest
#: document the library accepts is a chain of 8 embedded endorsements, each
#: nested through the issuer of the one before: 25 levels, 28 inside a CLR
#: member (context validation refuses a 9th with its own message); the
#: 49 1EdTech examples and test documents nest 2 to 10. The bound is not about pyld's work, which is
#: linear in depth. It is about where the deepest node sits on the call stack:
#: CPython 3.11 and 3.12 allocate the data stack in 16 KiB chunks, and a tight
#: loop whose calls straddle a chunk boundary pays an allocation per call.
#: pyld's duplicate check for the values of a node property
#: (``compare_values``, up to MAX_NODE_MAP_PAIRS of them, see ``_canon_guard``)
#: is such a loop: 28 KB of JSON cost 5 to 10 s of CPU instead of 0.35 s. The
#: boundary's place relative to the document depends on how deep the caller
#: already is. For the worst document shape (objects nested directly, 400
#: values) at least 86 % of the caller depths have a hit at some nesting depth
#: within the 128 levels ``_safejson`` allows, and 22 % at or below this bound.
#: It lowers the odds, it does not remove the cliff: wiki/Security-Model.md.
MAX_DEPTH = 36

#: Most entries one ``@context`` array may list. Context validation accepts
#: eight; pyld processes an array of up to ten entries for ~0.06 ms an entry
#: and one of twelve or more for ~2 ms an entry.
MAX_CONTEXT_ENTRIES = 8

#: Most ``@context`` entries in a document (not weighted: an embedded
#: credential's contexts are not processed again at that cost).
MAX_CONTEXT_ENTRIES_TOTAL = 4_096


class StructureLimitExceeded(ValueError):
    """The document is over a structural limit. The message names the limit
    and the count, never a fragment of the document."""


class StructureStats(NamedTuple):
    """What :func:`screen` counted (embedded credentials weighted as above)."""
    nodes: int
    typed_nodes: int
    type_entries: int
    context_entries: int
    max_types: int          # the longest ``type`` array (unweighted)
    max_context: int        # the longest ``@context`` array (unweighted)
    max_depth: int          # embedded credentials nested that deep
    max_nesting: int = 0    # containers one inside another (the document: 1)


_TYPE_KEYS = ('type', '@type')
_ENDORSEMENT = 'endorsement'


def scoped_terms(contexts: Iterable[Any]) -> FrozenSet[str]:
    """Every term the JSON-LD context documents *contexts* define WITH an
    ``@context`` of their own, at any depth of the definitions.

    pyld applies such a context whenever the term is in use: once per ``type``
    entry that names it (a type-scoped context) and once per value of a
    property that is named by it (a property-scoped one), in expansion and
    again in compaction. A term of the first kind written as a property KEY
    costs the same as one of the second (``"DataIntegrityProof": [0, 0, ...]``
    in a node: 130,000 values, 6 to 9 s of CPU through OB3LdpVerifier.verify),
    so what counts is that the term has a context, not which kind it is. A
    value of such a key costs about a tenth of a type entry (22 to 50
    microseconds against 0.3 to 0.6 ms) and is counted as one.

    Iterative, so a context of any depth is walked."""
    found = set()
    todo: List[Any] = list(contexts)
    while todo:
        node = todo.pop()
        if isinstance(node, dict):
            for term, definition in node.items():
                if (isinstance(definition, dict) and '@context' in definition
                        and isinstance(term, str)
                        and not term.startswith('@')):
                    found.add(term)
                if isinstance(definition, (dict, list)):
                    todo.append(definition)
        elif isinstance(node, list):
            todo.extend(item for item in node
                        if isinstance(item, (dict, list)))
    return frozenset(found)


@functools.lru_cache(maxsize=1)
def bundled_scoped_terms() -> FrozenSet[str]:
    """:func:`scoped_terms` of the pinned contexts (``ob3/contexts``), derived
    from them the first time it is needed, so a context bump that adds a term
    with a context of its own is covered with no change here (and a test pins
    the set, so the limits are timed again). The CLR context is not bundled in
    that sense: the low-level functions are given it as ``extra_contexts`` and
    pass its terms in."""
    return scoped_terms(bundled_contexts().values())


def screen(document: Any, *, scale: int = 1, contexts: bool = True,
           limits: bool = True,
           scoped: Optional[AbstractSet[str]] = None) -> StructureStats:
    """Count the structure of *document* (parsed JSON) and, unless *limits*
    is false, raise :class:`StructureLimitExceeded` at the first limit it
    crosses. *scale* multiplies the node, typed-node and type-entry totals:
    the low-level functions that skip context validation process a node in
    about half the passes the verifier does, and pass ``scale=2``. *contexts*
    false leaves the ``@context`` limits to the caller, for the paths where
    context validation bounds them already, before any JSON-LD processing.
    *scoped* is the set of terms that have an ``@context`` of their own, whose
    use as a property key costs a type entry per value (default: the bundled
    contexts', :func:`bundled_scoped_terms`; a caller that hands the JSON-LD
    processor more contexts adds theirs, :func:`scoped_terms`).

    One explicit stack, no recursion. A document that contains itself is
    refused by the node limit; with ``limits=False`` it would not return.
    """
    scoped_keys = bundled_scoped_terms() if scoped is None else scoped
    typed_cap = MAX_TYPED_NODES * scale
    entries_cap = MAX_TYPE_ENTRIES * scale
    nodes_cap = MAX_NODES * scale
    context_cap = MAX_CONTEXT_ENTRIES_TOTAL
    nodes = typed = entries = context_entries = 0
    longest = longest_context = deepest = 0
    nesting = 0
    # (container, weight = 1 + embedding depth, container is an ``endorsement``
    # entry, container is an array under a key with a scoped context: its
    # leaves count, levels of containers down to it)
    stack: List[Tuple[Any, int, bool, bool, int]] = [
        (document, 1, False, False, 1)]
    while stack:
        value, weight, entry, counted, level = stack.pop()
        if not isinstance(value, (dict, list, tuple)):
            continue                # only the document itself can be a scalar
        if level > nesting:
            nesting = level
            if limits and level > MAX_DEPTH:
                raise StructureLimitExceeded(
                    "the document is nested more than %d levels deep"
                    % MAX_DEPTH)
        below = level + 1
        if isinstance(value, (list, tuple)):
            if not counted:
                stack.extend((item, weight, False, False, below)
                             for item in value
                             if isinstance(item, (dict, list, tuple)))
                continue
            # JSON-LD flattens nested arrays: every leaf is a value of the
            # property, and pyld applies the scoped context to each.
            leaves = 0
            for item in value:
                if isinstance(item, (list, tuple)):
                    stack.append((item, weight, False, True, below))
                    continue
                leaves += 1
                if isinstance(item, dict):
                    stack.append((item, weight, False, False, below))
            entries += weight * leaves
            if limits:
                _check('type entries', entries, entries_cap, deepest)
            continue
        if entry and '@context' in value:
            weight += 1             # an embedded credential: validated again
            deepest = max(deepest, weight - 1)
        nodes += weight
        node_types = values = 0
        for key, item in value.items():
            if key in _TYPE_KEYS:
                if isinstance(item, str):
                    node_types += 1
                elif isinstance(item, (list, tuple)):
                    if limits and len(item) > MAX_TYPES_PER_NODE:
                        raise StructureLimitExceeded(
                            "a node lists %d types; at most %d are accepted"
                            % (len(item), MAX_TYPES_PER_NODE))
                    names = [t for t in item if isinstance(t, str)]
                    if limits and len(set(names)) != len(names):
                        raise StructureLimitExceeded(
                            "a node lists the same type more than once")
                    node_types += len(item)
                    longest = max(longest, len(item))
            elif key == '@context':
                if isinstance(item, (list, tuple)):
                    if (limits and contexts
                            and len(item) > MAX_CONTEXT_ENTRIES):
                        raise StructureLimitExceeded(
                            "an @context lists %d entries; at most %d are "
                            "accepted" % (len(item), MAX_CONTEXT_ENTRIES))
                    context_entries += len(item)
                    longest_context = max(longest_context, len(item))
                else:
                    context_entries += 1
            elif key == _ENDORSEMENT:
                if isinstance(item, dict):
                    stack.append((item, weight, True, False, below))
                elif isinstance(item, (list, tuple)):
                    # the array is a level of its own, entered here
                    stack.extend((member, weight, True, False, below + 1)
                                 for member in item
                                 if isinstance(member, (dict, list, tuple)))
                    nesting = max(nesting, below)
            elif key in scoped_keys:
                if isinstance(item, (list, tuple)):
                    stack.append((item, weight, False, True, below))  # leaves
                else:
                    values += 1
                    if isinstance(item, dict):
                        stack.append((item, weight, False, False, below))
            elif isinstance(item, (dict, list, tuple)):
                stack.append((item, weight, False, False, below))
        if node_types:
            typed += weight
            longest = max(longest, node_types)
        entries += weight * (node_types + values)
        if limits:
            if node_types > MAX_TYPES_PER_NODE:
                raise StructureLimitExceeded(
                    "a node lists %d types; at most %d are accepted"
                    % (node_types, MAX_TYPES_PER_NODE))
            _check('objects', nodes, nodes_cap, deepest)
            _check('typed objects', typed, typed_cap, deepest)
            _check('type entries', entries, entries_cap, deepest)
            if contexts:
                _check('@context entries', context_entries, context_cap, 0)
    return StructureStats(nodes, typed, entries, context_entries, longest,
                          longest_context, deepest, nesting)


def _check(what: str, count: int, cap: int, embedded: int) -> None:
    if count > cap:
        raise StructureLimitExceeded(
            "the document has more than %d %s%s" % (
                cap, what, " (an embedded credential counts once more for "
                "each credential that holds it)" if embedded else ""))


def describe(stats: Optional[StructureStats]) -> str:
    """One line for a log or a test failure."""
    if stats is None:
        return 'n/a'
    return ('%d objects, %d typed, %d type entries (longest %d), %d @context '
            'entries (longest %d), embedded %d deep, nested %d levels'
            % (stats.nodes, stats.typed_nodes, stats.type_entries,
               stats.max_types, stats.context_entries, stats.max_context,
               stats.max_depth, stats.max_nesting))
