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
#   (a value of a property with a scoped @context of its own counts as one) or
#   MAX_NODES objects in all;
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
# What it does not do: it knows no context, so a ``type`` alias other than
# ``type`` and ``@type`` (only an extra_contexts entry of the low-level
# functions could define one) is not counted; it does not bound RDF
# canonicalization (see _canon_guard.py), the ecdsa-sd-2023 suite openvc-core
# runs on its own, or the bytes of a document the caller does not cap.

from typing import Any, List, NamedTuple, Optional, Tuple

#: Most entries one node's ``type`` may list. A real node has one to three
#: (``["VerifiableCredential", "OpenBadgeCredential"]``, ``["Profile"]``,
#: ``["Extension", "extensions:ApplicationProfile"]``).
MAX_TYPES_PER_NODE = 8

#: Most typed nodes (an object with a ``type`` or ``@type``) in a document,
#: embedded credentials counted once more per level of nesting.
MAX_TYPED_NODES = 1_600

#: Most ``type`` entries in a document (and values of the properties that
#: carry a scoped context, see _SCOPED_PROPERTIES), counted like the typed
#: nodes.
MAX_TYPE_ENTRIES = 2_000

#: Most objects in a document, counted like the typed nodes.
MAX_NODES = 8_000

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


_TYPE_KEYS = ('type', '@type')
_ENDORSEMENT = 'endorsement'

# The terms a bundled context defines WITH a scoped @context of their own (not
# a type's): pyld applies it to every value of the property, as it applies a
# type-scoped one per type entry, so each value costs about a third of a type
# entry and is counted as one. VC 2.0 defines ``cnf`` at the top level and
# ``verifiableCredential``, ``statusMessage`` and ``proofPurpose`` inside the
# contexts of a presentation, a status entry and a proof. A test derives this
# set from the bundled contexts, so a context that adds one fails it.
_SCOPED_PROPERTIES = frozenset(
    ('cnf', 'proofPurpose', 'statusMessage', 'verifiableCredential'))


def screen(document: Any, *, scale: int = 1, contexts: bool = True,
           limits: bool = True) -> StructureStats:
    """Count the structure of *document* (parsed JSON) and, unless *limits*
    is false, raise :class:`StructureLimitExceeded` at the first limit it
    crosses. *scale* multiplies the node, typed-node and type-entry totals:
    the low-level functions that skip context validation process a node in
    about half the passes the verifier does, and pass ``scale=2``. *contexts*
    false leaves the ``@context`` limits to the caller, for the paths where
    context validation bounds them already, before any JSON-LD processing.

    One explicit stack, no recursion. A document that contains itself is
    refused by the node limit; with ``limits=False`` it would not return.
    """
    typed_cap = MAX_TYPED_NODES * scale
    entries_cap = MAX_TYPE_ENTRIES * scale
    nodes_cap = MAX_NODES * scale
    context_cap = MAX_CONTEXT_ENTRIES_TOTAL
    nodes = typed = entries = context_entries = 0
    longest = longest_context = deepest = 0
    # (value, weight = 1 + embedding depth, value is an ``endorsement`` entry)
    stack: List[Tuple[Any, int, bool]] = [(document, 1, False)]
    while stack:
        value, weight, entry = stack.pop()
        if isinstance(value, (list, tuple)):
            stack.extend((item, weight, False) for item in value
                         if isinstance(item, (dict, list, tuple)))
            continue
        if not isinstance(value, dict):
            continue
        if entry and '@context' in value:
            weight += 1             # an embedded credential: validated again
            deepest = max(deepest, weight - 1)
        nodes += weight
        node_types = scoped = 0
        for key, item in value.items():
            if key in _SCOPED_PROPERTIES:
                scoped += len(item) if isinstance(item, (list, tuple)) else 1
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
                    stack.append((item, weight, True))
                elif isinstance(item, (list, tuple)):
                    stack.extend((member, weight, True) for member in item
                                 if isinstance(member, (dict, list, tuple)))
            elif isinstance(item, (dict, list, tuple)):
                stack.append((item, weight, False))
        if node_types:
            typed += weight
            longest = max(longest, node_types)
        entries += weight * (node_types + scoped)
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
                          longest_context, deepest)


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
            'entries (longest %d), embedded %d deep'
            % (stats.nodes, stats.typed_nodes, stats.type_entries,
               stats.max_types, stats.context_entries, stats.max_context,
               stats.max_depth))
