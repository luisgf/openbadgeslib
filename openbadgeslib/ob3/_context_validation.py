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

# JSON-LD context validation for the RDF-canonicalized Data Integrity
# cryptosuites (eddsa-rdfc-2022 natively, ecdsa-sd-2023 before delegating).
#
# Ported from openvc (openvc.proof._context_validation, openvc-core 1.30.2;
# same author, LGPL-3.0-or-later), with the OB 3.0 adaptations listed below.
#
# Those suites sign the RDF DATASET a document expands to, not its JSON. Every
# policy check after the signature -- the validity window, credentialStatus,
# the recipient, the issuer binding, proof.expires -- reads the JSON. The two
# only agree when the JSON spells the dataset the way the pinned contexts
# would, which is why VC Data Integrity 2.4.1 requires context validation.
# Without it a document can keep its signed dataset while showing other JSON:
#
# * a signed member re-keyed to its absolute IRI (or a compact IRI, a keyword
#   spelling, an @value object, an inline @context alias) disappears from the
#   key the policy reads;
# * a term no pinned context defines is dropped from the dataset, so its JSON
#   value is never signed at all;
# * @included / @reverse / a top-level @graph / a nested re-description of the
#   credential's own node move signed statements out of the object the policy
#   reads;
# * a statement whose subject, predicate or object is not an IRI the RDF
#   conversion keeps (an @id with whitespace, a blank-node predicate) is
#   silently dropped from the dataset -- a whole forged top-level node can ride
#   on that, with the genuine signed node tucked under @included or any IRI
#   property. (A relative IRI is resolved by the supported pyld against a
#   placeholder base, which compaction does not undo, so the comparison below
#   refuses it; older pyld 2.x kept it relative and dropped it, which the
#   safe-mode walk refuses, but [ldp] now requires pyld >= 3.3.0.)
# * an array nested in an array is flattened by expansion, so [[S]] signs as
#   S while every JSON reader that expects an object skips it -- a
#   credentialStatus wrapped that way would hide the revocation check.
#
# validate_document() closes all of them with one invariant: the document and
# its proof configuration must each be the COMPACTED FORM of their own
# expansion under a context the verifier trusts -- the VC 2.0 base context
# first, then only URLs the fail-closed bundled loader serves (or an inline
# object carrying nothing but an absolute-IRI @vocab, which can neither alias,
# re-map nor drop a term: a defined term always wins over @vocab when
# compacting) -- and the expansion must carry no statement the RDF conversion
# would drop (JSON-LD "safe mode"). The comparison tolerates exactly the two
# spellings JSON-LD treats as identical -- a one-element array vs its element
# (as a property value; never an array inside an array, which expansion
# flattens but JSON readers do not), and a node reference {"id": X} vs X --
# compared as canonical JSON so true/1 and 1/1.0 stay distinct.
#
# Being the compacted form is necessary but not sufficient. Compaction only
# folds a statement into a term when the value matches the term's definition;
# otherwise it keeps the predicate's absolute IRI (or a compact IRI, or a
# suffix relative to an inline @vocab) as the key -- and that spelling IS the
# compacted form. So a validUntil, validFrom or proof ``expires`` written as a
# plain (untyped) string under its absolute IRI, or as ``Until`` under
# {"@vocab": ".../credentials#valid"}, signs an untyped literal, survives the
# comparison unchanged, and is invisible to the reader of ``validUntil``: an
# issuer-signed expired credential would verify as never expiring. Hence the
# second rule (_misspelled_key): in the compacted form, a key whose IRI some
# pinned context defines a term for must be one of those terms. A conforming
# document always uses the terms, so only such shapes are refused; extension
# IRIs no pinned context defines are left alone.
#
# OB 3.0 adaptations (the 1EdTech "Complete OpenBadgeCredential" example must
# validate):
#
# (a) Embedded EndorsementCredentials. ``endorsement`` (an unscoped OB 3.0
#     term, so it can appear on the credential, on any Profile -- issuer,
#     achievement.creator, credentialSubject.source, parentOrg -- and on any
#     Achievement) carries whole credentials with their OWN @context, which
#     compaction never re-emits. Each one is therefore cut out of the outer
#     compaction comparison and validated as a document in its own right,
#     against its own @context, with the same rules (recursively). The
#     safe-mode walk still covers the whole expanded outer document, so
#     @included, a dropped node or a re-description of the credential inside
#     an endorsement is still refused. An ``endorsement`` entry without its own
#     @context (or that is not an EndorsementCredential) is refused.
# (b) ``type`` values are compared by the IRI they name, not by their
#     spelling: compaction picks the shortest term for an IRI, so
#     ``GeoCoordinates`` comes back as ``geo`` and ``AchievementCredential`` as
#     ``OpenBadgeCredential`` (pyld even renders ``geo`` where only the
#     parent's type-scoped context defines it, so re-expanding the compacted
#     spelling is no oracle). This is sound because the compacted form is a
#     deterministic function of the signed dataset and the pinned contexts: a
#     document equal to it everywhere but in type spellings is pinned down by
#     the dataset up to those spellings, and its own spelling is, by
#     construction, what produced the signed type IRI at that position. The
#     remaining freedom is narrowed to plain terms that some pinned context
#     defines as the same IRI (derived from the bundled contexts, see
#     _type_synonyms), and every reader of type spellings (_check_vc_types,
#     the status checker, the endorsement check below) fails closed on a
#     spelling it does not know.
# (c) A ``refreshService`` whose id is the credential's own id is tolerated
#     only when that object is exactly {id, type} (the 1EdTech example does
#     that); anything more is a re-description of the credential and refused.

import functools
import json
import re

from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple, Union

from .contexts import UnknownContextError, bundled_contexts
from .verifier import OB3VerificationError

#: The only first @context entry an OB 3.0 credential may carry.
VC2_CONTEXT = "https://www.w3.org/ns/credentials/v2"

# Expanded-form keywords refused outright. @included / @reverse let a
# statement about a node live outside that node's own JSON object; @index /
# @direction annotate JSON the RDF dataset does not carry (canonicalization
# runs without rdfDirection), so their values would be unsigned. None of them
# is produced by issuing a credential.
_REFUSED_KEYWORDS = ("@included", "@reverse", "@index", "@direction")

# pyld's own absolute-IRI test (pyld 2.0.4 and 3.x alike): toRDF drops a
# statement whose subject, predicate or IRI object fails it, and drops
# blank-node ("_:") predicates. Mirrored verbatim, not "fixed" to RFC 3987.
_RDF_IRI = re.compile(r"^([A-Za-z][A-Za-z0-9+-.]*|_):[^\s]*$")

_REFRESH_SERVICE = "https://www.w3.org/2018/credentials#refreshService"
_ENDORSEMENT = "endorsement"
_ENDORSEMENT_CREDENTIAL = "EndorsementCredential"

# Stand-in for a detached embedded credential in both sides of the outer
# comparison: an object no JSON document can contain, only ever equal to itself.
_EMBEDDED = object()

# Embedded credentials may nest (an endorsement's issuer Profile can carry
# endorsements); real documents stop at one or two levels.
_MAX_EMBEDDED_DEPTH = 8

_Path = Tuple[Union[str, int], ...]
_Loader = Callable[..., Any]


def validate_document(unsecured: dict[str, Any], proof_config: dict[str, Any],
                      loader: _Loader, jsonld: Any) -> None:
    """Require *unsecured* (the document without ``proof``) and *proof_config*
    (the proof without ``proofValue``, carrying the document ``@context``) to
    be in the canonical compacted form described in the module comment, else
    raise :class:`OB3VerificationError`.

    *loader* is the fail-closed bundled document loader canonicalization uses
    (contexts are never fetched); *jsonld* is the pyld ``jsonld`` module,
    imported by the caller through its actionable-error helper.
    """
    try:
        _check_form(unsecured, loader, jsonld, what="credential", depth=0)
        _check_form(proof_config, loader, jsonld, what="proof", depth=0)
    except OB3VerificationError:
        raise
    except Exception as exc:          # a non-JSON value (NaN, ...), deep nesting
        raise OB3VerificationError(
            "cannot validate the JSON-LD form of the Data Integrity document: "
            "%s" % (str(exc)[:300],)) from exc


# ── one document ─────────────────────────────────────────────────────────────

def _check_form(document: dict[str, Any], loader: _Loader, jsonld: Any, *,
                what: str, depth: int) -> None:
    _check_context(document.get("@context"), loader, what)
    expanded = _jsonld_call(jsonld.expand, what, document,
                            {"documentLoader": loader})
    if not (isinstance(expanded, list) and len(expanded) == 1
            and isinstance(expanded[0], dict)):
        raise OB3VerificationError(
            "the %s must describe exactly one top-level node" % what)
    node = expanded[0]
    if "@graph" in node:
        raise OB3VerificationError(
            "the %s uses a top-level @graph, which is not accepted" % what)
    _check_expanded(node, node.get("@id"), what, top=True)

    compacted = _jsonld_call(jsonld.compact, what, expanded,
                             document["@context"], {"documentLoader": loader})
    embedded: List[Tuple[_Path, dict[str, Any]]] = []
    ours = _detach(document, (), embedded)
    theirs = _detach(compacted, (), None)
    where = _difference(ours, theirs, ())
    if where is not None:
        raise OB3VerificationError(
            "the %s is not in compacted form under its @context (at %s): a "
            "member spelled as an IRI or keyword, a relative or malformed IRI, "
            "an inline alias, or a term no pinned context defines -- whose "
            "value the signature does not cover" % (what, _pointer(where)))

    # Literals of @json-typed terms compact to raw JSON, whose keys are data,
    # not properties: stub them out (rare, so a second compaction only then).
    stubbed = _stub_json_literals(expanded)
    if stubbed is not expanded:
        theirs = _detach(_jsonld_call(jsonld.compact, what, stubbed,
                                      document["@context"],
                                      {"documentLoader": loader}), (), None)
    where = _misspelled_key(theirs, (), _inline_vocabs(document["@context"]))
    if where is not None:
        raise OB3VerificationError(
            "the %s spells a property a pinned context defines other than by "
            "its term (at %s): its value does not match the term's definition "
            "(an untyped date, a literal for a node, ...), so the member the "
            "policy reads does not carry what was signed" % (what, _pointer(where)))

    for path, credential in embedded:
        _check_embedded(credential, path, loader, jsonld, what=what,
                        depth=depth + 1)


def _check_embedded(credential: dict[str, Any], path: _Path, loader: _Loader,
                    jsonld: Any, *, what: str, depth: int) -> None:
    """Validate an embedded EndorsementCredential against its own @context."""
    where = "endorsement at %s of the %s" % (_pointer(path), what)
    if depth > _MAX_EMBEDDED_DEPTH:
        raise OB3VerificationError("%s nests embedded credentials too deeply"
                                   % where)
    types = credential.get("type")
    types = [types] if isinstance(types, str) else types
    if not (isinstance(types, list) and _ENDORSEMENT_CREDENTIAL in types):
        raise OB3VerificationError("%s is not an %s"
                                   % (where, _ENDORSEMENT_CREDENTIAL))
    _check_form(credential, loader, jsonld, what=where, depth=depth)


def _check_context(context: Any, loader: _Loader, what: str) -> None:
    """The VC 2.0 base context first, then only bundled URLs (or an
    absolute-IRI ``@vocab``-only object). Runs before any expansion, so an
    inline term definition never reaches the JSON-LD processor."""
    entries = [context] if isinstance(context, str) else context
    if not isinstance(entries, list) or not entries:
        raise OB3VerificationError(
            "the %s @context must be a URL or a non-empty array" % what)
    if entries[0] != VC2_CONTEXT:
        raise OB3VerificationError(
            "the first @context entry of the %s must be the VC 2.0 base "
            "context %r" % (what, VC2_CONTEXT))
    for entry in entries:
        if isinstance(entry, str) and entry:
            try:
                loader(entry)            # fail-closed allowlist, no network
            except UnknownContextError as exc:
                raise OB3VerificationError(str(exc)) from exc
            continue
        if isinstance(entry, dict) and set(entry) == {"@vocab"}:
            if _is_predicate(entry["@vocab"]):
                continue
            raise OB3VerificationError(
                "an inline @vocab in the %s must be an absolute IRI" % what)
        raise OB3VerificationError(
            "the %s carries an inline @context object; only the pinned "
            "context URLs (and an inline {\"@vocab\": <absolute IRI>}) are "
            "accepted" % what)


def _jsonld_call(function: Callable[..., Any], what: str, *args: Any) -> Any:
    """Run a pyld call, mapping its failures to OB3VerificationError while
    keeping an unlisted-context error's own (allowlist) message."""
    try:
        return function(*args)
    except Exception as exc:          # pyld's JsonLdError, RecursionError, ...
        cause: Optional[BaseException] = exc
        while cause is not None:                    # unwrap pyld's JsonLdError
            if isinstance(cause, UnknownContextError):
                raise OB3VerificationError(str(cause)) from exc
            cause = cause.__cause__
        raise OB3VerificationError(
            "cannot validate the JSON-LD form of the %s: %s"
            % (what, str(exc)[:300])) from exc


# ── safe mode on the expanded form ──────────────────────────────────────────

def _is_predicate(value: Any) -> bool:
    return isinstance(value, str) and not value.startswith("_:") and bool(
        _RDF_IRI.match(value))


def _is_node_iri(value: Any) -> bool:
    return isinstance(value, str) and bool(_RDF_IRI.match(value))


def _check_expanded(value: Any, top_id: Any, what: str, *, top: bool = False,
                    via: Optional[str] = None) -> None:
    """Walk the expanded form: refuse the keywords that detach statements from
    their node, a nested re-description of the document's own node, and
    anything the RDF conversion would silently drop -- so the dataset holds
    exactly what the JSON says. *via* is the predicate that led here."""
    if isinstance(value, list):
        for item in value:
            _check_expanded(item, top_id, what, via=via)
        return
    if not isinstance(value, dict):
        return
    for keyword in _REFUSED_KEYWORDS:
        if keyword in value:
            raise OB3VerificationError(
                "the %s uses %s, which is not accepted" % (what, keyword))
    if "@value" in value:
        return                   # a literal (even an @json one) is data
    if "@id" in value and not _is_node_iri(value["@id"]):
        raise OB3VerificationError(
            "the %s has a node id the signed dataset drops: %s"
            % (what, _brief(value["@id"])))
    rdf_types = value.get("@type", [])
    for rdf_type in (rdf_types if isinstance(rdf_types, list) else [rdf_types]):
        if not _is_node_iri(rdf_type):
            raise OB3VerificationError(
                "the %s has a type the signed dataset drops: %s"
                % (what, _brief(rdf_type)))
    if (not top and isinstance(top_id, str) and value.get("@id") == top_id
            and set(value) - {"@id"}
            and not (via == _REFRESH_SERVICE
                     and set(value) == {"@id", "@type"})):
        raise OB3VerificationError(
            "the %s's own node %s is described again inside it"
            % (what, _brief(top_id)))
    for key, item in value.items():
        if not key.startswith("@") and not _is_predicate(key):
            raise OB3VerificationError(
                "the %s has a property the signed dataset drops: %s"
                % (what, _brief(key)))
        if key not in ("@id", "@type"):
            _check_expanded(item, top_id, what,
                            via=None if key.startswith("@") else key)


# ── compacted-form comparison ───────────────────────────────────────────────

def _detach(value: Any, path: _Path,
            embedded: Optional[List[Tuple[_Path, dict[str, Any]]]]) -> Any:
    """Copy *value* with every ``endorsement`` entry replaced by a stand-in.

    On the document side (*embedded* is a list) only entries that carry their
    own ``@context`` are detached -- and collected for their own validation;
    any other entry stays and so fails against the compacted side, where
    (*embedded* is None) every entry is detached: compaction never re-emits a
    nested @context, so a conforming embedded credential always differs there.
    """
    if isinstance(value, list):
        return [_detach(item, path + (index,), embedded)
                for index, item in enumerate(value)]
    if not isinstance(value, dict):
        return value
    copied: Dict[str, Any] = {}
    for key, item in value.items():
        if key != _ENDORSEMENT:
            copied[key] = _detach(item, path + (key,), embedded)
            continue
        entries = item if isinstance(item, list) else [item]
        detached: List[Any] = []
        for index, entry in enumerate(entries):
            where = path + (key,) + ((index,) if isinstance(item, list) else ())
            if embedded is None:
                detached.append(_EMBEDDED)
            elif isinstance(entry, dict) and "@context" in entry:
                embedded.append((where, entry))
                detached.append(_EMBEDDED)
            else:
                detached.append(_detach(entry, where, embedded))
        copied[key] = detached if isinstance(item, list) else detached[0]
    return copied


def _fold(value: Any, path: _Path) -> Tuple[Any, _Path]:
    """Fold the two spellings JSON-LD compaction treats as one: ``[x]`` ->
    ``x`` and the node reference ``{"id": X}`` -> ``X`` (``id`` is the
    protected ``@id`` alias of the VC 2.0 context). Tracks the path into the
    original structure.

    ``[x]`` folds only when *x* is not itself an array: expansion flattens an
    array nested in an array (outside ``@list``), so ``[[S]]`` keeps the
    dataset -- and the signature -- of ``S`` while every JSON reader that
    expects an object (the status checker, the model) skips it. Folding it
    away would hide exactly that difference."""
    while True:
        if (isinstance(value, list) and len(value) == 1
                and not isinstance(value[0], list)):
            value, path = value[0], path + (0,)
        elif isinstance(value, dict) and set(value) == {"id"}:
            value, path = value["id"], path + ("id",)
        else:
            return value, path


def _difference(ours: Any, theirs: Any, path: _Path) -> Optional[_Path]:
    """Path (into *ours*) of the first difference between the document and its
    compacted form, or None. Synonymous ``type`` terms are not a difference
    (see adaptation (b) in the module comment)."""
    ours, path = _fold(ours, path)
    theirs, _ = _fold(theirs, ())
    if ours is _EMBEDDED or theirs is _EMBEDDED:
        return None if ours is theirs else path
    if isinstance(ours, dict) and isinstance(theirs, dict):
        for key in sorted(set(ours) | set(theirs)):
            if key not in ours or key not in theirs:
                return path + (key,)
            if key == "type":
                where = _type_difference(ours[key], theirs[key], path + (key,))
            else:
                where = _difference(ours[key], theirs[key], path + (key,))
            if where is not None:
                return where
        return None
    if isinstance(ours, list) and isinstance(theirs, list):
        if len(ours) != len(theirs):
            return path
        for index, (mine, other) in enumerate(zip(ours, theirs)):
            # [x] == x holds for a property value only, never for an array
            # element: an array directly inside an array is either a
            # @list-of-lists (both sides carry it) or a flattened spelling
            # compaction never produces ([S1, [S2]] for [S1, S2]).
            if isinstance(mine, list) is not isinstance(other, list):
                return path + (index,)
            where = _difference(mine, other, path + (index,))
            if where is not None:
                return where
        return None
    return None if _canonical(ours) == _canonical(theirs) else path


def _is_term(value: Any) -> bool:
    return (isinstance(value, str) and bool(value) and ":" not in value
            and not value.startswith("@"))


def _type_difference(ours: Any, theirs: Any, path: _Path) -> Optional[_Path]:
    mine = ours if isinstance(ours, list) else [ours]
    other = theirs if isinstance(theirs, list) else [theirs]
    if len(mine) != len(other):
        return path
    for index, (a, b) in enumerate(zip(mine, other)):
        if isinstance(a, str) and a == b:
            continue
        if _is_term(a) and _is_term(b) and _synonyms(a, b):
            continue
        return path + ((index,) if isinstance(ours, list) else ())
    return None


def _synonyms(a: str, b: str) -> bool:
    names = _type_synonyms()
    return bool(names.get(a, frozenset()) & names.get(b, frozenset()))


@functools.lru_cache(maxsize=1)
def _type_synonyms() -> Dict[str, FrozenSet[str]]:
    """term -> every IRI some bundled context (top level or type/property
    scoped) defines it as. Derived, not hand-written, so a context bump that
    adds a synonym shows up in the tests rather than as a silent tolerance."""
    names: Dict[str, Set[str]] = {}
    for document in bundled_contexts().values():
        context = document.get("@context")
        for entry in (context if isinstance(context, list) else [context]):
            if isinstance(entry, dict):
                _collect_terms(entry, names)
    return {term: frozenset(iris) for term, iris in names.items()}


def _collect_terms(context: Dict[str, Any], names: Dict[str, Set[str]]) -> None:
    for term, definition in context.items():
        if term.startswith("@"):
            continue
        iri = definition.get("@id") if isinstance(definition, dict) else definition
        resolved = _resolve_definition(iri, context)
        if resolved is not None:
            names.setdefault(term, set()).add(resolved)
        if isinstance(definition, dict) and isinstance(definition.get("@context"), dict):
            _collect_terms(definition["@context"], names)


def _resolve_definition(iri: Any, context: Dict[str, Any]) -> Optional[str]:
    """The absolute IRI a term definition's ``@id`` names: itself, a compact
    IRI over a prefix the same context defines, or another term of that
    context (``"AchievementCredential": {"@id": "OpenBadgeCredential"}``)."""
    if not isinstance(iri, str) or iri.startswith("@"):
        return None
    prefix, colon, suffix = iri.partition(":")
    if not colon or not suffix.startswith("//"):
        target = context.get(prefix if colon else iri)
        target = target.get("@id") if isinstance(target, dict) else target
        if isinstance(target, str) and ":" in target and not target.startswith("@"):
            return target + suffix if colon else target
        if not colon:
            return None
    return iri


# ── term spelling of defined IRIs ───────────────────────────────────────────

def _stub_json_literals(value: Any) -> Any:
    """*value* (expanded form) with the content of every ``@json`` literal
    replaced by 0, or *value* itself when it holds none."""
    if isinstance(value, list):
        items = [_stub_json_literals(item) for item in value]
        changed = any(new is not old for new, old in zip(items, value))
        return items if changed else value
    if not isinstance(value, dict):
        return value
    if "@value" in value:
        return dict(value, **{"@value": 0}) if value.get("@type") == "@json" else value
    copied = {key: _stub_json_literals(item) for key, item in value.items()}
    changed = any(copied[key] is not value[key] for key in value)
    return copied if changed else value


def _inline_vocabs(context: Any) -> List[str]:
    entries = context if isinstance(context, list) else [context]
    return [entry["@vocab"] for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("@vocab"), str)]


def _misspelled_key(value: Any, path: _Path, vocabs: List[str]) -> Optional[_Path]:
    """Path of the first key of the compacted form *value* that stands for an
    IRI some pinned context defines a term for without being one of those
    terms, or None (see the module comment)."""
    if isinstance(value, list):
        for index, item in enumerate(value):
            where = _misspelled_key(item, path + (index,), vocabs)
            if where is not None:
                return where
        return None
    if not isinstance(value, dict) or "@value" in value:
        return None                  # a literal is data, not properties
    spellings = _term_spellings()
    for key, item in value.items():
        if key == "@context":
            continue
        if not key.startswith("@"):
            for iri in _key_iris(key, vocabs):
                if iri in spellings and key not in spellings[iri]:
                    return path + (key,)
        where = _misspelled_key(item, path + (key,), vocabs)
        if where is not None:
            return where
    return None


def _key_iris(key: str, vocabs: List[str]) -> List[str]:
    """The IRIs a non-keyword key of the compacted form may stand for. With a
    colon: itself, or a compact IRI over a term. Without one: a term (checked
    by spelling, not resolved) or a suffix of an inline ``@vocab`` -- no
    pinned context sets one. A superset, so the check fails closed."""
    if ":" not in key:
        return [vocab + key for vocab in vocabs]
    prefix, _, suffix = key.partition(":")
    iris = [key]
    if not suffix.startswith("//"):
        iris.extend(base + suffix for base in _type_synonyms().get(prefix, ()))
    return iris


@functools.lru_cache(maxsize=1)
def _term_spellings() -> Dict[str, FrozenSet[str]]:
    """IRI -> every term some bundled context defines as it (the inverse of
    _type_synonyms)."""
    spellings: Dict[str, Set[str]] = {}
    for term, iris in _type_synonyms().items():
        for iri in iris:
            spellings.setdefault(iri, set()).add(term)
    return {iri: frozenset(terms) for iri, terms in spellings.items()}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      allow_nan=False)


def _pointer(path: _Path) -> str:
    return "/" + "/".join(str(step) for step in path)


def _brief(value: Any) -> str:
    return repr(value)[:100] if isinstance(value, str) else type(value).__name__


__all__ = ["VC2_CONTEXT", "validate_document"]
