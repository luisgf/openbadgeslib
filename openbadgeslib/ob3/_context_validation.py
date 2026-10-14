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
# Ported from openvc (openvc.proof._context_validation, openvc-core 1.30.2,
# with the rules 1.33.2 added; same author, LGPL-3.0-or-later), with the
# OB 3.0 adaptations listed below.
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
# first, then only URLs the fail-closed bundled loader serves, each context
# document once and at most eight entries, so the JSON-LD processor's
# per-entry cost stays bounded -- and the expansion must carry no statement
# the RDF conversion would drop (JSON-LD "safe mode"). Those context bounds
# hold for every @context the processor applies, and are checked before it
# runs (_check_nested_contexts): below the top level only an embedded
# endorsement credential may carry one (adaptation (a)), and the credentials
# embedded are bounded in number, depth and total size, since each is
# expanded and compacted again on its own. Any other nested @context (outside
# an @json literal) would be refused by the comparison below anyway --
# compaction never re-emits one -- but only after the processor had spent the
# CPU to apply it, on unauthenticated input. No inline context object is
# accepted, not even one carrying only an @vocab (which openvc
# tolerates): OB 3.0 credentials name only published contexts, and an inline
# @vocab is a holder-chosen vocabulary that respells any IRI as a bare key
# (``Until`` under {"@vocab": ".../credentials#valid"}), so it could only add
# spellings to refuse. The comparison tolerates exactly the two spellings
# JSON-LD treats as identical -- a one-element array vs its element (as a
# property value; never an array inside an array, which expansion flattens
# but JSON readers do not), and a node reference {"id": X} vs X -- compared
# as canonical JSON so true/1 and 1/1.0 stay distinct.
#
# Being the compacted form is necessary but not sufficient. Compaction only
# folds a statement into a term when the value matches the term's definition;
# otherwise it keeps the predicate's absolute IRI (or a compact IRI) as the
# key -- and that spelling IS the compacted form. So a validUntil, validFrom
# or proof ``expires`` written as a plain (untyped) string under its absolute
# IRI signs an untyped literal, survives the comparison unchanged, and is
# invisible to the reader of ``validUntil``: an issuer-signed expired
# credential would verify as never expiring. Hence the second rule
# (_misspelled_key): in the compacted form, a key -- or a ``type`` value,
# which compaction spells the same vocabulary-relative way -- whose IRI some
# pinned context defines a term for must be one of those terms. A conforming
# document always uses the terms, so only such shapes are refused; extension
# IRIs no pinned context defines are left alone.
#
# Above that rule, an IRI the checks after the proof read (_POLICY_TERMS: the
# validity window of both VC data models, the proof's ``expires``,
# credentialStatus, credentialSchema, credentialSubject, issuer, and the
# status entry types and members of both status-list families) may only be
# spelled by the one key (or type) the policy reads it under, whether or not
# a pinned context defines it, and whatever term a pinned context gives it.
# issuanceDate / expirationDate have a term only in the VC 1.1 context and
# StatusList2021Entry and its members only in the StatusList2021 one, and
# neither is bundled. OB 3.0 was first published on VCDM 1.1, so issuers
# signed such badges, which are refused under their own @context; but a
# holder can re-compact one onto [VC 2.0, OB 3.0]: the dataset and the
# signature stay the same, compaction spells those members by full IRI, and
# the model, which reads validUntil / validFrom (then issuanceDate /
# expirationDate), saw no expiry, no not-before and no status entry type it
# knew.
#
# Third (_check_status_in_place), a credentialStatus entry is described where
# the status check reads it. RDF lets a node referenced from two properties be
# described under either, so when the issuer also names its status entry from
# another property (relatedResource: [{"id": S}], an endorsement's own
# credentialStatus, ...), a holder can move a signed member -- a statusSize
# of 2, say -- out from under credentialStatus with the dataset and the
# signature unchanged, and the status check then reads the wrong bit. So a
# node directly under the top-level credentialStatus whose @id is described
# anywhere else in the expanded document (any member besides @id) is
# refused, but see adaptation (d). The cost, as in openvc: an issuer-signed
# credential that describes its status node under a second property with
# more than its id is refused too.
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
#     @context (or that is not an EndorsementCredential) is refused. Any other
#     @context below the top level is refused before expansion, even one
#     inside an @json literal (``_sd``), whose keys are data the processor
#     never applies: telling those apart before expansion would mean
#     resolving terms, and no OB 3.0 credential needs the shape.
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
# (d) A description of a credentialStatus entry elsewhere is tolerated when it
#     is an exact copy of the entry (equal expanded node objects): an
#     embedded endorsement may carry the outer credential's credentialStatus
#     verbatim, as in the credential the tests model on the 1EdTech example.
#     RDF merges the two into the same statements, so a copy carries nothing
#     the entry lacks; moving any member out of the entry makes the two
#     differ, and is refused.

import functools
import json
import re

from types import MappingProxyType
from typing import (Any, Callable, Dict, FrozenSet, Iterable, List, Mapping,
                    Optional, Set, Tuple, Union)

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

_CRED = "https://www.w3.org/2018/credentials#"
_REFRESH_SERVICE = _CRED + "refreshService"
_CREDENTIAL_STATUS = _CRED + "credentialStatus"
_STATUS = "https://www.w3.org/ns/credentials/status#"
_STATUS_LIST_2021 = "https://w3id.org/vc/status-list#"

# The IRIs the checks after the proof read, each with the one key (or type
# value) they read it under: the validity window (credential.py, both VC data
# models; _check_validity_window), the proof's expiry (_validate_proof), the
# status entries of both status-list families (status.py and
# _reject_unsigned_ldp_aliases), credentialSchema, and the issuer and subject
# the model, the issuer binding and _check_recipient read. In the compacted
# form such an IRI may only be spelled by that key, whatever a pinned context
# defines (see the module comment): a static table, not one derived from the
# bundled contexts, because the VC 1.1 and StatusList2021 contexts that give
# some of them a term are deliberately not bundled.
_POLICY_TERMS: Mapping[str, str] = MappingProxyType({
    _CRED + "validFrom": "validFrom",
    _CRED + "validUntil": "validUntil",
    _CRED + "issuanceDate": "issuanceDate",                 # VC 1.1 only
    _CRED + "expirationDate": "expirationDate",             # VC 1.1 only
    _CREDENTIAL_STATUS: "credentialStatus",
    _CRED + "credentialSchema": "credentialSchema",
    _CRED + "credentialSubject": "credentialSubject",
    _CRED + "issuer": "issuer",
    "https://w3id.org/security#expiration": "expires",
    _STATUS + "BitstringStatusListEntry": "BitstringStatusListEntry",
    _STATUS + "statusPurpose": "statusPurpose",
    _STATUS + "statusListIndex": "statusListIndex",
    _STATUS + "statusListCredential": "statusListCredential",
    _STATUS + "statusSize": "statusSize",
    _STATUS_LIST_2021 + "StatusList2021Entry": "StatusList2021Entry",
    _STATUS_LIST_2021 + "statusPurpose": "statusPurpose",
    _STATUS_LIST_2021 + "statusListIndex": "statusListIndex",
    _STATUS_LIST_2021 + "statusListCredential": "statusListCredential",
})

# The keys of the compacted form whose values are type IRIs: "type" is the
# VC 2.0 (and OB 3.0) alias of @type.
_TYPE_KEYS = ("type", "@type")

_ENDORSEMENT = "endorsement"
_ENDORSEMENT_CREDENTIAL = "EndorsementCredential"

# Stand-in for a detached embedded credential in both sides of the outer
# comparison: an object no JSON document can contain, only ever equal to itself.
_EMBEDDED = object()

# Embedded credentials may nest (an endorsement's issuer Profile can carry
# endorsements); real documents stop at one or two levels.
_MAX_EMBEDDED_DEPTH = 8

# At most this many embedded credentials in all, at any depth: each costs its
# own expansion and compaction. The 1EdTech "Complete OpenBadgeCredential"
# example embeds five.
_MAX_EMBEDDED_CREDENTIALS = 64

# Each embedded credential is expanded and compacted again on its own, so
# JSON nested k credentials deep is processed k + 1 times: without a bound a
# chain of eight endorsements made a document cost nine times its size. The
# embedded credentials' compact JSON, each counted in full (a nested one once
# per credential that holds it), may total at most this many characters --
# the size the verifier caps the whole document at
# (ldp.MAX_LDP_DOCUMENT_BYTES), so endorsements one level deep, which never
# overlap, fit.
_MAX_EMBEDDED_SIZE = 256 * 1024

# A conforming OB 3.0 credential lists two to four contexts (VC 2.0, OB 3.0,
# the extensions, perhaps a Data Integrity one).
_MAX_CONTEXT_ENTRIES = 8

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
    if depth == 0:
        # The expansion below also applies every nested @context, those of
        # the embedded credentials validated after it included.
        _check_nested_contexts(document, loader, what)
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
    _check_status_in_place(node, what)

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
    where = _misspelled_key(theirs, ())
    if where is not None:
        raise OB3VerificationError(
            "the %s spells a property (or a type) a pinned context defines, or "
            "one the policy reads, other than by its term (at %s): its value "
            "does not match the term's definition (an untyped date, a literal "
            "for a node, ...) or the context defining the term is not bundled "
            "(VC 1.1, StatusList2021), so the member the policy reads does not "
            "carry what was signed" % (what, _pointer(where)))

    for path, credential in embedded:
        _check_embedded(credential, path, loader, jsonld, what=what,
                        depth=depth + 1)


def _check_embedded(credential: dict[str, Any], path: _Path, loader: _Loader,
                    jsonld: Any, *, what: str, depth: int) -> None:
    """Validate an embedded EndorsementCredential against its own @context
    (already bounded, as its nesting, by _check_nested_contexts)."""
    where = _embedded_where(path, what)
    types = credential.get("type")
    types = [types] if isinstance(types, str) else types
    if not (isinstance(types, list) and _ENDORSEMENT_CREDENTIAL in types):
        raise OB3VerificationError("%s is not an %s"
                                   % (where, _ENDORSEMENT_CREDENTIAL))
    _check_form(credential, loader, jsonld, what=where, depth=depth)


def _check_context(context: Any, loader: _Loader, what: str) -> None:
    """The VC 2.0 base context first, then only bundled URLs -- no inline
    context object -- each context document once and at most
    _MAX_CONTEXT_ENTRIES entries in all. Runs before any expansion, so an
    inline definition or @vocab never reaches the JSON-LD processor -- nor
    does a padded list: pyld re-processes a context once per entry, so a
    pinned URL repeated thousands of times cost seconds of CPU per pass, on
    unauthenticated input, before any key was resolved."""
    entries = [context] if isinstance(context, str) else context
    if not isinstance(entries, list) or not entries:
        raise OB3VerificationError(
            "the %s @context must be a URL or a non-empty array" % what)
    if entries[0] != VC2_CONTEXT:
        raise OB3VerificationError(
            "the first @context entry of the %s must be the VC 2.0 base "
            "context %r" % (what, VC2_CONTEXT))
    if len(entries) > _MAX_CONTEXT_ENTRIES:
        raise OB3VerificationError(
            "the %s @context lists %d entries; at most %d are accepted"
            % (what, len(entries), _MAX_CONTEXT_ENTRIES))
    documents: Set[str] = set()
    for entry in entries:
        if not (isinstance(entry, str) and entry):
            # An object (term definitions, an @vocab, ...), null, a number:
            # OB 3.0 credentials name only published contexts.
            raise OB3VerificationError(
                "the %s carries an inline @context object (or another entry "
                "that is not a context URL: %s); only the pinned context URLs "
                "are accepted" % (what, _brief(entry)))
        try:
            loaded = loader(entry)       # fail-closed allowlist, no network
        except UnknownContextError as exc:
            raise OB3VerificationError(str(exc)) from exc
        # By document, not URL: an alias (context.json) of a listed URL
        # (context-3.0.3.json) applies the very same definitions again.
        document = _canonical(loaded.get("document")
                              if isinstance(loaded, dict) else loaded)
        if document in documents:
            raise OB3VerificationError(
                "the %s @context lists the context %r when the same "
                "context document is already listed" % (what, entry))
        documents.add(document)


def _check_nested_contexts(document: dict[str, Any], loader: _Loader,
                           what: str) -> None:
    """Bound, before any JSON-LD processing, every @context below the top
    level of *document* (whose own @context _check_context has bounded): an
    embedded endorsement credential's -- an ``endorsement`` entry carrying
    one, exactly as _detach picks them -- is held to _check_context, and the
    embedded credentials to _MAX_EMBEDDED_DEPTH, _MAX_EMBEDDED_CREDENTIALS
    and _MAX_EMBEDDED_SIZE; any other is refused. Iterative, so a deeply
    nested document reaches the processor's own recursion limit, not this.

    pyld applies a nested @context, entry by entry, as it reaches it, so
    checking only the top-level one let a padded @context on
    credentialSubject (refused only afterwards, by the comparison) cost
    seconds of CPU on unauthenticated input."""
    embedded = 0
    size = 0
    # (value, its path inside the innermost document holding it, that
    #  document's description, its embedding depth, whether value is an
    #  ``endorsement`` entry)
    stack: List[Tuple[Any, _Path, str, int, bool]] = [
        (document, (), what, 0, False)]
    while stack:
        value, path, where, depth, entry = stack.pop()
        if isinstance(value, list):
            stack.extend((item, path + (index,), where, depth, False)
                         for index, item in reversed(list(enumerate(value))))
            continue
        if not isinstance(value, dict):
            continue
        if "@context" in value and value is not document:
            if not entry:
                raise OB3VerificationError(
                    "the %s carries an @context below its top level (at %s): "
                    "only an embedded endorsement credential may carry its "
                    "own" % (where, _pointer(path + ("@context",))))
            where, depth, path = _embedded_where(path, where), depth + 1, ()
            embedded += 1
            if depth > _MAX_EMBEDDED_DEPTH:
                raise OB3VerificationError(
                    "%s nests embedded credentials too deeply" % where)
            if embedded > _MAX_EMBEDDED_CREDENTIALS:
                raise OB3VerificationError(
                    "the %s embeds more than %d credentials (endorsements, "
                    "at any depth)" % (what, _MAX_EMBEDDED_CREDENTIALS))
            size += len(json.dumps(value, ensure_ascii=False,
                                   separators=(",", ":")))
            if size > _MAX_EMBEDDED_SIZE:
                raise OB3VerificationError(
                    "the credentials embedded in the %s total more than %d "
                    "characters of JSON, a nested one counted once per "
                    "credential that holds it (each is validated again on "
                    "its own)" % (what, _MAX_EMBEDDED_SIZE))
            _check_context(value["@context"], loader, where)
        for key, item in reversed(list(value.items())):
            if key == "@context":
                continue                # bounded above, or the top level's
            if key == _ENDORSEMENT and isinstance(item, list):
                stack.extend((member, path + (key, index), where, depth, True)
                             for index, member in reversed(list(enumerate(item))))
            else:
                stack.append((item, path + (key,), where, depth,
                              key == _ENDORSEMENT))


def _embedded_where(path: _Path, what: str) -> str:
    return "endorsement at %s of the %s" % (_pointer(path), what)


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


def _check_status_in_place(node: dict[str, Any], what: str) -> None:
    """Refuse a ``credentialStatus`` entry of the top-level *node* (expanded
    form) whose ``@id`` is also described -- given any member besides
    ``@id`` -- anywhere else in it, unless that description is an exact copy
    of the entry (see adaptation (d) in the module comment). The whole
    expanded node is walked: embedded endorsements, ``@list`` and ``@graph``
    values, and a nested node's own ``credentialStatus`` included."""
    entries: Dict[str, Set[str]] = {}
    for entry in _as_items(node.get(_CREDENTIAL_STATUS)):
        if isinstance(entry, dict) and isinstance(entry.get("@id"), str):
            entries.setdefault(entry["@id"], set()).add(_canonical(entry))
    if not entries:
        return
    moved = _status_described_elsewhere(node, entries, top=True)
    if moved is not None:
        raise OB3VerificationError(
            "the %s's credentialStatus entry %s is described outside "
            "credentialStatus, where the status check does not read it"
            % (what, _brief(moved)))


def _as_items(value: Any) -> List[Any]:
    if isinstance(value, dict) and "@list" in value:
        value = value["@list"]
    return value if isinstance(value, list) else [] if value is None else [value]


def _status_described_elsewhere(value: Any, entries: Dict[str, Set[str]], *,
                                top: bool = False,
                                in_status: bool = False) -> Optional[str]:
    """The ``@id`` of the first node object outside the top-level
    ``credentialStatus`` that describes one of *entries* (``@id`` -> the
    canonical forms of its entries there) other than as an exact copy, or
    None. *in_status* marks the entries themselves, which are not checked
    but are walked: a description nested inside one is elsewhere too."""
    if isinstance(value, list):
        for item in value:
            found = _status_described_elsewhere(item, entries)
            if found is not None:
                return found
        return None
    if not isinstance(value, dict) or "@value" in value:
        return None                     # a literal (even an @json one) is data
    if "@list" in value:
        return _status_described_elsewhere(value["@list"], entries,
                                           in_status=in_status)
    node_id = value.get("@id")
    if (not in_status and isinstance(node_id, str) and node_id in entries
            and set(value) - {"@id"}
            and _canonical(value) not in entries[node_id]):
        return node_id
    for key, item in value.items():
        if key in ("@id", "@type"):
            continue
        if top and key == _CREDENTIAL_STATUS:
            for entry in _as_items(item):
                found = _status_described_elsewhere(entry, entries,
                                                    in_status=True)
                if found is not None:
                    return found
            continue
        found = _status_described_elsewhere(item, entries)
        if found is not None:
            return found
    return None


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


def _misspelled_key(value: Any, path: _Path) -> Optional[_Path]:
    """Path of the first key -- or ``type`` value -- of the compacted form
    *value* that stands for an IRI some pinned context defines a term for
    without being one of those terms, or for an IRI the policy reads
    (_POLICY_TERMS) without being the key it reads, or None (see the module
    comment)."""
    if isinstance(value, list):
        for index, item in enumerate(value):
            where = _misspelled_key(item, path + (index,))
            if where is not None:
                return where
        return None
    if not isinstance(value, dict) or "@value" in value:
        return None                  # a literal is data, not properties
    for key, item in value.items():
        if key == "@context":
            continue
        if not key.startswith("@") and _is_misspelled(key):
            return path + (key,)
        if key in _TYPE_KEYS:
            # A type is vocabulary-relative like a key, so compaction keeps an
            # IRI no term in scope names (StatusList2021Entry) in full, on
            # both sides of the comparison: the status check, for one, then
            # skips an entry whose type it does not know.
            many = isinstance(item, list)
            for index, spelling in enumerate(item if many else [item]):
                if (isinstance(spelling, str) and not spelling.startswith("@")
                        and _is_misspelled(spelling)):
                    return path + (key,) + ((index,) if many else ())
        where = _misspelled_key(item, path + (key,))
        if where is not None:
            return where
    return None


def _is_misspelled(spelling: str) -> bool:
    """Whether *spelling* (a non-keyword key or type of the compacted form)
    may stand for an IRI in _POLICY_TERMS without being the one key the
    policy reads it under, or for another IRI some pinned context defines a
    term for without being one of those terms."""
    spellings = _term_spellings()
    for iri in _key_iris(spelling):
        policy_term = _POLICY_TERMS.get(iri)
        terms = (frozenset((policy_term,)) if policy_term is not None
                 else spellings.get(iri))
        if terms and spelling not in terms:
            return True
    return False


def _key_iris(key: str) -> Iterable[str]:
    """The IRIs a non-keyword key (or type) of the compacted form may stand
    for. Without a colon: every IRI some pinned context defines that term as,
    in any scope (no pinned context sets @vocab and no inline context is
    accepted, so a bare key that is no term is dropped by expansion, which
    the comparison refuses). With one: itself, or a compact IRI over a term.
    A superset, so the check fails closed."""
    if ":" not in key:
        return _type_synonyms().get(key, frozenset())
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
