"""Structural limits on an untrusted Data Integrity document —
ob3/_structure_screen.py, wired into ob3/ldp.py.

pyld applies a type-scoped @context once per entry of every node's ``type``
array (duplicates included) and once per typed node, in expansion and again
in compaction, and the document-size cap does not bound that: 22,500 repeated
types over ~300 nodes (258 KB) cost 9 to 11 s of CPU through
``OB3LdpVerifier.verify`` and ended in "signature mismatch"; so did a flood of
~7,000 distinct typed nodes and the same shapes inside one embedded
endorsement (12 to 15 s). These tests pin that

* the screen counts what it claims to and refuses a document over a limit
  before any JSON-LD processor runs (a pyld call on a refused document
  fails the test);
* it is wired in front of every Data Integrity entry point, with the strict
  limits where context validation runs after it and the doubled ones where it
  does not;
* its message names the limit and never echoes the document;
* what real credentials look like (the "Complete OpenBadgeCredential" model,
  a badge with 200 alignments, 500 evidence entries and 50 results, a CLR of
  100 signed member badges) is untouched.

The screen itself needs no pyld; the end-to-end tests do and skip without it.
"""
import copy
import importlib.util
import json
import time

import pytest

from openbadgeslib.errors import ErrorSigningFile
from openbadgeslib.ob3 import (
    OB3LdpSigner, OB3LdpVerifier, OB3VerificationError,
    add_data_integrity_proof, verify_data_integrity_proof)
from openbadgeslib.ob3 import ldp

from ldp_helpers import b58encode, did_key

HAS_PYLD = importlib.util.find_spec('pyld') is not None
needs_pyld = pytest.mark.skipif(not HAS_PYLD, reason='needs the [ldp] extra')

VC2 = 'https://www.w3.org/ns/credentials/v2'
OB3 = 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'
REFUSED = 'refusing the credential'
SENTINEL = 'SENTINEL-TYPE-NAME'


def _screen():
    """The module under test, imported late so that a tree without it fails
    these tests one by one instead of failing the collection."""
    from openbadgeslib.ob3 import _structure_screen
    return _structure_screen


# ── documents ────────────────────────────────────────────────────────────────

def _node(*types, **members):
    node = dict(members)
    if types:
        node['type'] = list(types)
    return node


def _credential(**members):
    """A small OB3 credential shape (never signed: the screen reads JSON)."""
    doc = {
        '@context': [VC2, OB3],
        'id': 'urn:uuid:00000000-0000-0000-0000-0000000000c1',
        'type': ['VerifiableCredential', 'OpenBadgeCredential'],
        'issuer': {'id': 'did:example:issuer', 'type': ['Profile'],
                   'name': 'Issuer'},
        'validFrom': '2026-01-01T00:00:00Z',
        'name': 'Badge',
        'credentialSubject': {
            'id': 'did:example:subject', 'type': ['AchievementSubject'],
            'achievement': {
                'id': 'urn:uuid:00000000-0000-0000-0000-0000000000a1',
                'type': ['Achievement'], 'name': 'A', 'description': 'd',
                'criteria': {'narrative': 'n'}}},
    }
    doc.update(members)
    return doc


def _tree(count, types, fan=25, ids=True):
    """*count* nodes with *types*, nested through the propagating
    ``alignment`` term so that no single property holds many values."""
    made = [0]

    def make():
        node = {'type': list(types)} if types else {}
        if ids:
            made[0] += 1
            node['id'] = 'https://x.example/n/%d' % made[0]
        return node
    root = make()
    level, total = [root], 1
    while total < count:
        following = []
        for parent in level:
            kids = []
            while len(kids) < fan and total < count:
                kid = make()
                kids.append(kid)
                following.append(kid)
                total += 1
            if kids:
                parent['alignment'] = kids
        level = following
    return root


def _endorsement(number, **members):
    doc = {
        '@context': [VC2, OB3],
        'id': 'https://e.example/e/%d' % number,
        'type': ['VerifiableCredential', 'EndorsementCredential'],
        'issuer': {'id': 'https://e.example/i', 'type': ['Profile'],
                   'name': 'E'},
        'validFrom': '2026-01-01T00:00:00Z',
        'name': 'Endorsement',
        'credentialSubject': {'id': 'did:example:issuer',
                              'type': ['EndorsementSubject'],
                              'endorsementComment': 'ok'},
    }
    doc.update(members)
    return doc


def _chain(depth, **innermost):
    """*depth* endorsements, each inside the previous one's issuer."""
    cur = _endorsement(depth, **innermost)
    for level in range(depth - 1, 0, -1):
        outer = _endorsement(level)
        outer['issuer'] = {'id': 'https://e.example/i%d' % level,
                           'type': ['Profile'], 'name': 'E',
                           'endorsement': [cur]}
        cur = outer
    return cur


def _evidence(doc, nodes):
    doc = copy.deepcopy(doc)
    doc['evidence'] = nodes
    return doc


def _hostile(scale=1):
    """name -> document: shapes that cost seconds through pyld (the first
    three on the published 4.6.2 as they stand), each over the limits that
    apply with *scale* (1: the verifier and the signer, 2: the low-level
    functions)."""
    s = _screen()
    base = _credential()
    return {
        'dupmany': _evidence(base, [_node(*(['Profile'] * 75))
                                    for _ in range(300)]),
        'one-node-20000-types': _evidence(base, [_node(*(['Profile'] * 20000))]),
        'dup-in-an-endorsement': dict(base, endorsement=[
            _endorsement(1, evidence=[_node(*(['Profile'] * 75))
                                      for _ in range(300)])]),
        'distinct-typed-flood': _evidence(
            base, [_tree(scale * s.MAX_TYPED_NODES + 100, ['Profile'])]),
        'two-types-per-node': _evidence(
            base, [_tree(scale * s.MAX_TYPE_ENTRIES // 2 + 50,
                         ['Achievement', 'Profile'])]),
        'untyped-flood': _evidence(
            base, [_tree(scale * s.MAX_NODES + 100, [], ids=False)]),
        'scoped-property-flood': _evidence(base, [
            {'cnf': {'kid': 'https://x.example/k/%d' % i}}
            for i in range(scale * s.MAX_TYPE_ENTRIES + 100)]),
        'endorsed-flood': dict(base, endorsement=[_endorsement(
            1, evidence=[_tree(scale * s.MAX_TYPED_NODES // 2 + 50,
                               ['Profile'])])]),
    }


HOSTILE = ['dupmany', 'one-node-20000-types', 'dup-in-an-endorsement',
           'distinct-typed-flood', 'two-types-per-node', 'untyped-flood',
           'scoped-property-flood', 'endorsed-flood']


@pytest.fixture(scope='module')
def keypair():
    from openbadgeslib.keys import KeyEd25519
    return KeyEd25519().generate_keypair()


def _secured(doc, pub_pem):
    secured = copy.deepcopy(doc)
    did = did_key(pub_pem)
    secured['proof'] = {
        'type': 'DataIntegrityProof', 'cryptosuite': 'eddsa-rdfc-2022',
        'created': '2026-07-03T00:00:00Z',
        'verificationMethod': '%s#%s' % (did, did[len('did:key:'):]),
        'proofPurpose': 'assertionMethod',
        'proofValue': 'z' + b58encode(bytes([7]) * 64)}
    return secured


class Reached(Exception):
    """A step that must not run on a refused document."""


@pytest.fixture()
def no_json_ld(monkeypatch):
    """Make any JSON-LD processing fail the test: the screen must refuse
    before pyld (and before the canonicalizer) sees the document."""
    def reached(*args, **kwargs):
        raise Reached('the JSON-LD processor was reached')
    monkeypatch.setattr(ldp, '_require_jsonld', reached)
    monkeypatch.setattr(ldp, '_canonize', reached)
    monkeypatch.setattr(ldp, '_hash_data', reached)


# ── the screen itself ────────────────────────────────────────────────────────

class TestCounting:
    def test_counts_a_plain_document(self):
        doc = {'@context': [VC2, OB3],
               'type': ['VerifiableCredential', 'OpenBadgeCredential'],
               'issuer': {'id': 'did:example:i', 'type': 'Profile'},
               'evidence': [{'type': ['Evidence']}, {'name': 'x'}],
               'tag': ['a', 'b', 'c']}
        stats = _screen().screen(doc)
        assert stats.nodes == 4                 # root, issuer, two evidence
        assert stats.typed_nodes == 3
        assert stats.type_entries == 2 + 1 + 1
        assert stats.context_entries == 2
        assert stats.max_types == 2
        assert stats.max_context == 2
        assert stats.max_depth == 0

    def test_both_spellings_of_type_add_up_on_one_node(self):
        stats = _screen().screen({'type': 'A', '@type': ['B', 'C']})
        assert (stats.nodes, stats.typed_nodes, stats.type_entries) == (1, 1, 3)

    def test_a_context_that_is_a_string_or_an_object_is_one_entry(self):
        s = _screen()
        assert s.screen({'@context': VC2}).context_entries == 1
        assert s.screen({'@context': {'@vocab': 'x:'}}).context_entries == 1

    def test_a_value_of_a_property_with_a_scoped_context_is_a_type_entry(self):
        s = _screen()
        stats = s.screen({'cnf': {'kid': 'x'}, 'e': [
            {'statusMessage': [{'id': 'a'}, {'id': 'b'}, {'id': 'c'}]},
            {'proofPurpose': 'assertionMethod'}]})
        assert stats.type_entries == 1 + 3 + 1
        assert stats.typed_nodes == 0

    def test_the_scoped_properties_are_the_ones_the_bundled_contexts_define(
            self):
        # A pinned context that gains a property with a scoped @context of
        # its own must be added to _SCOPED_PROPERTIES (and the limits timed
        # again): pyld applies it to every value of the property.
        from openbadgeslib.ob3.contexts import bundled_contexts
        found = set()

        def walk(node):
            if isinstance(node, dict):
                for term, definition in node.items():
                    if (isinstance(definition, dict) and '@context' in definition
                            and not term.startswith('@')
                            and not term[:1].isupper()):
                        found.add(term)
                    walk(definition)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        for document in bundled_contexts().values():
            walk(document)
        assert found == set(_screen()._SCOPED_PROPERTIES)

    def test_the_inside_of_a_context_is_not_walked(self):
        # Term definitions are not nodes; an inline context is bounded by the
        # callers (context validation, the entry limits), not counted here.
        stats = _screen().screen(
            {'@context': [{'a': {'@id': 'x:a', 'type': ['T', 'T']}}]})
        assert (stats.nodes, stats.typed_nodes) == (1, 0)

    def test_scalars_and_the_values_of_a_type_are_not_nodes(self):
        stats = _screen().screen(
            {'tag': ['a'] * 1000, 'n': 1, 'x': None,
             'type': [{'@id': 'x'}, 5]})
        assert stats.nodes == 1
        assert stats.type_entries == 2

    def test_tuples_count_like_lists(self):
        stats = _screen().screen({'e': ({'type': ('A', 'B')},)})
        assert (stats.nodes, stats.typed_nodes, stats.type_entries) == (2, 1, 2)

    def test_limits_off_returns_the_counts_of_a_hostile_document(self):
        doc = _hostile()['dupmany']
        stats = _screen().screen(doc, limits=False)
        assert stats.max_types == 75
        assert stats.type_entries >= 300 * 75

    def test_describe_is_one_line(self):
        s = _screen()
        line = s.describe(s.screen(_credential()))
        assert '\n' not in line and 'typed' in line
        assert s.describe(None) == 'n/a'


class TestEmbeddedCredentialsCountOncePerLevel:
    """Context validation expands and compacts every embedded credential
    again on its own, so a node k endorsements deep is processed k + 1 times
    and counted k + 1 times."""

    def test_an_endorsement_counts_twice(self):
        s = _screen()
        plain = s.screen(_credential(evidence=[_node('Profile')] * 10))
        inner = s.screen(_credential(endorsement=[_endorsement(
            1, evidence=[_node('Profile')] * 10)]))
        outer = s.screen(_credential(endorsement=[_endorsement(1)]))
        # ten more typed nodes, each counted twice
        assert inner.typed_nodes - outer.typed_nodes == 20
        assert plain.typed_nodes - s.screen(_credential()).typed_nodes == 10
        assert inner.max_depth == 1

    def test_the_weight_is_one_plus_the_depth(self):
        s = _screen()
        for depth in (1, 2, 5):
            stats = s.screen(_credential(endorsement=[
                _chain(depth, evidence=[_node('Profile')] * 7)]), limits=False)
            floor = s.screen(_credential(endorsement=[_chain(depth)]),
                             limits=False)
            assert stats.typed_nodes - floor.typed_nodes == 7 * (depth + 1)
            assert stats.max_depth == depth

    def test_a_nested_context_outside_endorsement_is_not_reprocessed(self):
        # A CLR carries whole signed member credentials by value. Context
        # validation refuses them under the verifier; the low-level functions
        # do not validate, so each is processed once.
        member = _credential()
        clr = {'@context': [VC2, OB3], 'type': ['ClrCredential'],
               'credentialSubject': {'type': 'ClrSubject',
                                     'verifiableCredential': [member] * 5}}
        stats = _screen().screen(clr)
        one = _screen().screen(member)
        assert stats.max_depth == 0
        assert stats.typed_nodes == 2 + 5 * one.typed_nodes

    def test_an_endorsement_entry_without_its_own_context_is_not_embedded(self):
        stats = _screen().screen(_credential(
            endorsement=[{'type': ['EndorsementCredential']}]))
        assert stats.max_depth == 0

    def test_an_endorsement_that_is_one_object_is_embedded_too(self):
        stats = _screen().screen(_credential(endorsement=_endorsement(1)))
        assert stats.max_depth == 1


class TestLimits:
    def _refused(self, doc, match, **kwargs):
        with pytest.raises(_screen().StructureLimitExceeded, match=match):
            _screen().screen(doc, **kwargs)

    def test_a_repeated_type_is_refused_even_when_short(self):
        self._refused(_node('Profile', 'Profile'), 'same type more than once')
        self._refused({'@type': ['A', 'B', 'A']}, 'same type more than once')

    def test_distinct_types_are_not_a_repeat(self):
        _screen().screen(_node('Achievement', 'Profile'))

    def test_a_type_array_is_bounded(self):
        s = _screen()
        ok = [str(i) for i in range(s.MAX_TYPES_PER_NODE)]
        s.screen(_node(*ok))
        self._refused(_node(*ok, 'one more'), 'at most %d' % s.MAX_TYPES_PER_NODE)

    def test_the_two_spellings_of_type_share_the_bound(self):
        s = _screen()
        half = s.MAX_TYPES_PER_NODE // 2 + 1
        self._refused({'type': [str(i) for i in range(half)],
                       '@type': ['x%d' % i for i in range(half)]},
                      'at most %d' % s.MAX_TYPES_PER_NODE)

    def test_unlimited_does_not_raise(self):
        _screen().screen(_node('A', 'A'), limits=False)

    @pytest.mark.parametrize('constant, what, build', [
        ('MAX_TYPED_NODES', 'typed objects',
         lambda n: {'e': [_node('A')] * n}),
        ('MAX_TYPE_ENTRIES', 'type entries',
         lambda n: {'e': [_node('A', 'B')] * (n // 2)}),
        ('MAX_NODES', 'objects',
         lambda n: {'e': [{}] * n}),
    ])
    def test_a_total_is_a_boundary(self, monkeypatch, constant, what, build):
        s = _screen()
        monkeypatch.setattr(s, constant, 40)
        # the root object is counted too
        s.screen(build(39 if constant != 'MAX_TYPE_ENTRIES' else 38))
        self._refused(build(41 if constant != 'MAX_TYPE_ENTRIES' else 42),
                      'more than 40 %s' % what)

    def test_scale_multiplies_the_totals(self, monkeypatch):
        s = _screen()
        monkeypatch.setattr(s, 'MAX_TYPED_NODES', 40)
        doc = {'e': [_node('A')] * 70}
        self._refused(doc, 'more than 40 typed objects')
        s.screen(doc, scale=2)
        self._refused({'e': [_node('A')] * 90}, 'more than 80 typed objects',
                      scale=2)

    def test_scale_does_not_loosen_the_per_node_bounds(self):
        self._refused(_node('Profile', 'Profile'), 'same type', scale=2)
        self._refused(_node(*[str(i) for i in range(20)]), 'at most', scale=2)

    def test_an_embedded_node_uses_up_the_total_twice(self, monkeypatch):
        s = _screen()
        monkeypatch.setattr(s, 'MAX_TYPED_NODES', 40)
        nodes = [_node('A')] * 19
        s.screen({'endorsement': [{'@context': [VC2], 'e': nodes}]})
        self._refused({'endorsement': [{'@context': [VC2],
                                        'e': nodes + [_node('A')] * 2}]},
                      'more than 40 typed objects')

    def test_a_context_array_is_bounded(self):
        s = _screen()
        s.screen({'@context': [VC2] * s.MAX_CONTEXT_ENTRIES})
        self._refused({'@context': [VC2] * (s.MAX_CONTEXT_ENTRIES + 1)},
                      'lists %d entries' % (s.MAX_CONTEXT_ENTRIES + 1))

    def test_a_nested_context_array_is_bounded_too(self):
        self._refused({'credentialSubject': {'@context': [VC2] * 50}},
                      'lists 50 entries')

    def test_the_context_total_is_bounded(self, monkeypatch):
        s = _screen()
        monkeypatch.setattr(s, 'MAX_CONTEXT_ENTRIES_TOTAL', 20)
        doc = lambda n: {'e': [{'@context': [VC2, OB3]}] * n}      # noqa: E731
        s.screen(doc(10))
        self._refused(doc(11), 'more than 20 @context entries')

    def test_the_context_limits_can_be_left_to_the_caller(self):
        # OB3LdpVerifier / OB3LdpSigner: context validation bounds them, with
        # its own message, right after the screen.
        s = _screen()
        stats = s.screen({'@context': [VC2] * 5000}, contexts=False)
        assert stats.context_entries == 5000
        self._refused({'@context': [VC2] * 5000}, 'lists 5000 entries')

    def test_the_message_says_so_when_embedded_credentials_were_counted_twice(
            self, monkeypatch):
        s = _screen()
        monkeypatch.setattr(s, 'MAX_TYPED_NODES', 10)
        with pytest.raises(s.StructureLimitExceeded) as plain:
            s.screen({'e': [_node('A')] * 20})
        assert 'embedded' not in str(plain.value)
        with pytest.raises(s.StructureLimitExceeded, match='embedded'):
            s.screen({'endorsement': [{'@context': [VC2],
                                       'e': [_node('A')] * 20}]})

    def test_the_message_never_echoes_the_document(self):
        s = _screen()
        for doc in (_node(SENTINEL, SENTINEL),
                    _node(*[SENTINEL + str(i) for i in range(50)]),
                    {'@context': [SENTINEL] * 50}):
            with pytest.raises(s.StructureLimitExceeded) as caught:
                s.screen(doc)
            assert SENTINEL not in str(caught.value)


class TestNoMatterHowTheDocumentIsShaped:
    def test_survives_nesting_far_past_the_recursion_limit(self):
        s = _screen()
        deep = {}
        cur = deep
        for _ in range(300_000):
            cur['x'] = {}
            cur = cur['x']
        with pytest.raises(s.StructureLimitExceeded, match='objects'):
            s.screen(deep)
        stats = s.screen(deep, limits=False)
        assert stats.nodes == 300_001

    def test_survives_lists_nested_a_million_deep(self):
        deep = []
        cur = deep
        for _ in range(1_000_000):
            nxt = []
            cur.append(nxt)
            cur = nxt
        assert _screen().screen(deep).nodes == 0

    def test_a_document_that_contains_itself_is_refused_not_looped(self):
        loop = {'type': ['A']}
        loop['again'] = loop
        with pytest.raises(_screen().StructureLimitExceeded):
            _screen().screen(loop)
        listed = []
        listed.append({'e': listed})
        with pytest.raises(_screen().StructureLimitExceeded):
            _screen().screen(listed)

    def test_a_root_that_is_not_a_container_has_nothing_to_count(self):
        for root in ('x', 5, None):
            assert _screen().screen(root).nodes == 0

    def test_odd_values_do_not_raise(self):
        s = _screen()
        s.screen({'type': [{'a': 1}, {'a': 1}, [1], None], 5: {'type': 'A'},
                  'e': {'type': {'@id': 'x'}}})

    def test_a_long_array_of_scalars_is_cheap(self):
        started = time.monotonic()
        stats = _screen().screen({'tag': ['x'] * 500_000})
        assert stats.nodes == 1
        assert time.monotonic() - started < 2.0

    def test_screening_a_large_legitimate_document_is_cheap(self):
        doc = _credential(evidence=[_node('Evidence', id='urn:e:%d' % i)
                                    for i in range(1000)])
        started = time.monotonic()
        for _ in range(20):
            _screen().screen(doc)
        assert (time.monotonic() - started) / 20 < 0.1


# ── wired in front of the entry points ───────────────────────────────────────

class TestVerifierRefusesBeforeJsonLd:
    @pytest.mark.parametrize('name', HOSTILE)
    def test_verify(self, keypair, no_json_ld, name):
        doc = _secured(_hostile()[name], keypair[1])
        text = json.dumps(doc, separators=(',', ':'))
        verifier = OB3LdpVerifier(pubkey_pem=keypair[1])
        with pytest.raises(OB3VerificationError, match=REFUSED):
            verifier.verify(doc)
        with pytest.raises(OB3VerificationError, match=REFUSED):
            verifier.verify(text.encode('utf-8'))
        if len(text) <= ldp.MAX_LDP_DOCUMENT_BYTES:
            with pytest.raises(OB3VerificationError, match=REFUSED):
                verifier.verify(text)

    def test_the_message_names_a_limit_not_the_document(
            self, keypair, no_json_ld):
        doc = _credential(evidence=[_node(SENTINEL, SENTINEL)])
        with pytest.raises(OB3VerificationError) as caught:
            OB3LdpVerifier(pubkey_pem=keypair[1]).verify(
                _secured(doc, keypair[1]))
        assert SENTINEL not in str(caught.value)
        assert 'same type more than once' in str(caught.value)

    def test_it_runs_before_the_policy_checks_read_the_json(self, keypair,
                                                            no_json_ld):
        # Even a document no policy check would let through is refused by the
        # screen first: nothing reads it before.
        doc = _secured(_hostile()['dupmany'], keypair[1])
        doc['type'] = ['SomethingElse']
        with pytest.raises(OB3VerificationError, match=REFUSED):
            OB3LdpVerifier(pubkey_pem=keypair[1]).verify(doc)

    def test_the_verifier_uses_the_strict_limits(self, keypair, monkeypatch):
        seen = []
        real = ldp.screen_structure
        monkeypatch.setattr(
            ldp, 'screen_structure',
            lambda document, **kwargs: seen.append(kwargs) or real(
                document, **kwargs))
        monkeypatch.setattr(ldp, '_check_json_ld_form',
                            lambda *a, **k: (_ for _ in ()).throw(Reached()))
        doc = _secured(_credential(), keypair[1])
        with pytest.raises(Reached):
            OB3LdpVerifier(pubkey_pem=keypair[1]).verify(doc)
        assert seen == [{'scale': 1, 'contexts': False}]

    def test_a_document_at_the_limit_gets_through_the_screen(
            self, keypair, monkeypatch):
        s = _screen()
        monkeypatch.setattr(ldp, '_check_json_ld_form',
                            lambda *a, **k: (_ for _ in ()).throw(Reached()))
        base = _credential()
        allowed = (s.MAX_TYPED_NODES
                   - s.screen(_secured(base, keypair[1])).typed_nodes)
        ok = _evidence(base, [_tree(allowed, ['Profile'])])
        with pytest.raises(Reached):
            OB3LdpVerifier(pubkey_pem=keypair[1]).verify(
                _secured(ok, keypair[1]))
        over = _evidence(base, [_tree(allowed + 1, ['Profile'])])
        with pytest.raises(OB3VerificationError, match=REFUSED):
            OB3LdpVerifier(pubkey_pem=keypair[1]).verify(
                _secured(over, keypair[1]))


class TestLowLevelFunctions:
    @pytest.fixture()
    def stub_suites(self, monkeypatch):
        """The cryptosuites stop at Reached: whatever got there passed the
        screen."""
        def reached(*args, **kwargs):
            raise Reached()
        monkeypatch.setitem(ldp._CRYPTOSUITES, 'eddsa-rdfc-2022', reached)
        monkeypatch.setitem(ldp._CRYPTOSUITES, 'ecdsa-sd-2023', reached)

    @pytest.mark.parametrize('name', HOSTILE)
    def test_verify_data_integrity_proof(self, keypair, no_json_ld, name):
        doc = _secured(_hostile(2)[name], keypair[1])
        with pytest.raises(OB3VerificationError, match=REFUSED):
            verify_data_integrity_proof(doc, keypair[1])

    def test_it_holds_the_looser_limits_where_nothing_is_validated(
            self, keypair, stub_suites):
        s = _screen()
        count = s.MAX_TYPED_NODES + 100
        doc = _secured(_evidence(_credential(),
                                 [_tree(count, ['Profile'])]), keypair[1])
        with pytest.raises(Reached):
            verify_data_integrity_proof(doc, keypair[1])
        doc = _secured(_evidence(_credential(),
                                 [_tree(2 * s.MAX_TYPED_NODES + 100,
                                        ['Profile'])]), keypair[1])
        with pytest.raises(OB3VerificationError, match=REFUSED):
            verify_data_integrity_proof(doc, keypair[1])

    def test_ecdsa_sd_keeps_the_strict_limits(self, keypair, stub_suites):
        s = _screen()
        doc = _secured(_evidence(_credential(), [
            _tree(s.MAX_TYPED_NODES + 100, ['Profile'])]), keypair[1])
        doc['proof']['cryptosuite'] = 'ecdsa-sd-2023'
        with pytest.raises(OB3VerificationError, match=REFUSED):
            verify_data_integrity_proof(doc, keypair[1])

    def test_a_padded_context_is_refused_here_too(self, keypair, no_json_ld):
        # The verifier has context validation for this; the low-level
        # functions run the document through pyld as it stands (3.4 ms of
        # CPU per entry past the tenth, on a document of any size).
        doc = _credential()
        doc['@context'] = [VC2, OB3] + [OB3] * 1000
        with pytest.raises(OB3VerificationError, match='lists 1002 entries'):
            verify_data_integrity_proof(_secured(doc, keypair[1]), keypair[1])
        with pytest.raises(ErrorSigningFile, match='lists 1002 entries'):
            add_data_integrity_proof(doc, keypair[0], 'did:example:vm')

    def test_a_nested_context_array_is_refused_too(self, keypair, no_json_ld):
        member = _credential()
        member['@context'] = [VC2, OB3] + [OB3] * 30
        clr = _credential(type=['ClrCredential'])
        clr['credentialSubject'] = {'type': 'ClrSubject',
                                    'verifiableCredential': [member] * 5}
        with pytest.raises(OB3VerificationError, match='lists 32 entries'):
            verify_data_integrity_proof(_secured(clr, keypair[1]), keypair[1])

    @pytest.mark.parametrize('name', HOSTILE)
    def test_add_data_integrity_proof(self, keypair, no_json_ld, name):
        with pytest.raises(ErrorSigningFile, match=REFUSED):
            add_data_integrity_proof(_hostile(2)[name], keypair[0],
                                     'did:example:vm')

    def test_add_data_integrity_proof_screens_after_the_cheap_checks(
            self, keypair, no_json_ld):
        doc = _hostile()['dupmany']
        with pytest.raises(ErrorSigningFile, match='verificationMethod'):
            add_data_integrity_proof(doc, keypair[0], '')


class TestSigner:
    @pytest.fixture()
    def signer(self, keypair):
        return OB3LdpSigner(keypair[0])

    @pytest.fixture()
    def issue(self, monkeypatch, ob3_credential):
        """Make the credential render as *document*."""
        def make(document):
            monkeypatch.setattr(type(ob3_credential), 'to_vc',
                                lambda self: copy.deepcopy(document))
            return ob3_credential
        return make

    @pytest.mark.parametrize('name', HOSTILE)
    def test_sign_refuses_before_json_ld(self, signer, issue, no_json_ld,
                                         name):
        with pytest.raises(ErrorSigningFile, match=REFUSED):
            signer.sign(issue(_hostile()[name]))

    def test_sign_holds_the_strict_limits(self, signer, issue, monkeypatch):
        # add_data_integrity_proof alone would take this (the doubled limits
        # of the paths without context validation); sign() validates what it
        # emits, as the verifier does, and so keeps the verifier's limits.
        s = _screen()
        doc = _evidence(_credential(), [
            _tree(s.MAX_TYPED_NODES + 100, ['Profile'])])
        monkeypatch.setattr(ldp, '_hash_data',
                            lambda *a, **k: (_ for _ in ()).throw(Reached()))
        with pytest.raises(Reached):
            add_data_integrity_proof(doc, signer.privkey_pem, 'did:example:vm')
        with pytest.raises(ErrorSigningFile, match=REFUSED):
            signer.sign(issue(doc))

    def test_sign_does_not_screen_twice_for_nothing(self, signer, issue,
                                                    monkeypatch):
        # one strict screen of the credential, one of the paths without
        # validation inside add_data_integrity_proof: both pass for a badge
        calls = []
        real = ldp.screen_structure
        monkeypatch.setattr(
            ldp, 'screen_structure',
            lambda document, **kwargs: calls.append(kwargs) or real(
                document, **kwargs))
        monkeypatch.setattr(ldp, '_hash_data',
                            lambda *a, **k: (_ for _ in ()).throw(Reached()))
        with pytest.raises(Reached):
            signer.sign(issue(_credential()))
        assert calls == [{'scale': 1, 'contexts': False},
                         {'scale': 2, 'contexts': True}]


# ── real credentials are untouched, hostile ones cost milliseconds ──────────

def _alignment(code):
    return {'type': ['Alignment'], 'targetCode': 'c%d' % code,
            'targetName': 'Target %d' % code,
            'targetUrl': 'https://university.example/catalog/%d' % code}


def _big_badge():
    """200 alignments, 500 evidence entries and 50 results."""
    doc = _credential(id='https://issuer.example/credentials/1')
    achievement = doc['credentialSubject']['achievement']
    achievement['alignment'] = [_alignment(i) for i in range(200)]
    doc['evidence'] = [{'id': 'https://issuer.example/ev/%d' % i,
                        'type': ['Evidence'], 'name': 'Evidence %d' % i}
                       for i in range(500)]
    doc['credentialSubject']['result'] = [
        {'type': ['Result'], 'status': 'Completed', 'value': 'A',
         'alignment': [_alignment(1000 + i)]} for i in range(50)]
    return doc


@needs_pyld
class TestLegitimateDocumentsAreUntouched:
    def test_a_big_badge_signs_and_verifies(self, keypair):
        priv, pub = keypair
        did = did_key(pub)
        signed = add_data_integrity_proof(
            _big_badge(), priv, '%s#%s' % (did, did[len('did:key:'):]))
        stats = _screen().screen(signed)
        assert stats.typed_nodes >= 800     # far more than a real badge has
        assert stats.typed_nodes < _screen().MAX_TYPED_NODES
        verify_data_integrity_proof(signed, pub)
        OB3LdpVerifier(pubkey_pem=pub).verify(signed)

    def test_the_complete_example_model_passes_with_a_wide_margin(
            self, keypair):
        from test_ob3_ldp_context_validation import _complete_document
        stats = _screen().screen(_complete_document())
        assert stats.max_depth == 1                 # embedded endorsements
        s = _screen()
        assert stats.typed_nodes * 10 < s.MAX_TYPED_NODES
        assert stats.type_entries * 10 < s.MAX_TYPE_ENTRIES
        assert stats.nodes * 10 < s.MAX_NODES
        assert stats.max_types * 2 <= s.MAX_TYPES_PER_NODE

    def test_a_clr_of_signed_member_badges_signs_and_verifies(self, keypair):
        from openbadgeslib.ob3 import (
            build_clr_credential, bundled_clr_contexts, sign_clr_credential)
        priv, pub = keypair
        did = did_key(pub)
        vm = '%s#%s' % (did, did[len('did:key:'):]),
        vm = vm[0]
        members = []
        for i in range(60):
            member = _credential(id='https://issuer.example/credentials/%d' % i)
            member['credentialSubject']['achievement']['alignment'] = [
                _alignment(k) for k in range(3)]
            member['evidence'] = [{'type': ['Evidence'], 'name': 'e'}]
            members.append(add_data_integrity_proof(member, priv, vm))
        clr = build_clr_credential(
            {'id': did, 'type': ['Profile'], 'name': 'Issuer'},
            [{'type': 'IdentityObject', 'hashed': True,
              'identityHash': 'sha256$abc', 'identityType': 'emailAddress',
              'salt': 's'}], members,
            credential_id='https://issuer.example/clr/1')
        signed = sign_clr_credential(clr, priv, vm)
        stats = _screen().screen(signed, scale=2)
        assert stats.max_depth == 0                 # not reprocessed
        verify_data_integrity_proof(signed, pub,
                                    extra_contexts=bundled_clr_contexts())

    def test_the_accepted_ceiling_leaves_room_for_a_big_clr(self):
        # What the doubled limits admit: ~280 member badges of eleven typed
        # objects each, or ~3,000 achievements and associations.
        s = _screen()
        assert 2 * s.MAX_TYPED_NODES // 11 >= 280
        assert 2 * s.MAX_TYPE_ENTRIES // 14 >= 280     # + a proofPurpose each
        assert 2 * s.MAX_NODES >= 12 * 280


@needs_pyld
class TestHostileDocumentsAreRefusedInMilliseconds:
    DEADLINE = 1.0       # the published 4.6.2 spends 9 to 15 s on each of these

    @pytest.mark.parametrize('name', ['dupmany', 'one-node-20000-types',
                                      'dup-in-an-endorsement',
                                      'distinct-typed-flood',
                                      'endorsed-flood'])
    def test_verify(self, keypair, name):
        doc = _secured(_hostile()[name], keypair[1])
        started = time.monotonic()
        with pytest.raises(OB3VerificationError, match=REFUSED):
            OB3LdpVerifier(pubkey_pem=keypair[1]).verify(doc)
        assert time.monotonic() - started < self.DEADLINE

    def test_sign(self, keypair):
        started = time.monotonic()
        with pytest.raises(ErrorSigningFile, match=REFUSED):
            add_data_integrity_proof(_hostile()['dupmany'], keypair[0],
                                     'did:example:vm')
        assert time.monotonic() - started < self.DEADLINE
