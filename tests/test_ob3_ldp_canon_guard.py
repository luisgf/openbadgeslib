"""Bounded RDF canonicalization of untrusted Data Integrity documents —
ob3/_canon_guard.py, used by ob3.ldp._canonize.

A Data Integrity proof signs the canonical form of the RDF dataset a document
expands to, so the verifier canonicalizes BEFORE it can tell whether the
signature is any good. RDFC-1.0 (pyld calls it URDNA2015) is factorial on
groups of blank nodes it cannot tell apart: a 2.6 KB credential that passes
context validation kept a worker busy for ~25 s on an unpatched pyld 3.3.0.
These tests pin that

* every hostile shape below is refused, through the real verifier and the
  signer, within a fraction of a second of CPU (unguarded each one costs 5 to
  40 s or more), and that the CPU-time allowance, not the unit model, is what
  bounds the work on an interpreter where the model is off;
* nothing legitimate pays for it: the guarded output is byte-identical to
  jsonld.normalize and spends a tiny fraction of the budget;
* the JSON-LD to RDF conversion that precedes canonicalization is bounded too
  (the duplicate checks pyld makes there, @reverse included);
* the guard fails CLOSED when pyld is not the implementation its cost model
  was fitted to, never touches process-global state, and serializes pyld's
  thread-unsafe JSON-LD processor.

The hostile documents only use members the pinned contexts define (the
propagating ``alignment`` term, under ``evidence``), which the credential model
tolerates, so context validation lets them through and the cost lands in
canonicalization.

Time assertions measure CPU (``time.process_time``) with a wide margin and
scale it for coverage tracing, which multiplies CPU by up to ~10 on CPython
3.10-3.12; where a test is about structure it counts work instead.

Needs the [ldp] extra (pyld); skipped otherwise.
"""
import contextlib
import copy
import hashlib
import itertools
import json
import random
import re
import sys
import threading
import time

from pathlib import Path

import pytest

pytest.importorskip('pyld')

from pyld import jsonld  # noqa: E402

from openbadgeslib.errors import ErrorSigningFile  # noqa: E402
from openbadgeslib.ob3 import (  # noqa: E402
    OB3GuardUnavailable, OB3LdpSigner, OB3LdpVerifier, OB3VerificationError,
    add_data_integrity_proof, verify_data_integrity_proof)
from openbadgeslib.ob3 import _canon_guard as guard  # noqa: E402
from openbadgeslib.ob3 import ldp  # noqa: E402
from openbadgeslib.ob3.contexts import document_loader  # noqa: E402

from ldp_helpers import b58encode, did_key  # noqa: E402
from test_ob3_ldp_context_validation import _complete_document  # noqa: E402

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / 'fixtures' / 'vc_di_eddsa'
REFUSED = 'refusing to canonicalize'
#: CPU seconds. Generous: a refusal costs 0.05-0.25 s (0.85 s inside the
#: CPython 3.11/3.12 window), unguarded these cost 5-40 s or more.
CPU_BOUND = 5.0


def _coverage_slowdown():
    """Coverage tracing multiplies CPU by up to ~10 on CPython 3.10-3.12."""
    cov = sys.modules.get('coverage')
    running = cov is not None and cov.Coverage.current() is not None
    return 10 if running else 1


@contextlib.contextmanager
def cpu_below(seconds):
    started = time.process_time()
    yield
    spent = time.process_time() - started
    limit = seconds * _coverage_slowdown()
    assert spent < limit, 'took %.2f s of CPU, expected under %.1f' % (
        spent, limit)


# ── hostile documents ────────────────────────────────────────────────────────

def _evidence(base, nodes):
    doc = copy.deepcopy(base)
    doc['evidence'] = nodes
    return doc


def clique(base, n):
    """n labelled blank nodes, each linking to every other (unguarded:
    n=7 2 s, n=8 24 s)."""
    return _evidence(base, [
        {'id': '_:b%d' % i,
         'alignment': [{'id': '_:b%d' % j} for j in range(n) if j != i]}
        for i in range(n)])


def tree(base, branching, depth):
    """Unlabelled tree of nested nodes (branching 8, depth 2: 19 s)."""
    def grow(level):
        if level == 0:
            return {}
        return {'alignment': [grow(level - 1) for _ in range(branching)]}
    return _evidence(base, [grow(depth)])


def ring(base, n):
    """Directed ring of n labelled blank nodes (n=400: 16 s, ~n^2.8)."""
    return _evidence(base, [
        {'id': '_:b%d' % i, 'alignment': [{'id': '_:b%d' % ((i + 1) % n)}]}
        for i in range(n)])


def circulant(base, n, offsets=(1, 2, 3)):
    """Ring whose nodes also link to the next `offsets` ones: the shape that
    costs 5-7 times more per work unit on CPython 3.11/3.12 for some n."""
    return _evidence(base, [
        {'id': '_:b%d' % i,
         'alignment': [{'id': '_:b%d' % ((i + o) % n)} for o in offsets]}
        for i in range(n)])


def identical_children(base, n):
    """Two identical blank parents with n identical blank children each
    (n=8: 4 s, n=9: ~40 s)."""
    return _evidence(base, [{'alignment': [{} for _ in range(n)]},
                            {'alignment': [{} for _ in range(n)]}])


def many_cliques(base, count, size):
    """count disjoint cliques: every one under a per-clique allowance, all of
    them over the shared budget."""
    nodes = []
    for c in range(count):
        for i in range(size):
            nodes.append({'id': '_:c%d_%d' % (c, i), 'alignment': [
                {'id': '_:c%d_%d' % (c, j)} for j in range(size) if j != i]})
    return _evidence(base, nodes)


def flat_tags(base, n):
    """One property with n values: pyld's node map costs n^2/2 (8000: 12 s)."""
    doc = copy.deepcopy(base)
    doc['credentialSubject']['achievement']['tag'] = ['t%d' % i for i in range(n)]
    return doc


def merged_node(base, parents, per_parent):
    """Many short arrays naming the same node, which pyld merges into one
    property of parents*per_parent values."""
    return _evidence(base, [{'alignment': [
        {'id': 'https://x.example/shared', 'name': 'v%d_%d' % (p, k)}
        for k in range(per_parent)]} for p in range(parents)])


def reverse_flood(base, parents, per_parent):
    """parents x per_parent nodes that all @reverse into ONE node: no single
    array is long, but pyld's node map gets parents*per_parent values on it
    (80 x 75 = 6,000 children, 231 KB: 18 million comparisons, 6-9 s)."""
    return _evidence(base, [
        {'alignment': [{'@reverse': {'urn:p': {'@id': 'urn:t'}}}
                       for _ in range(per_parent)]}
        for _ in range(parents)])


def hub_results(base, n):
    """An identifier-only subject (no @id: a blank node) with n Results that
    are identical to the first-degree hash, one blank alignment each: all
    legitimate, and the component of blank nodes is as large as the document."""
    doc = copy.deepcopy(base)
    doc['credentialSubject'].pop('id', None)
    doc['credentialSubject']['result'] = [
        {'type': ['Result'], 'status': 'Completed', 'alignment': [{}]}
        for _ in range(n)]
    return doc


def shared_creator(base, n):
    """n distinct alignments re-stating the same typed node."""
    creator = {'id': 'https://x.example/creator', 'type': ['Profile'],
               'name': 'Creator'}
    return _evidence(base, [{'alignment': [
        {'id': 'urn:a:%d' % i, 'name': 'a%d' % i, 'targetFramework': creator}
        for i in range(n)]}])


@pytest.fixture(scope='module')
def base_vc(ob3_credential):
    return ob3_credential.to_vc()


@pytest.fixture(scope='module')
def verifier(ed25519_keypair):
    return OB3LdpVerifier(pubkey_pem=ed25519_keypair[1])


def _with_bogus_proof(doc, pub_pem):
    secured = copy.deepcopy(doc)
    did = did_key(pub_pem)
    secured['proof'] = {
        'type': 'DataIntegrityProof', 'cryptosuite': 'eddsa-rdfc-2022',
        'created': '2026-07-03T00:00:00Z',
        'verificationMethod': '%s#%s' % (did, did[len('did:key:'):]),
        'proofPurpose': 'assertionMethod',
        'proofValue': 'z' + b58encode(bytes([7]) * 64),
    }
    return secured


@pytest.fixture(scope='module')
def p256_pem():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(autouse=True)
def _fresh_guard():
    """The guard's pyld check is cached per process; tests that change pyld
    must not leak (or inherit) that state."""
    guard._bounded_class.cache_clear()
    guard._processor_class.cache_clear()
    yield
    guard._bounded_class.cache_clear()
    guard._processor_class.cache_clear()


@pytest.fixture
def half_budget(monkeypatch):
    """A budget two cliques of five (115k units each) overrun together."""
    monkeypatch.setattr(guard, 'MAX_CANON_WORK', 150_000)


def _stock(doc, loader):
    return jsonld.normalize(copy.deepcopy(doc), {
        'algorithm': 'URDNA2015', 'format': 'application/n-quads',
        'documentLoader': loader})


def _real_pairs(doc, loader, monkeypatch):
    """The comparisons pyld really makes converting *doc* to RDF."""
    calls = []
    real = jsonld.JsonLdProcessor.compare_values
    monkeypatch.setattr(
        jsonld.JsonLdProcessor, 'compare_values',
        staticmethod(lambda a, b: calls.append(1) or real(a, b)))
    jsonld.to_rdf(copy.deepcopy(doc), {'documentLoader': loader,
                                       'produceGeneralizedRdf': False})
    monkeypatch.undo()
    return len(calls)


def _model_pairs(doc, loader):
    return guard.node_map_pairs(jsonld.expand(copy.deepcopy(doc),
                                              {'documentLoader': loader}))


# ── legitimate documents pay nothing ─────────────────────────────────────────

def _documents(base_vc):
    examples = {'https://www.w3.org/ns/credentials/examples/v2': json.loads(
        (FIXTURES / 'credentials-examples-v2.json').read_text())}
    vector = json.loads((FIXTURES / 'signed-credential.json').read_text())
    vector.pop('proof')
    yield 'w3c vector', vector, document_loader(examples)
    yield 'ob3 credential', copy.deepcopy(base_vc), document_loader()
    yield ('complete OpenBadgeCredential', _complete_document(),
           document_loader())


class TestLegitimateDocuments:
    def test_output_is_byte_identical_to_stock_pyld(self, base_vc):
        for name, doc, loader in _documents(base_vc):
            assert ldp._canonize(copy.deepcopy(doc), loader) == \
                _stock(doc, loader), name

    def test_spend_is_a_tiny_fraction_of_the_budget(self, base_vc):
        # The false-positive rate: the whole suite's canonicalizations spend
        # at most 1,129 units (the complete example, whose embedded proofs
        # share every statement and so need real permutation work).
        for name, doc, loader in _documents(base_vc):
            budget = guard.WorkBudget()
            guard.canonize(jsonld, doc, loader, budget)
            assert budget.spent < 5000, (name, budget.spent)
            assert budget.spent < guard.MAX_CANON_WORK / 50, name

    def test_embedded_proof_graph_repeats_one_node_in_a_group(self):
        # A proof node's quads all name the same blank graph, so pyld sees a
        # group of six identical entries: 6! = 720 permutations if counted
        # naively, ONE if counted as pyld enumerates them. The guard meters
        # what happens, so the real document is not charged for the naive
        # count.
        budget = guard.WorkBudget()
        guard.canonize(jsonld, _complete_document(), document_loader(), budget)
        assert 0 < budget.spent < 2000

    def test_a_big_embedded_proof_graph_is_not_a_permutation_problem(self):
        # More than _MAX_GROUP (12) entries naming ONE graph: a group whose
        # members are all the same node is enumerated once by pyld, so it is
        # neither pre-refused nor charged size! (a proof carrying the
        # standard challenge / domain / expires / nonce terms has 10+).
        doc = _complete_document()
        endorsements = doc['credentialSubject']['achievement']['creator'][
            'endorsement']
        for endorsement in endorsements:
            endorsement['proof'][0].update(
                challenge='c', nonce='n', expires='2030-01-01T00:00:00Z',
                domain=['a.example', 'b.example', 'c.example', 'd.example'])
        loader = document_loader()
        budget = guard.WorkBudget()
        out = guard.canonize(jsonld, doc, loader, budget)
        assert out == _stock(doc, loader)
        assert 'security#challenge' in out         # the terms are really there
        assert budget.spent < 5000, budget.spent

    def test_the_largest_legitimate_shapes_have_headroom(self, base_vc):
        # Hundreds of identical blank Results under an identifier-only
        # subject, or the same typed node re-stated by every entry of a long
        # array: bounded by pyld's own quadratic node map long before they
        # approach the work budget (byte-identity to stock pyld is pinned on
        # the real documents above). They assert units, not time: the CPU
        # allowance is lifted so coverage tracing cannot trip it.
        loader = document_loader()
        budget = guard.WorkBudget(seconds=60.0)
        guard.canonize(jsonld, hub_results(base_vc, 700), loader, budget)
        assert budget.spent < guard.MAX_CANON_WORK / 2, budget.spent
        budget = guard.WorkBudget(seconds=60.0)
        guard.canonize(jsonld, shared_creator(base_vc, 900), loader, budget)
        assert budget.spent == 0
        # ... up to the node-map cap itself (1,400 Results: 161,000 units).
        budget = guard.WorkBudget(seconds=60.0)
        guard.canonize(jsonld, hub_results(base_vc, 1400), loader, budget)
        assert budget.spent < guard.MAX_CANON_WORK

    def test_option_parity_with_jsonld_normalize(self):
        # produceGeneralizedRdf=False: a blank-node PROPERTY ('_:p') yields no
        # statement in stock normalize; with generalized RDF it would, and the
        # signature would cover a different dataset.
        doc = {'@id': 'https://example.org/s', '_:p': 'generalized',
               'http://example.org/q': 'x',
               '@included': [{'@id': 'https://example.org/i',
                              'http://example.org/q': 'y'}]}
        stock = _stock(doc, None)
        assert 'generalized' not in stock
        assert guard.canonize(jsonld, copy.deepcopy(doc), None) == stock

    def test_the_default_allowance_is_small(self):
        # ~100x what any real credential spends, not the 2M units (0.4-0.8 s)
        # of 4.6.3's first cut, and a CPU allowance of about a second.
        assert guard.MAX_CANON_WORK <= 400_000
        assert guard.MAX_CANON_SECONDS <= 2.0


# ── hostile documents are refused ────────────────────────────────────────────

HOSTILE = [
    ('clique', lambda b: clique(b, 8)),
    ('clique-too-big-to-permute', lambda b: clique(b, 40)),
    ('tree-8x2', lambda b: tree(b, 8, 2)),
    ('tree-3x4', lambda b: tree(b, 3, 4)),
    ('ring-400', lambda b: ring(b, 400)),
    ('circulant-146', lambda b: circulant(b, 146)),
    ('identical-children-9', lambda b: identical_children(b, 9)),
    ('identical-children-40', lambda b: identical_children(b, 40)),
    ('many-cliques', lambda b: many_cliques(b, 60, 5)),
]


class TestHostileDocuments:
    @pytest.mark.parametrize('make', [m for _, m in HOSTILE],
                             ids=[n for n, _ in HOSTILE])
    def test_verifier_refuses_in_a_fraction_of_a_second(
            self, base_vc, verifier, ed25519_keypair, make):
        doc = _with_bogus_proof(make(base_vc), ed25519_keypair[1])
        with cpu_below(CPU_BOUND):
            with pytest.raises(OB3VerificationError, match=REFUSED):
                verifier.verify(doc)

    def test_the_proof_options_are_attacker_input_too(self, base_vc, verifier,
                                                      ed25519_keypair):
        doc = _with_bogus_proof(base_vc, ed25519_keypair[1])
        doc['proof']['alignment'] = clique(base_vc, 8)['evidence']
        with cpu_below(CPU_BOUND):
            with pytest.raises(OB3VerificationError, match=REFUSED):
                verifier.verify(doc)

    def test_document_and_proof_options_share_one_budget(self, base_vc,
                                                         half_budget):
        # Each half costs 115k units, under the budget alone, over it
        # together.
        half = clique(base_vc, 5)
        config = {'@context': half['@context'], 'type': 'DataIntegrityProof',
                  'alignment': half['evidence']}
        loader = document_loader()
        alone = guard.WorkBudget()
        ldp._canonize(copy.deepcopy(half), loader, alone)
        assert guard.MAX_CANON_WORK / 2 < alone.spent < guard.MAX_CANON_WORK
        shared = guard.WorkBudget()
        ldp._canonize(copy.deepcopy(half), loader, shared)
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._canonize(config, loader, shared)

    def test_hash_data_shares_one_budget_between_document_and_options(
            self, base_vc, half_budget):
        # The production call site, not only _canonize with an explicit
        # budget: the same two halves, each fine alone, must be refused by
        # hashData itself.
        half = clique(base_vc, 5)
        config = {'@context': half['@context'], 'type': 'DataIntegrityProof',
                  'alignment': half['evidence']}
        loader = document_loader()
        ldp._hash_data(copy.deepcopy(half), {'@context': half['@context'],
                                             'type': 'DataIntegrityProof'},
                       loader)
        ldp._hash_data(copy.deepcopy(base_vc), copy.deepcopy(config), loader)
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._hash_data(copy.deepcopy(half), copy.deepcopy(config), loader)

    def test_signer_refuses_the_same_documents(self, base_vc, ed25519_keypair):
        priv, pub = ed25519_keypair
        did = did_key(pub)
        for make in (lambda b: clique(b, 8), lambda b: ring(b, 400)):
            with pytest.raises(ErrorSigningFile, match=REFUSED):
                add_data_integrity_proof(make(base_vc), priv,
                                         '%s#%s' % (did, did[len('did:key:'):]))

    def test_ob3_ldp_signer_refuses_a_hostile_credential(
            self, ob3_credential, ed25519_keypair, monkeypatch):
        hostile = clique(ob3_credential.to_vc(), 8)
        monkeypatch.setattr(type(ob3_credential), 'to_vc',
                            lambda self: copy.deepcopy(hostile))
        with pytest.raises(ErrorSigningFile, match=REFUSED):
            OB3LdpSigner(ed25519_keypair[0]).sign(ob3_credential)

    def test_recursion_depth_fails_closed(self, base_vc):
        # A ring this long runs out of Python stack before it runs out of a
        # (here enlarged) budget: still a typed refusal, not a RecursionError.
        budget = guard.WorkBudget(limit=10 ** 9, seconds=600)
        with pytest.raises(OB3VerificationError,
                           match='could not canonicalize'):
            ldp._canonize(ring(base_vc, 1200), document_loader(), budget)

    def test_a_group_too_big_to_permute_is_refused_without_enumerating(
            self, base_vc, monkeypatch):
        # 13 distinct blank nodes in one group: 13! permutations, none of
        # them avoidable. The pre-refusal rejects the group at once; without
        # it the budget is spent walking ~2,000 hash_n_degree_quads calls.
        from pyld import canon
        guard._bounded_class()                      # build outside the count
        calls = []
        real = canon.URDNA2015.create_hash_to_related
        monkeypatch.setattr(
            canon.URDNA2015, 'create_hash_to_related',
            lambda self, *a: calls.append(1) or real(self, *a))
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._canonize(clique(base_vc, 13), document_loader())
        assert len(calls) < 50, len(calls)

    def test_no_factorial_is_computed_for_a_big_group(self, base_vc,
                                                      monkeypatch):
        argument = []
        real = guard.math.factorial
        monkeypatch.setattr(guard.math, 'factorial',
                            lambda n: argument.append(n) or real(n))
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._canonize(identical_children(base_vc, 40), document_loader())
        assert argument and max(argument) <= 12      # (never 40!)


class TestCostModel:
    def test_the_canaries_spend_exactly_what_the_model_says(self):
        # Pins every term of the model together (the call, the quads, the
        # permutation step and the issuer a step copies, the per-swap meter):
        # change a constant on purpose and change these numbers with it. The
        # run-time canary tolerates less than this on purpose (it checks a
        # range), so this is where an accidental change is caught.
        bounded = guard._bounded_class()
        seen = []
        for document, nquads, swaps, units in guard._CANARIES:
            budget = guard.WorkBudget(limit=10 ** 8, seconds=60)
            assert guard._run(jsonld, bounded, document, None, budget) == nquads
            seen.append((budget.spent, budget.swaps))
        assert seen == [(10_332, 92), (308, 0)]

    def test_nodes_with_a_canonical_id_are_not_charged_to_every_permutation(
            self, base_vc):
        # A permutation copies the issuer, which only ever holds blank nodes
        # that have no canonical identifier yet. Charging the whole connected
        # component made the work of N identical Results under an anonymous
        # subject grow with N squared (700 Results: 2.0M units, now 80k) and
        # refused credentials stock pyld canonicalizes in 0.2 s.
        loader = document_loader()
        spent = {}
        for n in (200, 400):
            budget = guard.WorkBudget(seconds=60.0)
            guard.canonize(jsonld, hub_results(base_vc, n), loader, budget)
            spent[n] = budget.spent
        assert spent[400] < 2.6 * spent[200], spent
        assert spent[400] < guard.MAX_CANON_WORK / 4


class TestBudgetArithmetic:
    def test_a_charge_over_the_limit_raises_one_at_the_limit_does_not(self):
        budget = guard.WorkBudget(limit=5)
        budget.charge(5)
        with pytest.raises(guard.CanonicalizationWorkExceeded):
            budget.charge(1)

    def test_each_item_assignment_pays_half_a_permutation_and_is_counted(self):
        budget = guard.WorkBudget(limit=10 ** 6)
        group = guard._MeteredGroup(['a', 'b'], budget, 10)
        group[0], group[1] = group[1], group[0]
        assert group == ['b', 'a']
        assert budget.swaps == 2
        assert budget.spent == 2 * (10 // 2 + 1)

    def test_the_cpu_clock_is_read_from_a_swap_loop_too(self, monkeypatch):
        # A document can spend a long time between two Hash N-Degree Quads
        # calls (every permutation copies the issuer): the deadline must be
        # read from the per-swap meter as well.
        now = [0.0]
        monkeypatch.setattr(guard, '_cpu_seconds', lambda: now[0])
        budget = guard.WorkBudget(limit=10 ** 9, seconds=1.0)
        group = guard._MeteredGroup(['a', 'b'], budget, 2)
        budget.begin()
        now[0] = 5.0
        with pytest.raises(guard.CanonicalizationWorkExceeded,
                           match='CPU time limit'):
            for _ in range(200):
                group[0] = 'a'
        assert budget.swaps <= guard._TICK_MASK + 1


class TestCpuDeadline:
    def test_it_measures_cpu_not_waiting(self):
        # A thread parked on the pyld lock or the GIL, or a host that is
        # paused or overloaded, spends no CPU: it must not lose the document
        # its allowance.
        budget = guard.WorkBudget(seconds=0.05)
        budget.begin()
        time.sleep(0.3)
        budget.check_time()
        budget.end()

    def test_a_coarse_clock_still_bounds_the_work_and_spares_real_documents(
            self, base_vc, monkeypatch):
        # Windows reads a thread's CPU time from GetThreadTimes, which only
        # advances once per scheduler tick (documented as about 15.6 ms; not
        # measured there). Emulated: two readings of that clock subtract to 0
        # or to a whole tick, so a span is over- or under-charged by up to one
        # tick. Real canonicalizations take 1 to 100 ms in at most two spans
        # per signature check, a poison graph is cut off within a tick or two
        # of its allowance.
        tick = 0.015625
        monkeypatch.setattr(
            guard, '_CLOCK', lambda: int(time.thread_time() / tick) * tick)
        for name, doc, loader in _documents(base_vc):
            assert ldp._canonize(copy.deepcopy(doc), loader) == \
                _stock(doc, loader), name
        budget = guard.WorkBudget(limit=10 ** 12, seconds=0.25)
        with cpu_below(CPU_BOUND):
            with pytest.raises(OB3VerificationError, match='CPU time limit'):
                ldp._canonize(circulant(base_vc, 146), document_loader(),
                              budget)
        assert 0.25 < budget._cpu_used < 0.25 + 3 * tick

    def test_it_counts_this_threads_cpu_only(self):
        budget = guard.WorkBudget(seconds=0.05)
        stop = threading.Event()

        def spin():
            while not stop.is_set():
                pass
        spinner = threading.Thread(target=spin)
        spinner.start()
        try:
            budget.begin()
            time.sleep(0.3)             # another thread burns CPU meanwhile
            budget.check_time()
        finally:
            stop.set()
            spinner.join()

    def test_a_thread_held_up_elsewhere_is_not_charged_for_the_wait(
            self, base_vc, ed25519_keypair):
        # Another thread sits on the pyld lock for longer than the CPU
        # allowance. Canonicalization needs no lock, so it is not held up; the
        # check that compacts (it asks for an inverse context) is, and still
        # finishes within its own allowance once it gets in.
        loader = document_loader()
        expected = ldp._canonize(copy.deepcopy(base_vc), loader)
        canonized = []
        checked = threading.Event()
        budget = guard.WorkBudget(seconds=0.2)
        signed = _with_bogus_proof(base_vc, ed25519_keypair[1])

        def check():
            ldp._check_json_ld_form(
                {k: v for k, v in signed.items() if k != 'proof'},
                signed['proof'], loader)
            checked.set()
        with guard.PYLD_LOCK:
            worker = threading.Thread(target=lambda: canonized.append(
                ldp._canonize(copy.deepcopy(base_vc), loader, budget)))
            blocked = threading.Thread(target=check)
            worker.start()
            blocked.start()
            worker.join(30)
            assert canonized == [expected]          # not held up by the lock
            time.sleep(0.6)
            assert not checked.is_set()             # held up, as it must be
        blocked.join(30)
        assert checked.is_set()

    def test_it_is_the_operative_bound_where_the_unit_model_is_wrong(
            self, base_vc):
        # Units unlimited, a short CPU allowance: the poison graph is cut off
        # by the clock, on whatever interpreter this runs on.
        budget = guard.WorkBudget(limit=10 ** 12, seconds=0.25)
        with cpu_below(CPU_BOUND):
            with pytest.raises(OB3VerificationError, match='CPU time limit'):
                ldp._canonize(circulant(base_vc, 146), document_loader(),
                              budget)
        assert budget.spent > 0

    def test_it_is_shared_by_the_canonicalizations_of_one_check(self,
                                                                monkeypatch):
        now = [0.0]
        monkeypatch.setattr(guard, '_cpu_seconds', lambda: now[0])
        budget = guard.WorkBudget(seconds=1.0)
        for _ in range(2):
            budget.begin()
            now[0] += 0.4
            budget.end()
        budget.begin()
        now[0] += 0.3
        with pytest.raises(guard.CanonicalizationWorkExceeded):
            budget.check_time()

    def test_the_clock_is_read_when_a_node_is_first_hashed(self, base_vc):
        # Even a document with too few charges to reach the periodic read.
        budget = guard.WorkBudget(seconds=-1)
        with pytest.raises(OB3VerificationError, match='CPU time limit'):
            ldp._canonize(identical_children(base_vc, 2), document_loader(),
                          budget)
        assert budget.spent < 64

    def test_the_time_backstop_through_the_verifier_path(self, base_vc):
        budget = guard.WorkBudget(seconds=-1)     # already past its allowance
        with pytest.raises(OB3VerificationError, match='time limit'):
            ldp._canonize(identical_children(base_vc, 3), document_loader(),
                          budget)

    def test_the_linear_stages_are_not_charged_to_the_allowance(self,
                                                                base_vc,
                                                                monkeypatch):
        # Expansion and RDF conversion are bounded by the document size cap
        # and the duplicate-check allowance, not by the allowance for
        # URDNA2015: a large legitimate document must not lose it there.
        now = [0.0]
        monkeypatch.setattr(guard, '_cpu_seconds', lambda: now[0])
        real = jsonld.to_rdf

        def slow_to_rdf(*args, **kwargs):
            now[0] += 100.0
            return real(*args, **kwargs)
        monkeypatch.setattr(jsonld, 'to_rdf', slow_to_rdf)
        budget = guard.WorkBudget(seconds=0.5)
        ldp._canonize(copy.deepcopy(base_vc), document_loader(), budget)


class TestNodeMapBound:
    """Not canonicalization: pyld's JSON-LD to RDF conversion compares every
    new value of a node property with the ones already there."""

    @pytest.mark.parametrize('make', [
        lambda b: flat_tags(b, 2000),
        lambda b: merged_node(b, 60, 30),
    ], ids=['one-array', 'merged-across-arrays'])
    def test_refused_before_pyld_builds_the_node_map(self, base_vc, make):
        with cpu_below(2.0):
            with pytest.raises(OB3VerificationError,
                               match='too many values on its node properties'):
                ldp._canonize(make(base_vc), document_loader())

    def test_the_refusal_names_the_total_and_the_widest_property(self,
                                                                 base_vc):
        with pytest.raises(OB3VerificationError) as caught:
            ldp._canonize(flat_tags(base_vc, 2000), document_loader())
        text = str(caught.value)
        assert re.search(r'199\d{4} duplicate checks, 1000000 allowed', text)
        assert 'holds 2000 values' in text

    def test_a_realistic_large_array_passes(self, base_vc):
        out = ldp._canonize(flat_tags(base_vc, 600), document_loader())
        assert '"t0"' in out and '"t599"' in out

    def test_pairs(self):
        expanded = [{'@id': 'a', 'p': [{'@value': 1}] * 4, 'q': [{'@id': 'b'}]},
                    {'@id': 'a', 'p': [{'@value': 2}] * 3},
                    {'p': [{'@value': 3}] * 5}]
        # a.p: 7 occurrences of 2 distinct values -> 1 + 5*2; a.q: 1 value
        # -> 0; the anonymous node's p: 5 occurrences of one value -> 4
        assert guard.node_map_pairs(expanded) == 15
        # n distinct values -> n(n-1)/2
        assert guard.node_map_pairs(
            [{'@id': 'a', 'p': [{'@value': i} for i in range(10)]}]) == 45
        # a @list keeps duplicates without comparing them: linear in pyld
        assert guard.node_map_pairs(
            [{'@id': 'a', 'p': [{'@list': [{'@value': 1}] * 5000}]}]) == 0
        # @graph and @included members are not compared either
        assert guard.node_map_pairs(
            [{'@id': 'a', '@graph': [{'@id': 'g%d' % i} for i in range(500)],
              '@included': [{'@id': 'i%d' % i} for i in range(500)]}]) == 0

    def test_a_repeated_node_is_not_a_quadratic_problem(self, base_vc,
                                                        monkeypatch):
        # 900 alignments each embedding the same typed creator: pyld stops at
        # the first match, so re-stating it is O(1) per entry. Counting every
        # occurrence as distinct charged 900^2/2 per property and refused it.
        doc = shared_creator(base_vc, 900)
        loader = document_loader()
        assert _model_pairs(doc, loader) <= 1_000_000
        assert _real_pairs(doc, loader, monkeypatch) <= _model_pairs(doc, loader)
        assert guard.canonize(jsonld, doc, loader) == _stock(doc, loader)

    def test_the_cap_is_the_sum_over_every_property(self, base_vc):
        # Documented as such: pyld's cost is the sum of the quadratics, so
        # two 1,100-value properties of one node cost what one 1,553-value
        # property does.
        doc = copy.deepcopy(base_vc)
        doc['evidence'] = [{'id': 'https://x.example/e',
                            'alignment': [{'id': 'urn:a:%d' % i}
                                          for i in range(1100)],
                            'name': ['u%d' % i for i in range(1100)]}]
        assert _model_pairs(doc, document_loader()) > 1_000_000
        with pytest.raises(OB3VerificationError, match='too many values'):
            ldp._canonize(doc, document_loader())
        doc['evidence'][0]['name'] = doc['evidence'][0]['name'][:600]
        assert ldp._canonize(doc, document_loader())

    def test_document_and_proof_options_share_the_allowance(self, base_vc):
        loader = document_loader()
        tags = flat_tags(base_vc, 1100)             # ~600k pairs: fine alone
        config = {'@context': base_vc['@context'], 'type': 'DataIntegrityProof',
                  'challenge': ['c%d' % i for i in range(1100)]}
        ldp._canonize(copy.deepcopy(tags), loader)
        ldp._canonize(copy.deepcopy(config), loader)
        with pytest.raises(OB3VerificationError, match='too many values'):
            ldp._hash_data(copy.deepcopy(tags), copy.deepcopy(config), loader)

    def test_a_long_list_of_distinct_values_is_not_a_node_map_problem(
            self, base_vc):
        doc = copy.deepcopy(base_vc)
        doc['evidence'] = [{'type': ['ResultDescription'],
                            'allowedValue': ['v%d' % i for i in range(3000)]}]
        out = ldp._canonize(doc, document_loader())
        assert '"v2999"' in out

    def test_a_long_list_of_identical_values_is_a_poison_chain(self, base_vc):
        # Every cell of the RDF list looks like the next one: a chain of blank
        # nodes the algorithm can only tell apart by walking it. 150 identical
        # values, 2 KB of JSON, is already over the budget.
        doc = copy.deepcopy(base_vc)
        doc['evidence'] = [{'type': ['ResultDescription'],
                            'allowedValue': ['A'] * 150}]
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._canonize(doc, document_loader())


class TestReverse:
    """``@reverse`` adds one reference to the REVERSED-INTO node's property per
    entry, so entries spread over many parents still pile up on one node:
    the model that treated a ``@reverse`` map as a node of its own counted
    none of them (24 million comparisons, 7-9 s of CPU, for a 242 KB
    document through the two low-level functions)."""

    def test_a_reverse_flood_is_refused_before_pyld_builds_the_node_map(
            self, base_vc):
        doc = reverse_flood(base_vc, 80, 75)
        assert len(json.dumps(doc)) < ldp.MAX_LDP_DOCUMENT_BYTES
        with cpu_below(2.0):
            with pytest.raises(OB3VerificationError,
                               match='too many values on its node properties'):
                ldp._canonize(doc, document_loader())

    def test_through_the_two_low_level_functions(self, base_vc,
                                                 ed25519_keypair):
        priv, pub = ed25519_keypair
        did = did_key(pub)
        doc = reverse_flood(base_vc, 45, 40)            # 1,800 children
        with cpu_below(2.0):
            with pytest.raises(ErrorSigningFile, match='too many values'):
                add_data_integrity_proof(doc, priv,
                                         '%s#%s' % (did, did[len('did:key:'):]))
            with pytest.raises(OB3VerificationError, match='too many values'):
                verify_data_integrity_proof(_with_bogus_proof(doc, pub), pub)

    def test_the_count_is_pylds_own(self, base_vc, monkeypatch):
        loader = document_loader()
        doc = reverse_flood(base_vc, 8, 6)
        real = _real_pairs(doc, loader, monkeypatch)
        assert real > 1000                  # (it was 0 in the model)
        assert _model_pairs(doc, loader) == real

    def test_a_reverse_into_distinct_nodes_adds_nothing(self, base_vc,
                                                        monkeypatch):
        # 300 children of one parent, each reversing into a node of its own:
        # the only quadratic property is the parent's own 300-value array.
        loader = document_loader()
        doc = _evidence(base_vc, [{'alignment': [
            {'name': 'c%d' % i, '@reverse': {'urn:p': {'@id': 'urn:t%d' % i}}}
            for i in range(300)]}])
        assert 300 * 299 // 2 <= _model_pairs(doc, loader) < 300 * 299 // 2 + 10
        assert _model_pairs(doc, loader) == _real_pairs(doc, loader, monkeypatch)
        assert ldp._canonize(doc, loader)

    def test_a_node_used_as_a_reverse_target_by_few_parents_still_passes(
            self, base_vc, monkeypatch):
        loader = document_loader()
        doc = _evidence(base_vc, [{'alignment': [
            {'name': 'c%d_%d' % (i, k), '@reverse': {'urn:p': {'@id': 'urn:t'}}}
            for k in range(40)]} for i in range(5)])
        assert _model_pairs(doc, loader) == _real_pairs(doc, loader, monkeypatch)
        assert _model_pairs(doc, loader) < 100_000
        assert ldp._canonize(doc, loader)


class TestModelAgainstPyld:
    """node_map_pairs is a replica of what pyld does while it builds the node
    map. These pin it to the real thing: never below what pyld compares, and
    exactly equal when the values are distinct."""

    def _random_document(self, rnd):
        ids = ['urn:n%d' % i for i in range(6)] + ['_:b%d' % i for i in range(4)]

        def value(level):
            kind = rnd.randrange(5)
            if kind == 0:
                return rnd.choice(['x', 'y', 'z', 1, 2, True])
            if kind == 1:
                return {'@id': rnd.choice(ids)}
            if kind == 2:
                return {'@value': rnd.choice(['x', 'y']), '@language': 'en'}
            if kind == 3:
                return {'@list': [rnd.choice(['x', 'y', 'z'])
                                  for _ in range(rnd.randrange(4))]}
            return node(level + 1)

        def node(level):
            n = {'@id': rnd.choice(ids)} if rnd.random() < 0.8 else {}
            for _ in range(rnd.randrange(4)):
                prop = rnd.choice(['urn:p', 'urn:q', 'urn:r'])
                n.setdefault(prop, []).extend(
                    value(level) for _ in range(rnd.randrange(1, 5)))
            if level < 2 and rnd.random() < 0.4:
                n['@reverse'] = {rnd.choice(['urn:rp', 'urn:rq']): [
                    node(level + 1) for _ in range(rnd.randrange(1, 4))]}
            if level < 2 and rnd.random() < 0.15:
                n['@included'] = [node(level + 1)]
            if rnd.random() < 0.4:
                n['@type'] = rnd.sample(['urn:T1', 'urn:T2', 'urn:T3'],
                                        rnd.randrange(1, 3))
            return n
        return {'@context': {'@vocab': 'urn:v#'},
                '@graph': [node(0) for _ in range(rnd.randrange(1, 6))]}

    def test_the_model_never_undercounts_a_random_corpus(self, monkeypatch):
        rnd = random.Random(2026)
        loader = document_loader()
        checked = 0
        for _ in range(100):
            doc = self._random_document(rnd)
            try:
                model = _model_pairs(doc, loader)
                real = _real_pairs(doc, loader, monkeypatch)
            except Exception:
                monkeypatch.undo()
                continue                # (a random document pyld rejects)
            assert model >= real, (model, real, json.dumps(doc))
            checked += 1
        assert checked > 60

    def test_distinct_values_are_counted_exactly(self, base_vc, monkeypatch):
        loader = document_loader()
        for doc in (flat_tags(base_vc, 300),
                    reverse_flood(base_vc, 6, 5), hub_results(base_vc, 40),
                    shared_creator(base_vc, 60)):
            assert _model_pairs(doc, loader) == \
                _real_pairs(doc, loader, monkeypatch)

    def test_repeated_values_are_bounded_whatever_the_order(self, base_vc,
                                                            monkeypatch):
        loader = document_loader()
        for tags in (['a', 'b', 'a', 'b', 'c', 'a'] * 20, ['b'] + ['a'] * 30,
                     ['a'] * 30 + ['b'], [str(i % 7) for i in range(80)]):
            doc = copy.deepcopy(base_vc)
            doc['credentialSubject']['achievement']['tag'] = tags
            assert _model_pairs(doc, loader) >= \
                _real_pairs(doc, loader, monkeypatch)


# ── fail closed when pyld is not what the cost model describes ───────────────

class TestFailsClosed:
    def _canonize_must_refuse(self, base_vc, match='cannot canonicalize safely',
                              error=OB3GuardUnavailable):
        with pytest.raises(error, match=match) as caught:
            ldp._canonize(copy.deepcopy(base_vc), document_loader())
        return str(caught.value)

    def test_pyld_4_is_refused_not_run_unmetered(self, base_vc, monkeypatch):
        import pyld.__about__ as about
        monkeypatch.setattr(about, '__version__', '4.0.0')
        calls = []
        real = jsonld.normalize
        monkeypatch.setattr(jsonld, 'normalize',
                            lambda *a, **k: calls.append(1) or real(*a, **k))
        self._canonize_must_refuse(base_vc, 'pyld 4.0.0 is not supported')
        assert not calls

    def test_a_missing_hook_is_refused(self, base_vc, monkeypatch):
        from pyld import canon
        monkeypatch.delattr(canon.URDNA2015, 'create_hash_to_related')
        self._canonize_must_refuse(base_vc, 'no create_hash_to_related')

    def test_a_pyld_that_permutes_differently_is_refused(self, base_vc,
                                                         monkeypatch):
        # pyld 4 enumerates with itertools.permutations: no in-place swaps, so
        # the per-step meter would see nothing and a hostile group would run
        # unmetered.
        from pyld import canon
        monkeypatch.setattr(
            canon, 'permutations',
            lambda items: (list(p) for p in itertools.permutations(sorted(items))))
        text = self._canonize_must_refuse(base_vc, 'permutations')
        assert 'steps through 0 permutations' in text

    def test_a_pyld_that_stops_swapping_groups_of_three_or_more_is_refused(
            self, base_vc, monkeypatch):
        # A generator that still swaps in place for pairs but not beyond:
        # the first canary (a group of two) alone would pass.
        from pyld import canon
        real = canon.permutations

        def partial(elements):
            if len(elements) > 2:
                return (list(p) for p in itertools.permutations(sorted(elements)))
            return real(elements)
        monkeypatch.setattr(canon, 'permutations', partial)
        self._canonize_must_refuse(base_vc, 'steps through')

    def test_a_pyld_that_enumerates_repeated_members_is_refused(
            self, base_vc, monkeypatch):
        # pyld 3.x enumerates a group of equal entries once; one that did not
        # (Heap's algorithm below swaps in place and visits every ordering,
        # equal or not) would make every embedded proof cost size!
        # permutations. The distinct canary cannot tell it from pyld 3.3.0
        # (23 swaps either way); the repeated-member one can.
        from pyld import canon

        def heap(elements):
            elements.sort()
            n = len(elements)
            counters = [0] * n
            yield elements
            i = 0
            while i < n:
                if counters[i] < i:
                    j = 0 if i % 2 == 0 else counters[i]
                    elements[j], elements[i] = elements[i], elements[j]
                    yield elements
                    counters[i] += 1
                    i = 0
                else:
                    counters[i] = 0
                    i += 1
        monkeypatch.setattr(canon, 'permutations', heap)
        text = self._canonize_must_refuse(base_vc, 'steps through')
        assert 'expects 0' in text

    def test_a_small_recalibration_is_tolerated_a_large_one_is_not(
            self, base_vc, monkeypatch):
        # The canary's unit range is a tolerance, not an equality: a pyld that
        # does a little more work, or a constant nudged by one, must not brick
        # verification and signing.
        monkeypatch.setattr(guard, '_PERM_UNITS', guard._PERM_UNITS + 1)
        assert ldp._canonize(copy.deepcopy(base_vc), document_loader())
        guard._bounded_class.cache_clear()
        monkeypatch.setattr(guard, '_PERM_UNITS', 400)
        text = self._canonize_must_refuse(base_vc, 'work units')
        assert 'calibrated on' in text

    def test_a_changed_output_is_refused(self, base_vc, monkeypatch):
        document, nquads, swaps, units = guard._CANARIES[0]
        monkeypatch.setattr(guard, '_CANARIES', (
            (document, 'not what pyld emits\n', swaps, units),)
            + guard._CANARIES[1:])
        self._canonize_must_refuse(base_vc, 'known output')

    def test_the_message_says_what_to_do(self, base_vc, monkeypatch):
        document, nquads, swaps, units = guard._CANARIES[0]
        monkeypatch.setattr(guard, '_CANARIES', (
            (document, nquads, swaps + 2, units),) + guard._CANARIES[1:])
        text = self._canonize_must_refuse(base_vc, 'steps through')
        assert 'pyld 3.' in text                    # the version it found
        assert '%d' % (swaps + 2) in text           # what it expected
        assert 'pin pyld==3.3.0' in text            # the remedy

    def test_the_canary_proves_the_budget_is_enforced(self, monkeypatch):
        monkeypatch.setattr(guard.WorkBudget, 'charge', lambda self, units: None)
        with pytest.raises(guard.CanonicalizationGuardUnavailable):
            guard._bounded_class()

    def test_verifier_surfaces_it_as_a_verification_error(
            self, base_vc, verifier, ed25519_keypair, monkeypatch):
        import pyld.__about__ as about
        monkeypatch.setattr(about, '__version__', '4.0.0')
        with pytest.raises(OB3VerificationError,
                           match='cannot canonicalize') as caught:
            verifier.verify(_with_bogus_proof(base_vc, ed25519_keypair[1]))
        # ... of a kind a deployment can alert on apart from a bad credential
        assert isinstance(caught.value, OB3GuardUnavailable)

    def test_a_bad_credential_is_not_a_guard_failure(
            self, base_vc, verifier, ed25519_keypair):
        with pytest.raises(OB3VerificationError, match=REFUSED) as caught:
            verifier.verify(_with_bogus_proof(clique(base_vc, 8),
                                              ed25519_keypair[1]))
        assert not isinstance(caught.value, OB3GuardUnavailable)

    def test_signing_reports_it_with_the_guard_as_the_cause(
            self, base_vc, ed25519_keypair, monkeypatch):
        import pyld.__about__ as about
        monkeypatch.setattr(about, '__version__', '4.0.0')
        priv, pub = ed25519_keypair
        did = did_key(pub)
        with pytest.raises(ErrorSigningFile, match='cannot canonicalize') as c:
            add_data_integrity_proof(copy.deepcopy(base_vc), priv,
                                     '%s#%s' % (did, did[len('did:key:'):]))
        assert isinstance(c.value.__cause__, OB3GuardUnavailable)

    def test_the_canary_runs_once_however_many_threads_start_cold(
            self, base_vc, monkeypatch):
        builds = []
        real = guard._build_bounded_class

        def counting():
            builds.append(1)
            time.sleep(0.05)
            return real()
        monkeypatch.setattr(guard, '_build_bounded_class', counting)
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-5)
        try:
            threads = [threading.Thread(target=guard._bounded_class)
                       for _ in range(16)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            sys.setswitchinterval(old)
        assert len(builds) == 1


class TestSelfTestErrors:
    def test_an_unimportable_canonicalizer_is_refused(self, base_vc, monkeypatch):
        monkeypatch.setitem(__import__('sys').modules, 'pyld.canon', None)
        with pytest.raises(OB3VerificationError, match='not importable'):
            ldp._canonize(copy.deepcopy(base_vc), document_loader())

    def test_an_unexpected_error_in_the_canary_is_refused(self, base_vc,
                                                          monkeypatch):
        def boom(*args, **kwargs):
            raise ValueError('pyld changed')
        monkeypatch.setattr(guard, '_run', boom)
        with pytest.raises(guard.CanonicalizationGuardUnavailable,
                           match=r"self-test failed on pyld 3\.\d+\.\d+: "
                                 r"ValueError\('pyld changed'\)"):
            guard._bounded_class()

    @pytest.mark.parametrize('error', [MemoryError(), RecursionError('deep')],
                             ids=['memory', 'recursion'])
    def test_a_transient_resource_error_is_not_a_verdict_on_pyld(
            self, base_vc, monkeypatch, error):
        # Not "the guard cannot meter this pyld": the master text for the
        # same failure, and the next call (nothing was cached) just works.
        real = guard._run
        failures = []

        def flaky(*args, **kwargs):
            if not failures:
                failures.append(1)
                raise error
            return real(*args, **kwargs)
        monkeypatch.setattr(guard, '_run', flaky)
        with pytest.raises(OB3VerificationError,
                           match='could not canonicalize the credential') as c:
            ldp._canonize(copy.deepcopy(base_vc), document_loader())
        assert not isinstance(c.value, OB3GuardUnavailable)
        assert ldp._canonize(copy.deepcopy(base_vc), document_loader())

    def test_a_budget_that_never_trips_is_reported(self, monkeypatch):
        # (the canary must see the budget enforced, not just counted)
        monkeypatch.setattr(guard.WorkBudget, 'charge',
                            lambda self, units: setattr(self, 'spent',
                                                        self.spent + units))
        with pytest.raises(guard.CanonicalizationGuardUnavailable,
                           match='not enforced'):
            guard._bounded_class()

    def test_a_long_error_text_is_cut(self, base_vc, monkeypatch):
        def boom(*args, **kwargs):
            raise ValueError('x' * 5000)
        guard._bounded_class()                      # (its probe expands too)
        monkeypatch.setattr(jsonld, 'expand', boom)
        with pytest.raises(OB3VerificationError) as caught:
            ldp._canonize(copy.deepcopy(base_vc), document_loader())
        assert str(caught.value).startswith(
            'could not canonicalize the credential: xxx')
        assert len(str(caught.value)) < 400

    def test_malformed_json_ld_keeps_a_short_useful_message(self, base_vc):
        doc = copy.deepcopy(base_vc)
        doc['evidence'] = [{'type': 5, 'name': 'x' * 100_000}]
        with pytest.raises(OB3VerificationError) as caught:
            ldp._canonize(doc, document_loader())
        text = str(caught.value)
        assert text.startswith('could not canonicalize the credential: ')
        assert 'Invalid JSON-LD syntax' in text
        assert len(text) < 450, len(text)


# ── instance state only, and pyld's thread-unsafe caches ─────────────────────

class TestNoGlobalState:
    def test_pyld_is_left_untouched(self, base_vc):
        from pyld import canon
        before = (canon.URDNA2015.create_hash_to_related, canon.permutations,
                  canon.URDNA2015.hash_n_degree_quads, jsonld.normalize)
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._canonize(clique(base_vc, 8), document_loader())
        after = (canon.URDNA2015.create_hash_to_related, canon.permutations,
                 canon.URDNA2015.hash_n_degree_quads, jsonld.normalize)
        assert before == after

    def test_concurrent_checks_have_separate_budgets(self, base_vc):
        loader = document_loader()
        benign = copy.deepcopy(base_vc)
        expected = ldp._canonize(copy.deepcopy(benign), loader)
        hostile = clique(base_vc, 8)
        outcomes = {'refused': 0, 'ok': 0, 'wrong': 0}
        lock = threading.Lock()

        def run(doc, hostile_run):
            for _ in range(2):
                try:
                    result = ldp._canonize(copy.deepcopy(doc), loader)
                    key = 'ok' if (not hostile_run and result == expected) \
                        else 'wrong'
                except OB3VerificationError as exc:
                    key = 'refused' if (hostile_run and REFUSED in str(exc)) \
                        else 'wrong'
                with lock:
                    outcomes[key] += 1

        threads = ([threading.Thread(target=run, args=(hostile, True))
                    for _ in range(2)]
                   + [threading.Thread(target=run, args=(benign, False))
                      for _ in range(2)])
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes == {'refused': 4, 'ok': 4, 'wrong': 0}


class TestThreadSafety:
    """pyld keeps its resolved-context and inverse-context caches in plain
    LRU caches shared by the whole process: concurrent expand / compact /
    to_rdf calls interleave inside them, a cachetools LRUCache that raced
    keeps a stale key at its head, and every later call that must evict then
    fails with a KeyError for as long as the process lives (signing too)."""

    def _hammer(self, work, threads=16, rounds=4):
        errors = []
        results = []

        def run(index):
            for _ in range(rounds):
                try:
                    results.append(work(index))
                except Exception as exc:        # (a spurious failure is the bug)
                    errors.append(repr(exc)[:200])
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-5)
        try:
            pool = [threading.Thread(target=run, args=(i,))
                    for i in range(threads)]
            for t in pool:
                t.start()
            for t in pool:
                t.join(120)
        finally:
            sys.setswitchinterval(old)
        return errors, results

    def test_concurrent_verifications_never_fail_spuriously(
            self, base_vc, ed25519_keypair):
        loader = document_loader()
        priv, pub = ed25519_keypair
        did = did_key(pub)
        method = '%s#%s' % (did, did[len('did:key:'):])
        signed = add_data_integrity_proof(copy.deepcopy(base_vc), priv, method)
        hostile = _with_bogus_proof(identical_children(base_vc, 9), pub)
        expected = ldp._canonize(copy.deepcopy(base_vc), loader)

        def work(index):
            if index % 4 == 3:                          # a poison graph
                with pytest.raises(OB3VerificationError, match=REFUSED):
                    verify_data_integrity_proof(copy.deepcopy(hostile), pub)
                return None
            verify_data_integrity_proof(copy.deepcopy(signed), pub)
            ldp._check_json_ld_form(
                copy.deepcopy({k: v for k, v in signed.items()}),
                signed['proof'], loader)
            return ldp._canonize(copy.deepcopy(base_vc), loader)

        errors, results = self._hammer(work)
        assert errors == []
        assert [r for r in results if r is not None]
        assert all(r in (None, expected) for r in results)
        # a poisoned process fails every later call too
        verify_data_integrity_proof(copy.deepcopy(signed), pub)

    def test_the_lock_is_not_held_while_a_poison_graph_burns_its_allowance(
            self, base_vc, monkeypatch):
        # Another thread's canonicalization (URDNA2015) must not queue behind
        # a hostile one: only pyld's JSON-LD calls take the lock.
        from pyld import canon
        loader = document_loader()
        guard._bounded_class()                      # built before the patch
        entered = threading.Event()
        release = threading.Event()
        real = canon.URDNA2015.create_hash_to_related

        def parked(self, *args):
            entered.set()
            release.wait(30)
            return real(self, *args)
        monkeypatch.setattr(canon.URDNA2015, 'create_hash_to_related', parked)
        holder = threading.Thread(target=lambda: ldp._canonize(
            identical_children(base_vc, 3), loader))
        holder.start()
        try:
            assert entered.wait(30)
            # the other thread is inside URDNA2015 now: the lock is free
            assert guard.PYLD_LOCK.acquire(timeout=5)
            guard.PYLD_LOCK.release()
        finally:
            release.set()
            holder.join(60)

    def test_a_forked_child_does_not_inherit_a_held_lock(self):
        lock = threading.RLock()
        held = threading.Event()
        done = threading.Event()

        def hold():
            lock.acquire()
            held.set()
            done.wait(30)
        owner = threading.Thread(target=hold)
        owner.start()
        assert held.wait(30)
        try:
            guard._reinit_after_fork(lock)
            assert lock.acquire(timeout=5)
            lock.release()
        finally:
            done.set()
            owner.join(30)


class Interrupt(BaseException):
    """What a signal handler's timeout raises in the middle of a call (not
    KeyboardInterrupt itself, which would abort the test session)."""


def _spy_cache(name, size, seen, interrupt=None):
    """A stand-in for one of pyld's process-wide caches that records every
    access with the thread that made it and whether that thread held
    :data:`guard.PYLD_LOCK`."""
    from cachetools import LRUCache

    class Spy(LRUCache):
        def _note(self, op):
            seen[name].append(
                (op, threading.current_thread().name,
                 guard.PYLD_LOCK._is_owned()))

        def get(self, key, default=None):
            self._note('get')
            return super().get(key, default)

        def __getitem__(self, key):
            self._note('getitem')
            return super().__getitem__(key)

        def __contains__(self, key):
            self._note('in')
            return super().__contains__(key)

        def __setitem__(self, key, value):
            self._note('set')
            super().__setitem__(key, value)
            if interrupt is not None and interrupt['armed']:
                interrupt['armed'] = False
                # the entry is in, the bookkeeping is not: a stale key at the
                # head of the eviction order, as a torn update leaves it
                order = getattr(self, '_LRUCache__order', None)
                if order is not None:
                    order['stale'] = None
                    order.move_to_end('stale', last=False)
                raise Interrupt()
    return Spy(maxsize=size)


@pytest.fixture
def spies(monkeypatch):
    """pyld's two process-wide caches, replaced by recording ones."""
    seen = {'resolved': [], 'inverse': []}
    control = {'armed': False}
    monkeypatch.setattr(jsonld, '_resolved_context_cache',
                        _spy_cache('resolved', 100, seen))
    monkeypatch.setattr(jsonld, '_inverse_context_cache',
                        _spy_cache('inverse', 20, seen, control))
    seen['control'] = control
    return seen


def _method(pub):
    did = did_key(pub)
    return '%s#%s' % (did, did[len('did:key:'):])


class TestPrivateCaches:
    """The Data Integrity path keeps pyld's context caches apart per thread
    (ob3/_canon_guard.py): only the derivation of an inverse context, which
    pyld stores in a cache of its own, takes the process-wide lock."""

    def test_pyld_resolved_context_cache_is_never_used(
            self, base_vc, ed25519_keypair, verifier, spies):
        priv, pub = ed25519_keypair
        signed = add_data_integrity_proof(
            copy.deepcopy(base_vc), priv, _method(pub))
        verify_data_integrity_proof(copy.deepcopy(signed), pub)
        verifier.verify(copy.deepcopy(signed))
        with pytest.raises(OB3VerificationError, match='signature'):
            verifier.verify(_with_bogus_proof(base_vc, pub))
        with pytest.raises(OB3VerificationError, match=REFUSED):
            verifier.verify(_with_bogus_proof(clique(base_vc, 8), pub))
        assert spies['resolved'] == []

    def test_pyld_inverse_context_cache_is_only_used_under_the_lock(
            self, base_vc, ed25519_keypair, verifier, spies):
        priv, pub = ed25519_keypair
        signed = add_data_integrity_proof(
            copy.deepcopy(base_vc), priv, _method(pub))
        workers = [threading.Thread(
            target=lambda: verifier.verify(copy.deepcopy(signed)))
            for _ in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(60)
        accesses = spies['inverse']
        assert accesses and all(owned for _, _, owned in accesses)

    def test_a_cache_torn_by_an_interrupt_is_emptied_not_reused(
            self, base_vc, ed25519_keypair, verifier, spies):
        # An asynchronous exception between the two halves of a store leaves
        # pyld's LRU with a stale key at its head, and every later call that
        # must evict then fails with a KeyError for as long as the process
        # lives. The cache is put back to empty instead.
        priv, pub = ed25519_keypair
        signed = add_data_integrity_proof(
            copy.deepcopy(base_vc), priv, _method(pub))
        for index in range(20):
            jsonld._inverse_context_cache['filler%d' % index] = {'x': index}
        spies['control']['armed'] = True
        with pytest.raises(Interrupt):
            verifier.verify(copy.deepcopy(signed))
        for _ in range(3):                  # enough derivations to evict
            verifier.verify(copy.deepcopy(signed))

    def test_an_interrupted_call_discards_the_threads_contexts(self, base_vc):
        real = document_loader()
        guard._discard_thread_contexts()                # cold: it will fetch
        thread_cache = guard._thread_contexts()
        thread_cache['poisoned'] = object()

        def loader(url, options=None):
            raise Interrupt()
        with pytest.raises(Interrupt):
            ldp._canonize(copy.deepcopy(base_vc), loader)
        assert guard._thread_contexts() is not thread_cache
        assert 'poisoned' not in guard._thread_contexts()
        assert ldp._canonize(copy.deepcopy(base_vc), real)

    def test_a_rejected_document_costs_the_next_call_a_cold_start_only(
            self, base_vc):
        # Any exception out of a pyld call, a plain rejection included, drops
        # the thread's contexts: it cannot tell a refusal from an interrupt.
        loader = document_loader()
        expected = ldp._canonize(copy.deepcopy(base_vc), loader)
        warm = guard._thread_contexts()
        assert warm
        stranger = copy.deepcopy(base_vc)
        stranger['@context'] = stranger['@context'] + [
            'https://example.org/not-bundled']
        with pytest.raises(OB3VerificationError, match='not in the bundled'):
            ldp._canonize(stranger, loader)
        assert guard._thread_contexts() is not warm
        assert ldp._canonize(copy.deepcopy(base_vc), loader) == expected

    def test_a_threads_contexts_are_bounded(self):
        cache = guard._Cache(3)
        for key in 'abcde':
            cache[key] = key
        assert list(cache) == ['c', 'd', 'e']
        cache['d'] = 'again'                    # a known key makes no room
        assert list(cache) == ['c', 'd', 'e']

    def test_a_threads_contexts_are_its_own(self):
        seen = []
        threading.Thread(target=lambda: seen.append(
            guard._thread_contexts())).start()
        time.sleep(0.2)
        assert seen and seen[0] is not guard._thread_contexts()

    def test_the_output_is_the_same_on_a_cold_and_a_warm_cache(self, base_vc):
        for name, doc, loader in _documents(base_vc):
            guard._discard_thread_contexts()
            cold = ldp._canonize(copy.deepcopy(doc), loader)
            warm = ldp._canonize(copy.deepcopy(doc), loader)
            assert cold == warm == _stock(doc, loader), name

    def test_a_legitimate_check_does_not_queue_behind_a_hostile_one(
            self, base_vc, ed25519_keypair, verifier):
        # One request that passes every screen and costs well over a tenth of
        # a second to refuse (1,400 distinct tags: 980,000 duplicate checks)
        # is in flight. A legitimate check, which costs a few milliseconds
        # alone, finishes while it is still running; behind the old
        # process-wide lock it waited for the hostile one to be done.
        priv, pub = ed25519_keypair
        signed = add_data_integrity_proof(
            copy.deepcopy(base_vc), priv, _method(pub))
        hostile = _with_bogus_proof(flat_tags(base_vc, 1400), pub)
        verifier.verify(copy.deepcopy(signed))              # warm
        verifier.verify(copy.deepcopy(signed))

        def attack():
            with pytest.raises(OB3VerificationError):
                verifier.verify(copy.deepcopy(hostile))
        attacker = threading.Thread(target=attack)
        attacker.start()
        overlapped = 0
        waits = []
        try:
            time.sleep(0.05)
            for _ in range(5):
                started = time.perf_counter()
                verifier.verify(copy.deepcopy(signed))
                waits.append(time.perf_counter() - started)
                overlapped += attacker.is_alive()
        finally:
            attacker.join(120)
        assert overlapped >= 3, overlapped
        # (7 to 20 ms measured on a loaded laptop, 0.6 s and more before)
        assert min(waits) < 0.25 * _coverage_slowdown(), waits

    def test_a_pyld_that_ignores_the_cache_it_is_given_is_refused(
            self, base_vc, verifier, ed25519_keypair, monkeypatch):
        from cachetools import LRUCache
        real = jsonld.ContextResolver
        monkeypatch.setattr(
            jsonld, 'ContextResolver',
            lambda cache, loader: real(LRUCache(maxsize=10), loader))
        with pytest.raises(OB3GuardUnavailable,
                           match='without using the cache'):
            verifier.verify(_with_bogus_proof(base_vc, ed25519_keypair[1]))

    def test_a_pyld_without_the_inverse_context_hook_is_refused(
            self, base_vc, verifier, ed25519_keypair, monkeypatch):
        monkeypatch.delattr(jsonld.JsonLdProcessor, '_get_inverse_context')
        with pytest.raises(OB3GuardUnavailable, match='_get_inverse_context'):
            verifier.verify(_with_bogus_proof(base_vc, ed25519_keypair[1]))

    def test_a_pyld_that_never_asks_for_an_inverse_context_is_refused(
            self, base_vc, verifier, ed25519_keypair, monkeypatch):
        monkeypatch.setattr(jsonld.JsonLdProcessor, 'compact',
                            lambda self, document, context, options: document)
        with pytest.raises(OB3GuardUnavailable,
                           match='without asking for an inverse'):
            verifier.verify(_with_bogus_proof(base_vc, ed25519_keypair[1]))


class TestStorm:
    def test_a_mixed_storm_never_fails_spuriously(
            self, base_vc, ed25519_keypair):
        # Signing, verifying, context validation, the typed and the
        # many-values documents that pass every screen, and a poison graph,
        # sixteen threads, the interpreter switching threads every 10
        # microseconds.
        loader = document_loader()
        priv, pub = ed25519_keypair
        method = _method(pub)
        signed = add_data_integrity_proof(copy.deepcopy(base_vc), priv, method)
        typed = _with_bogus_proof(_evidence(base_vc, [
            {'type': ['DataIntegrityProof']} for _ in range(150)]), pub)
        tags = _with_bogus_proof(flat_tags(base_vc, 500), pub)
        poison = _with_bogus_proof(identical_children(base_vc, 9), pub)

        def work(index):
            kind = index % 5
            if kind == 0:
                verify_data_integrity_proof(copy.deepcopy(signed), pub)
                ldp._check_json_ld_form(
                    {k: v for k, v in signed.items() if k != 'proof'},
                    signed['proof'], loader)
            elif kind == 1:
                add_data_integrity_proof(copy.deepcopy(base_vc), priv, method)
            elif kind == 2:
                for doc in (typed, tags):
                    with pytest.raises(OB3VerificationError,
                                       match='signature'):
                        verify_data_integrity_proof(copy.deepcopy(doc), pub)
            elif kind == 3:
                with pytest.raises(OB3VerificationError, match=REFUSED):
                    verify_data_integrity_proof(copy.deepcopy(poison), pub)
            else:
                assert ldp._canonize(copy.deepcopy(base_vc), loader)
        errors, _ = TestThreadSafety()._hammer(work, threads=16, rounds=3)
        assert errors == []
        verify_data_integrity_proof(copy.deepcopy(signed), pub)   # not poisoned


# ── the signing side ─────────────────────────────────────────────────────────

class TestSigningInputBound:
    def test_an_oversized_document_is_refused_before_any_pyld_call(
            self, base_vc, ed25519_keypair, monkeypatch):
        calls = []
        for name in ('expand', 'to_rdf', 'compact', 'normalize'):
            real = getattr(jsonld, name)
            monkeypatch.setattr(
                jsonld, name,
                lambda *a, _real=real, **k: calls.append(1) or _real(*a, **k))
        doc = copy.deepcopy(base_vc)
        doc['evidence'] = [{'narrative': 'x' * (ldp.MAX_LDP_DOCUMENT_BYTES + 1)}]
        priv, pub = ed25519_keypair
        did = did_key(pub)
        with pytest.raises(ErrorSigningFile, match='over the .*-byte limit'):
            add_data_integrity_proof(doc, priv,
                                     '%s#%s' % (did, did[len('did:key:'):]))
        assert not calls

    def test_a_document_that_is_not_json_is_refused(self, base_vc,
                                                    ed25519_keypair):
        doc = copy.deepcopy(base_vc)
        doc['evidence'] = [{'narrative': object()}]
        priv, pub = ed25519_keypair
        did = did_key(pub)
        with pytest.raises(ErrorSigningFile, match='not plain JSON'):
            add_data_integrity_proof(doc, priv,
                                     '%s#%s' % (did, did[len('did:key:'):]))

    def test_a_compact_non_ascii_document_under_the_limit_still_signs(
            self, base_vc, ed25519_keypair):
        # Measured as the smallest text it can be sent as, not as json.dumps
        # escapes it (6 bytes per CJK character): a verifier accepts this.
        priv, pub = ed25519_keypair
        did = did_key(pub)
        doc = copy.deepcopy(base_vc)
        doc['credentialSubject']['achievement']['description'] = '学' * 70000
        assert len(json.dumps(doc)) > ldp.MAX_LDP_DOCUMENT_BYTES
        signed = add_data_integrity_proof(
            doc, priv, '%s#%s' % (did, did[len('did:key:'):]))
        verify_data_integrity_proof(signed, pub)

    def test_a_normal_document_still_signs(self, base_vc, ed25519_keypair):
        priv, pub = ed25519_keypair
        did = did_key(pub)
        signed = add_data_integrity_proof(
            copy.deepcopy(base_vc), priv, '%s#%s' % (did, did[len('did:key:'):]))
        verify_data_integrity_proof(signed, pub)


# ── the delegated ecdsa-sd-2023 path ─────────────────────────────────────────

class TestEcdsaSdPrescreen:
    """openvc-core canonicalizes with an unbounded pyld, so the document is
    canonicalized here first. A screen, not a bound — see the docstring of
    ldp._prescreen_canonicalization."""

    @pytest.fixture
    def fake_openvc(self, monkeypatch):
        calls = []

        class ProofError(Exception):
            pass

        class Suite:
            def verify(self, document, **kwargs):
                calls.append(document)

        monkeypatch.setattr(ldp, '_require_openvc_ecdsa_sd',
                            lambda: (Suite, ProofError))
        return calls

    def _secured(self, doc):
        secured = copy.deepcopy(doc)
        secured['proof'] = {
            'type': 'DataIntegrityProof', 'cryptosuite': 'ecdsa-sd-2023',
            'created': '2026-07-03T00:00:00Z',
            'verificationMethod': 'did:key:zDnaexample#zDnaexample',
            'proofPurpose': 'assertionMethod', 'proofValue': 'u2V0'}
        return secured

    def test_a_poison_graph_never_reaches_the_delegate(
            self, base_vc, p256_pem, fake_openvc):
        document = self._secured(clique(base_vc, 8))
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._verify_ecdsa_sd_2023(document, document['proof'], p256_pem,
                                      document_loader())
        assert not fake_openvc

    def test_a_poison_graph_in_the_proof_options_alone_is_refused(
            self, base_vc, p256_pem, fake_openvc):
        document = self._secured(base_vc)
        document['proof']['alignment'] = clique(base_vc, 8)['evidence']
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._verify_ecdsa_sd_2023(document, document['proof'], p256_pem,
                                      document_loader())
        assert not fake_openvc

    def test_the_document_and_the_proof_options_share_one_budget(
            self, base_vc, p256_pem, fake_openvc, half_budget):
        half = clique(base_vc, 5)
        document = self._secured(half)
        document['proof']['alignment'] = clique(base_vc, 5)['evidence']
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._verify_ecdsa_sd_2023(document, document['proof'], p256_pem,
                                      document_loader())
        assert not fake_openvc

    def test_a_cheap_document_is_handed_over(
            self, base_vc, p256_pem, fake_openvc):
        document = self._secured(base_vc)
        ldp._verify_ecdsa_sd_2023(document, document['proof'], p256_pem,
                                  document_loader())
        assert fake_openvc == [document]


def test_canonize_output_feeds_the_signature_unchanged(base_vc):
    # hashData is computed from the guarded output: if it ever differed from
    # stock pyld's, every signature made before this guard would stop
    # verifying. The W3C vector pins the digests; this pins the plumbing.
    loader = document_loader()
    stock = hashlib.sha256(_stock(base_vc, loader).encode()).digest()
    config = {'@context': base_vc['@context'], 'type': 'DataIntegrityProof'}
    data = ldp._hash_data(copy.deepcopy(base_vc), copy.deepcopy(config), loader)
    assert data[32:] == stock
