"""Bounded RDF canonicalization of untrusted Data Integrity documents —
ob3/_canon_guard.py, used by ob3.ldp._canonize.

A Data Integrity proof signs the canonical form of the RDF dataset a document
expands to, so the verifier canonicalizes BEFORE it can check the signature.
RDFC-1.0 (pyld calls it URDNA2015) is factorial on groups of blank nodes it
cannot tell apart: a 2.6 KB credential that passes context validation kept a
worker busy for minutes on an unpatched pyld 3.3.0. These tests pin that

* every hostile shape below is refused, through the real verifier and the
  signer, within seconds (unguarded each one costs 13-40 s or more);
* nothing legitimate pays for it: the guarded output is byte-identical to
  jsonld.normalize and spends a tiny fraction of the budget;
* the guard fails CLOSED when pyld is not the implementation its cost model
  was fitted to, and never touches process-global state.

The hostile documents only use members the pinned contexts define (the
propagating ``alignment`` term, under ``evidence``), which the credential model
tolerates, so context validation lets them through and the cost lands in
canonicalization.

Needs the [ldp] extra (pyld); skipped otherwise.
"""
import copy
import hashlib
import itertools
import json
import threading
import time

from pathlib import Path

import pytest

pytest.importorskip('pyld')

from pyld import jsonld  # noqa: E402

from openbadgeslib.errors import ErrorSigningFile  # noqa: E402
from openbadgeslib.ob3 import (  # noqa: E402
    OB3LdpSigner, OB3LdpVerifier, OB3VerificationError,
    add_data_integrity_proof)
from openbadgeslib.ob3 import _canon_guard as guard  # noqa: E402
from openbadgeslib.ob3 import ldp  # noqa: E402
from openbadgeslib.ob3.contexts import document_loader  # noqa: E402

from ldp_helpers import b58encode, did_key  # noqa: E402
from test_ob3_ldp_context_validation import _complete_document  # noqa: E402

FIXTURES = Path(__file__).parent / 'fixtures' / 'vc_di_eddsa'
REFUSED = 'refusing to canonicalize'
#: Generous: the budget takes ~0.4 s on a laptop; unguarded these cost 13-40 s.
DEADLINE = 10.0


# ── hostile documents ────────────────────────────────────────────────────────

def _evidence(base, nodes):
    doc = copy.deepcopy(base)
    doc['evidence'] = nodes
    return doc


def clique(base, n):
    """n labelled blank nodes, each linking to every other (unguarded:
    n=7 2 s, n=8 20 s)."""
    return _evidence(base, [
        {'id': '_:b%d' % i,
         'alignment': [{'id': '_:b%d' % j} for j in range(n) if j != i]}
        for i in range(n)])


def tree(base, branching, depth):
    """Unlabelled tree of nested nodes (branching 8, depth 2: 15 s)."""
    def grow(level):
        if level == 0:
            return {}
        return {'alignment': [grow(level - 1) for _ in range(branching)]}
    return _evidence(base, [grow(depth)])


def ring(base, n):
    """Directed ring of n labelled blank nodes (n=400: 13 s, ~n^2.8)."""
    return _evidence(base, [
        {'id': '_:b%d' % i, 'alignment': [{'id': '_:b%d' % ((i + 1) % n)}]}
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
    shared = [{'id': 'https://x.example/shared', 'name': 'v%d' % k}
              for k in range(per_parent)]
    return _evidence(base, [{'alignment': copy.deepcopy(shared)}
                            for _ in range(parents)])


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
    yield
    guard._bounded_class.cache_clear()


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
            stock = jsonld.normalize(copy.deepcopy(doc), {
                'algorithm': 'URDNA2015', 'format': 'application/n-quads',
                'documentLoader': loader})
            assert ldp._canonize(copy.deepcopy(doc), loader) == stock, name

    def test_spend_is_a_tiny_fraction_of_the_budget(self, base_vc):
        # The false-positive rate: the whole suite's ~640 canonicalizations
        # spend at most 1,129 units (the complete example, whose six
        # identical embedded proofs need real permutation work).
        for name, doc, loader in _documents(base_vc):
            budget = guard.WorkBudget()
            guard.canonize(jsonld, doc, loader, budget)
            assert budget.spent < 5000, (name, budget.spent)
            assert budget.spent < guard.MAX_CANON_WORK / 100, name

    def test_embedded_proof_graph_repeats_one_node_in_a_group(self):
        # A proof node's quads all name the same blank graph, so pyld sees a
        # group of six identical entries: 6! = 720 permutations if counted
        # naively, ONE if counted as pyld enumerates them. The guard meters
        # what happens, so the real document is not charged for the naive
        # count.
        budget = guard.WorkBudget()
        guard.canonize(jsonld, _complete_document(), document_loader(), budget)
        assert 0 < budget.spent < 2000


# ── hostile documents are refused ────────────────────────────────────────────

HOSTILE = [
    ('clique', lambda b: clique(b, 8)),
    ('clique-too-big-to-permute', lambda b: clique(b, 40)),
    ('tree-8x2', lambda b: tree(b, 8, 2)),
    ('tree-3x4', lambda b: tree(b, 3, 4)),
    ('ring-400', lambda b: ring(b, 400)),
    ('identical-children-9', lambda b: identical_children(b, 9)),
    ('identical-children-40', lambda b: identical_children(b, 40)),
    ('many-cliques', lambda b: many_cliques(b, 60, 5)),
]


class TestHostileDocuments:
    @pytest.mark.parametrize('make', [m for _, m in HOSTILE],
                             ids=[n for n, _ in HOSTILE])
    def test_verifier_refuses_in_seconds(self, base_vc, verifier,
                                         ed25519_keypair, make):
        doc = _with_bogus_proof(make(base_vc), ed25519_keypair[1])
        started = time.monotonic()
        with pytest.raises(OB3VerificationError, match=REFUSED):
            verifier.verify(doc)
        assert time.monotonic() - started < DEADLINE

    def test_the_proof_options_are_attacker_input_too(self, base_vc, verifier,
                                                      ed25519_keypair):
        doc = _with_bogus_proof(base_vc, ed25519_keypair[1])
        doc['proof']['alignment'] = clique(base_vc, 8)['evidence']
        started = time.monotonic()
        with pytest.raises(OB3VerificationError, match=REFUSED):
            verifier.verify(doc)
        assert time.monotonic() - started < DEADLINE

    def test_document_and_proof_options_share_one_budget(self, base_vc):
        # Each half costs 1.08M units, under the 2M budget alone, over it
        # together.
        half = clique(base_vc, 6)
        config = {'@context': half['@context'], 'type': 'DataIntegrityProof',
                  'alignment': half['evidence']}
        loader = document_loader()
        alone = guard.WorkBudget()
        ldp._canonize(copy.deepcopy(half), loader, alone)
        assert alone.spent < guard.MAX_CANON_WORK
        shared = guard.WorkBudget()
        ldp._canonize(copy.deepcopy(half), loader, shared)
        with pytest.raises(OB3VerificationError, match=REFUSED):
            ldp._canonize(config, loader, shared)

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

    def test_time_backstop(self, base_vc):
        budget = guard.WorkBudget(seconds=-1)     # already past its deadline
        with pytest.raises(OB3VerificationError, match='time limit'):
            ldp._canonize(identical_children(base_vc, 3), document_loader(),
                          budget)


class TestNodeMapBound:
    """Not canonicalization: pyld's JSON-LD to RDF conversion compares every
    new value of a node property with the ones already there."""

    @pytest.mark.parametrize('make', [
        lambda b: flat_tags(b, 2000),
        lambda b: merged_node(b, 60, 30),
    ], ids=['one-array', 'merged-across-arrays'])
    def test_refused_before_pyld_builds_the_node_map(self, base_vc, make):
        started = time.monotonic()
        with pytest.raises(OB3VerificationError,
                           match='too many values on one node property'):
            ldp._canonize(make(base_vc), document_loader())
        assert time.monotonic() - started < 1.0

    def test_a_realistic_large_array_passes(self, base_vc):
        out = ldp._canonize(flat_tags(base_vc, 600), document_loader())
        assert '"t0"' in out and '"t599"' in out

    def test_pairs(self):
        expanded = [{'@id': 'a', 'p': [{'@value': 1}] * 4, 'q': [{'@id': 'b'}]},
                    {'@id': 'a', 'p': [{'@value': 2}] * 3},
                    {'p': [{'@value': 3}] * 5}]
        # a.p: 7 values -> 21; a.q: 1 -> 0; the anonymous node's p: 10
        assert guard.node_map_pairs(expanded) == 31
        # a @list keeps duplicates without comparing them: linear in pyld
        assert guard.node_map_pairs(
            [{'@id': 'a', 'p': [{'@list': [{'@value': 1}] * 5000}]}]) == 0

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


# ── fail closed when pyld is not what the cost model describes ───────────────

class TestFailsClosed:
    def _canonize_must_refuse(self, base_vc, match='cannot canonicalize safely'):
        with pytest.raises(OB3VerificationError, match=match):
            ldp._canonize(copy.deepcopy(base_vc), document_loader())

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
        # unmetered. The canary's exact spend notices.
        from pyld import canon
        monkeypatch.setattr(
            canon, 'permutations',
            lambda items: (list(p) for p in itertools.permutations(sorted(items))))
        self._canonize_must_refuse(base_vc, 'work of the canary document')

    def test_a_recalibrated_cost_model_must_update_the_canary(self, base_vc,
                                                              monkeypatch):
        monkeypatch.setattr(guard, '_PERM_UNITS', guard._PERM_UNITS + 1)
        self._canonize_must_refuse(base_vc, 'work of the canary document')

    def test_a_changed_output_is_refused(self, base_vc, monkeypatch):
        monkeypatch.setattr(guard, '_CANARY_NQUADS', 'not what pyld emits\n')
        self._canonize_must_refuse(base_vc, 'known output')

    def test_the_canary_proves_the_budget_is_enforced(self, monkeypatch):
        monkeypatch.setattr(guard.WorkBudget, 'charge', lambda self, units: None)
        with pytest.raises(guard.CanonicalizationGuardUnavailable):
            guard._bounded_class()

    def test_verifier_surfaces_it_as_a_verification_error(
            self, base_vc, verifier, ed25519_keypair, monkeypatch):
        import pyld.__about__ as about
        monkeypatch.setattr(about, '__version__', '4.0.0')
        with pytest.raises(OB3VerificationError, match='cannot canonicalize'):
            verifier.verify(_with_bogus_proof(base_vc, ed25519_keypair[1]))


# ── instance state only ──────────────────────────────────────────────────────

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
            for _ in range(3):
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
                    for _ in range(3)]
                   + [threading.Thread(target=run, args=(benign, False))
                      for _ in range(3)])
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes == {'refused': 9, 'ok': 9, 'wrong': 0}


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
    stock = hashlib.sha256(jsonld.normalize(copy.deepcopy(base_vc), {
        'algorithm': 'URDNA2015', 'format': 'application/n-quads',
        'documentLoader': loader}).encode()).digest()
    config = {'@context': base_vc['@context'], 'type': 'DataIntegrityProof'}
    data = ldp._hash_data(copy.deepcopy(base_vc), copy.deepcopy(config), loader)
    assert data[32:] == stock


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
                           match='self-test failed: pyld changed'):
            guard._bounded_class()

    def test_a_budget_that_never_trips_is_reported(self, monkeypatch):
        # (the canary must see the budget enforced, not just counted)
        monkeypatch.setattr(guard.WorkBudget, 'charge',
                            lambda self, units: setattr(self, 'spent',
                                                        self.spent + units))
        with pytest.raises(guard.CanonicalizationGuardUnavailable,
                           match='not enforced'):
            guard._bounded_class()
