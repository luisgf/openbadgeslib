"""Hostile and oversized documents through the delegated ecdsa-sd-2023 verify,
with the REAL openvc-core (the screen tests of test_ob3_ldp_canon_guard.py run
a fake delegate).

openvc-core canonicalizes with an unbounded pyld, and round-trips the dataset
through N-Quads text, which pyld parses in time quadratic in the number of
statements. ob3.ldp therefore screens a credential before delegating
(``_prescreen_canonicalization``: the poison-graph work under the work budget,
and ``MAX_DELEGATED_QUADS``), and canonicalizes it once more, after the
signature has verified, to index the statements the mandatory-lifecycle check
reads (``_sd_disclosed_statements``). That second pass must be metered too, and
must read the very graph openvc verified.

The signer below is a test helper: it hand-signs a derived proof over the
document AS PRESENTED, the way openvc-core's ``verify`` recomputes it, with
openvc's own (private) primitives, because openvc cannot issue a credential
that carries ``urn:bnid:`` IRIs.
"""
import contextlib
import copy
import json
import secrets
import signal
import threading
import time

import pytest

from openbadgeslib.ob3 import OB3VerificationError, ldp
from openbadgeslib.ob3.contexts import bundled_contexts, document_loader
from openbadgeslib.ob3.did import did_key_from_pem
from openbadgeslib.ob3.ldp import (MAX_DELEGATED_QUADS, OB3LdpVerifier,
                                   verify_data_integrity_proof)

from test_ob3_ldp_ecdsa_sd import (_issue_and_derive, _lifecycle_credential,
                                   _p256_pem_pair, _require_ldp_sd)

REFUSED_QUADS = 'statements, more than the'

_CRED = 'https://www.w3.org/2018/credentials#'
_LIFECYCLE_PREDICATES = tuple('<%s%s>' % (_CRED, p) for p in (
    'validFrom', 'validUntil', 'credentialStatus'))
_STATUS_NODE = '<https://example.com/status/1#0>'


# ── helpers ──────────────────────────────────────────────────────────────────

class _TooSlow(BaseException):
    """BaseException, so that verify's own ``except Exception`` cannot turn the
    alarm into an ordinary verification failure."""


@contextlib.contextmanager
def _within(seconds):
    """Fail the test, instead of hanging the run, when the block is still
    running after *seconds* (a regression here costs minutes, not a wrong
    answer). A no-op where SIGALRM is not available."""
    if not (hasattr(signal, 'setitimer')
            and threading.current_thread() is threading.main_thread()):
        yield
        return

    def alarm(signum, frame):
        raise _TooSlow()

    previous = signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    except _TooSlow:
        pytest.fail('still running after %s s' % seconds, pytrace=False)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class _Issuer:
    """A P-256 did:key, the issuer of everything below."""

    def __init__(self):
        self.priv_pem, self.pub_pem = _p256_pem_pair()
        self.did = did_key_from_pem(self.pub_pem)
        self.vm = '%s#%s' % (self.did, self.did[len('did:key:'):])


def _credential(ob3_credential, issuer):
    doc = _lifecycle_credential(ob3_credential).to_vc()
    doc['issuer'] = {'id': issuer.did, 'type': ['Profile'],
                     'name': 'Test Issuer', 'url': 'https://example.com'}
    return doc


def _hand_signed(doc, issuer, mandatory=lambda statement: True):
    """*doc* secured with an ecdsa-sd-2023 derived proof signed by *issuer*;
    the statements that ``mandatory`` accepts are covered by the base
    signature, the others by one ephemeral signature each. Returns the
    secured document and the statements openvc-core's verify indexes."""
    from openvc.keys import P256SigningKey
    from openvc.proof import ecdsa_sd as sd
    from openvc.proof.contexts import document_loader as openvc_loader

    loader = openvc_loader(bundled_contexts())
    unsecured = {k: v for k, v in doc.items() if k != 'proof'}
    lines, issued = sd._canonicalize(sd._to_nquads(unsecured, loader))
    hmac_key = secrets.token_bytes(32)
    label_map = {c[2:]: sd.hmac_label(hmac_key, c[2:])
                 for c in set(issued.values())}
    statements = sd._relabel(
        lines, {'_:' + k: '_:' + v for k, v in label_map.items()})
    indexes = [i for i, s in enumerate(statements) if mandatory(s)]
    chosen = set(indexes)
    ephemeral = P256SigningKey.generate(kid='urn:ephemeral')
    public_key = sd.p256_public_multikey(ephemeral.public_jwk())
    proof = {'type': 'DataIntegrityProof', 'cryptosuite': 'ecdsa-sd-2023',
             'created': '2026-07-03T00:00:00Z',
             'verificationMethod': issuer.vm,
             'proofPurpose': 'assertionMethod'}
    to_sign = (sd._proof_config_hash(proof, doc['@context'], loader)
               + public_key
               + sd._sha256_lines([s for i, s in enumerate(statements)
                                   if i in chosen]))
    value = sd.encode_derived_proof(
        base_signature=P256SigningKey.from_pem(
            issuer.priv_pem, kid=issuer.vm).sign(to_sign),
        public_key=public_key,
        signatures=[ephemeral.sign(sd._utf8_nquads(s + '\n', 'a statement'))
                    for i, s in enumerate(statements) if i not in chosen],
        label_map=label_map, mandatory_indexes=indexes)
    secured = copy.deepcopy(unsecured)
    secured['proof'] = dict(proof, proofValue=value)
    return secured, statements


def _named_clique(size):
    """*size* evidence nodes, each aligned with every other, all NAMED
    (``urn:bnid:`` IRIs): an IRI is not a blank node, so openvc-core's verify
    and the screen see no work in it. Spelled ``_:c0`` instead, the same graph
    is a poison graph and the screen refuses it."""
    return [{'id': 'urn:bnid:c%d' % i,
             'alignment': [{'id': 'urn:bnid:c%d' % j}
                           for j in range(size) if j != i]}
            for i in range(size)]


def _dense(nodes, values):
    """*nodes* evidence nodes of 3 + *values* statements each, no poison
    graph: the cost is the number of statements alone."""
    return [dict({'type': ['Evidence'], 'name': 'e%d' % i},
                 **({'audience': ['a%d' % k for k in range(values)]}
                    if values else {}))
            for i in range(nodes)]


@pytest.fixture(scope='module')
def issuer():
    _require_ldp_sd()
    return _Issuer()


@pytest.fixture
def delegate_calls(monkeypatch):
    """Count how many times the real EcdsaSdProofSuite.verify runs."""
    from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
    real = EcdsaSdProofSuite.verify
    calls = []

    def verify(self, *args, **kwargs):
        calls.append(1)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(EcdsaSdProofSuite, 'verify', verify)
    return calls


@pytest.fixture(scope='module')
def derived(ob3_credential):
    """A genuine derived credential (issued and derived by openvc-core)."""
    _require_ldp_sd()
    return _issue_and_derive(
        _lifecycle_credential(ob3_credential),
        selective=['/credentialSchema', '/validUntil', '/credentialStatus'])


def _statements(doc):
    """What the screen counts: the canonical statements of the document."""
    text = ldp._canonize({k: v for k, v in doc.items() if k != 'proof'},
                         document_loader())
    return text.count('\n')


# ── the post-signature statement indexing is metered and reads openvc's graph ─

class TestNamedNodesAreNotBlankNodes:
    """``_sd_disclosed_statements`` used to turn every ``urn:bnid:`` IRI of the
    presented document into a blank node before canonicalizing it with an
    unmetered pyld, after the signature check: another graph than the one
    openvc-core verified and the screen metered. It now reads the document as
    presented, through the guard."""

    def test_a_named_clique_verifies_in_no_time(self, ob3_credential, issuer):
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = _named_clique(9)
        secured, _ = _hand_signed(doc, issuer)
        assert len(json.dumps(secured)) < 5000
        start = time.process_time()
        with _within(30):
            try:
                OB3LdpVerifier().verify(secured)
            except OB3VerificationError:
                pass                    # refused is as good as verified
        assert time.process_time() - start < 2.0

    def test_the_same_clique_as_blank_nodes_is_refused(self, derived,
                                                       delegate_calls):
        # The control: spelled with blank nodes, the graph is the poison graph
        # the budget exists for, and the screen refuses it before the delegate.
        document, pub_pem, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = [
            {'id': e['id'].replace('urn:bnid:', '_:'),
             'alignment': [{'id': a['id'].replace('urn:bnid:', '_:')}
                           for a in e['alignment']]}
            for e in _named_clique(9)]
        with _within(30), pytest.raises(OB3VerificationError,
                                        match='refusing to canonicalize'):
            OB3LdpVerifier(pubkey_pem=pub_pem).verify(hostile)
        assert not delegate_calls

    def test_only_metered_canonicalizations_come_from_this_library(
            self, ob3_credential, issuer, monkeypatch):
        # Every URDNA2015 pass a verification starts is either openvc-core's
        # own (two: the document and the proof options) or a metered one.
        from pyld import canon
        runs = []
        real = canon.URDNA2015.main

        def main(self, *args, **kwargs):
            runs.append(type(self).__name__)
            return real(self, *args, **kwargs)

        monkeypatch.setattr(canon.URDNA2015, 'main', main)
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = _named_clique(4)
        secured, _ = _hand_signed(doc, issuer)
        runs.clear()
        OB3LdpVerifier().verify(secured)
        assert runs.count('URDNA2015') == 2, runs
        assert runs.count('BoundedURDNA2015') >= 3, runs
        assert set(runs) == {'URDNA2015', 'BoundedURDNA2015'}

    def test_both_views_of_the_statements_are_equal(self, ob3_credential,
                                                    issuer):
        from openvc.proof import ecdsa_sd as sd
        from openvc.proof.contexts import document_loader as openvc_loader
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = [{'id': 'urn:bnid:x%d' % i,
                            'name': 'e%d' % i} for i in range(3)]
        secured, signed_view = _hand_signed(
            doc, issuer, mandatory=lambda s: 'evidence' not in s)
        statements, mandatory = ldp._sd_disclosed_statements(
            secured, secured['proof'])
        assert any('urn:bnid:x0' in s for s in statements)
        assert statements == signed_view
        # and the signed view is what openvc-core's verify reads
        lines, _ = sd._canonicalize(sd._to_nquads(
            {k: v for k, v in secured.items() if k != 'proof'},
            openvc_loader(bundled_contexts())))
        parsed = sd.decode_derived_proof(secured['proof']['proofValue'])
        assert sd._relabel(lines, {
            '_:' + k: '_:' + v for k, v in parsed['label_map'].items()
        }) == statements
        assert mandatory == set(parsed['mandatory_indexes'])

    def test_a_lifecycle_the_issuer_made_mandatory_is_accepted(
            self, ob3_credential, issuer):
        # Deskolemizing shifted the statements, so the mandatory indexes of
        # the signed list pointed at other statements in the checked one and
        # this credential was refused.
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = [{'id': 'urn:bnid:x%d' % i,
                            'name': 'e%d' % i} for i in range(3)]
        secured, _ = _hand_signed(
            doc, issuer, mandatory=lambda s: 'urn:bnid:' not in s)
        OB3LdpVerifier(pubkey_pem=issuer.pub_pem).verify(secured)

    def test_a_lifecycle_the_issuer_left_selective_is_refused(
            self, ob3_credential, issuer):
        # ... and the other way round: the same shift let a credential whose
        # lifecycle statements were selective pass as mandatory.
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = [{'id': 'urn:bnid:x%d' % i,
                            'name': 'e%d' % i} for i in range(3)]

        def lifecycle(statement):
            return (statement.startswith(_STATUS_NODE)
                    or any(p in statement for p in _LIFECYCLE_PREDICATES))

        secured, _ = _hand_signed(doc, issuer,
                                  mandatory=lambda s: not lifecycle(s))
        with pytest.raises(OB3VerificationError, match='did not make mandatory'):
            OB3LdpVerifier(pubkey_pem=issuer.pub_pem).verify(secured)


class TestStatementViewsParity:
    """The statements the lifecycle check indexes are those openvc-core
    verified, for documents with blank nodes, named nodes and the literals
    whose N-Quads spelling is easiest to get wrong."""

    @pytest.mark.parametrize('extra', [
        {},
        {'evidence': [{'id': 'urn:bnid:x0', 'name': 'n'}]},
        {'evidence': [{'type': ['Evidence'], 'name': 'a "quoted"\nline \\ é 日本'},
                      {'type': ['Evidence'], 'name': 'twin'},
                      {'type': ['Evidence'], 'name': 'twin'}]},
        {'evidence': [{'type': ['Evidence'], 'name': 'e%d' % i,
                       'audience': ['a', 'b']} for i in range(40)]},
    ])
    def test_guarded_and_openvc_canonical_lines_agree(
            self, ob3_credential, issuer, extra):
        from openvc.proof import ecdsa_sd as sd
        from openvc.proof.contexts import document_loader as openvc_loader
        doc = _credential(ob3_credential, issuer)
        doc.update(extra)
        ours = ldp._canonize(doc, document_loader())
        theirs, _ = sd._canonicalize(sd._to_nquads(
            doc, openvc_loader(bundled_contexts())))
        assert sorted({ln for ln in ours.split('\n') if ln}) == theirs


# ── the statement count ──────────────────────────────────────────────────────

class TestStatementCap:
    def test_a_dense_document_is_refused_before_the_delegate(
            self, derived, delegate_calls):
        document, pub_pem, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = _dense(1000, 9)
        assert _statements(hostile) > 12000
        start = time.process_time()
        with _within(60), pytest.raises(OB3VerificationError,
                                        match=REFUSED_QUADS):
            verify_data_integrity_proof(hostile, pub_pem)
        assert time.process_time() - start < 5.0
        assert not delegate_calls

    def test_through_the_verifier(self, derived, delegate_calls):
        document, pub_pem, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = _dense(1000, 9)
        for verifier in (OB3LdpVerifier(), OB3LdpVerifier(pubkey_pem=pub_pem)):
            with _within(60), pytest.raises(OB3VerificationError,
                                            match=REFUSED_QUADS):
                verifier.verify(hostile)
        assert not delegate_calls

    def test_the_cap_is_a_count_of_statements(self, derived, delegate_calls,
                                              monkeypatch):
        document, pub_pem, _ = derived
        count = _statements(document)
        loader = document_loader()
        monkeypatch.setattr(ldp, 'MAX_DELEGATED_QUADS', count)
        verify_data_integrity_proof(document, pub_pem)
        assert len(delegate_calls) == 1
        monkeypatch.setattr(ldp, 'MAX_DELEGATED_QUADS', count - 1)
        with pytest.raises(OB3VerificationError, match=REFUSED_QUADS):
            ldp._prescreen_canonicalization(document, document['proof'], loader)
        assert len(delegate_calls) == 1

    def test_a_document_at_the_cap_reaches_the_delegate(self, derived,
                                                        delegate_calls):
        # (its signature is wrong: the point is that the delegate was asked)
        document, pub_pem, _ = derived
        big = copy.deepcopy(document)
        big['evidence'] = _dense(MAX_DELEGATED_QUADS // 3 - 20, 0)
        assert MAX_DELEGATED_QUADS - 100 < _statements(big) <= MAX_DELEGATED_QUADS
        with _within(60), pytest.raises(OB3VerificationError,
                                        match='signature'):
            verify_data_integrity_proof(big, pub_pem)
        assert len(delegate_calls) == 1

    def test_the_cap_leaves_room_for_a_rich_credential(self, ob3_credential,
                                                       issuer):
        # 100 alignments and 100 pieces of evidence: 1,428 statements.
        doc = _credential(ob3_credential, issuer)
        doc['credentialSubject']['achievement']['alignment'] = [
            {'type': ['Alignment'], 'targetName': 'Skill %d' % i,
             'targetUrl': 'https://frameworks.example/skills/%d' % i,
             'targetFramework': 'Framework', 'targetCode': 'S%d' % i,
             'targetDescription': 'Description of skill %d' % i}
            for i in range(100)]
        doc['evidence'] = [
            {'type': ['Evidence'], 'id': 'https://e.example/%d' % i,
             'name': 'Evidence %d' % i, 'description': 'd', 'narrative': 'n',
             'genre': 'g', 'audience': 'a'} for i in range(100)]
        assert 1400 < _statements(doc) < MAX_DELEGATED_QUADS * 0.6
        secured, _ = _hand_signed(doc, issuer)
        with _within(60):
            OB3LdpVerifier(pubkey_pem=issuer.pub_pem).verify(secured)


# ── a genuine credential, and what the screen costs it ──────────────────────

class TestGenuineCredential:
    def test_verifies(self, derived, delegate_calls):
        document, pub_pem, did = derived
        credential = OB3LdpVerifier(pubkey_pem=pub_pem).verify(document)
        assert credential.issuer.id == did
        assert len(delegate_calls) == 1

    def test_the_screen_is_cheap_next_to_the_delegate(self, derived):
        # Measured with loose bounds. The screen canonicalizes a genuine
        # credential twice (document and proof options) and the delegate does
        # the same, so the screen is of that order, a fraction of a second at
        # the very most.
        from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
        document, pub_pem, _ = derived
        loader = document_loader()
        jwk = ldp._p256_pem_to_jwk(pub_pem)

        def cpu(fn, repeat=5):
            fn()
            start = time.process_time()
            for _ in range(repeat):
                fn()
            return (time.process_time() - start) / repeat

        screen = cpu(lambda: ldp._prescreen_canonicalization(
            document, document['proof'], loader))
        delegate = cpu(lambda: EcdsaSdProofSuite().verify(
            document, public_key_jwk=jwk, extra_contexts=bundled_contexts()))
        assert screen < 0.5
        assert screen < 10 * delegate


# ── the cheap checks come first, and a one-element proof array verifies ─────

class TestProofValue:
    @pytest.mark.parametrize('value', [None, 12345, ['u2V0'], {}, '', 'z3abc',
                                       'uAAAA', 'u'])
    def test_a_value_that_is_no_derived_proof_costs_nothing(
            self, derived, monkeypatch, delegate_calls, value):
        document, pub_pem, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = _named_clique(7)
        hostile['proof']['proofValue'] = value
        spent = []
        monkeypatch.setattr(ldp, '_canonize',
                            lambda *a, **k: spent.append(1) or '')
        with pytest.raises(OB3VerificationError, match='proofValue'):
            verify_data_integrity_proof(hostile, pub_pem)
        assert not spent and not delegate_calls


class TestProofArray:
    def test_a_one_element_array_verifies(self, derived):
        document, pub_pem, did = derived
        wrapped = copy.deepcopy(document)
        wrapped['proof'] = [wrapped['proof']]
        verify_data_integrity_proof(wrapped, pub_pem)
        credential = OB3LdpVerifier(pubkey_pem=pub_pem).verify(wrapped)
        assert credential.issuer.id == did
        assert OB3LdpVerifier().verify(wrapped).issuer.id == did

    def test_a_tampered_one_element_array_is_refused(self, derived):
        document, pub_pem, _ = derived
        wrapped = copy.deepcopy(document)
        wrapped['proof'] = [wrapped['proof']]
        wrapped['name'] = 'Bachelor of Villainy'
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=pub_pem).verify(wrapped)

    def test_the_lifecycle_check_still_applies_to_an_array(self, ob3_credential):
        _require_ldp_sd()
        from test_ob3_ldp_ecdsa_sd import LAX_MANDATORY
        lax, pub_pem, _ = _issue_and_derive(
            _lifecycle_credential(ob3_credential),
            selective=['/validUntil', '/credentialStatus'],
            mandatory=LAX_MANDATORY)
        lax['proof'] = [lax['proof']]
        with pytest.raises(OB3VerificationError, match='did not make mandatory'):
            OB3LdpVerifier(pubkey_pem=pub_pem).verify(lax)

    def test_two_proofs_are_still_ambiguous(self, derived):
        document, pub_pem, _ = derived
        twice = copy.deepcopy(document)
        twice['proof'] = [twice['proof'], copy.deepcopy(twice['proof'])]
        with pytest.raises(OB3VerificationError, match='multiple'):
            OB3LdpVerifier(pubkey_pem=pub_pem).verify(twice)
