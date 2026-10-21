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
import random
import secrets
import signal
import sys
import threading
import time

import pytest

from openbadgeslib.ob3 import OB3VerificationError, ldp
from openbadgeslib.ob3.contexts import bundled_contexts, document_loader
from openbadgeslib.ob3.did import did_key_from_pem
from openbadgeslib.ob3._canon_guard import PYLD_LOCK
from openbadgeslib.ob3.ldp import (MAX_DELEGATED_QUADS, OB3LdpSigner,
                                   OB3LdpVerifier, verify_data_integrity_proof)

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


def _blank_clique(size):
    """The same graph spelled with blank nodes: the poison graph the work
    budget exists for."""
    return [{'id': e['id'].replace('urn:bnid:', '_:'),
             'alignment': [{'id': a['id'].replace('urn:bnid:', '_:')}
                           for a in e['alignment']]}
            for e in _named_clique(size)]


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
        hostile['evidence'] = _blank_clique(9)
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
        # the proof options and the document, once each: the lines of the
        # document are computed before the delegate runs and read again by
        # the lifecycle check, not canonicalized a third time
        assert runs.count('BoundedURDNA2015') == 2, runs
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


class TestStatementIndexingRefusals:
    """What ``_sd_disclosed_statements`` refuses, and how."""

    def test_a_graph_over_the_work_budget_is_refused(self, derived):
        # (the screen would have refused it first; this is the pass after the
        # signature, called by itself)
        document, _, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = _blank_clique(8)
        with _within(20), pytest.raises(OB3VerificationError,
                                        match='refusing to canonicalize'):
            ldp._sd_disclosed_statements(hostile, hostile['proof'])

    def test_a_refusal_of_the_guard_keeps_its_message(self, derived,
                                                      monkeypatch):
        document, _, _ = derived

        def refuse(*args, **kwargs):
            raise OB3VerificationError('refusing to canonicalize: over budget')

        monkeypatch.setattr(ldp, 'canonize_dataset', refuse)
        with pytest.raises(OB3VerificationError) as caught:
            ldp._sd_disclosed_statements(document, document['proof'])
        assert str(caught.value) == 'refusing to canonicalize: over budget'

    def test_a_proof_value_that_does_not_decode_is_refused(self, derived):
        document, _, _ = derived
        proof = dict(document['proof'], proofValue='u2V0BAAAA')
        with pytest.raises(OB3VerificationError,
                           match='cannot read the mandatory statements'):
            ldp._sd_disclosed_statements(document, proof)


# Literals whose N-Quads spelling is easiest to get wrong: pyld escapes a
# backslash, TAB, LF, CR and quote and unescapes them with a chain of
# replacements that is not its inverse, so openvc-core's round trip of the
# dataset through N-Quads text changes a literal that holds a backslash
# followed by t, n or r.
AWKWARD_LITERALS = [
    'plain text',
    'proof of \\theta',                 # backslash, t
    'a\\nb',                            # backslash, n
    'carriage \\return',                # backslash, r
    'C:\\Users\\new\\temp',
    'see \\textbf{x}',
    'caf\\u00e9 \\U0001F600',           # backslash, u: not an N-Quads escape here
    'quote\\"x',                        # backslash, quote
    'say "hi"',
    'line1\nline2',                     # a real LF
    'a\tb',                             # a real TAB
    'a\\\tb',                           # backslash, TAB
    'cr\rlf',                           # a real CR
    'é 日本 😀',
    'end\\',
    'a\\\\tb',                          # two backslashes, t
    '\\\\n',
    '\\ \\t \\n \\r',
    'tab\t\\t',
]


def _unsecured(document):
    return {k: v for k, v in document.items() if k != 'proof'}


def _openvc_lines(document):
    """The canonical lines openvc-core's verify canonicalizes the document to."""
    from openvc.proof import ecdsa_sd as sd
    from openvc.proof.contexts import document_loader as openvc_loader
    return sd._canonicalize(sd._to_nquads(
        _unsecured(document), openvc_loader(bundled_contexts())))[0]


def _verify_statements(secured, pub_pem):
    """Run openvc-core's own verify on *secured* and return the list of
    statements it relabeled and indexed, as it computed it (captured from its
    ``_relabel``), and the mandatory indexes it read."""
    from unittest import mock

    from openvc.proof import ecdsa_sd as sd
    seen = []
    real = sd._relabel

    def spy(lines, mapping):
        out = real(lines, mapping)
        seen.append(out)
        return out

    with mock.patch.object(sd, '_relabel', spy):
        sd.EcdsaSdProofSuite().verify(
            secured, public_key_jwk=ldp._p256_pem_to_jwk(pub_pem),
            extra_contexts=bundled_contexts())
    assert len(seen) == 1
    parsed = sd.decode_derived_proof(secured['proof']['proofValue'])
    return seen[0], set(parsed['mandatory_indexes'])


class TestStatementViewsParity:
    """The statements the lifecycle check indexes are the ones openvc-core's
    verify indexes, byte for byte, whatever the literals and the blank nodes
    look like. openvc-core canonicalizes the dataset after an N-Quads round
    trip that pyld does not invert, so this is NOT the canonical form of the
    dataset the JSON expands to: asserted here against openvc-core's own
    helpers and against its verify."""

    @pytest.mark.parametrize('extra', [
        {},
        {'evidence': [{'id': 'urn:bnid:x0', 'name': 'n'}]},
        {'evidence': [{'type': ['Evidence'], 'name': 'a "quoted"\nline \\ é 日本'},
                      {'type': ['Evidence'], 'name': 'twin'},
                      {'type': ['Evidence'], 'name': 'twin'}]},
        {'evidence': [{'type': ['Evidence'], 'name': 'e%d' % i,
                       'audience': ['a', 'b']} for i in range(40)]},
    ])
    def test_the_lines_are_the_ones_openvc_canonicalizes(
            self, ob3_credential, issuer, extra):
        doc = _credential(ob3_credential, issuer)
        doc.update(extra)
        ours = ldp._sd_canonical_lines(doc, ldp.WorkBudget())
        assert ours == _openvc_lines(doc)

    @pytest.mark.parametrize('literal', AWKWARD_LITERALS)
    def test_the_lines_survive_awkward_literals(self, ob3_credential, issuer,
                                                literal):
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = [{'type': ['Evidence'], 'name': literal},
                           {'type': ['Evidence'], 'name': literal + 'x'},
                           {'type': ['Evidence'], 'name': 'other'}]
        doc['credentialStatus'] = [{
            'type': 'BitstringStatusListEntry', 'statusPurpose': 'revocation',
            'statusListIndex': '7',
            'statusListCredential': 'https://example.com/status/1'}]
        ours = ldp._sd_canonical_lines(doc, ldp.WorkBudget())
        assert ours == _openvc_lines(doc)

    def test_the_dataset_the_json_expands_to_is_not_the_one_openvc_reads(
            self, ob3_credential, issuer):
        # Why the parametrization above matters: for a backslash followed by
        # t, n or r the canonical form of the dataset as the JSON expands to
        # it is NOT what openvc-core canonicalizes.
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = [{'type': ['Evidence'], 'name': 'proof of \\theta'}]
        direct = ldp._canonize(doc, document_loader())
        direct_lines = sorted({ln for ln in direct.split('\n') if ln})
        assert direct_lines != _openvc_lines(doc)
        assert ldp._sd_canonical_lines(doc, ldp.WorkBudget()) == _openvc_lines(doc)

    def test_the_statements_and_the_mandatory_indexes_are_the_ones_verify_reads(
            self, ob3_credential, issuer):
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = [{'id': 'urn:bnid:x%d' % i,
                            'name': 'e%d' % i} for i in range(3)]
        secured, signed_view = _hand_signed(
            doc, issuer, mandatory=lambda s: 'evidence' not in s)
        statements, mandatory = ldp._sd_disclosed_statements(
            secured, secured['proof'])
        assert any('urn:bnid:x0' in s for s in statements)
        assert statements == signed_view
        verified, verified_mandatory = _verify_statements(
            secured, issuer.pub_pem)
        assert statements == verified and mandatory == verified_mandatory

    def test_a_corpus_of_generated_credentials(self, ob3_credential, issuer):
        # Seeded, so a failure reproduces: documents with up to six blank
        # nodes carrying awkward literals, a status entry with and without an
        # id, alignments and evidence in arrays, and a random choice of the
        # statements the issuer made mandatory. For each, the statements and
        # the mandatory indexes the lifecycle check reads are what openvc-core
        # indexed in its verify, and the lifecycle verdict is the one the
        # helpers of 4.6.2 gave on the document as presented.
        rnd = random.Random(20261021)
        seen_difference = False
        verdicts = set()
        for case in range(60):
            doc = _credential(ob3_credential, issuer)
            status = {'type': 'BitstringStatusListEntry',
                      'statusPurpose': rnd.choice(['revocation', 'suspension']),
                      'statusListIndex': str(rnd.randrange(10 ** 6)),
                      'statusListCredential': 'https://example.com/status/1'}
            if rnd.random() < 0.5:
                status['id'] = 'https://example.com/status/1#%d' % case
            doc['credentialStatus'] = [status]
            doc['evidence'] = [
                {'type': ['Evidence'],
                 'name': rnd.choice(AWKWARD_LITERALS) + rnd.choice(['', 'x', '\\t']),
                 'audience': [rnd.choice(AWKWARD_LITERALS)
                              for _ in range(rnd.randrange(3))]}
                for _ in range(rnd.randrange(7))]
            if rnd.random() < 0.5:
                doc['credentialSubject']['achievement']['alignment'] = [
                    {'type': ['Alignment'], 'targetName': rnd.choice(AWKWARD_LITERALS),
                     'targetUrl': 'https://frameworks.example/%d' % i}
                    for i in range(rnd.randrange(4))]
            keep = rnd.choice([0.0, 0.5, 1.0])
            secured, _ = _hand_signed(doc, issuer,
                                      mandatory=lambda s: rnd.random() < keep)
            statements, mandatory = ldp._sd_disclosed_statements(
                secured, secured['proof'])
            verified, verified_mandatory = _verify_statements(
                secured, issuer.pub_pem)
            assert (statements, mandatory) == (verified, verified_mandatory), case
            seen_difference |= (sorted({ln for ln in ldp._canonize(
                _unsecured(secured), document_loader()).split('\n') if ln})
                != _openvc_lines(secured))

            def verdict():
                try:
                    ldp._reject_selective_sd_lifecycle(secured, secured['proof'])
                except OB3VerificationError as exc:
                    return str(exc)
                return None

            def legacy_verdict():
                from unittest import mock
                with mock.patch.object(
                        ldp, '_sd_disclosed_statements',
                        lambda doc, proof, lines=None: (verified, verified_mandatory)):
                    try:
                        ldp._reject_selective_sd_lifecycle(secured, secured['proof'])
                    except OB3VerificationError as exc:
                        return str(exc)
                    return None

            assert verdict() == legacy_verdict(), case
            verdicts.add(verdict() is None)
        assert seen_difference     # the corpus does exercise the round trip
        assert verdicts == {True, False}     # and both verdicts


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
        monkeypatch.setattr(ldp, 'MAX_DELEGATED_QUADS', count)
        verify_data_integrity_proof(document, pub_pem)
        assert len(delegate_calls) == 1
        monkeypatch.setattr(ldp, 'MAX_DELEGATED_QUADS', count - 1)
        with pytest.raises(OB3VerificationError, match=REFUSED_QUADS):
            ldp._prescreen_canonicalization(document, document['proof'])
        assert len(delegate_calls) == 1

    def test_the_statements_are_counted_before_the_quadratic_parse(
            self, derived, delegate_calls, monkeypatch):
        # pyld's N-Quads parser compares each statement with all the earlier
        # ones: a document over the cap must be refused on the count of its
        # text, before anything parses it.
        from pyld.jsonld import JsonLdProcessor
        document, pub_pem, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = _dense(1000, 9)
        parsed = []
        real = JsonLdProcessor.parse_nquads
        monkeypatch.setattr(JsonLdProcessor, 'parse_nquads', staticmethod(
            lambda text: parsed.append(1) or real(text)))
        with _within(60), pytest.raises(OB3VerificationError,
                                        match=REFUSED_QUADS):
            verify_data_integrity_proof(hostile, pub_pem)
        assert not parsed and not delegate_calls

    def test_the_duplicate_checks_of_the_conversion_are_counted_here_too(
            self, derived, delegate_calls):
        # One property of 1,500 distinct values is 1.1 million comparisons in
        # pyld's JSON-LD to RDF conversion, over the allowance shared with the
        # guard: refused before the conversion and before the delegate.
        document, pub_pem, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = [{'type': ['Evidence'],
                                'audience': ['a%d' % i for i in range(1500)]}]
        with _within(60), pytest.raises(OB3VerificationError,
                                        match='too many values'):
            verify_data_integrity_proof(hostile, pub_pem)
        assert not delegate_calls

    def test_a_clr_is_not_verifiable_with_ecdsa_sd_at_all(self, derived,
                                                          delegate_calls):
        # The delegate is given the bundled OB3 contexts alone, and so is the
        # screen: the CLR context (extra_contexts is ignored for this
        # cryptosuite) is unknown to both, so a CLR presentation, however
        # many statements it holds, is refused for that before any count.
        from openbadgeslib.ob3.clr import (CLR_CONTEXT_URL, bundled_clr_contexts,
                                           build_clr_credential)
        document, pub_pem, did = derived
        member = {k: v for k, v in document.items() if k != 'proof'}
        clr = build_clr_credential(did, [], [member], credential_id='urn:uuid:1')
        assert CLR_CONTEXT_URL in json.dumps(clr['@context'])
        clr['proof'] = document['proof']
        with pytest.raises(OB3VerificationError, match='context'):
            verify_data_integrity_proof(
                clr, pub_pem, extra_contexts=bundled_clr_contexts())
        assert not delegate_calls

    def test_a_guard_that_cannot_run_never_falls_back_to_pyld(
            self, derived, delegate_calls, monkeypatch):
        from openbadgeslib.ob3 import OB3GuardUnavailable
        from openbadgeslib.ob3._canon_guard import CanonicalizationGuardUnavailable
        document, pub_pem, _ = derived

        def down(*args, **kwargs):
            raise CanonicalizationGuardUnavailable('no meter')

        monkeypatch.setattr(ldp, 'canonize_dataset', down)
        with pytest.raises(OB3GuardUnavailable, match='cannot canonicalize safely'):
            verify_data_integrity_proof(document, pub_pem)
        assert not delegate_calls

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
        assert 1400 < _statements(doc) <= MAX_DELEGATED_QUADS / 1.1
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

    def test_the_screen_costs_what_the_delegate_costs(self, derived):
        # Measured with loose bounds. The screen replays the delegate's
        # pipeline on the document and the proof options (that is the point:
        # it must canonicalize what the delegate will), so it is of the
        # delegate's order, a fraction of a second at the very most.
        from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
        document, pub_pem, _ = derived
        jwk = ldp._p256_pem_to_jwk(pub_pem)

        def cpu(fn, repeat=5):
            fn()
            start = time.process_time()
            for _ in range(repeat):
                fn()
            return (time.process_time() - start) / repeat

        screen = cpu(lambda: ldp._prescreen_canonicalization(
            document, document['proof']))
        delegate = cpu(lambda: EcdsaSdProofSuite().verify(
            document, public_key_jwk=jwk, extra_contexts=bundled_contexts()))
        assert screen < 0.5
        assert screen < 5 * delegate


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


# ── a credential openvc-core issued and derived, read back by openvc-core ────

def _openvc_issue_and_derive(doc, issuer, *, selective):
    """*doc* issued by openvc-core with the strict mandatory pointers of
    test_ob3_ldp_ecdsa_sd.MANDATORY, then derived by it revealing those and
    *selective*."""
    from openvc.keys import P256SigningKey
    from openvc.proof.ecdsa_sd import EcdsaSdProofSuite

    from test_ob3_ldp_ecdsa_sd import MANDATORY
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(
        doc, signing_key=P256SigningKey.from_pem(issuer.priv_pem, kid=issuer.vm),
        verification_method=issuer.vm, mandatory_pointers=MANDATORY,
        extra_contexts=bundled_contexts())
    return suite.derive_proof(base, selective_pointers=selective,
                              extra_contexts=bundled_contexts())


def _delegate_accepts(derived, pub_pem):
    from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
    EcdsaSdProofSuite().verify(
        derived, public_key_jwk=ldp._p256_pem_to_jwk(pub_pem),
        extra_contexts=bundled_contexts())


class TestLegitimateCredentialsAreAccepted:
    """4.6.3 read the dataset the JSON expands to, where openvc-core reads the
    one its N-Quads round trip makes, so a credential openvc-core issued,
    derived and verifies was refused ("did not make mandatory") whenever a
    literal held a backslash followed by t, n or r and the status entry had no
    ``id``: the blank-node blocks landed on other statements than the ones the
    issuer marked mandatory (37 of 40 refused with six blank nodes)."""

    def test_forty_credentials_with_backslash_literals_and_a_status_without_id(
            self, ob3_credential, issuer):
        accepted = 0
        for trial in range(40):
            doc = _credential(ob3_credential, issuer)
            doc['credentialStatus'] = [{
                'type': 'BitstringStatusListEntry',
                'statusPurpose': 'revocation',
                'statusListIndex': str(1000 + trial),
                'statusListCredential': 'https://example.com/status/1'}]
            doc['evidence'] = [{'type': ['Evidence'], 'name': 'proof of \\theta%d' % i}
                               for i in range(6)]
            derived_doc = _openvc_issue_and_derive(
                doc, issuer, selective=['/evidence'])
            _delegate_accepts(derived_doc, issuer.pub_pem)
            assert OB3LdpVerifier(pubkey_pem=issuer.pub_pem).verify(
                derived_doc).issuer.id == issuer.did
            accepted += 1
        assert accepted == 40

    @pytest.mark.parametrize('literal', ['a\\nb', 'C:\\Users\\new\\temp',
                                         'see \\textbf{x}', 'carriage \\return'])
    def test_each_backslash_sequence(self, ob3_credential, issuer, literal):
        for trial in range(8):
            doc = _credential(ob3_credential, issuer)
            doc['credentialStatus'] = [{
                'type': 'BitstringStatusListEntry', 'statusPurpose': 'revocation',
                'statusListIndex': str(trial),
                'statusListCredential': 'https://example.com/status/1'}]
            doc['evidence'] = [{'type': ['Evidence'], 'name': '%s%d' % (literal, i)}
                               for i in range(4)]
            derived_doc = _openvc_issue_and_derive(
                doc, issuer, selective=['/evidence'])
            OB3LdpVerifier(pubkey_pem=issuer.pub_pem).verify(derived_doc)

    def test_a_status_entry_the_issuer_left_selective_is_still_refused(
            self, ob3_credential, issuer):
        # The other direction: with the same literals, an issuer who left the
        # members of a status entry without an id selective is refused every
        # time, whatever the HMAC key puts where.
        def members(statement):
            return statement.startswith('_:') and any(
                name in statement for name in
                ('statusPurpose', 'statusListIndex', 'statusListCredential'))

        for trial in range(20):
            doc = _credential(ob3_credential, issuer)
            doc['credentialStatus'] = [{
                'type': 'BitstringStatusListEntry', 'statusPurpose': 'suspension',
                'statusListIndex': str(trial),
                'statusListCredential': 'https://example.com/status/1'}]
            doc['evidence'] = [{'type': ['Evidence'], 'name': 'e%d\\t' % i}
                               for i in range(6)]
            secured, _ = _hand_signed(doc, issuer,
                                      mandatory=lambda s: not members(s))
            with pytest.raises(OB3VerificationError,
                               match='did not make mandatory'):
                OB3LdpVerifier(pubkey_pem=issuer.pub_pem).verify(secured)


# ── a clique that only the N-Quads round trip makes a clique ────────────────

def _decodable_proof_value():
    """A derived proofValue that decodes (the delegate decodes it before it
    canonicalizes anything) and signs nothing: what an attacker without any
    key attaches to a hostile document."""
    from openvc.keys import P256SigningKey
    from openvc.proof import ecdsa_sd as sd
    ephemeral = P256SigningKey.generate(kid='urn:ephemeral')
    return sd.encode_derived_proof(
        base_signature=b'\0' * 64,
        public_key=sd.p256_public_multikey(ephemeral.public_jwk()),
        signatures=[], label_map={}, mandatory_indexes=[])


def _collapsing_clique(base, size, collapse):
    """*size* evidence nodes, each aligned with every other, named by one of
    eight spellings of the same text: a backslash followed by ``t`` or by a
    TAB, three times over. The JSON tells the eight apart, so the dataset it
    expands to has no indistinguishable blank node and canonicalizes at once;
    openvc-core's N-Quads round trip turns every spelling into the same
    literal, and the clique is a poison graph for it (size 8: 22 to 29 s of
    CPU for a 2 KB document). Without *collapse* every node has a name of its
    own."""
    def name(i):
        if not collapse:
            return 'x%d' % i
        return 'x' + ''.join(
            ('\\\t' if (i >> bit) & 1 else '\\t') + 'y' for bit in range(3))

    doc = copy.deepcopy(base)
    doc['evidence'] = [
        {'id': '_:c%d' % i, 'type': ['Evidence'], 'name': name(i),
         'alignment': [{'id': '_:c%d' % j} for j in range(size) if j != i]}
        for i in range(size)]
    return doc


class TestNQuadsRoundTripCollapse:
    @pytest.fixture
    def attack(self, derived):
        document, pub_pem, _ = derived
        proof = dict(document['proof'], proofValue=_decodable_proof_value())

        def build(size, collapse=True):
            hostile = _collapsing_clique(document, size, collapse)
            hostile['proof'] = proof
            return hostile
        return build, pub_pem

    def test_the_spellings_are_one_literal_to_openvc_and_many_to_the_json(
            self, attack):
        build, _ = attack

        def evidence_names(lines):
            return {ln.split(' ', 2)[2] for ln in lines
                    if ln.startswith('_:') and '/name>' in ln.split(' ', 2)[1]}

        small = build(4)
        assert len({e['name'] for e in small['evidence']}) == 4    # the JSON
        direct = ldp._canonize(small, document_loader())
        assert len(evidence_names(direct.split('\n'))) == 4       # the dataset
        assert len(evidence_names(_openvc_lines(small))) == 1      # openvc's

    def test_a_clique_of_eight_is_refused_in_no_time(self, attack,
                                                     delegate_calls):
        build, pub_pem = attack
        hostile = build(8)
        assert len(json.dumps(hostile)) < 6000
        start = time.process_time()
        for verifier in (OB3LdpVerifier(), OB3LdpVerifier(pubkey_pem=pub_pem)):
            with _within(20), pytest.raises(OB3VerificationError,
                                            match='refusing to canonicalize'):
                verifier.verify(hostile)
        assert time.process_time() - start < 3.0
        assert not delegate_calls

    def test_through_the_low_level_entry_too(self, attack, delegate_calls):
        build, pub_pem = attack
        with _within(20), pytest.raises(OB3VerificationError,
                                        match='refusing to canonicalize'):
            verify_data_integrity_proof(build(8), pub_pem)
        assert not delegate_calls

    def test_a_clique_of_five_is_within_the_budget_and_reaches_the_delegate(
            self, attack, delegate_calls):
        # five indistinguishable nodes cost 115,000 units: allowed. The
        # signature is wrong, so the delegate refuses it: the point is that
        # the screen let it through.
        build, pub_pem = attack
        with _within(30), pytest.raises(OB3VerificationError,
                                        match='signature'):
            verify_data_integrity_proof(build(5), pub_pem)
        assert len(delegate_calls) == 1

    def test_the_same_clique_with_names_of_its_own_is_no_poison_graph(
            self, attack, delegate_calls):
        build, pub_pem = attack
        with _within(30), pytest.raises(OB3VerificationError,
                                        match='signature'):
            verify_data_integrity_proof(build(8, collapse=False), pub_pem)
        assert len(delegate_calls) == 1


# ── what openvc-core cannot canonicalize is refused before it is asked ──────

class TestUnreadableNQuads:
    """openvc-core splits the N-Quads text it parses with ``splitlines``, which
    breaks a line at a Unicode line separator (U+2028, U+2029, U+0085), VT, FF,
    FS, GS and RS, and its IRI pattern stops at a ``>``. A literal or an IRI
    that holds one can be neither signed nor verified by it, so the credential
    is refused here, before the delegate, with that limit named; every other
    character is canonicalized as before."""

    SEPARATORS = ['\u2028', '\u2029', '\x85', '\x0b', '\x0c', '\x1c', '\x1d',
                  '\x1e']

    @pytest.mark.parametrize('char', SEPARATORS)
    def test_a_line_separator_in_a_literal(self, derived, delegate_calls, char):
        document, pub_pem, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = [{'type': ['Evidence'], 'name': 'a%sb' % char}]
        with pytest.raises(OB3VerificationError,
                           match='openvc-core cannot canonicalize') as caught:
            verify_data_integrity_proof(hostile, pub_pem)
        assert 'Evidence' not in str(caught.value)      # never echoes the document
        assert not delegate_calls

    def test_a_closing_bracket_in_an_iri(self, derived, delegate_calls):
        document, pub_pem, _ = derived
        hostile = copy.deepcopy(document)
        hostile['evidence'] = [{'type': ['Evidence'],
                                'id': 'https://e.example/a>b'}]
        with pytest.raises(OB3VerificationError,
                           match='openvc-core cannot canonicalize'):
            verify_data_integrity_proof(hostile, pub_pem)
        assert not delegate_calls

    @pytest.mark.parametrize('char', SEPARATORS + ['\x1f', '\x00', '\x7f',
                                                   '\ufeff', ' ', 'é'])
    def test_the_refusal_is_exactly_openvcs(self, ob3_credential, issuer, char):
        # Differential: this library refuses a document exactly when
        # openvc-core's canonicalization raises on it.
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = [{'type': ['Evidence'], 'name': 'a%sb' % char}]
        try:
            _openvc_lines(doc)
            openvc_reads_it = True
        except Exception:
            openvc_reads_it = False
        try:
            ldp._sd_canonical_lines(_unsecured(doc), ldp.WorkBudget())
            we_read_it = True
        except OB3VerificationError:
            we_read_it = False
        assert we_read_it == openvc_reads_it == (char not in self.SEPARATORS)


# ── the delegate shares pyld's caches with everything else ──────────────────

@pytest.fixture(scope='module')
def derived_set(ob3_credential, issuer):
    """Three genuine derived credentials of different sizes."""
    documents = []
    for i in range(3):
        doc = _credential(ob3_credential, issuer)
        doc['evidence'] = [{'type': ['Evidence'], 'name': 'e%d-%d' % (i, k)}
                           for k in range(2 + i)]
        documents.append(_openvc_issue_and_derive(
            doc, issuer, selective=['/evidence']))
    return documents


def _hammer(jobs, threads, seconds):
    """Call the *jobs* (zero-argument callables, one per thread in turn) from
    *threads* threads for *seconds*, at the shortest thread switch interval
    that makes a data race likely; stop at the first failure. Returns (calls
    that returned, the failures, the threads still running after a minute)."""
    original = sys.getswitchinterval()
    stop = threading.Event()
    guard = threading.Lock()
    failures, calls = [], [0]

    def work(n):
        while not stop.is_set():
            try:
                jobs[n % len(jobs)]()
                with guard:
                    calls[0] += 1
            except Exception as exc:     # a regression: report it, don't hang
                with guard:
                    failures.append('%s: %s' % (type(exc).__name__, str(exc)[:160]))
                stop.set()

    workers = [threading.Thread(target=work, args=(n,), daemon=True)
               for n in range(threads)]
    sys.setswitchinterval(1e-5)
    try:
        for worker in workers:
            worker.start()
        stop.wait(seconds)
        stop.set()
        for worker in workers:
            worker.join(60)
    finally:
        sys.setswitchinterval(original)
    return calls[0], failures, [w for w in workers if w.is_alive()]


def _lock_is_free():
    """Whether another thread could take the pyld lock right now (the lock is
    reentrant, so the caller's own thread cannot tell)."""
    free = []

    def probe():
        if PYLD_LOCK.acquire(blocking=False):
            PYLD_LOCK.release()
            free.append(True)
        else:
            free.append(False)

    thread = threading.Thread(target=probe)
    thread.start()
    thread.join()
    return free[0]


class TestDelegateRunsUnderThePyldLock:
    """openvc-core's verify calls pyld on its own, and pyld's context caches
    are plain LRU caches shared by the whole process: concurrent calls
    corrupt them. Valid credentials were refused at random (several percent of
    them at 16 threads), and once corrupted every verification or signature
    in the process failed until a restart, for every cryptosuite, because the
    calls that held the library's lock read the same caches the delegate
    mutated without it."""

    def test_the_lock_is_held_while_the_delegate_runs(self, derived,
                                                      monkeypatch):
        from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
        document, pub_pem, _ = derived
        real = EcdsaSdProofSuite.verify
        held = []

        def verify(self, *args, **kwargs):
            held.append(not _lock_is_free())
            return real(self, *args, **kwargs)

        monkeypatch.setattr(EcdsaSdProofSuite, 'verify', verify)
        verify_data_integrity_proof(document, pub_pem)
        assert held == [True]

    def test_and_released_when_it_refuses(self, derived):
        document, _, _ = derived
        _, other_pub = _p256_pem_pair()
        with pytest.raises(OB3VerificationError):
            verify_data_integrity_proof(document, other_pub)
        assert _lock_is_free()

    def test_sixteen_threads_verifying_valid_credentials_never_fail(
            self, derived_set, issuer):
        verifier = OB3LdpVerifier(pubkey_pem=issuer.pub_pem)
        jobs = [lambda d=d: verifier.verify(copy.deepcopy(d))
                for d in derived_set]
        calls, failures, stuck = _hammer(jobs, 16, 6.0)
        assert not stuck
        assert not failures, failures[:3]
        assert calls >= 16
        verifier.verify(copy.deepcopy(derived_set[0]))      # and afterwards

    def test_and_neither_do_the_eddsa_verifications_beside_them(
            self, derived_set, issuer, ob3_credential, ed25519_keypair):
        # The signatures and verifications that already held the lock failed
        # too, because the delegate mutated the caches they read.
        priv, pub = ed25519_keypair
        signed = OB3LdpSigner(priv).sign(ob3_credential)
        sd_verifier = OB3LdpVerifier(pubkey_pem=issuer.pub_pem)
        ed_verifier = OB3LdpVerifier(pubkey_pem=pub)
        jobs = ([lambda d=d: sd_verifier.verify(copy.deepcopy(d))
                 for d in derived_set]
                + [lambda: ed_verifier.verify(copy.deepcopy(signed)),
                   lambda: OB3LdpSigner(priv).sign(ob3_credential)])
        calls, failures, stuck = _hammer(jobs, 16, 6.0)
        assert not stuck
        assert not failures, failures[:3]
        assert calls >= 16
        ed_verifier.verify(copy.deepcopy(signed))
