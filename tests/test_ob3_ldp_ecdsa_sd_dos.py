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
from openbadgeslib.ob3.ldp import OB3LdpVerifier

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
