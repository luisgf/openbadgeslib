"""Context validation of OB 3.0 Data Integrity (LDP) credentials — ob3.ldp and
ob3/_context_validation.py.

eddsa-rdfc-2022 (and the delegated ecdsa-sd-2023) sign the RDF DATASET a
document expands to, while OB3LdpVerifier reads the validity window, status,
recipient and issuer from the JSON. These tests pin that the verifier refuses
any JSON that is not exactly the compacted form of what was signed — each
exploit below still carries a valid signature over the RDF dataset, which the
low-level verify_data_integrity_proof keeps accepting (by design: it checks
the proof alone) — and that every legitimate shape still verifies, including
one modelled on the 1EdTech "Complete OpenBadgeCredential" example.

Needs the [ldp] extra (pyld); skipped otherwise. The ecdsa-sd-2023 tests also
need [ldp-sd] (openvc-core) and follow its skip/fail policy (#221).
"""
import copy
import json
import re
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

import pytest

pytest.importorskip('pyld')

from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    load_pem_private_key)

from openbadgeslib.errors import ErrorSigningFile  # noqa: E402
from openbadgeslib.ob3 import (  # noqa: E402
    Achievement, Issuer, OB3LdpSigner, OB3LdpVerifier, OB3VerificationError,
    OpenBadgeCredential, add_data_integrity_proof, verify_data_integrity_proof)
from openbadgeslib.ob3 import _context_validation as cv  # noqa: E402
from openbadgeslib.ob3 import ldp  # noqa: E402
from openbadgeslib.ob3.contexts import document_loader  # noqa: E402
from openbadgeslib.ob3.credential import (  # noqa: E402
    Alignment, Evidence, IdentityObject, Result, ResultDescription)
from openbadgeslib.ob3.did import _b58btc_encode, did_key_from_pem  # noqa: E402
from test_ob3_status import _encoded_list  # noqa: E402

UTC = timezone.utc
VC = 'https://www.w3.org/2018/credentials#'
SEC = 'https://w3id.org/security#'
XSD_DATETIME = 'http://www.w3.org/2001/XMLSchema#dateTime'
OB3_CONTEXT = [
    'https://www.w3.org/ns/credentials/v2',
    'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',
    'https://purl.imsglobal.org/spec/ob/v3p0/extensions.json',
]
STATUS_ENTRY = {
    'id': 'https://issuer.example/status/1#5',
    'type': 'BitstringStatusListEntry',
    'statusPurpose': 'revocation',
    'statusListIndex': '5',
    'statusListCredential': 'https://issuer.example/status/1',
}
VECTORS = Path(__file__).parent / 'fixtures' / 'vc_di_eddsa'


# ── helpers ──────────────────────────────────────────────────────────────────

def _did_vm(pub_pem):
    did = did_key_from_pem(pub_pem)
    return did, '%s#%s' % (did, did[len('did:key:'):])


def _credential(issuer_id, **overrides):
    fields = dict(
        id='urn:uuid:00000000-0000-0000-0000-0000000000a1',
        issuer=Issuer(id=issuer_id, name='Real Issuer'),
        recipient_id='mailto:alice@example.com',
        achievement=Achievement(
            id='https://issuer.example/achievements/attendance',
            name='Attendance', description='d', criteria_narrative='c'),
        issuance_date=datetime(2020, 1, 1, tzinfo=UTC))
    fields.update(overrides)
    return OpenBadgeCredential(**fields)


def _sign_with_proof_options(document, priv_pem, vm, **options):
    """eddsa-rdfc-2022 over *document* with extra proof options (e.g.
    ``expires``), which add_data_integrity_proof does not take."""
    proof = {'type': 'DataIntegrityProof', 'cryptosuite': 'eddsa-rdfc-2022',
             'created': '2020-01-01T00:00:00Z', 'verificationMethod': vm,
             'proofPurpose': 'assertionMethod', **options}
    config = dict(proof, **{'@context': document['@context']})
    data = ldp._hash_data(document, config, document_loader())
    signature = load_pem_private_key(priv_pem, password=None).sign(data)
    return dict(document, proof=dict(proof, proofValue='z' + _b58btc_encode(signature)))


def _rejected(document, match, verifier=None, **kwargs):
    with pytest.raises(OB3VerificationError, match=match):
        (verifier or OB3LdpVerifier()).verify(document, **kwargs)


def _check(document):
    """Context validation alone, as OB3LdpVerifier runs it."""
    ldp._check_json_ld_form(document, document['proof'], document_loader())


def _status_lists(set_bits):
    """A download stub serving, for each URL of *set_bits*, a revocation
    Bitstring Status List with those bits set. Unsigned: the tests pass
    verify_status_list=False only to keep the fixture small."""
    def download(url, *args, **kwargs):
        return json.dumps({
            '@context': ['https://www.w3.org/ns/credentials/v2'], 'id': url,
            'type': ['VerifiableCredential', 'BitstringStatusListCredential'],
            'credentialSubject': {
                'id': url + '#list', 'type': 'BitstringStatusList',
                'statusPurpose': 'revocation',
                'encodedList': _encoded_list(set_bits[url])}}).encode()
    return download


@pytest.fixture()
def issuer(ed25519_keypair):
    """(priv, pub, did, vm) of a did:key issuer: the DID-resolved, issuer-bound
    path (no pinned key) is the realistic one for these forgeries."""
    priv, pub = ed25519_keypair
    did, vm = _did_vm(pub)
    return priv, pub, did, vm


@pytest.fixture()
def expired(issuer):
    """A genuinely issued badge that expired in 2021."""
    priv, _, did, _ = issuer
    return OB3LdpSigner(priv).sign(
        _credential(did, expiration_date=datetime(2021, 1, 1, tzinfo=UTC)))


def _genuine_node(signed):
    return {k: v for k, v in signed.items() if k not in ('@context', 'proof')}


def _forged_root(signed, issuer_did, where):
    """A forged top-level credential whose statements the RDF conversion all
    drops (invalid IRIs), keeping the real issuer DID and recipient by
    reference, with the genuine signed node under *where* so the dataset — and
    the signature — are unchanged."""
    return {
        '@context': signed['@context'],
        'id': 'urn:forged x',
        'type': ['VerifiableCredential', 'OpenBadgeCredential'],
        'issuer': issuer_did,
        'credentialSubject': {
            'id': 'mailto:alice@example.com', 'type': ['AchievementSubject'],
            'achievement': {
                'id': 'https://evil.example/phd x', 'type': ['Achievement'],
                'name': 'PhD', 'description': 'x',
                'criteria': {'id': 'https://evil.example/c x', 'narrative': 'x'}}},
        'validFrom': '2020-01-01T00:00:00Z',
        'validUntil': '2099-01-01T00:00:00Z',
        where: [_genuine_node(signed)],
        'proof': signed['proof'],
    }


# ── exploits: a valid signature over the dataset, JSON that says otherwise ──

class TestForgedRoot:
    @pytest.mark.parametrize('where, match', [
        ('@included', '@included'),
        ('https://example.org/anyprop', 'node id the signed dataset drops'),
    ])
    def test_forged_root_did_path(self, issuer, expired, where, match):
        _, pub, did, _ = issuer
        forged = _forged_root(expired, did, where)
        verify_data_integrity_proof(forged, pub)   # the dataset is unchanged
        _rejected(forged, match)
        _rejected(forged, match, OB3LdpVerifier.for_issuer_did(did))

    @pytest.mark.parametrize('where', ['@included', 'https://example.org/anyprop'])
    def test_forged_root_pinned_key(self, issuer, expired, where):
        _, pub, did, _ = issuer
        forged = _forged_root(expired, did, where)
        forged['issuer'] = {'id': 'https://evil.example/issuer x',
                            'type': ['Profile'], 'name': 'Evil'}
        verify_data_integrity_proof(forged, pub)
        _rejected(forged, 'not accepted|drops', OB3LdpVerifier(pubkey_pem=pub))


class TestRekeyedPolicyMembers:
    def test_valid_until_as_full_iri(self, issuer, expired):
        _, pub, _, _ = issuer
        doc = copy.deepcopy(expired)
        doc[VC + 'validUntil'] = {'@value': doc.pop('validUntil'),
                                  '@type': XSD_DATETIME}
        verify_data_integrity_proof(doc, pub)
        _rejected(doc, 'not in compacted form')

    def test_valid_until_behind_inline_alias(self, issuer, expired):
        _, pub, _, _ = issuer
        doc = copy.deepcopy(expired)
        doc['@context'] = list(doc['@context']) + [
            {'vu': {'@id': VC + 'validUntil', '@type': XSD_DATETIME}}]
        doc['vu'] = doc.pop('validUntil')
        verify_data_integrity_proof(doc, pub)
        _rejected(doc, 'inline @context object')

    def test_credential_status_as_full_iri_is_not_skipped(self, issuer):
        priv, pub, did, _ = issuer
        signed = OB3LdpSigner(priv).sign(
            _credential(did, credential_status=[dict(STATUS_ENTRY)]))
        doc = copy.deepcopy(signed)
        doc[VC + 'credentialStatus'] = doc.pop('credentialStatus')
        verify_data_integrity_proof(doc, pub)
        fetched = []

        def download(url, *args, **kwargs):
            fetched.append(url)
            raise AssertionError('the status list must not be fetched')

        _rejected(doc, 'not in compacted form', check_status=True,
                  download=download)
        assert fetched == []

    def test_proof_expires_as_full_iri(self, issuer):
        priv, pub, did, vm = issuer
        unsecured = _credential(did).to_vc()
        signed = _sign_with_proof_options(unsecured, priv, vm,
                                          expires='2021-01-01T00:00:00Z')
        _rejected(signed, 'proof has expired')
        doc = copy.deepcopy(signed)
        doc['proof'][SEC + 'expiration'] = {
            '@value': doc['proof'].pop('expires'), '@type': XSD_DATETIME}
        verify_data_integrity_proof(doc, pub)
        _rejected(doc, 'the proof is not in compacted form')

    def test_undefined_term_is_refused(self, issuer, expired):
        doc = copy.deepcopy(expired)
        doc['credentialSubject']['creditsEarnedX'] = 99
        _rejected(doc, r'compacted form .*credentialSubject/creditsEarnedX')


def _no_fetch(url, *args, **kwargs):
    raise AssertionError('nothing must be fetched: %s' % url)


class TestDefinedTermSpelling:
    """A value that does not match its term's definition (an untyped date, a
    language-tagged one, a literal where the term takes a node) is compacted
    under its predicate's absolute IRI or an inline-@vocab suffix -- which IS
    its compacted form -- so it hides from the member the policy reads. Each
    document here is freshly signed: the issuer's own key (a self-asserted
    did:key, or a signer that emits the shape) over an out-of-policy value.
    The full IRI is refused by the term rule; an inline @vocab is refused
    outright, before it can respell anything."""

    SPELLINGS = {
        # spelling: (inline @vocab, the key, refused with)
        'iri': (None, lambda field: VC + field, 'credential spells a property'),
        'iri-with-vocab': (VC, lambda field: VC + field,
                           'credential carries an inline @context object'),
        'vocab-suffix': (VC + 'valid', lambda field: field[len('valid'):],
                         'credential carries an inline @context object'),
    }

    @pytest.mark.parametrize('spelling', sorted(SPELLINGS))
    @pytest.mark.parametrize('field', ['validUntil', 'validFrom'])
    @pytest.mark.parametrize('pinned', [False, True], ids=['did', 'pinned'])
    def test_out_of_window_date(self, issuer, pinned, field, spelling):
        priv, pub, did, vm = issuer
        if field == 'validUntil':
            dates = dict(expiration_date=datetime(2021, 1, 1, tzinfo=UTC))
            outside = 'has expired'
        else:
            dates = dict(issuance_date=datetime(2099, 1, 1, tzinfo=UTC),
                         expiration_date=datetime(2100, 1, 1, tzinfo=UTC))
            outside = 'not yet valid'
        if pinned:
            issuer_id, vm = 'https://issuer.example/i', 'did:example:issuer#k1'
            verifier = OB3LdpVerifier(pubkey_pem=pub)
        else:
            issuer_id, verifier = did, OB3LdpVerifier()
        body = _credential(issuer_id, **dates).to_vc()
        _rejected(add_data_integrity_proof(dict(body), priv, vm), outside, verifier)

        vocab, spell, match = self.SPELLINGS[spelling]
        if vocab:
            body['@context'] = list(body['@context']) + [{'@vocab': vocab}]
        body[spell(field)] = body.pop(field)
        doc = add_data_integrity_proof(body, priv, vm)
        verify_data_integrity_proof(doc, pub)
        with pytest.raises(OB3VerificationError, match=match):
            _check(doc)                       # the signer guard's check, too
        _rejected(doc, match, verifier)

    def test_language_tagged_date(self, issuer):
        priv, _, did, vm = issuer
        body = _credential(did, expiration_date=datetime(2021, 1, 1, tzinfo=UTC)).to_vc()
        body[VC + 'validUntil'] = {'@value': body.pop('validUntil'), '@language': 'en'}
        _rejected(add_data_integrity_proof(body, priv, vm), 'spells a property')

    @pytest.mark.parametrize('vocab, key, match', [
        (None, SEC + 'expiration', 'the proof spells a property'),
        (SEC + 'expira', 'tion', 'carries an inline @context object'),
    ], ids=['iri', 'vocab-suffix'])
    @pytest.mark.parametrize('pinned', [False, True], ids=['did', 'pinned'])
    def test_expired_proof(self, issuer, pinned, vocab, key, match):
        priv, pub, did, vm = issuer
        if pinned:
            issuer_id, vm = 'https://issuer.example/i', 'did:example:issuer#k1'
            verifier = OB3LdpVerifier(pubkey_pem=pub)
        else:
            issuer_id, verifier = did, OB3LdpVerifier()
        unsecured = _credential(issuer_id).to_vc()
        _rejected(_sign_with_proof_options(unsecured, priv, vm,
                                           expires='2000-01-01T00:00:00Z'),
                  'proof has expired', verifier)
        if vocab:
            unsecured['@context'] = list(unsecured['@context']) + [{'@vocab': vocab}]
        doc = _sign_with_proof_options(unsecured, priv, vm,
                                       **{key: '2000-01-01T00:00:00Z'})
        verify_data_integrity_proof(doc, pub)
        _rejected(doc, match, verifier)

    def test_status_as_a_literal(self, issuer):
        # credentialStatus takes a node; a plain string under its IRI is a
        # literal the status checker would never see.
        priv, _, did, vm = issuer
        body = _credential(did).to_vc()
        body[VC + 'credentialStatus'] = STATUS_ENTRY['id']
        doc = add_data_integrity_proof(body, priv, vm)
        _rejected(doc, 'spells a property', check_status=True, download=_no_fetch)

    def test_nested_member_inside_a_list(self, issuer):
        # statusListCredential takes a node; a literal under its IRI, inside
        # the credentialStatus array, is found wherever it sits.
        priv, _, did, vm = issuer
        hidden = dict(STATUS_ENTRY, id='https://issuer.example/status/1#6',
                      statusListIndex='6')
        hidden['https://www.w3.org/ns/credentials/status#statusListCredential'] = \
            hidden.pop('statusListCredential')
        body = _credential(did, credential_status=[dict(STATUS_ENTRY), hidden]).to_vc()
        doc = add_data_integrity_proof(body, priv, vm)
        _rejected(doc, r'spells a property .*/credentialStatus/1/https://',
                  check_status=True, download=_no_fetch)

    def test_extension_iris_are_left_alone(self, issuer):
        # IRIs no pinned context defines carry no term to spell them by.
        priv, _, did, vm = issuer
        body = _credential(did).to_vc()
        body['https://example.org/ext#note'] = 'x'
        body['urn:example:tag'] = 'y'
        OB3LdpVerifier().verify(add_data_integrity_proof(body, priv, vm))

    def test_json_literal_content_is_data(self, issuer):
        # The keys inside an @json literal (VC 2.0 "_sd") are not properties.
        priv, _, did, vm = issuer
        body = _credential(did).to_vc()
        body['_sd'] = [{VC + 'validUntil': '2021-01-01T00:00:00Z'}]
        OB3LdpVerifier().verify(add_data_integrity_proof(body, priv, vm))

    def test_term_spellings_are_derived_from_the_pinned_contexts(self):
        spellings = cv._term_spellings()
        assert spellings[VC + 'validUntil'] == {'validUntil'}
        assert spellings[SEC + 'expiration'] == {'expires'}
        assert spellings[VC + 'credentialStatus'] == {'credentialStatus'}


V1_CONTEXT = 'https://www.w3.org/2018/credentials/v1'
DI_CONTEXT = 'https://w3id.org/security/data-integrity/v2'
SL2021 = 'https://w3id.org/vc/status-list#'
SL2021_CONTEXT_URL = 'https://w3id.org/vc/status-list/2021/v1'
SL2021_CONTEXT = {'@context': {
    '@protected': True,
    'StatusList2021Entry': {'@id': SL2021 + 'StatusList2021Entry', '@context': {
        '@protected': True, 'id': '@id', 'type': '@type',
        'statusPurpose': SL2021 + 'statusPurpose',
        'statusListIndex': SL2021 + 'statusListIndex',
        'statusListCredential': {'@id': SL2021 + 'statusListCredential',
                                 '@type': '@id'}}}}}


def _vc11_signing_contexts():
    """The VC 1.1 base context (pyld bundles a copy; openbadgeslib does not
    serve it, and must not) and a StatusList2021 one: for SIGNING the
    issuer's VC 1.1 badge in these tests only."""
    frozen = pytest.importorskip('pyld.documentloader.frozen')
    path = frozen.BUNDLED_CONTEXTS.get(V1_CONTEXT)
    if path is None:
        pytest.skip('this pyld does not bundle the VC 1.1 context')
    return {V1_CONTEXT: json.loads(Path(path).read_text('utf-8')),
            SL2021_CONTEXT_URL: SL2021_CONTEXT}


class TestVc11Rebased:
    """OB 3.0 was first published on VCDM 1.1, so issuers signed badges under
    the VC 1.1 base context: issuanceDate / expirationDate, perhaps a
    StatusList2021Entry. Such a badge is refused as issued (VC 1.1 is not
    bundled), but a holder can re-compact it onto [VC 2.0, OB 3.0]: the
    dataset, and so the signature, stay the same, and compaction spells those
    members by full IRI, since no bundled context has a term for them. The
    model reads validUntil / validFrom (then issuanceDate / expirationDate),
    so it saw no expiry and no not-before, and the status entry's type was
    an IRI. Every IRI the policy reads must now be spelled by the one key it
    reads it under (_POLICY_TERMS), whether or not a bundled context
    defines it."""

    CASES = {
        # case: (VC 1.1 members, where the rebased form is refused)
        'expired': ({'expirationDate': '2021-01-01T00:00:00Z'},
                    '/' + VC + 'expirationDate'),
        'not-yet-valid': ({'issuanceDate': '2099-01-01T00:00:00Z'},
                          '/' + VC + 'issuanceDate'),
        'sl2021-status': ({'credentialStatus': {
            'id': 'https://issuer.example/status/1#5',
            'type': 'StatusList2021Entry', 'statusPurpose': 'revocation',
            'statusListIndex': '5',
            'statusListCredential': 'https://issuer.example/status/1'}},
            '/credentialStatus/type'),
    }

    @staticmethod
    def _issue(issuer_id, priv, vm, members):
        """A VC 1.1-shaped OB 3.0 badge, signed by its issuer with the
        low-level signer and the VC 1.1 context."""
        extra = _vc11_signing_contexts()
        body = _credential(issuer_id).to_vc()
        body['@context'] = [V1_CONTEXT] + body['@context'][1:] + [DI_CONTEXT]
        if 'credentialStatus' in members:
            body['@context'].append(SL2021_CONTEXT_URL)
        body['issuanceDate'] = body.pop('validFrom')
        body.update(members)
        return add_data_integrity_proof(body, priv, vm, extra_contexts=extra), extra

    @staticmethod
    def _rebased(signed, extra):
        """What the holder does: expand the badge under its own contexts and
        compact it onto the bundled ones, keeping the issuer's proof."""
        jsonld = ldp._require_jsonld()
        context = [cv.VC2_CONTEXT] + [
            url for url in signed['@context'][1:]
            if url not in (DI_CONTEXT, SL2021_CONTEXT_URL)]
        unsecured = {k: v for k, v in signed.items() if k != 'proof'}
        expanded = jsonld.expand(unsecured, {'documentLoader': document_loader(extra)})
        rebased = jsonld.compact(expanded, context, {'documentLoader': document_loader()})
        rebased['proof'] = signed['proof']
        return rebased

    def _verifiers(self, issuer, pinned):
        priv, pub, did, vm = issuer
        if pinned:
            return 'https://issuer.example/i', 'did:example:issuer#k1', [
                OB3LdpVerifier(pubkey_pem=pub)]
        return did, vm, [OB3LdpVerifier(), OB3LdpVerifier.for_issuer_did(did)]

    @pytest.mark.parametrize('case', sorted(CASES))
    @pytest.mark.parametrize('pinned', [False, True], ids=['did', 'pinned'])
    def test_rebased_badge_is_refused(self, issuer, pinned, case):
        priv, pub, _, _ = issuer
        issuer_id, vm, verifiers = self._verifiers(issuer, pinned)
        members, where = self.CASES[case]
        signed, extra = self._issue(issuer_id, priv, vm, members)
        verify_data_integrity_proof(signed, pub, extra_contexts=extra)
        # as issued: refused, since VC 1.1 is not bundled
        _rejected(signed, "carries '(issuanceDate|expirationDate)'", verifiers[0])
        with pytest.raises(OB3VerificationError, match='VC 2.0 base context'):
            _check(signed)

        rebased = self._rebased(signed, extra)
        assert rebased['@context'][0] == cv.VC2_CONTEXT
        assert V1_CONTEXT not in rebased['@context']
        verify_data_integrity_proof(rebased, pub)      # same dataset, bundled contexts
        with pytest.raises(OB3VerificationError,
                           match='spells a property .*at %s\\)' % re.escape(where)):
            _check(rebased)                            # the signer guard's check, too
        for verifier in verifiers:
            _rejected(rebased, 'credential spells a property', verifier,
                      check_status=True, download=_no_fetch)

    def test_rebased_badge_verified_before_the_fix(self, issuer, monkeypatch):
        # What the table closes, pinned so the tests above cannot pass for
        # another reason: without it, the rebased badges verified as never
        # expiring, already valid, and with a status entry no checker knows.
        priv, pub, did, vm = issuer
        monkeypatch.setattr(cv, '_POLICY_TERMS', {})
        verified = {}
        for case, (members, _) in self.CASES.items():
            signed, extra = self._issue(did, priv, vm, members)
            verified[case] = OB3LdpVerifier().verify(self._rebased(signed, extra))
        assert verified['expired'].expiration_date is None
        assert verified['not-yet-valid'].issuance_date < datetime(2099, 1, 1, tzinfo=UTC)
        assert verified['sl2021-status'].credential_status[0]['type'] == \
            SL2021 + 'StatusList2021Entry'

    def test_policy_terms_agree_with_the_pinned_contexts(self):
        # A context bump that gave a policy IRI another term (an alias the
        # policy never reads) shows up here; the table refuses it anyway.
        spellings = cv._term_spellings()
        for iri, term in cv._POLICY_TERMS.items():
            assert spellings.get(iri, frozenset()) <= {term}, iri
        for iri in (VC + 'issuanceDate', VC + 'expirationDate',
                    SL2021 + 'StatusList2021Entry', SL2021 + 'statusListIndex'):
            assert iri not in spellings               # no bundled term at all

    @pytest.mark.parametrize('iri, term', sorted(cv._POLICY_TERMS.items()))
    def test_policy_iris_are_refused_under_any_other_spelling(
            self, iri, term, monkeypatch):
        assert cv._is_misspelled(iri)                 # its full IRI
        assert not cv._is_misspelled(term)            # the key the policy reads
        namespace, _, local = iri.rpartition('#')
        # an alias, and a prefix for a compact IRI, a pinned context could add
        synonyms = dict(cv._type_synonyms(), alias=frozenset({iri}),
                        ns=frozenset({namespace + '#'}))
        monkeypatch.setattr(cv, '_type_synonyms', lambda: synonyms)
        assert cv._is_misspelled('alias')
        assert cv._is_misspelled('ns:' + local)
        assert not cv._is_misspelled(term)
        where = cv._misspelled_key({'credentialStatus': {'type': ['x', 'ns:' + local]}}, ())
        assert where == ('credentialStatus', 'type', 1)


class TestRefusedShapes:
    """Shapes refused outright, before any signature is checked."""

    def _doc(self, expired):
        return copy.deepcopy(expired)

    def test_reverse(self, expired):
        doc = self._doc(expired)
        doc['@reverse'] = {'https://example.org/p': {'id': 'https://x.example/n'}}
        _rejected(doc, '@reverse')

    def test_top_level_graph_beside_properties(self, expired):
        doc = self._doc(expired)
        doc['@graph'] = [{'id': 'https://x.example/n', 'name': 'n'}]
        _rejected(doc, 'top-level @graph')

    def test_graph_only_document(self, expired):
        doc = {'@context': expired['@context'], '@graph': [_genuine_node(expired)],
               'proof': expired['proof']}
        with pytest.raises(OB3VerificationError, match='compacted form'):
            _check(doc)
        doc['@graph'].append({'id': 'https://x.example/n', 'name': 'n'})
        with pytest.raises(OB3VerificationError, match='exactly one top-level node'):
            _check(doc)

    def test_index(self, expired):
        doc = self._doc(expired)
        doc['credentialSubject']['@index'] = 'i'
        _rejected(doc, '@index')

    def test_direction(self, expired):
        doc = self._doc(expired)
        doc['name'] = {'@value': 'Attendance', '@direction': 'rtl'}
        _rejected(doc, '@direction')

    def test_nested_redescription_of_the_credential(self, expired):
        doc = self._doc(expired)
        doc['evidence'] = [{'id': doc['id'], 'type': ['VerifiableCredential'],
                            'validUntil': '2021-01-01T00:00:00Z'}]
        _rejected(doc, 'described again')

    # The supported pyld (>= 3.3.0) resolves a relative IRI against a
    # placeholder base (http://example.org/base/), which compaction does not
    # undo: the comparison refuses it. (pyld 2.x, below the [ldp] floor, kept
    # it relative and toRDF dropped it: the safe-mode walk refuses that.)
    @pytest.mark.parametrize('node_id', ['alice@example.com', 'urn:x y'])
    def test_node_id_the_dataset_drops(self, expired, node_id):
        doc = self._doc(expired)
        doc['credentialSubject']['id'] = node_id
        _rejected(doc, 'node id the signed dataset drops|compacted form')

    def test_undefined_type(self, expired):
        doc = self._doc(expired)
        doc['credentialSubject']['type'] = ['AchievementSubject', 'Undefined']
        _rejected(doc, 'type the signed dataset drops|compacted form')

    def test_type_with_whitespace(self, expired):
        doc = self._doc(expired)
        doc['credentialSubject']['type'] = ['AchievementSubject', 'urn:x y']
        _rejected(doc, 'type the signed dataset drops')

    def test_blank_node_property(self, expired):
        doc = self._doc(expired)
        doc['credentialSubject']['_:p'] = 'unsigned'
        _rejected(doc, 'property the signed dataset drops')

    def test_undefined_term_inside_a_list_item(self, expired):
        doc = self._doc(expired)
        doc['credentialSchema'][0]['undefinedX'] = 1
        _rejected(doc, r'compacted form .*credentialSchema/0/undefinedX')

    def test_nested_array_is_not_compacted_form(self, expired):
        doc = self._doc(expired)
        doc['credentialSchema'] = [doc['credentialSchema'][0],
                                   [dict(doc['credentialSchema'][0], id='urn:x:1'),
                                    dict(doc['credentialSchema'][0], id='urn:x:2')]]
        _rejected(doc, r'compacted form .*credentialSchema\)')

    def test_non_json_document(self, expired):
        doc = self._doc(expired)
        doc['credentialSubject']['narrative'] = {1, 2}
        with pytest.raises(OB3VerificationError, match='not plain JSON'):
            _check(doc)

    def test_nested_context(self, expired, monkeypatch):
        # Refused before expansion (see TestNestedContextBound) ...
        doc = self._doc(expired)
        doc['credentialSubject']['@context'] = list(doc['@context'])
        _rejected(doc, r'@context below its top level \(at '
                       r'/credentialSubject/@context\)')
        # ... and by the comparison, which runs after it, on its own.
        monkeypatch.setattr(cv, '_check_nested_contexts', lambda *args: None)
        _rejected(doc, r'compacted form .*credentialSubject/@context')

    @pytest.mark.parametrize('context, match', [
        ('https://www.w3.org/ns/credentials/v2', 'compacted form|@context'),
        ([], 'non-empty array'),
        ({'@vocab': 'https://example.org/'}, 'non-empty array'),
        (['https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'],
         'VC 2.0 base context'),
    ])
    def test_context_shape(self, expired, context, match):
        doc = self._doc(expired)
        doc['@context'] = context
        with pytest.raises(OB3VerificationError, match=match):
            _check(doc)

    def test_unlisted_context(self, expired):
        doc = self._doc(expired)
        doc['@context'] = list(doc['@context']) + ['https://evil.example/ctx']
        _rejected(doc, 'allowlist')

    @pytest.mark.parametrize('entry', [
        {'@vocab': 'relative/'}, {'@vocab': 'https://example.org/v#'},
        {'@vocab': VC}, {'@vocab': None}, {}, None, 1, ''])
    def test_inline_or_non_url_context_entry(self, expired, entry):
        doc = self._doc(expired)
        doc['@context'] = list(doc['@context']) + [entry]
        _rejected(doc, 'inline @context object')

    def test_oversized_document(self, expired):
        # Bounded once, on the input as received (_parse_document).
        doc = self._doc(expired)
        doc['description'] = 'x' * (ldp.MAX_LDP_DOCUMENT_BYTES + 1)
        _rejected(doc, 'byte limit')
        _rejected(json.dumps(doc).encode('utf-8'), 'byte limit')

    def test_non_json_value(self, expired):
        doc = self._doc(expired)
        doc['credentialSubject']['creditsEarned'] = float('nan')
        with pytest.raises(OB3VerificationError):
            _check(doc)

    def test_deep_dict_input_fails_closed(self, expired):
        # Deeper than json.dumps / deepcopy recurse: OB3VerificationError on
        # every interpreter, never a bare RecursionError.
        doc = self._doc(expired)
        node = doc['issuer'] = {'id': doc['issuer'], 'type': ['Profile'],
                                'name': 'I'}
        for level in range(3000):
            node['parentOrg'] = {'id': 'https://org.example/%d' % level}
            node = node['parentOrg']
        _rejected(doc, None)

    @pytest.mark.parametrize('depth', [1000, 100000])
    def test_deep_bytes_input_fails_closed(self, expired, depth):
        doc = self._doc(expired)
        doc['description'] = None
        text = json.dumps(doc).replace(
            '"description": null', '"description": ' + '[' * depth + ']' * depth)
        _rejected(text.encode('utf-8'), None)

    def test_deep_document_issuer_peek_fails_closed(self):
        from openbadgeslib.verify import issuer_did_from_document
        with pytest.raises(OB3VerificationError):
            issuer_did_from_document('{"x": ' + '[' * 100000 + ']' * 100000 + '}')

    def test_deep_nesting_fails_closed(self, expired):
        doc = self._doc(expired)
        nested: list = []
        for _ in range(3000):
            nested = [nested]
        doc['credentialSubject']['narrative'] = nested
        with pytest.raises(OB3VerificationError):
            cv.validate_document(_genuine_node(doc) | {'@context': doc['@context']},
                                 {'@context': doc['@context']},
                                 document_loader(), ldp._require_jsonld())


class TestNestedArrays:
    """Expansion flattens an array nested in an array (outside @list), so
    [[S]] signs exactly as S, while the model and the status checker read only
    objects and skip it: a wrapped credentialStatus hid the revocation check.
    The validator (an array element never folds into a non-array) and the
    status backstop in _reject_unsigned_ldp_aliases each refuse it on their
    own, so each is pinned on its own here."""

    SUSPENSION = dict(STATUS_ENTRY, id='https://issuer.example/status/2#5',
                      statusPurpose='suspension',
                      statusListCredential='https://issuer.example/status/2')

    SHAPES = ['[[S]]', '[S1,[S2]]', '[[S1,S2]]', '[[S1],[S2]]']

    def _wrapped(self, issuer, shape):
        """A genuinely signed credential whose credentialStatus is then
        re-spelled as *shape*: same dataset, same signature."""
        priv, pub, did, _ = issuer
        statuses = [dict(STATUS_ENTRY)]
        if shape != '[[S]]':
            statuses.append(dict(self.SUSPENSION))
        doc = OB3LdpSigner(priv).sign(_credential(did, credential_status=statuses))
        issued = doc['credentialStatus']
        issued = issued if isinstance(issued, list) else [issued]
        first, second = issued[0], issued[-1]
        doc['credentialStatus'] = {
            '[[S]]': [[first]],
            '[S1,[S2]]': [first, [second]],
            '[[S1,S2]]': [[first, second]],
            '[[S1],[S2]]': [[first], [second]],
        }[shape]
        return doc, pub

    @pytest.mark.parametrize('shape', SHAPES)
    def test_validator_refuses_wrapped_status(self, issuer, shape):
        doc, pub = self._wrapped(issuer, shape)
        verify_data_integrity_proof(doc, pub)          # the dataset is unchanged
        with pytest.raises(OB3VerificationError,
                           match=r'compacted form .*/credentialStatus'):
            _check(doc)

    @pytest.mark.parametrize('shape', SHAPES)
    def test_status_is_never_skipped(self, issuer, shape):
        doc, _ = self._wrapped(issuer, shape)

        def download(url, *args, **kwargs):
            raise AssertionError('refused before any status list is fetched')

        _rejected(doc, 'credentialStatus entry that is not a JSON object',
                  check_status=True, download=download)

    def test_bare_status_reference_is_refused(self, issuer):
        # A valid compacted node reference, but one no checker can read.
        doc, _ = self._wrapped(issuer, '[[S]]')
        doc['credentialStatus'] = STATUS_ENTRY['id']
        _rejected(doc, 'credentialStatus entry that is not a JSON object')

    def test_wrapped_validity_is_refused(self, expired):
        doc = copy.deepcopy(expired)
        doc['validUntil'] = [[doc['validUntil']]]
        with pytest.raises(OB3VerificationError, match=r'compacted form .*/validUntil'):
            _check(doc)

    @pytest.mark.parametrize('allowed', [
        [['A', 'B']], ['A', ['B', 'C']], [['A'], ['B']], [[['A']]]])
    def test_list_of_lists_still_validates(self, ed25519_keypair, allowed):
        # allowedValue is `@container: @list` (ResultDescription): a JSON-LD
        # 1.1 list of lists is signed as nested lists, and compaction emits
        # it back nested, so both sides carry it and it compares equal.
        priv, pub = ed25519_keypair
        _, vm = _did_vm(pub)
        document = _complete_document()
        document['credentialSubject']['achievement']['resultDescription'][0][
            'allowedValue'] = allowed
        _check(add_data_integrity_proof(document, priv, vm))


class TestStatusDescribedElsewhere:
    """RDF lets a node referenced from two properties be described under
    either. When the issuer also names its status entry from another
    property, a holder can move a signed member out from under
    credentialStatus with the dataset, and the signature, unchanged: a
    statusSize of 2 moved away made the checker read bit 5 where entry 5 is
    bits 10-11. A node under the top-level credentialStatus described
    anywhere else (other than as an exact copy) is refused."""

    def test_moved_status_size_is_refused(self, issuer):
        priv, pub, did, vm = issuer
        entry = dict(STATUS_ENTRY, statusSize=2)
        document = _credential(did, credential_status=[entry]).to_vc()
        document['relatedResource'] = [{'id': entry['id']}]   # issuer names it too
        signed = add_data_integrity_proof(document, priv, vm)
        # entry 5 occupies bits 10-11; bit 5 belongs to another entry
        download = _status_lists({entry['statusListCredential']: [10, 11]})
        _rejected(signed, 'unsupported statusSize', check_status=True,
                  download=download, verify_status_list=False)      # control

        moved = copy.deepcopy(signed)
        size = moved['credentialStatus'].pop('statusSize')
        moved['relatedResource'] = [{'id': entry['id'],
                                     'type': 'BitstringStatusListEntry',
                                     'statusSize': size}]
        verify_data_integrity_proof(moved, pub)                      # same dataset
        with pytest.raises(OB3VerificationError,
                           match='described outside credentialStatus'):
            _check(moved)
        _rejected(moved, 'described outside credentialStatus', check_status=True,
                  download=download, verify_status_list=False)

    def test_typeless_stub_is_refused_by_the_validator(self, issuer):
        # Not only by the checker ("unsupported credentialStatus type"): the
        # entry left under credentialStatus is an {"id": S} stub.
        priv, pub, did, vm = issuer
        document = _credential(did, credential_status=[dict(STATUS_ENTRY)]).to_vc()
        document['relatedResource'] = [{'id': STATUS_ENTRY['id']}]
        signed = add_data_integrity_proof(document, priv, vm)
        moved = copy.deepcopy(signed)
        moved['relatedResource'] = [moved['credentialStatus']]
        moved['credentialStatus'] = {'id': STATUS_ENTRY['id']}
        verify_data_integrity_proof(moved, pub)
        with pytest.raises(OB3VerificationError,
                           match='described outside credentialStatus'):
            _check(moved)

    def test_moved_into_a_nested_credential_status(self, issuer):
        # A nested node's own credentialStatus is never read by the checker.
        priv, pub, did, vm = issuer
        entry = dict(STATUS_ENTRY, statusSize=2)
        document = _credential(did, credential_status=[entry]).to_vc()
        subject = document['credentialSubject']
        subject['type'] = ['AchievementSubject', 'VerifiableCredential']
        subject['credentialStatus'] = {'id': entry['id']}
        signed = add_data_integrity_proof(document, priv, vm)
        moved = copy.deepcopy(signed)
        moved['credentialSubject']['credentialStatus'] = moved['credentialStatus']
        moved['credentialStatus'] = {'id': entry['id']}
        verify_data_integrity_proof(moved, pub)
        _rejected(moved, 'described outside credentialStatus', check_status=True,
                  download=_no_fetch)

    def test_member_moved_into_an_endorsement_copy(self, ed25519_keypair):
        # Each embedded endorsement of the complete example carries the outer
        # credential's credentialStatus verbatim (adaptation (d)): an exact
        # copy adds nothing, but one the outer entry no longer matches does.
        priv, pub = ed25519_keypair
        _, vm = _did_vm(pub)
        document = _complete_document()
        for status in _status_entries(document):
            status['statusSize'] = 2
        signed = add_data_integrity_proof(document, priv, vm)
        verifier = OB3LdpVerifier(pubkey_pem=pub)
        download = _status_lists({COMPLETE_STATUS['statusListCredential']: [46, 47]})
        _rejected(signed, 'unsupported statusSize', verifier, check_status=True,
                  download=download, verify_status_list=False)      # control
        moved = copy.deepcopy(signed)
        del moved['credentialStatus']['statusSize']
        verify_data_integrity_proof(moved, pub)                      # same dataset
        _rejected(moved, 'described outside credentialStatus', verifier,
                  check_status=True, download=download, verify_status_list=False)


def _status_entries(value):
    """Every object in *value* with the complete example's status id."""
    if isinstance(value, list):
        return [found for item in value for found in _status_entries(item)]
    if not isinstance(value, dict):
        return []
    here = [value] if value.get('id') == COMPLETE_STATUS['id'] else []
    return here + [found for item in value.values()
                   for found in _status_entries(item)]


class TestContextEntryBound:
    """pyld re-processes a context once per @context entry: a pinned URL
    repeated thousands of times cost seconds of CPU per validation pass,
    before any key was resolved. Each context document may be listed once,
    with eight entries in all, and no inline object (so no pile of inline
    @vocab objects either)."""

    @pytest.mark.parametrize('extra', [
        ['https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'],
        # an alias of the 3.0.3 URL the signer lists: the same document
        ['https://purl.imsglobal.org/spec/ob/v3p0/context.json'],
        ['https://www.w3.org/ns/credentials/v2'],
        [{'@vocab': 'https://x.example/%d/' % i} for i in range(64)],
        [{'@vocab': 'https://x.example/a/'}, {'@vocab': 'https://x.example/b/'}],
        ['https://w3id.org/security/data-integrity/v2'] * 6,
    ], ids=['duplicate', 'alias', 'base-again', 'vocabs', 'two-vocabs', 'cap'])
    def test_context_entries_are_bounded(self, issuer, extra):
        priv, _, did, _ = issuer
        doc = OB3LdpSigner(priv).sign(_credential(did))
        assert 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json' \
            in doc['@context']
        doc['@context'] = doc['@context'] + extra
        with pytest.raises(OB3VerificationError, match='@context'):
            _check(doc)
        _rejected(doc, '@context')

    def test_padded_context_is_refused_before_expansion(self, expired, monkeypatch):
        # The malformed, unsigned shape of the report: refused by counting,
        # with no JSON-LD processing at all.
        def expand(*args, **kwargs):
            raise AssertionError('nothing must be expanded')

        monkeypatch.setattr(ldp._require_jsonld(), 'expand', expand)
        doc = copy.deepcopy(expired)
        doc['@context'] = [doc['@context'][0]] + [
            'https://purl.imsglobal.org/spec/ob/v3p0/context.json'] * 4000
        _rejected(doc, 'at most 8')

    def test_endorsement_context_is_bounded(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        endorsement = doc['issuer']['endorsement'][0]
        endorsement['@context'] = endorsement['@context'] + [endorsement['@context'][1]]
        _rejected(doc, '@context', verifier)

    @pytest.mark.parametrize('entry', [
        {'@vocab': 'https://x.example/v#'},
        {'vu': {'@id': VC + 'validUntil', '@type': XSD_DATETIME}}])
    def test_inline_objects_are_refused_before_expansion(self, expired, entry,
                                                         monkeypatch):
        # Not even one inline @vocab reaches the JSON-LD processor (openvc
        # tolerates that one shape; OB 3.0 credentials need none of it).
        def expand(*args, **kwargs):
            raise AssertionError('nothing must be expanded')

        monkeypatch.setattr(ldp._require_jsonld(), 'expand', expand)
        doc = copy.deepcopy(expired)
        doc['@context'] = list(doc['@context']) + [entry]
        _rejected(doc, 'inline @context object')


def _forbid_expansion(monkeypatch):
    def expand(*args, **kwargs):
        raise AssertionError('nothing must be expanded')

    monkeypatch.setattr(ldp._require_jsonld(), 'expand', expand)


PADDED = [cv.VC2_CONTEXT] + [
    'https://purl.imsglobal.org/spec/ob/v3p0/context.json'] * 4000


def _bare_endorsement(context=None, **members):
    """The shape of an embedded endorsement credential, unsigned: everything
    here is refused (or bounded) before any JSON-LD processing."""
    return dict({'@context': list(context or OB3_CONTEXT),
                 'type': ['VerifiableCredential', 'EndorsementCredential']},
                **members)


class TestNestedContextBound:
    """pyld applies a nested @context, entry by entry, when expansion reaches
    it, and only the top-level one was bounded before expansion: a padded
    @context on credentialSubject (or on an embedded endorsement) was refused
    only afterwards, by the comparison (or the endorsement's own check), after
    seconds of CPU on unauthenticated input -- 0.76 s at 57 KB, 3 s at 225 KB.
    Every @context below the top level is now bounded first: an embedded
    endorsement's like the top level's, any other refused; and the embedded
    credentials, each validated again on its own, by number, depth and total
    size."""

    @pytest.mark.parametrize('context', [PADDED, list(OB3_CONTEXT)],
                             ids=['padded', 'plain'])
    @pytest.mark.parametrize('path', [
        ('credentialSubject',), ('credentialSubject', 'achievement'),
        ('credentialSubject', 'achievement', 'criteria'), ('issuer',),
        ('credentialSchema', 0)],
        ids=['subject', 'achievement', 'criteria', 'issuer', 'schema-entry'])
    def test_nested_context_is_refused_before_expansion(
            self, expired, monkeypatch, context, path):
        _forbid_expansion(monkeypatch)
        doc = copy.deepcopy(expired)
        node = doc
        for step in path:
            node = node[step]
        node['@context'] = context
        _rejected(doc, r'credential carries an @context below its top level '
                       r'\(at %s/@context\)' % re.escape(cv._pointer(path)))

    def test_nested_context_in_the_proof_is_refused_before_expansion(
            self, expired, monkeypatch):
        jsonld = ldp._require_jsonld()
        expand = jsonld.expand

        def expand_credential_only(document, *args, **kwargs):
            assert 'nonce' not in document, 'the proof must not be expanded'
            return expand(document, *args, **kwargs)

        monkeypatch.setattr(jsonld, 'expand', expand_credential_only)
        doc = copy.deepcopy(expired)
        doc['proof']['nonce'] = {'@context': PADDED, 'value': 'x'}
        _rejected(doc, r'the proof carries an @context below its top level '
                       r'\(at /nonce/@context\)')

    @pytest.mark.parametrize('entries, where', [
        ([_bare_endorsement(PADDED)], '/credentialSubject/achievement/endorsement/0'),
        (_bare_endorsement(PADDED), '/credentialSubject/achievement/endorsement'),
    ], ids=['list', 'single'])
    def test_padded_endorsement_context_is_refused_before_expansion(
            self, expired, monkeypatch, entries, where):
        _forbid_expansion(monkeypatch)
        doc = copy.deepcopy(expired)
        doc['credentialSubject']['achievement']['endorsement'] = entries
        _rejected(doc, r'endorsement at %s of the credential @context lists '
                       r'4001 entries; at most 8' % where)

    def test_context_nested_inside_an_endorsement(self, expired, monkeypatch):
        _forbid_expansion(monkeypatch)
        doc = copy.deepcopy(expired)
        doc['issuer']['endorsement'] = [_bare_endorsement(
            credentialSubject={'@context': PADDED, 'id': 'did:example:1'})]
        _rejected(doc, r'the endorsement at /issuer/endorsement/0 of the '
                       r'credential carries an @context below its top level '
                       r'\(at /credentialSubject/@context\)')

    def test_endorsement_entry_nested_in_an_array(self, expired, monkeypatch):
        # Not an entry _detach validates on its own, so not one here either.
        _forbid_expansion(monkeypatch)
        doc = copy.deepcopy(expired)
        doc['endorsement'] = [[_bare_endorsement()]]
        _rejected(doc, r'credential carries an @context below its top level '
                       r'\(at /endorsement/0/0/@context\)')

    def test_context_inside_a_json_literal_is_refused(self, issuer):
        # A deliberate narrowing: the keys of an @json literal are data the
        # processor never applies, but telling them apart before expansion
        # would mean resolving terms. Issuer-signed, and still refused.
        priv, _, did, vm = issuer
        body = _credential(did).to_vc()
        body['_sd'] = [{'@context': ['https://example.org/data'], 'x': 1}]
        _rejected(add_data_integrity_proof(body, priv, vm),
                  r'@context below its top level \(at /_sd/0/@context\)')

    def test_embedded_credentials_are_counted(self, expired, monkeypatch):
        doc = copy.deepcopy(expired)
        limit = cv._MAX_EMBEDDED_CREDENTIALS
        # Spread over two levels: counted at any depth.
        inner = [_bare_endorsement() for _ in range(limit - 1)]
        doc['endorsement'] = [_bare_endorsement(
            issuer={'id': 'https://accreditor.example/1', 'endorsement': inner})]
        unsecured = {k: v for k, v in doc.items() if k != 'proof'}
        cv._check_nested_contexts(unsecured, document_loader(), 'credential')
        inner.append(_bare_endorsement())
        _forbid_expansion(monkeypatch)
        _rejected(doc, 'credential embeds more than %d credentials' % limit)

    def test_embedded_credentials_are_bounded_in_size(self, expired, monkeypatch):
        # A chain of endorsements is re-validated level by level: four
        # levels over 80 KB made an 80 KB document cost about 400 KB.
        doc = copy.deepcopy(expired)
        holder = doc
        for level in range(4):
            entry = _bare_endorsement()
            holder['endorsement'] = [entry]
            holder = entry
        holder['description'] = 'x' * 80000
        assert len(json.dumps(doc)) < ldp.MAX_LDP_DOCUMENT_BYTES
        _forbid_expansion(monkeypatch)
        _rejected(doc, 'credentials embedded in the credential total more '
                       'than %d characters' % cv._MAX_EMBEDDED_SIZE)

    def test_one_level_of_endorsements_always_fits(self, expired):
        # One level deep the embedded credentials never overlap, so a
        # document within the size limit is within the embedded one too.
        doc = copy.deepcopy(expired)
        del doc['proof']
        doc['endorsement'] = [_bare_endorsement(description='x' * 120000),
                              _bare_endorsement(description='y' * 120000)]
        assert len(json.dumps(doc)) < ldp.MAX_LDP_DOCUMENT_BYTES
        cv._check_nested_contexts(doc, document_loader(), 'credential')


class TestStatusMemberShapes:
    """Status members respelled as non-strings fail closed as a verification
    error, never as a bare TypeError from verify()."""

    def test_one_element_status_purpose_fails_closed(self, issuer):
        priv, _, did, _ = issuer
        doc = OB3LdpSigner(priv).sign(_credential(did, credential_status=[dict(STATUS_ENTRY)]))
        doc['credentialStatus']['statusPurpose'] = ['revocation']   # same dataset
        _rejected(doc, 'invalid statusPurpose', check_status=True,
                  download=_no_fetch, verify_status_list=False)

    def test_language_tagged_status_purpose_fails_closed(self, issuer):
        priv, _, did, vm = issuer
        body = _credential(did, credential_status=[dict(STATUS_ENTRY)]).to_vc()
        body['credentialStatus']['statusPurpose'] = {'@value': 'revocation',
                                                     '@language': 'en'}
        doc = add_data_integrity_proof(body, priv, vm)
        _rejected(doc, 'invalid statusPurpose', check_status=True,
                  download=_no_fetch, verify_status_list=False)

    @pytest.mark.parametrize('types', [[['BitstringStatusListEntry']],
                                       {'@id': 'BitstringStatusListEntry'}])
    def test_unhashable_status_type_fails_closed(self, types):
        from openbadgeslib.ob3 import status
        with pytest.raises(OB3VerificationError, match='unsupported credentialStatus type'):
            status._check_entry(dict(STATUS_ENTRY, type=types), _no_fetch)

    def test_unhashable_credential_type_fails_closed(self):
        document = {'@context': [cv.VC2_CONTEXT],
                    'type': [['VerifiableCredential', 'OpenBadgeCredential']]}
        _rejected(document, 'not an OpenBadgeCredential')
        _rejected(json.dumps(document), 'not an OpenBadgeCredential')


class TestSizeLimit:
    """The size is bounded once, on the input as received; re-measuring the
    parsed document (ensure_ascii escapes, spaced separators) refused genuine
    compact non-ASCII credentials at a third to a half of the limit."""

    @pytest.mark.parametrize('text', ['学' * 70000, 'é' * 110000])
    def test_compact_non_ascii_document_within_the_limit(self, issuer, text):
        priv, _, did, vm = issuer
        document = _credential(did).to_vc()
        document['credentialSubject']['achievement']['description'] = text
        signed = add_data_integrity_proof(document, priv, vm)
        compact = json.dumps(signed, ensure_ascii=False, separators=(',', ':'))
        assert 128 * 1024 < len(compact.encode('utf-8')) <= ldp.MAX_LDP_DOCUMENT_BYTES
        assert len(json.dumps(signed)) > ldp.MAX_LDP_DOCUMENT_BYTES
        verifier = OB3LdpVerifier()
        assert verifier.verify(compact.encode('utf-8')).issuer.id == did
        assert verifier.verify(compact).issuer.id == did

    def test_signer_refuses_what_verifiers_would_refuse(self, issuer):
        # Measured as sign_to_json emits it (ensure_ascii), with its own
        # message rather than a context-validation one.
        priv, _, did, _ = issuer
        credential = _credential(did, achievement=Achievement(
            id='https://issuer.example/achievements/a', name='A',
            description='学' * 45000, criteria_narrative='c'))
        with pytest.raises(ErrorSigningFile, match='byte limit verifiers accept'):
            OB3LdpSigner(priv).sign(credential)


class TestIntegralCredits:
    def test_signed_as_the_integer_lexical_form(self, issuer):
        # Emitted as 3, an integral float canonicalizes as "3"^^xsd:float on
        # every pyld (and jsonld.js); pyld < 3.3 rendered the float 3.0 as
        # "3.0E0", so the proof depended on the pyld version.
        priv, _, did, _ = issuer
        credential = _credential(did, credits_earned=2.0, achievement=Achievement(
            id='https://issuer.example/achievements/a', name='A',
            description='d', criteria_narrative='c', credits_available=3.0))
        signed = OB3LdpSigner(priv).sign(credential)
        subject = signed['credentialSubject']
        assert type(subject['creditsEarned']) is int
        assert type(subject['achievement']['creditsAvailable']) is int
        unsecured = {k: v for k, v in signed.items() if k != 'proof'}
        nquads = ldp._canonize(unsecured, document_loader())
        for value in ('3', '2'):
            assert re.search(r'"%s"\^\^<https?://www\.w3\.org/2001/XMLSchema#float>'
                             % value, nquads), nquads
        verified = OB3LdpVerifier().verify(signed)
        assert verified.achievement.credits_available == 3.0
        assert verified.credits_earned == 2.0


# ── legitimate shapes keep verifying ────────────────────────────────────────

class TestSignerOutputs:
    def test_minimal_unpinned(self, issuer):
        priv, _, did, _ = issuer
        signed = OB3LdpSigner(priv).sign(_credential(did))
        assert OB3LdpVerifier().verify(signed).issuer.id == did

    def test_rich_pinned(self, issuer):
        priv, pub, _, _ = issuer
        alignment = Alignment(target_name='T', target_url='https://t.example',
                              target_framework='F', target_code='C',
                              target_description='D')
        description = ResultDescription(
            id='urn:uuid:11111111-1111-1111-1111-111111111111', name='Grade',
            result_type='LetterGrade', allowed_values=['A', 'B'],
            required_value='B', alignments=[alignment])
        credential = _credential(
            'https://issuer.example',
            issuer=Issuer(id='https://issuer.example', name='I',
                          url='https://issuer.example', email='i@issuer.example',
                          image_url='https://issuer.example/logo.png',
                          endorsement_jwts=['a.b.c']),
            achievement=Achievement(
                id='https://issuer.example/a/1', name='A', description='d',
                criteria_narrative='c', image_url='https://issuer.example/a.png',
                tags=['x', 'y'], endorsement_jwts=['d.e.f'],
                achievement_type='Badge', credits_available=3.0,
                alignments=[alignment], result_descriptions=[description]),
            expiration_date=datetime(2099, 1, 1, tzinfo=UTC),
            evidence=[Evidence(id='https://issuer.example/e/1', narrative='n',
                               name='E', description='d', genre='g',
                               audience='a'),
                      Evidence(narrative='narrative only')],
            credential_status=[dict(STATUS_ENTRY)], endorsement_jwts=['g.h.i'],
            credits_earned=2.5,
            identifiers=[IdentityObject.create('alice@example.com')],
            results=[Result(value='A', status='Completed',
                            result_description=description.id,
                            alignments=[alignment])])
        signed = OB3LdpSigner(priv).sign(credential)
        verified = OB3LdpVerifier(pubkey_pem=pub).verify(signed)
        assert verified.credential_status == [STATUS_ENTRY]
        assert verified.results[0].value == 'A'

    def test_node_reference_object_is_tolerated(self, issuer):
        # {"id": X} and X are the same node reference for an @id-typed term.
        priv, _, did, vm = issuer
        document = _credential(did).to_vc()
        document['issuer'] = {'id': did}
        signed = add_data_integrity_proof(document, priv, vm)
        assert OB3LdpVerifier().verify(signed).issuer.id == did

    def test_inline_absolute_vocab_is_refused(self, issuer):
        # An inline {"@vocab": <absolute IRI>} appended to a genuine badge
        # changes nothing signed (a defined term wins over @vocab), and was
        # tolerated until 4.6.1; OB 3.0 credentials name only published
        # contexts, so it is now refused like any inline object.
        priv, pub, did, _ = issuer
        doc = OB3LdpSigner(priv).sign(_credential(did))
        doc['@context'] = list(doc['@context']) + [{'@vocab': 'https://example.org/v#'}]
        verify_data_integrity_proof(doc, pub)          # the dataset is unchanged
        with pytest.raises(OB3VerificationError, match='inline @context object'):
            _check(doc)
        _rejected(doc, 'inline @context object')
        _rejected(doc, 'inline @context object', OB3LdpVerifier(pubkey_pem=pub))


class TestSignerGuard:
    def test_relative_recipient_is_not_issued(self, issuer):
        priv, _, did, _ = issuer
        with pytest.raises(ErrorSigningFile, match='does not cover'):
            OB3LdpSigner(priv).sign(_credential(did, recipient_id='alice@example.com'))

    def test_undefined_status_member_is_not_issued(self, issuer):
        priv, _, did, _ = issuer
        status = dict(STATUS_ENTRY, statusListIndexX='9')
        with pytest.raises(ErrorSigningFile, match='does not cover'):
            OB3LdpSigner(priv).sign(_credential(did, credential_status=[status]))

    def test_inline_context_object_is_not_issued(self, issuer, monkeypatch):
        # The signer guard runs the verifier's check, inline objects included.
        priv, _, did, _ = issuer
        to_vc = OpenBadgeCredential.to_vc

        def with_vocab(self):
            document = to_vc(self)
            document['@context'] = document['@context'] + [
                {'@vocab': 'https://example.org/v#'}]
            return document

        monkeypatch.setattr(OpenBadgeCredential, 'to_vc', with_vocab)
        with pytest.raises(ErrorSigningFile, match='inline @context object'):
            OB3LdpSigner(priv).sign(_credential(did))

    def test_low_level_signer_is_unchanged(self, issuer):
        # add_data_integrity_proof stays schema-agnostic (CLR, W3C vectors):
        # it still signs, and the RDF-only proof still verifies low-level.
        priv, pub, did, vm = issuer
        doc = _credential(did, recipient_id='alice@example.com').to_vc()
        signed = add_data_integrity_proof(doc, priv, vm)
        verify_data_integrity_proof(signed, pub)
        _rejected(signed, 'node id the signed dataset drops|compacted form')


class TestLowLevelUnchanged:
    def test_w3c_vector(self):
        from openbadgeslib.ob3 import resolve_verification_method
        vector = json.loads((VECTORS / 'signed-credential.json').read_text())
        key = json.loads((VECTORS / 'key-pair.json').read_text())
        pem = resolve_verification_method('did:key:%(k)s#%(k)s' % {
            'k': key['publicKeyMultibase']})
        examples = {'https://www.w3.org/ns/credentials/examples/v2': json.loads(
            (VECTORS / 'credentials-examples-v2.json').read_text())}
        verify_data_integrity_proof(vector, pem, extra_contexts=examples)

    def test_clr_round_trip(self, ob3_credential, issuer):
        from openbadgeslib.ob3 import (build_clr_credential,
                                       bundled_clr_contexts,
                                       sign_clr_credential)
        priv, pub, did, vm = issuer
        member = add_data_integrity_proof(ob3_credential.to_vc(), priv, vm)
        clr = build_clr_credential(
            issuer={'id': did, 'type': ['Profile'], 'name': 'I'},
            identifier=[{'type': 'IdentityObject', 'hashed': True,
                         'identityHash': 'sha256$abc',
                         'identityType': 'emailAddress', 'salt': 's'}],
            members=[member], credential_id='https://issuer.example/clr/1',
            valid_from=datetime(2026, 1, 1, tzinfo=UTC))
        signed = sign_clr_credential(clr, priv, vm)
        verify_data_integrity_proof(signed, pub,
                                    extra_contexts=bundled_clr_contexts())


# ── a credential shaped like 1EdTech's "Complete OpenBadgeCredential" ───────
#
# Our own values, the example's structure: EndorsementCredentials embedded at
# the credential, issuer, achievement and achievement.creator levels, each
# with its own @context, a proof array and a refreshService pointing at the
# OUTER credential; address.geo typed GeoCoordinates (compacted as `geo`);
# a top-level refreshService {id: <credential id>, type}; an integer
# statusListIndex; the issuer node re-used as achievement.creator.

CRED_ID = 'https://university.example/credentials/3732'
ISSUER_ID = 'https://university.example/issuers/565049'
ACH_ID = 'https://university.example/achievements/degree'
RD_ID = 'urn:uuid:f6ab24cd-86e8-4eaf-b8c6-ded74e8fd41c'
LEVEL_ID = 'urn:uuid:d05a0867-d0ad-4b03-bdb5-28fb5d2aab7a'
COMPLETE_STATUS = {
    'id': 'https://university.example/credentials/revocationList#23',
    'type': 'BitstringStatusListEntry', 'statusPurpose': 'revocation',
    'statusListIndex': 23,
    'statusListCredential': 'https://university.example/credentials/revocationList',
}


def _alignment(code):
    return {'type': ['Alignment'], 'targetCode': code,
            'targetDescription': 'Degree programmes.', 'targetName': 'Degree',
            'targetFramework': 'Programme Catalog', 'targetType': 'CFItem',
            'targetUrl': 'https://university.example/catalog/%s' % code}


def _endorsement(number, refresh_id=CRED_ID):
    return {
        '@context': list(OB3_CONTEXT),
        'id': 'https://university.example/endorsementcredential/%d' % number,
        'type': ['VerifiableCredential', 'EndorsementCredential'],
        'name': 'Accreditation endorsement',
        'issuer': {'id': 'https://accreditor.example/issuers/1',
                   'type': ['Profile'], 'name': 'Accrediting Agency'},
        'validFrom': '2010-01-01T00:00:00Z',
        'validUntil': '2020-01-01T00:00:00Z',
        'credentialSubject': {'id': ISSUER_ID, 'type': ['EndorsementSubject'],
                              'endorsementComment': 'In good standing'},
        'credentialSchema': [{
            'id': 'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/'
                  'ob_v3p0_endorsementcredential_schema.json',
            'type': '1EdTechJsonSchemaValidator2019'}],
        'credentialStatus': dict(COMPLETE_STATUS),
        'refreshService': {'id': refresh_id, 'type': '1EdTechCredentialRefresh'},
        'proof': [{
            'type': 'DataIntegrityProof', 'cryptosuite': 'eddsa-rdfc-2022',
            'created': '2010-01-01T19:23:24Z',
            'verificationMethod': 'https://accreditor.example/issuers/1#key-1',
            'proofPurpose': 'assertionMethod', 'proofValue': 'z' + '3' * 86}],
    }


def _profile(endorsements):
    return {
        'id': ISSUER_ID, 'type': ['Profile'], 'name': 'Example University',
        'url': 'https://university.example', 'phone': '1-222-333-4444',
        'description': 'Online degree programmes.', 'endorsement': endorsements,
        'image': {'id': 'https://university.example/logo.png', 'type': 'Image',
                  'caption': 'Logo'},
        'email': 'registrar@university.example',
        'address': {
            'type': ['Address'], 'addressCountry': 'Spain',
            'addressCountryCode': 'ES', 'addressRegion': 'Madrid',
            'addressLocality': 'Madrid', 'streetAddress': '1 Calle Mayor',
            'postOfficeBoxNumber': '1', 'postalCode': '28001',
            'geo': {'type': 'GeoCoordinates', 'latitude': 40.4, 'longitude': -3.7}},
        'otherIdentifier': [{'type': 'IdentifierEntry', 'identifier': '12345',
                             'identifierType': 'sourcedId'}],
        'official': 'The Rector',
        'parentOrg': {'id': 'did:example:123456789', 'type': ['Profile'],
                      'name': 'University Group'},
    }


def _complete_document():
    image = {'id': CRED_ID + '/image', 'type': 'Image', 'caption': 'Degree'}
    return {
        '@context': list(OB3_CONTEXT),
        'id': CRED_ID,
        'type': ['VerifiableCredential', 'OpenBadgeCredential'],
        'name': 'University Degree for Example Student',
        'description': 'University Degree Description',
        'image': image,
        'credentialSubject': {
            'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
            'type': ['AchievementSubject'],
            'activityEndDate': '2010-01-02T00:00:00Z',
            'activityStartDate': '2010-01-01T00:00:00Z',
            'creditsEarned': 42.0, 'licenseNumber': 'A-9320041',
            'role': 'Major Domo', 'term': 'Fall',
            'source': {'id': 'https://school.example/issuers/201234',
                       'type': ['Profile'], 'name': 'College of Arts'},
            'identifier': [{'type': 'IdentityObject',
                            'identityHash': 'student@university.example',
                            'identityType': 'emailAddress', 'hashed': False,
                            'salt': 'not-used'}],
            'achievement': {
                'id': ACH_ID, 'type': ['Achievement'],
                'alignment': [_alignment('degree')],
                'achievementType': 'Degree',
                'creator': _profile([_endorsement(1),
                                     _endorsement(2, 'https://state.example/c/1')]),
                'creditsAvailable': 36.0,
                'criteria': {'id': ACH_ID, 'narrative': '# Degree Requirements'},
                'description': 'University Degree Description',
                'endorsement': [_endorsement(3)],
                'fieldOfStudy': 'Research', 'humanCode': 'R1',
                'image': {'id': ACH_ID + '/image', 'type': 'Image',
                          'caption': 'University Degree'},
                'name': 'University Degree',
                'otherIdentifier': [{'type': 'IdentifierEntry',
                                     'identifier': 'abde',
                                     'identifierType': 'identifier'}],
                'resultDescription': [{
                    'id': RD_ID, 'type': ['ResultDescription'],
                    'alignment': [_alignment('project')],
                    'allowedValue': ['D', 'C', 'B', 'A'],
                    'name': 'Final Project Grade', 'requiredLevel': LEVEL_ID,
                    'requiredValue': 'C', 'resultType': 'LetterGrade',
                    'rubricCriterionLevel': [{
                        'id': LEVEL_ID, 'type': ['RubricCriterionLevel'],
                        'alignment': [_alignment('mastery')],
                        'description': 'Excellent work', 'level': 'Mastery',
                        'name': 'Mastery', 'points': '4'}],
                    'valueMax': 'D', 'valueMin': 'A'}],
                'specialization': 'Computer Science Research',
                'tag': ['research', 'computer science'],
            },
            'image': image,
            'narrative': 'There is a final project report.',
            'result': [{'type': ['Result'], 'alignment': [_alignment('project')],
                        'resultDescription': RD_ID, 'status': 'Completed',
                        'value': 'A'},
                       {'type': ['Result'], 'achievedLevel': LEVEL_ID,
                        'resultDescription': RD_ID}],
        },
        'endorsement': [_endorsement(4)],
        'evidence': [{'id': CRED_ID + '/evidence/1', 'type': ['Evidence'],
                      'narrative': '# Final Project Report', 'name': 'Report',
                      'description': 'The final project report.',
                      'genre': 'Research', 'audience': 'Department'}],
        'issuer': _profile([_endorsement(5)]),
        'validFrom': '2010-01-01T00:00:00Z',
        'validUntil': '2099-01-01T00:00:00Z',
        'credentialSchema': [{
            'id': 'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/'
                  'ob_v3p0_achievementcredential_schema.json',
            'type': '1EdTechJsonSchemaValidator2019'}],
        'credentialStatus': dict(COMPLETE_STATUS),
        'refreshService': {'id': CRED_ID, 'type': '1EdTechCredentialRefresh'},
    }


@pytest.fixture()
def complete(ed25519_keypair):
    """(signed complete document, its pinned verifier). The issuer is an
    https: id, so it verifies against a pinned key."""
    priv, pub = ed25519_keypair
    _, vm = _did_vm(pub)
    signed = add_data_integrity_proof(_complete_document(), priv, vm)
    return signed, OB3LdpVerifier(pubkey_pem=pub), (priv, vm)


class TestCompleteExample:
    def test_verifies(self, complete):
        signed, verifier, _ = complete
        credential = verifier.verify(signed)
        assert credential.achievement.name == 'University Degree'
        assert credential.credential_status == [COMPLETE_STATUS]

    def test_achievement_credential_alias_verifies(self, complete):
        _, verifier, (priv, vm) = complete
        document = _complete_document()
        document['type'] = ['VerifiableCredential', 'AchievementCredential']
        verifier.verify(add_data_integrity_proof(document, priv, vm))

    def test_type_synonyms_are_derived_from_the_pinned_contexts(self):
        # A new synonym (e.g. after a context bump) must show up here, not
        # silently widen what the comparison tolerates.
        groups: dict = {}
        for term, iris in cv._type_synonyms().items():
            for iri in iris:
                groups.setdefault(iri, set()).add(term)
        vocab = 'https://purl.imsglobal.org/spec/vc/ob/vocab.html#'
        assert {iri: terms for iri, terms in groups.items() if len(terms) > 1} == {
            vocab + 'Criteria': {'Criteria', 'criteria'},
            vocab + 'GeoCoordinates': {'GeoCoordinates', 'geo'},
            vocab + 'Image': {'Image', 'image'},
            vocab + 'OpenBadgeCredential': {'AchievementCredential',
                                            'OpenBadgeCredential'},
        }

    def test_type_spelled_as_iri_is_refused(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['issuer']['address']['geo']['type'] = (
            'https://purl.imsglobal.org/spec/vc/ob/vocab.html#GeoCoordinates')
        _rejected(doc, 'compacted form', verifier)

    def test_non_synonym_type_is_refused(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['image']['type'] = 'Evidence'
        _rejected(doc, 'compacted form', verifier)

    def test_refresh_service_with_more_than_id_and_type(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['refreshService']['name'] = 'A re-description'
        _rejected(doc, 'described again', verifier)

    def test_refresh_service_inside_an_endorsement_with_more(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['issuer']['endorsement'][0]['refreshService']['name'] = 'x'
        _rejected(doc, 'described again', verifier)

    def test_redescription_inside_an_endorsement(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['endorsement'][0]['credentialSubject'] = {
            'id': CRED_ID, 'type': ['VerifiableCredential'],
            'validUntil': '2099-01-01T00:00:00Z'}
        _rejected(doc, 'described again', verifier)

    def test_included_inside_an_endorsement(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['credentialSubject']['achievement']['endorsement'][0]['@included'] = [
            {'id': 'https://x.example/n', 'name': 'n'}]
        _rejected(doc, '@included', verifier)

    @pytest.mark.parametrize('context, match', [
        ([OB3_CONTEXT[0], {'x': 'https://example.org/x'}], 'inline @context object'),
        (OB3_CONTEXT + ['https://evil.example/ctx'], 'allowlist'),
        (OB3_CONTEXT[1:], 'VC 2.0 base context'),
    ])
    def test_endorsement_context(self, complete, context, match):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['credentialSubject']['achievement']['creator']['endorsement'][1][
            '@context'] = context
        _rejected(doc, match, verifier)

    def test_endorsement_without_own_context(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        del doc['endorsement'][0]['@context']
        _rejected(doc, r'compacted form .*endorsement/0', verifier)

    def test_endorsement_that_is_not_an_endorsement_credential(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['issuer']['endorsement'][0]['type'] = ['VerifiableCredential']
        _rejected(doc, 'is not an EndorsementCredential', verifier)

    def test_endorsement_rekeyed_member(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        endorsement = doc['issuer']['endorsement'][0]
        endorsement[VC + 'validUntil'] = {'@value': endorsement.pop('validUntil'),
                                          '@type': XSD_DATETIME}
        _rejected(doc, 'endorsement at /issuer/endorsement/0', verifier)

    def test_embedded_credentials_nest_too_deeply(self, complete, monkeypatch):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        holder = doc['issuer']['endorsement'][0]
        for level in range(cv._MAX_EMBEDDED_DEPTH + 1):
            inner = _endorsement(100 + level)
            holder['issuer'] = {
                'id': 'https://accreditor.example/issuers/%d' % level,
                'type': ['Profile'], 'name': 'Accreditor', 'endorsement': [inner]}
            holder = inner
        _forbid_expansion(monkeypatch)       # bounded before any processing
        _rejected(doc, 'nests embedded credentials too deeply', verifier)

    def test_endorsement_literal_entry(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['endorsement'] = ['https://elsewhere.example/endorsement/1']
        _rejected(doc, 'compacted form', verifier)


# ── the node an embedded endorsement names as its subject ───────────────────

def _achievement(document):
    return document['credentialSubject']['achievement']


# node: (its JSON object, the subject of the embedded endorsement naming it)
ENDORSED = {
    'achievement': (
        _achievement,
        lambda doc: _achievement(doc)['endorsement'][0]['credentialSubject']),
    'issuer': (lambda doc: doc['issuer'],
               lambda doc: doc['endorsement'][0]['credentialSubject']),
}
SUBJECT_MEMBER = 'gives its credentialSubject a member other than'


class TestEndorsementSubjectRelocation:
    """An embedded endorsement names the node it endorses as its
    credentialSubject, and RDF lets a node be described under any JSON object
    that references it: a holder could move the achievement's description,
    image or alignment (the issuer's name, url, image or description) into
    that subject with the dataset, and the signature, unchanged, and the model
    built from the JSON no longer showed them. The subject of an embedded
    credential may carry only id, type and endorsementComment, which is all
    an EndorsementSubject has."""

    @pytest.fixture()
    def endorsed(self, ed25519_keypair):
        """(signed, public key, pinned verifier) of the complete document
        with its achievement-level endorsement endorsing the achievement
        itself; the credential-level one endorses the issuer, as there."""
        priv, pub = ed25519_keypair
        _, vm = _did_vm(pub)
        document = _complete_document()
        ENDORSED['achievement'][1](document)['id'] = ACH_ID
        signed = add_data_integrity_proof(document, priv, vm)
        return signed, pub, OB3LdpVerifier(pubkey_pem=pub)

    def test_untouched_endorsements_verify(self, endorsed):
        signed, _, verifier = endorsed
        _check(signed)
        credential = verifier.verify(signed)
        assert credential.achievement.description == 'University Degree Description'
        assert credential.achievement.image_url == ACH_ID + '/image'
        assert [a.target_code for a in credential.achievement.alignments] == ['degree']
        assert credential.issuer.name == 'Example University'
        assert credential.issuer.url == 'https://university.example'

    @pytest.mark.parametrize('node, member', [
        ('achievement', 'description'), ('achievement', 'image'),
        ('achievement', 'alignment'), ('issuer', 'name'), ('issuer', 'url'),
        ('issuer', 'image'), ('issuer', 'description')])
    def test_member_moved_into_the_subject_is_refused(self, endorsed, node, member):
        signed, pub, verifier = endorsed
        moved = copy.deepcopy(signed)
        described, subject = (find(moved) for find in ENDORSED[node])
        subject[member] = described.pop(member)
        verify_data_integrity_proof(moved, pub)                      # same dataset
        where = {'achievement': '/credentialSubject/achievement/endorsement/0',
                 'issuer': '/endorsement/0'}[node]
        with pytest.raises(OB3VerificationError, match='endorsement at %s of the '
                           'credential %s' % (where, SUBJECT_MEMBER)):
            _check(moved)
        _rejected(moved, SUBJECT_MEMBER, verifier)

    def test_subject_type_moved_out_with_it(self, endorsed):
        # The rule cannot hang on the subject's EndorsementSubject type: a
        # type is a statement about the node like any other, so it (and the
        # endorsementComment its scoped context defines) moves to the outer
        # object while the description moves in.
        signed, pub, verifier = endorsed
        moved = copy.deepcopy(signed)
        described, subject = (find(moved) for find in ENDORSED['achievement'])
        described['type'] = ['Achievement'] + subject.pop('type')
        described['endorsementComment'] = subject.pop('endorsementComment')
        subject['description'] = described.pop('description')
        assert subject == {'id': ACH_ID,
                           'description': 'University Degree Description'}
        verify_data_integrity_proof(moved, pub)                      # same dataset
        _rejected(moved, SUBJECT_MEMBER, verifier)

    def test_copied_member_is_refused_too(self, endorsed):
        # The cost: the subject may not repeat a member either, since a
        # repeated statement is the same dataset and the next step is to
        # drop it from the object the model reads.
        signed, pub, verifier = endorsed
        copied = copy.deepcopy(signed)
        described, subject = (find(copied) for find in ENDORSED['issuer'])
        subject['name'] = described['name']
        verify_data_integrity_proof(copied, pub)
        _rejected(copied, SUBJECT_MEMBER, verifier)

    def test_member_of_another_scope_was_refused_already(self, endorsed):
        # criteria is a term of the Achievement type only: under the
        # endorsement subject it is no term, so the dataset loses it and the
        # endorsement is not its own compacted form (a regression assertion;
        # the rule above is not what refuses this one).
        signed, pub, verifier = endorsed
        moved = copy.deepcopy(signed)
        described, subject = (find(moved) for find in ENDORSED['achievement'])
        subject['criteria'] = described.pop('criteria')
        with pytest.raises(OB3VerificationError, match='signature mismatch'):
            verify_data_integrity_proof(moved, pub)
        _rejected(moved, r'endorsement at \S+ of the credential is not in '
                         r'compacted form .*/credentialSubject/criteria', verifier)

    def test_issuer_signed_extra_subject_member_is_refused(self, ed25519_keypair):
        # Not only a holder's move: an embedded endorsement whose subject
        # carries more than an EndorsementSubject has is not accepted.
        priv, pub = ed25519_keypair
        _, vm = _did_vm(pub)
        document = _complete_document()
        ENDORSED['issuer'][1](document)['name'] = 'Example University'
        signed = add_data_integrity_proof(document, priv, vm)
        _rejected(signed, r'endorsement at /endorsement/0 of the credential %s '
                          r'id, type and endorsementComment \(%s\)'
                  % (SUBJECT_MEMBER, re.escape("'https://schema.org/name'")),
                  OB3LdpVerifier(pubkey_pem=pub))

    def test_nested_endorsement_subject(self, ed25519_keypair):
        # An endorsement of the endorser, embedded in the endorsement: its
        # subject is held to the same members.
        priv, pub = ed25519_keypair
        _, vm = _did_vm(pub)
        document = _complete_document()
        inner = _endorsement(6)
        inner['credentialSubject'] = {
            'id': 'https://accreditor.example/issuers/1',
            'type': ['EndorsementSubject'], 'endorsementComment': 'Listed'}
        document['endorsement'][0]['issuer']['endorsement'] = [inner]
        verifier = OB3LdpVerifier(pubkey_pem=pub)
        verifier.verify(add_data_integrity_proof(document, priv, vm))
        inner['credentialSubject']['name'] = 'Accrediting Agency'
        _rejected(add_data_integrity_proof(document, priv, vm),
                  r'endorsement at /endorsement/0 of the credential %s'
                  % SUBJECT_MEMBER, verifier)


# ── a node the model reads, described in more than one place ────────────────

TWICE = 'in more than one place'
ACH = '/credentialSubject/achievement'
SUBJECT_ID = 'did:example:ebfeb1f712ebc6f1c276e12ec21'
CRITERIA_ID = 'https://university.example/achievements/degree/criteria'
EVIDENCE_ID = CRED_ID + '/evidence/1'
IDS = 'https://university.example/nodes/'


def _not_read_at(member, read_at, found_at):
    return re.escape("its %s is not at '%s', where the model reads it, but at "
                     "'%s'" % (member, read_at, found_at))


def _not_the_same(member, read_at, other):
    return re.escape("its %s at '%s', where the model reads it, is not the "
                     "same as at '%s'" % (member, read_at, other))


def _small_profile():
    return {'id': ISSUER_ID, 'type': ['Profile'], 'name': 'Example University',
            'url': 'https://university.example',
            'email': 'registrar@university.example',
            'image': {'id': 'https://university.example/logo.png',
                      'type': 'Image', 'caption': 'Logo'}}


def _description_into_criteria(document):
    achievement = _achievement(document)
    achievement['criteria']['description'] = achievement.pop('description')


def _issuer_member_left_in_creator(member):
    def change(document):
        del document['issuer'][member]
    return change


def _narrative_into_achievement(document):
    achievement = _achievement(document)
    achievement['narrative'] = achievement['criteria'].pop('narrative')


def _narrative_into_achievement_bare_criteria(document):
    _narrative_into_achievement(document)
    _achievement(document)['criteria'] = ACH_ID


def _achievement_members_into_criteria(document):
    achievement = _achievement(document)
    achievement['criteria']['type'] = ['Achievement']
    for member in ('tag', 'alignment', 'achievementType', 'creditsAvailable',
                   'resultDescription'):
        achievement['criteria'][member] = achievement.pop(member)


# what a holder does to the signed Complete example: (the change, the refusal)
RELOCATIONS = {
    'description into criteria': (
        _description_into_criteria,
        _not_read_at('description', ACH, ACH + '/criteria')),
    'issuer name left in creator': (
        _issuer_member_left_in_creator('name'),
        _not_read_at('name', '/issuer', ACH + '/creator')),
    'issuer url left in creator': (
        _issuer_member_left_in_creator('url'),
        _not_read_at('url', '/issuer', ACH + '/creator')),
    'issuer email left in creator': (
        _issuer_member_left_in_creator('email'),
        _not_read_at('email', '/issuer', ACH + '/creator')),
    'issuer image left in creator': (
        _issuer_member_left_in_creator('image'),
        _not_read_at('image', '/issuer', ACH + '/creator')),
    'narrative into the achievement': (
        _narrative_into_achievement,
        _not_read_at('narrative', ACH + '/criteria', ACH)),
    'narrative into the achievement, criteria a bare IRI': (
        _narrative_into_achievement_bare_criteria,
        _not_read_at('narrative', ACH + '/criteria', ACH)),
    'achievement members into criteria': (
        _achievement_members_into_criteria,
        _not_read_at('achievementType', ACH, ACH + '/criteria')),
}


def _identified_document():
    """The complete document with an id on every node the model reads, and
    each of those nodes named once more by a ``related`` entry of the
    achievement that carries no member the model reads: a second description
    as legitimate as an endorsement's subject."""
    document = _complete_document()
    subject = document['credentialSubject']
    achievement = subject['achievement']
    del achievement['creator']
    achievement['criteria']['id'] = CRITERIA_ID
    achievement['alignment'][0]['id'] = IDS + 'alignment'
    achievement['resultDescription'][0]['alignment'][0]['id'] = IDS + 'rd-alignment'
    subject['result'][0]['id'] = IDS + 'result'
    subject['result'][0]['alignment'][0]['id'] = IDS + 'result-alignment'
    subject['identifier'][0]['id'] = IDS + 'identifier'
    achievement['related'] = [
        {'id': node_id, 'type': ['Related'], 'inLanguage': 'en', 'version': '1'}
        for node_id in (ISSUER_ID, SUBJECT_ID, ACH_ID, CRITERIA_ID, RD_ID,
                        EVIDENCE_ID, IDS + 'alignment', IDS + 'rd-alignment',
                        IDS + 'result', IDS + 'result-alignment',
                        IDS + 'identifier')]
    return document


# position the model reads a node at: (the node there, a member it reads from
# it, where a refusal says it reads it, the model's value for it)
POSITIONS = {
    'issuer': (
        lambda doc: doc['issuer'], 'email', '/issuer',
        lambda cred: cred.issuer.email, 'registrar@university.example'),
    'credentialSubject': (
        lambda doc: doc['credentialSubject'], 'creditsEarned',
        '/credentialSubject', lambda cred: cred.credits_earned, 42.0),
    'achievement': (
        _achievement, 'tag', ACH,
        lambda cred: cred.achievement.tags, ['research', 'computer science']),
    'criteria': (
        lambda doc: _achievement(doc)['criteria'], 'narrative', ACH + '/criteria',
        lambda cred: cred.achievement.criteria_narrative, '# Degree Requirements'),
    'achievement alignment': (
        lambda doc: _achievement(doc)['alignment'][0], 'targetCode',
        ACH + '/alignment/0',
        lambda cred: cred.achievement.alignments[0].target_code, 'degree'),
    'resultDescription': (
        lambda doc: _achievement(doc)['resultDescription'][0], 'requiredValue',
        ACH + '/resultDescription/0',
        lambda cred: cred.achievement.result_descriptions[0].required_value, 'C'),
    'resultDescription alignment': (
        lambda doc: _achievement(doc)['resultDescription'][0]['alignment'][0],
        'targetFramework', ACH + '/resultDescription/0/alignment/0',
        lambda cred: cred.achievement.result_descriptions[0].alignments[0]
        .target_framework, 'Programme Catalog'),
    'result': (
        lambda doc: doc['credentialSubject']['result'][0], 'status',
        '/credentialSubject/result/0',
        lambda cred: cred.results[0].status, 'Completed'),
    'result alignment': (
        lambda doc: doc['credentialSubject']['result'][0]['alignment'][0],
        'targetDescription', '/credentialSubject/result/0/alignment/0',
        lambda cred: cred.results[0].alignments[0].target_description,
        'Degree programmes.'),
    'identifier': (
        lambda doc: doc['credentialSubject']['identifier'][0], 'salt',
        '/credentialSubject/identifier/0',
        lambda cred: cred.identifiers[0].salt, 'not-used'),
    'evidence': (
        lambda doc: doc['evidence'][0], 'genre', '/evidence/0',
        lambda cred: cred.evidence[0].genre, 'Research'),
}


class _Spy(dict):
    """A JSON object that notes every key read from it, by where it is."""

    def __init__(self, data, path, reads):
        super().__init__({key: _spied(value, path + (key,), reads)
                          for key, value in data.items()})
        self._note = lambda key: reads.setdefault(path, set()).add(key)

    def get(self, key, default=None):
        self._note(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self._note(key)
        return super().__getitem__(key)


def _spied(value, path, reads):
    if isinstance(value, dict):
        return _Spy(value, path, reads)
    if isinstance(value, list):
        return [_spied(item, path, reads) for item in value]
    return value


def _table_positions(reads, path=()):
    """position -> the keys _MODEL_READS says the model reads from a node
    there."""
    positions = {path: set(reads)} if path and reads else {}
    for key, below in (reads or {}).items():
        positions.update(_table_positions(below, path + (key,)))
    return positions


def _read_for_the_id(reads, path=()):
    """The positions _MODEL_READS marks as a node read for its id alone."""
    return {found for key, below in reads.items()
            for found in ({path + (key,)} if below is None
                          else _read_for_the_id(below, path + (key,)))}


class TestNodeDescribedTwice:
    """RDF has one node per id, however many JSON objects describe it, and
    the signature covers the node: a member can sit in any of them. The model
    reads each member from one fixed object. The 1EdTech Complete example
    describes two nodes twice in the credential itself (the issuer again as
    achievement.creator, a criteria with the achievement's id), and any node
    with an id can be split over two entries of the array that holds it, so
    a holder could leave what the model reads only in the object it does not
    read, or exchange two values. Every description of a node the model
    reads must agree with the one it reads on each member it reads."""

    @pytest.fixture()
    def keys(self, ed25519_keypair):
        """(sign, public key, pinned verifier)"""
        priv, pub = ed25519_keypair
        _, vm = _did_vm(pub)
        return (lambda document: add_data_integrity_proof(document, priv, vm),
                pub, OB3LdpVerifier(pubkey_pem=pub))

    @staticmethod
    def _moved(signed, pub, change):
        """*signed* after *change*, not signed again: the same dataset under
        the same proof, as the low-level check confirms."""
        moved = copy.deepcopy(signed)
        change(moved)
        verify_data_integrity_proof(moved, pub)
        return moved

    def test_complete_example_shows_what_was_signed(self, keys):
        sign, _, verifier = keys
        credential = verifier.verify(sign(_complete_document()))
        assert credential.issuer.name == 'Example University'
        assert credential.issuer.url == 'https://university.example'
        assert credential.issuer.email == 'registrar@university.example'
        assert credential.issuer.image_url == 'https://university.example/logo.png'
        achievement = credential.achievement
        assert achievement.description == 'University Degree Description'
        assert achievement.criteria_narrative == '# Degree Requirements'
        assert achievement.tags == ['research', 'computer science']

    @pytest.mark.parametrize('relocation', sorted(RELOCATIONS))
    def test_relocation_is_refused(self, keys, relocation):
        sign, pub, verifier = keys
        change, refusal = RELOCATIONS[relocation]
        moved = self._moved(sign(_complete_document()), pub, change)
        with pytest.raises(OB3VerificationError, match=TWICE) as refused:
            _check(moved)
        assert re.search(refusal, str(refused.value)), str(refused.value)
        _rejected(moved, refusal, verifier)

    def test_relocations_verified_before_the_fix(self, keys, monkeypatch):
        # What the rule is for: without it each of them verifies, and the
        # model no longer shows what the issuer signed.
        sign, pub, verifier = keys
        monkeypatch.setattr(cv, '_check_read_in_place', lambda *args: None)
        signed = sign(_complete_document())
        moved = self._moved(signed, pub, _description_into_criteria)
        assert verifier.verify(moved).achievement.description == ''
        moved = self._moved(signed, pub, _narrative_into_achievement)
        assert verifier.verify(moved).achievement.criteria_narrative == ''
        moved = copy.deepcopy(signed)
        for member in ('name', 'url', 'email'):
            del moved['issuer'][member]
        verify_data_integrity_proof(moved, pub)
        issuer = verifier.verify(moved).issuer
        assert (issuer.name, issuer.url, issuer.email) == ('', None, None)

    def test_two_values_are_refused_whichever_is_shown(self, keys):
        # The cost: a credential whose issuer gives one node two values for a
        # member the model reads is refused as signed, since exchanging them
        # is the same dataset and the model would report the other one.
        sign, pub, verifier = keys
        document = _complete_document()
        _achievement(document)['creator']['name'] = 'Another Name'
        signed = sign(document)
        refusal = _not_the_same('name', '/issuer', ACH + '/creator')
        _rejected(signed, refusal, verifier)

        def exchange(doc):
            creator = _achievement(doc)['creator']
            doc['issuer']['name'], creator['name'] = (creator['name'],
                                                      doc['issuer']['name'])
        exchanged = self._moved(signed, pub, exchange)
        assert exchanged['issuer']['name'] == 'Another Name'
        _rejected(exchanged, refusal, verifier)

    def test_issuer_as_a_bare_iri_beside_a_full_creator_is_refused(self, keys):
        # A recorded decision: this issuer-signed, schema-valid shape cannot
        # be told from a credential signed with the profile under both
        # members whose holder cut the issuer down to its id -- the two are
        # the same document. The issuer has to describe itself under
        # ``issuer``, where the model reads it.
        sign, pub, verifier = keys
        both = _complete_document()
        both['issuer'] = _small_profile()
        _achievement(both)['creator'] = _small_profile()
        signed_both = sign(both)
        assert verifier.verify(signed_both).issuer.name == 'Example University'

        bare = _complete_document()
        bare['issuer'] = ISSUER_ID
        _achievement(bare)['creator'] = _small_profile()
        signed_bare = sign(bare)

        def cut(doc):
            doc['issuer'] = ISSUER_ID
        stripped = self._moved(signed_both, pub, cut)
        assert ({k: v for k, v in stripped.items() if k != 'proof'}
                == {k: v for k, v in signed_bare.items() if k != 'proof'})
        for document in (signed_bare, stripped):
            _rejected(document, r"describes the node '%s' %s, and %s"
                      % (re.escape(ISSUER_ID), TWICE,
                         _not_read_at('image', '/issuer', ACH + '/creator')),
                      verifier)

    def test_poorer_issuer_than_creator_is_refused(self, keys):
        # The same for an issuer object with fewer of the members the model
        # reads than another description of it.
        sign, _, verifier = keys
        document = _complete_document()
        document['issuer'] = {'id': ISSUER_ID, 'type': ['Profile'],
                              'name': 'Example University'}
        _achievement(document)['creator'] = _small_profile()
        _rejected(sign(document),
                  _not_read_at('image', '/issuer', ACH + '/creator'), verifier)

    def test_poorer_second_description_verifies(self, keys):
        # Another description may carry fewer members, or none: a creator
        # with the name only, a ``source`` that only names the issuer.
        sign, _, verifier = keys
        document = _complete_document()
        _achievement(document)['creator'] = {
            'id': ISSUER_ID, 'type': ['Profile'], 'name': 'Example University'}
        document['credentialSubject']['source'] = {'id': ISSUER_ID,
                                                   'type': ['Profile']}
        credential = verifier.verify(sign(document))
        assert credential.issuer.email == 'registrar@university.example'

    def test_image_is_compared_by_the_id_the_model_reads(self, keys):
        # The model reads the id of an image and nothing else, from the
        # object and from the bare IRI alike, so an issuer whose image is
        # only named in one description and described in the other shows
        # the same image either way ...
        sign, pub, verifier = keys
        logo = 'https://university.example/logo.png'
        document = _complete_document()
        document['issuer']['image'] = {'id': logo}
        signed = sign(document)
        assert verifier.verify(signed).issuer.image_url == logo

        def as_a_string(doc):
            doc['issuer']['image'] = logo
        assert verifier.verify(
            self._moved(signed, pub, as_a_string)).issuer.image_url == logo

        # ... and a holder who cuts a described image down to its id, in
        # either spelling, changes nothing the model shows
        def cut(spelling):
            def change(doc):
                doc['issuer']['image'] = spelling
            return change
        described = sign(_complete_document())
        for spelling in ({'id': logo}, logo):
            moved = self._moved(described, pub, cut(spelling))
            assert verifier.verify(moved).issuer.image_url == logo

        # Two images of one node are still two values of a member the model
        # reads, and an image only in the other description is still not
        # where the model reads it.
        document = _complete_document()
        _achievement(document)['creator']['image'] = {
            'id': 'https://university.example/seal.png', 'type': 'Image'}
        _rejected(sign(document),
                  _not_the_same('image', '/issuer', ACH + '/creator'), verifier)

    def test_order_of_the_values_is_not_compared(self, keys):
        # The values of a property are a set in the dataset.
        sign, _, verifier = keys
        document = _complete_document()
        document['issuer']['endorsementJwt'] = ['a.b.c', 'd.e.f']
        _achievement(document)['creator']['endorsementJwt'] = ['d.e.f', 'a.b.c']
        credential = verifier.verify(sign(document))
        assert credential.issuer.endorsement_jwts == ['a.b.c', 'd.e.f']
        _achievement(document)['creator']['endorsementJwt'] = ['d.e.f']
        _rejected(sign(document), _not_the_same('endorsementJwt', '/issuer',
                                                ACH + '/creator'), verifier)

    def test_values_are_compared_as_canonical_json(self):
        def values(items, below=MappingProxyType({})):
            return cv._values(items, below)
        assert values([{'@value': True}]) != values([{'@value': 1}])
        assert values([{'@value': 1}]) != values([{'@value': 1.0}])
        assert values([{'a': 1, 'b': 2}, 'x']) == values(['x', {'b': 2, 'a': 1}])
        assert values({'@id': 'x'}) == values([{'@id': 'x'}])
        # Of a node the model reads members of: its id and those members.
        below = {'urn:read': ('read', {})}
        node = {'@id': 'urn:n', 'urn:read': [{'@value': 1}], 'urn:other': [1]}
        assert values([node], below) == values(
            [{'@id': 'urn:n', 'urn:read': [{'@value': 1}]}], below)
        assert values([node], below) != values([dict(node, **{'@id': 'urn:m'})], below)
        assert values([node], below) != values(
            [dict(node, **{'urn:read': [{'@value': 2}]})], below)
        assert values([node], below) != values([node])
        # Of a node the model reads for its id alone: that id.
        assert values([node], None) == values([{'@id': 'urn:n'}], None)
        assert values([node], None) != values([{'@id': 'urn:m'}], None)
        assert values([{'urn:other': [1]}], None) == values([{'urn:other': [2]}], None)
        # a literal, a list or a graph under such a member is compared whole
        for keyword in ('@value', '@list', '@graph'):
            for reads in (below, None):
                assert values([{keyword: [1], 'urn:other': 1}], reads) != values(
                    [{keyword: [1], 'urn:other': 2}], reads)

    def test_second_description_without_what_the_model_reads_verifies(self, keys):
        sign, _, verifier = keys
        credential = verifier.verify(sign(_identified_document()))
        for _, _, _, shown, value in POSITIONS.values():
            assert shown(credential) == value

    @pytest.mark.parametrize('position', sorted(POSITIONS))
    def test_member_moved_out_of_any_position_is_refused(self, keys, position):
        sign, pub, verifier = keys
        find, member, read_at, _, _ = POSITIONS[position]

        def move(doc):
            node = find(doc)
            other = next(entry for entry in _achievement(doc)['related']
                         if entry['id'] == node['id'])
            # a type the node has brings the scoped context that spells the
            # member; stating it twice is the same dataset
            types = node.get('type', [])
            other['type'] += [types] if isinstance(types, str) else types
            other[member] = node.pop(member)
        signed = sign(_identified_document())
        moved = self._moved(signed, pub, move)
        assert member not in find(moved)
        _rejected(moved, r"describes the node '%s' %s, and its %s is not at "
                         r"'%s', where the model reads it, but at "
                         r"'%s/related/\d+'"
                  % (re.escape(find(moved)['id']), TWICE, member, read_at, ACH),
                  verifier)

    def test_identical_descriptions_verify(self, keys):
        # The same node described twice with the same members: every node
        # under the subject, by a second, equal entry; the evidence likewise;
        # the issuer as the creator (as in the example).
        sign, _, verifier = keys
        document = _identified_document()
        del _achievement(document)['related']
        document['credentialSubject'] = [
            document['credentialSubject'],
            copy.deepcopy(document['credentialSubject'])]
        document['evidence'] = document['evidence'] + copy.deepcopy(
            document['evidence'])
        credential = verifier.verify(sign(document))
        assert credential.credits_earned == 42.0
        assert [e.genre for e in credential.evidence] == ['Research', 'Research']

    def test_unread_member_of_a_value_is_no_reason_to_refuse(self, keys):
        # A member that is itself a node the model reads is compared by what
        # the model reads of it: a second description of the subject whose
        # achievement lacks fieldOfStudy, and whose alignment lacks
        # targetType, shows the same model whichever is read.
        sign, _, verifier = keys
        document = _identified_document()
        del _achievement(document)['related']
        second = copy.deepcopy(document['credentialSubject'])
        del second['achievement']['fieldOfStudy']
        del second['achievement']['alignment'][0]['targetType']
        document['credentialSubject'] = [document['credentialSubject'], second]
        credential = verifier.verify(sign(document))
        assert credential.achievement.alignments[0].target_code == 'degree'
        # ... but not a member the model reads of it
        # (the subject, the achievement and the alignment each say so; which
        # is named first is not pinned)
        del second['achievement']['alignment'][0]['targetCode']
        _rejected(sign(document), r"%s, and its (achievement at "
                  r"'/credentialSubject/0'|alignment at '%s'|targetCode is "
                  r"not at '/credentialSubject/1/achievement/alignment/0')"
                  % (TWICE, '/credentialSubject/0/achievement'), verifier)

    def test_node_split_over_two_array_entries_is_refused(self, keys):
        # No second description by the issuer is needed where the model
        # accepts an array: the holder writes the node twice, each entry
        # with part of it. The model reads the first credentialSubject only.
        sign, pub, verifier = keys
        signed = sign(_complete_document())
        assert verifier.verify(signed).credits_earned == 42.0

        def split(doc):
            subject = doc['credentialSubject']
            doc['credentialSubject'] = [subject, {
                'id': subject['id'], 'type': ['AchievementSubject'],
                'creditsEarned': subject.pop('creditsEarned'),
                'result': subject.pop('result'),
                'identifier': subject.pop('identifier')}]
        moved = self._moved(signed, pub, split)
        _rejected(moved, r"describes the node '%s' %s, and its \w+ is not at "
                         r"'/credentialSubject/[01]', where the model reads it, "
                         r"but at '/credentialSubject/[01]'"
                  % (re.escape(SUBJECT_ID), TWICE), verifier)

        def split_evidence(doc):
            first = doc['evidence'][0]
            doc['evidence'].append({'id': first['id'], 'type': ['Evidence'],
                                    'narrative': first.pop('narrative')})
        _rejected(self._moved(signed, pub, split_evidence),
                  _not_read_at('narrative', '/evidence/0', '/evidence/1'),
                  verifier)

        # A node without an id is split the same way under a blank node
        # label, which is as good as an id inside one document.
        def split_result(doc):
            first = doc['credentialSubject']['result'][0]
            first['id'] = '_:r'
            doc['credentialSubject']['result'].append(
                {'id': '_:r', 'type': ['Result'], 'status': first.pop('status')})
        assert verifier.verify(signed).results[0].status == 'Completed'
        _rejected(self._moved(signed, pub, split_result),
                  r"describes the node '_:r' %s, and its \w+ is not at "
                  r"'/credentialSubject/result/[02]', where the model reads it"
                  % TWICE, verifier)

    def test_description_inside_an_embedded_credential_counts(self, keys):
        # The issuer endorses itself: the endorsement's own issuer is one
        # more description of the node, inside a credential validated on its
        # own, and the member cannot be left there either.
        sign, pub, verifier = keys
        document = _complete_document()
        del _achievement(document)['creator']
        document['endorsement'][0]['issuer'] = {
            'id': ISSUER_ID, 'type': ['Profile'], 'name': 'Example University'}
        signed = sign(document)
        assert verifier.verify(signed).issuer.url == 'https://university.example'

        def move(doc):
            doc['endorsement'][0]['issuer']['url'] = doc['issuer'].pop('url')
        _rejected(self._moved(signed, pub, move),
                  _not_read_at('url', '/issuer', '/endorsement/0/issuer'),
                  verifier)

    def test_self_issued_badge(self, keys):
        # The subject is the issuer: one node under issuer and under
        # credentialSubject, each object with its own members.
        sign, pub, verifier = keys
        document = _complete_document()
        document['credentialSubject']['id'] = ISSUER_ID
        # The cost: the subject's image and the issuer's are two images of
        # one node, and which is the issuer's logo is not signed.
        _rejected(sign(document),
                  _not_the_same('image', '/issuer', '/credentialSubject'),
                  verifier)
        del document['credentialSubject']['image']
        signed = sign(document)
        credential = verifier.verify(signed)
        assert credential.recipient_id == credential.issuer.id == ISSUER_ID
        assert (credential.credits_earned, len(credential.results)) == (42.0, 2)

        def into_the_issuer(doc):
            issuer, subject = doc['issuer'], doc['credentialSubject']
            issuer['type'] = issuer['type'] + subject['type']
            issuer['creditsEarned'] = subject.pop('creditsEarned')
            issuer['result'] = subject.pop('result')
        _rejected(self._moved(signed, pub, into_the_issuer),
                  _not_read_at('creditsEarned', '/credentialSubject', '/issuer'),
                  verifier)

        def into_the_subject(doc):
            doc['credentialSubject']['name'] = doc['issuer'].pop('name')
        _rejected(self._moved(signed, pub, into_the_subject),
                  _not_read_at('name', '/issuer', '/credentialSubject'), verifier)

    def test_endorsements_verify(self, keys):
        # An achievement-level endorsement of the achievement and a
        # credential-level one of the issuer: a subject carries no member
        # the model reads, so it agrees with any description.
        sign, _, verifier = keys
        document = _complete_document()
        ENDORSED['achievement'][1](document)['id'] = ACH_ID
        assert ENDORSED['issuer'][1](document)['id'] == ISSUER_ID
        credential = verifier.verify(sign(document))
        assert credential.achievement.description == 'University Degree Description'
        assert credential.issuer.name == 'Example University'

    def test_library_issued_credential_is_unaffected(self, issuer):
        # What this library issues describes no node twice: no creator, a
        # criteria without id.
        priv, _, did, _ = issuer
        alignment = Alignment(target_name='n', target_url='https://f.example/1',
                              target_code='c')
        signed = OB3LdpSigner(priv).sign(_credential(
            did,
            issuer=Issuer(id=did, name='Real Issuer', url='https://issuer.example',
                          email='i@issuer.example',
                          image_url='https://issuer.example/logo.png'),
            achievement=Achievement(
                id='https://issuer.example/achievements/attendance',
                name='Attendance', description='d', criteria_narrative='c',
                image_url='https://issuer.example/a.png', tags=['t'],
                alignments=[alignment],
                result_descriptions=[ResultDescription(
                    id='urn:uuid:00000000-0000-0000-0000-0000000000b1',
                    name='Grade', result_type='LetterGrade',
                    alignments=[alignment])]),
            evidence=[Evidence(id='https://issuer.example/e/1', narrative='n')],
            results=[Result(value='A', alignments=[alignment])],
            identifiers=list(HASHED_IDENTITY)))
        criteria = _achievement(signed)['criteria']
        assert 'id' not in criteria and 'creator' not in _achievement(signed)
        credential = OB3LdpVerifier().verify(signed)
        assert credential.achievement.criteria_narrative == 'c'
        assert credential.issuer.email == 'i@issuer.example'

    def test_signer_does_not_issue_two_values_for_a_node(self, issuer):
        priv, _, did, _ = issuer
        evidence = [Evidence(id='https://issuer.example/e/1', name='one'),
                    Evidence(id='https://issuer.example/e/1', name='another')]
        with pytest.raises(ErrorSigningFile, match=TWICE):
            OB3LdpSigner(priv).sign(_credential(did, evidence=evidence))

    def test_table_is_what_the_model_reads(self):
        # Both ways: a member the model starts reading must get the rule, and
        # a member it does not read must never be a reason to refuse.
        reads: dict = {}
        document = _identified_document()
        OpenBadgeCredential.from_vc_document(_spied(document, (), reads))
        below = {path: keys - {'id'} for path, keys in reads.items() if path}
        # (credentialStatus entries are kept as they are, for the status
        # check, and have a rule of their own)
        assert {path[0] for path in below} == set(cv._MODEL_READS)
        assert ({path: keys for path, keys in below.items() if keys}
                == _table_positions(cv._MODEL_READS))
        # a node read for its id alone has no member, so no rule of its
        # own, and is marked so in the table: the images
        assert {path for path, keys in below.items() if not keys} == {
            ('issuer', 'image'), ('credentialSubject', 'achievement', 'image')
        } == _read_for_the_id(cv._MODEL_READS)

    def test_table_by_iri_is_derived_from_the_pinned_contexts(self):
        ob = 'https://purl.imsglobal.org/spec/vc/ob/vocab.html#'
        reads = cv._model_reads()
        assert set(reads) == {VC + 'issuer', VC + 'credentialSubject',
                              VC + 'evidence'}
        key, issuer = reads[VC + 'issuer']
        assert key == 'issuer'
        assert {iri: below for iri, below in issuer.items()} == {
            'https://schema.org/name': ('name', {}),
            'https://schema.org/url': ('url', {}),
            'https://schema.org/email': ('email', {}),
            ob + 'endorsementJwt': ('endorsementJwt', {}),
            # the term is also the alias of the Image type; None: a node
            # read for its id alone
            ob + 'image': ('image', None), ob + 'Image': ('image', None),
        }
        _, subject = reads[VC + 'credentialSubject']
        _, achievement = subject[ob + 'achievement']
        assert achievement['https://schema.org/keywords'] == ('tag', {})
        assert achievement[ob + 'Criteria'] == (
            'criteria', {ob + 'narrative': ('narrative', {})})

        def keys(reads):
            for key, below in reads.values():
                yield key
                yield from keys(below or {})

        def terms(reads):
            for key, below in reads.items():
                yield key
                yield from terms(below or {})
        assert set(keys(reads)) == set(terms(cv._MODEL_READS))

    def test_refusal_points_into_the_document(self):
        # _where follows the document where it can; where the document is
        # not the compact form of the expansion it goes on by the terms.
        ob = 'https://purl.imsglobal.org/spec/vc/ob/vocab.html#'
        node: dict = {'@id': 'urn:x'}
        root = {VC + 'credentialSubject': [
            {'@id': 'urn:s', ob + 'achievement': [
                {'@id': 'urn:a', ob + 'Criteria': [{'@id': 'urn:c'}, node]}]}]}
        document = {'credentialSubject': [
            {'id': 'urn:s', 'achievement': {
                'id': 'urn:a', 'criteria': [{'id': 'urn:c'}, {'id': 'urn:x'}]}}]}
        assert cv._where(document, root, node) == repr(
            '/credentialSubject/0/achievement/criteria/1')
        assert cv._where({'credentialSubject': 'urn:s'}, root, node) == repr(
            '/credentialSubject/achievement/criteria/1')
        assert cv._where(document, {'urn:p': [node]}, node) == repr('/urn:p')
        assert cv._where(document, root, {'@id': 'urn:x'}) == repr('/')

    def test_ecdsa_sd_member_revealed_only_at_the_other_pointer(self):
        # Selective disclosure reveals a statement at the JSON pointer the
        # holder selects. For a node described twice the same statement has
        # two pointers, and one revealed only where the model does not read
        # it is the relocated member: the presentation is refused, and the
        # holder reveals it at the pointer the model reads.
        from test_ob3_ldp_ecdsa_sd import _p256_pem_pair, _require_ldp_sd
        _require_ldp_sd()
        from openvc.keys import P256SigningKey
        from openvc.proof.ecdsa_sd import EcdsaSdProofSuite
        from openbadgeslib.ob3.contexts import bundled_contexts

        priv, pub = _p256_pem_pair()
        did, vm = _did_vm(pub)
        document = _credential(
            did, issuer=Issuer(id=did, name='Real Issuer',
                               url='https://issuer.example'),
            expiration_date=datetime(2099, 1, 1, tzinfo=UTC),
            credential_status=[dict(STATUS_ENTRY)]).to_vc()
        _achievement(document)['creator'] = dict(document['issuer'])
        suite, contexts = EcdsaSdProofSuite(), bundled_contexts()
        base = suite.add_base_proof(
            document, signing_key=P256SigningKey.from_pem(priv, kid=vm),
            verification_method=vm, extra_contexts=contexts,
            mandatory_pointers=['/id', '/type', '/validFrom', '/validUntil',
                                '/credentialStatus', '/issuer/id',
                                '/issuer/type', '/credentialSubject'])

        def derive(*selective):
            return suite.derive_proof(base, selective_pointers=list(selective),
                                      extra_contexts=contexts)
        shown = derive('/issuer/name', '/issuer/url')
        credential = OB3LdpVerifier().verify(shown)
        assert (credential.issuer.name, credential.issuer.url) == (
            'Real Issuer', 'https://issuer.example')

        hidden = derive()
        assert set(hidden['issuer']) == {'id', 'type'}
        assert _achievement(hidden)['creator']['name'] == 'Real Issuer'
        verify_data_integrity_proof(hidden, pub)
        _rejected(hidden, _not_read_at('name', '/issuer', ACH + '/creator'))
        _rejected(derive('/issuer/name'),
                  _not_read_at('url', '/issuer', ACH + '/creator'))


# ── two spellings of one statement, read as one by the model ────────────────

def _wrapped(find, key):
    def change(document):
        find(document)[key] = [find(document)[key]]
    return change


def _twice(find, key):
    def change(document):
        value = find(document)[key]
        find(document)[key] = [value, copy.deepcopy(value)]
    return change


def _unwrapped(find, key):
    def change(document):
        (find(document)[key],) = find(document)[key]
    return change


def _criteria_twice(document):
    criteria = _achievement(document)['criteria']
    _achievement(document)['criteria'] = [
        criteria, dict(criteria, narrative=[criteria['narrative']])]


def _image_twice(document):
    image = _achievement(document)['image']
    _achievement(document)['image'] = [image, dict(image, type=[image['type']])]


def _issuer_of(document):
    return document['issuer']


def _subject_of(document):
    return document['credentialSubject']


def _document(document):
    return document


# what a holder does to the spelling of the signed Complete example
RESPELLINGS = {
    'criteria in an array': _wrapped(_achievement, 'criteria'),
    'criteria twice': _twice(_achievement, 'criteria'),
    'criteria twice, the narrative of one in an array': _criteria_twice,
    'criteria narrative in an array': _wrapped(
        lambda doc: _achievement(doc)['criteria'], 'narrative'),
    'achievement image in an array': _wrapped(_achievement, 'image'),
    'achievement image twice': _twice(_achievement, 'image'),
    'achievement image twice, the type of one in an array': _image_twice,
    'issuer image in an array': _wrapped(_issuer_of, 'image'),
    'creditsEarned in an array': _wrapped(_subject_of, 'creditsEarned'),
    'creditsEarned twice': _twice(_subject_of, 'creditsEarned'),
    'creditsAvailable in an array': _wrapped(_achievement, 'creditsAvailable'),
    'description in an array': _wrapped(_achievement, 'description'),
    'description twice': _twice(_achievement, 'description'),
    'achievementType in an array': _wrapped(_achievement, 'achievementType'),
    'issuer name in an array': _wrapped(_issuer_of, 'name'),
    'issuer name twice': _twice(_issuer_of, 'name'),
    'issuer url in an array': _wrapped(_issuer_of, 'url'),
    'issuer email in an array': _wrapped(_issuer_of, 'email'),
    'credential name in an array': _wrapped(_document, 'name'),
    'resultDescription out of its array': _unwrapped(
        _achievement, 'resultDescription'),
    'identifier out of its array': _unwrapped(_subject_of, 'identifier'),
    'alignment out of its array': _unwrapped(_achievement, 'alignment'),
    'evidence out of its array': _unwrapped(_document, 'evidence'),
    'evidence genre in an array': _wrapped(
        lambda doc: doc['evidence'][0], 'genre'),
    'result status in an array': _wrapped(
        lambda doc: doc['credentialSubject']['result'][0], 'status'),
    'alignment targetCode in an array': _wrapped(
        lambda doc: _achievement(doc)['alignment'][0], 'targetCode'),
}


class TestSpellingsReadAsOne:
    """Context validation takes the spellings JSON-LD treats as one for one
    (a node reference as an object with its id alone or as a bare IRI; a
    value and the one-entry array of it), and a value written twice is the
    same statement once, so a holder can exchange them under a valid proof;
    the model must read them as one too."""

    def test_image_given_as_a_bare_iri(self, issuer):
        priv, pub, did, vm = issuer
        badge = 'https://issuer.example/achievements/attendance.png'
        logo = 'https://issuer.example/logo.png'
        document = _credential(did).to_vc()
        _achievement(document)['image'] = {'id': badge}
        document['issuer']['image'] = {'id': logo}
        signed = add_data_integrity_proof(document, priv, vm)
        credential = OB3LdpVerifier().verify(signed)
        assert (credential.achievement.image_url, credential.issuer.image_url) == (
            badge, logo)

        respelled = copy.deepcopy(signed)                    # not signed again
        _achievement(respelled)['image'] = badge
        respelled['issuer']['image'] = logo
        verify_data_integrity_proof(respelled, pub)          # the same dataset
        credential = OB3LdpVerifier().verify(respelled)
        assert (credential.achievement.image_url, credential.issuer.image_url) == (
            badge, logo)

    def test_issuer_signed_string_image(self, issuer):
        priv, _, did, vm = issuer
        document = _credential(did).to_vc()
        document['issuer']['image'] = 'https://issuer.example/logo.png'
        credential = OB3LdpVerifier().verify(
            add_data_integrity_proof(document, priv, vm))
        assert credential.issuer.image_url == 'https://issuer.example/logo.png'

    @staticmethod
    def _shown(credential):
        return repr(replace(credential, raw=None))

    @pytest.mark.parametrize('respell', sorted(RESPELLINGS))
    def test_respelled_member_reads_the_same(self, complete, respell):
        # A value, its one-entry array and the value written twice are the
        # same statements: the holder of the Complete example re-spells a
        # member, the proof stays valid, and the model must not change.
        signed, verifier, _ = complete
        respelled = copy.deepcopy(signed)
        RESPELLINGS[respell](respelled)
        assert respelled != signed
        verify_data_integrity_proof(respelled, verifier.pubkey_pem)
        assert self._shown(verifier.verify(respelled)) == self._shown(
            verifier.verify(signed))

    def test_repeated_entry_of_a_list_is_shown_twice(self, complete):
        # Open, and exactly this: where the model reads a LIST, an entry
        # can be written twice under the same proof, and the model lists it
        # twice. Nothing is removed or altered. A scalar and a node with an
        # id repeat as they are; a node without an id only under a blank
        # node label shared by the two copies (its bare copy is a second
        # blank node, which the signature does not cover).
        signed, verifier, _ = complete
        pub = verifier.pubkey_pem
        repeated = copy.deepcopy(signed)
        _achievement(repeated)['tag'].append('research')
        repeated['evidence'].append(copy.deepcopy(repeated['evidence'][0]))
        verify_data_integrity_proof(repeated, pub)
        credential = verifier.verify(repeated)
        assert credential.achievement.tags == [
            'research', 'computer science', 'research']
        assert [e.id for e in credential.evidence] == [EVIDENCE_ID, EVIDENCE_ID]

        for find in (lambda doc: _achievement(doc)['alignment'],
                     lambda doc: doc['credentialSubject']['result'],
                     lambda doc: doc['credentialSubject']['identifier']):
            repeated = copy.deepcopy(signed)
            assert 'id' not in find(repeated)[0]
            find(repeated).append(copy.deepcopy(find(repeated)[0]))
            with pytest.raises(OB3VerificationError, match='signature mismatch'):
                verify_data_integrity_proof(repeated, pub)
            _rejected(repeated, 'signature mismatch', verifier)

        repeated = copy.deepcopy(signed)
        alignments = _achievement(repeated)['alignment']
        alignments[0]['id'] = '_:a'
        alignments.append(copy.deepcopy(alignments[0]))
        verify_data_integrity_proof(repeated, pub)
        assert len(verifier.verify(signed).achievement.alignments) == 1
        assert len(verifier.verify(repeated).achievement.alignments) == 2

    def test_every_member_the_model_reads_is_in_one_of_the_lists(self):
        # The guard: tests/test_ob3_credential.py exercises each member in
        # both spellings, by these four lists. A member the model starts
        # reading has to be put in one of them -- read as one value, read
        # as a list, read from either already, or refused as an array --
        # which is the decision this makes visible.
        from test_ob3_credential import (EITHER_ALREADY, MANY_VALUES,
                                         ONE_VALUE, REFUSED_AS_ARRAY, _rich_vc)
        reads: dict = {}
        OpenBadgeCredential.from_vc_document(_spied(_rich_vc(), (), reads))
        read = {(path, key) for path, keys in reads.items() for key in keys
                if key not in ('id', '@context')}
        listed = ONE_VALUE + MANY_VALUES + EITHER_ALREADY + REFUSED_AS_ARRAY
        assert len(set(listed)) == len(listed)
        assert read == set(listed)


# ── a blank node label where the model reads an identifier ──────────────────

PINNED_ISSUER = 'https://issuer.example/i'
UNIDENTIFIED_STATUS = {k: v for k, v in STATUS_ENTRY.items() if k != 'id'}
HASHED_IDENTITY = [IdentityObject.create('alice@example.com')]


def _first(value):
    return value[0] if isinstance(value, list) else value


# position: (the JSON object the id goes on, the id the model reports for
#            it, how the refusal names it)
ID_POSITIONS = {
    'credential': (lambda doc: doc, lambda c: c.id, 'as its id'),
    'issuer': (lambda doc: doc['issuer'], lambda c: c.issuer.id,
               'as the id of its issuer'),
    'subject': (lambda doc: _first(doc['credentialSubject']),
                lambda c: c.recipient_id, 'as the id of its credentialSubject'),
    'status': (lambda doc: _first(doc['credentialStatus']),
               lambda c: c.credential_status[0].get('id'),
               'as the id of a credentialStatus entry'),
}


def _unidentified(position):
    """An unsecured credential with no id at *position*. Its subject (a
    hashed identifier only) and its status entry never carry one, which
    OB 3.0 allows; the credential and the issuer must, so without theirs the
    model refuses it."""
    body = _credential(PINNED_ISSUER, recipient_id=None,
                       identifiers=list(HASHED_IDENTITY),
                       credential_status=[dict(UNIDENTIFIED_STATUS)]).to_vc()
    if position == 'credential':
        del body['id']
    elif position == 'issuer':
        del body['issuer']['id']
    return body


class TestBlankNodeIds:
    """A blank node label is not part of the RDF dataset: canonicalization
    relabels blank nodes, so ``"id": "_:b7"`` written on a node that was
    signed without an id leaves the signature valid, and the model read the
    label as the identifier of the credential, the issuer, the subject or a
    status entry. With eddsa-rdfc-2022 no label is accepted in those four
    positions, of the credential and of each embedded one."""

    @pytest.fixture()
    def keys(self, ed25519_keypair):
        priv, pub = ed25519_keypair
        return priv, pub, _did_vm(pub)[1], OB3LdpVerifier(pubkey_pem=pub)

    def _labelled(self, keys, position):
        priv, pub, vm, _ = keys
        signed = add_data_integrity_proof(_unidentified(position), priv, vm)
        labelled = copy.deepcopy(signed)
        ID_POSITIONS[position][0](labelled)['id'] = '_:b7'
        verify_data_integrity_proof(labelled, pub)                   # same dataset
        return signed, labelled

    def test_identifier_only_credential_verifies(self, issuer):
        priv, _, did, _ = issuer
        signed = OB3LdpSigner(priv).sign(_credential(
            did, recipient_id=None, identifiers=list(HASHED_IDENTITY),
            credential_status=[dict(UNIDENTIFIED_STATUS)]))
        for verifier in (OB3LdpVerifier(), OB3LdpVerifier.for_issuer_did(did)):
            credential = verifier.verify(signed)
            assert credential.recipient_id is None
            assert credential.credential_status == [UNIDENTIFIED_STATUS]

    @pytest.mark.parametrize('position', sorted(ID_POSITIONS))
    def test_label_added_after_signing_is_refused(self, keys, position):
        _, labelled = self._labelled(keys, position)
        match = "credential has the blank node label '_:b7' %s" % (
            ID_POSITIONS[position][2],)
        with pytest.raises(OB3VerificationError, match=match):
            _check(labelled)
        _rejected(labelled, match, keys[3])

    @pytest.mark.parametrize('position', sorted(ID_POSITIONS))
    def test_label_was_read_as_an_identifier_before_the_fix(
            self, keys, position, monkeypatch):
        # What the rule closes, pinned so the test above cannot pass for
        # another reason. Without a label the model has no id to report for
        # the subject or the status entry, and refuses a credential or an
        # issuer without one; with it, it reported the label.
        signed, labelled = self._labelled(keys, position)
        read = ID_POSITIONS[position][1]
        if position in ('credential', 'issuer'):
            _rejected(signed, 'missing required field', keys[3])
        else:
            assert read(keys[3].verify(signed)) is None
        monkeypatch.setattr(cv, '_reject_blank_node_ids', lambda *args: None)
        assert read(keys[3].verify(labelled)) == '_:b7'

    def test_expected_recipient_cannot_be_a_label(self, issuer):
        priv, pub, did, _ = issuer
        signed = OB3LdpSigner(priv).sign(_credential(
            did, recipient_id=None, identifiers=list(HASHED_IDENTITY)))
        signed['credentialSubject']['id'] = '_:b7'
        verify_data_integrity_proof(signed, pub)
        for verifier in (OB3LdpVerifier(), OB3LdpVerifier.for_issuer_did(did),
                         OB3LdpVerifier(pubkey_pem=pub)):
            _rejected(signed, 'blank node label', verifier)
            _rejected(signed, 'blank node label', verifier,
                      expected_recipient='_:b7')

    @pytest.mark.parametrize('position', ['subject', 'status'])
    def test_label_on_an_entry_of_an_array(self, keys, position):
        # [x] and x are one spelling to compaction, and the model reads the
        # first subject and every status entry of an array.
        _, labelled = self._labelled(keys, position)
        key = {'subject': 'credentialSubject', 'status': 'credentialStatus'}[position]
        labelled[key] = [labelled[key]]
        verify_data_integrity_proof(labelled, keys[1])
        _rejected(labelled, "blank node label '_:b7' %s" % ID_POSITIONS[position][2],
                  keys[3])

    @pytest.mark.parametrize('members, whose', [
        ({'@id': '_:c'}, 'as its id'),
        ({'issuer': '_:i'}, 'as the id of its issuer'),
        ({'issuer': {'@id': '_:i'}}, 'as the id of its issuer'),
        ({'issuer': [{'id': '_:i'}]}, 'as the id of its issuer'),
        ({'credentialSubject': {'@id': '_:s'}}, 'as the id of its credentialSubject'),
        ({'credentialSubject': [{'id': 'did:example:1'}, {'id': '_:s'}]},
         'as the id of its credentialSubject'),
        ({'credentialSubject': '_:s'}, 'as the id of its credentialSubject'),
        ({'credentialStatus': [dict(STATUS_ENTRY), dict(STATUS_ENTRY, id='_:e')]},
         'as the id of a credentialStatus entry'),
        ({'credentialStatus': {'@id': '_:e', 'type': 'BitstringStatusListEntry'}},
         'as the id of a credentialStatus entry'),
    ], ids=['credential-@id', 'issuer-string', 'issuer-@id', 'issuer-array',
            'subject-@id', 'subject-array', 'subject-string', 'status-array',
            'status-@id'])
    def test_every_spelling_of_the_id(self, members, whose):
        # The keyword spelling, a bare reference and an array are not the
        # compacted form or not what the model takes; refused all the same,
        # before the JSON-LD processor sees them.
        document = dict(_credential(PINNED_ISSUER).to_vc(), **members)
        with pytest.raises(OB3VerificationError,
                           match="the credential has the blank node label "
                                 "'_:[cise]' %s: " % whose):
            cv._reject_blank_node_ids(document, 'credential', False)

    def test_only_labels_in_those_positions(self):
        # An IRI that merely contains the prefix, an id that is no string
        # (the model's and the processor's to refuse), an entry nested in an
        # array (not the compacted form) and any other node are not this
        # rule's: ecdsa-sd-2023 presentations label criteria, for one.
        document = _credential('urn:_:i', id='urn:uuid:_:1',
                               credential_status=[dict(STATUS_ENTRY)]).to_vc()
        document['credentialSubject']['id'] = 7
        document['credentialSubject']['achievement']['criteria']['id'] = '_:b0'
        document['credentialStatus'] = [[dict(STATUS_ENTRY, id='_:e')]]
        document['evidence'] = [{'id': '_:b1', 'type': ['Evidence']}]
        cv._reject_blank_node_ids(document, 'credential', False)

    @pytest.mark.parametrize('position', sorted(ID_POSITIONS))
    def test_label_inside_an_embedded_endorsement(self, keys, position):
        priv, pub, vm, verifier = keys
        document = _complete_document()
        find = ID_POSITIONS[position][0]
        del find(document['endorsement'][0])['id']
        signed = add_data_integrity_proof(document, priv, vm)
        verifier.verify(signed)                       # an id is not required
        labelled = copy.deepcopy(signed)
        find(labelled['endorsement'][0])['id'] = '_:b7'
        verify_data_integrity_proof(labelled, pub)                   # same dataset
        _rejected(labelled, "endorsement at /endorsement/0 of the credential has "
                            "the blank node label '_:b7' %s"
                  % ID_POSITIONS[position][2], verifier)

    @pytest.mark.parametrize('fields, whose', [
        (dict(recipient_id='_:r'), 'as the id of its credentialSubject'),
        (dict(id='_:c'), 'as its id'),
        (dict(credential_status=[dict(STATUS_ENTRY, id='_:e')]),
         'as the id of a credentialStatus entry'),
    ], ids=['subject', 'credential', 'status'])
    def test_signer_does_not_issue_a_label(self, issuer, fields, whose):
        priv, pub, did, vm = issuer
        credential = _credential(did, **fields)
        with pytest.raises(ErrorSigningFile, match="does not cover: the credential "
                           "has the blank node label '_:[rce]' %s" % whose):
            OB3LdpSigner(priv).sign(credential)
        # The low-level signer stays schema-agnostic, and its proof verifies
        # low-level: only the dataset is at stake there.
        signed = add_data_integrity_proof(credential.to_vc(), priv, vm)
        verify_data_integrity_proof(signed, pub)
        _rejected(signed, 'blank node label')

    def test_jwt_vc_is_not_concerned(self, ob3_ed25519_signer,
                                     ob3_ed25519_verifier, ob3_credential):
        # A JWT signs its bytes: whatever id it carries is what was issued.
        token = ob3_ed25519_signer.sign(replace(ob3_credential, recipient_id='_:b7'))
        assert ob3_ed25519_verifier.verify(token).recipient_id == '_:b7'


# ── ecdsa-sd-2023: validated before the delegation; openvc version guard ────

class TestEcdsaSd:
    @pytest.fixture()
    def derived(self, ob3_credential):
        from test_ob3_ldp_ecdsa_sd import (_issue_and_derive,
                                           _lifecycle_credential,
                                           _require_ldp_sd)
        _require_ldp_sd()
        return _issue_and_derive(
            _lifecycle_credential(ob3_credential),
            selective=['/credentialSchema', '/validUntil', '/credentialStatus'])

    def test_derived_presentation_verifies(self, derived):
        document, pub, did = derived
        assert OB3LdpVerifier().verify(document).issuer.id == did
        OB3LdpVerifier(pubkey_pem=pub).verify(document)

    def test_rekeyed_member_refused_before_delegation(self, derived, monkeypatch):
        document, pub, _ = derived
        doc = copy.deepcopy(document)
        # Not a lifecycle member: hiding one of those fails even earlier.
        doc['https://schema.org/name'] = doc.pop('name')

        def delegate(*args, **kwargs):
            raise AssertionError('the delegate must not run')

        monkeypatch.setitem(ldp._CRYPTOSUITES, 'ecdsa-sd-2023', delegate)
        _rejected(doc, 'not in compacted form', OB3LdpVerifier(pubkey_pem=pub))

    @pytest.mark.parametrize('version', ['1.33.1', '1.33.0', '1.30.2', '0.9', 'dev', None])
    def test_old_openvc_fails_closed(self, derived, monkeypatch, version):
        import openvc
        monkeypatch.setattr(openvc, '__version__', version, raising=False)
        with pytest.raises(OB3VerificationError, match=r'openvc-core >= 1\.33\.2'):
            ldp._require_openvc_ecdsa_sd()
        document, pub, _ = derived
        _rejected(document, r'openvc-core >= 1\.33\.2', OB3LdpVerifier(pubkey_pem=pub))

    def test_missing_openvc_version_fails_closed(self, derived, monkeypatch):
        import openvc
        monkeypatch.delattr(openvc, '__version__')
        with pytest.raises(OB3VerificationError, match=r'openvc-core >= 1\.33\.2'):
            ldp._require_openvc_ecdsa_sd()

    @pytest.mark.parametrize('version', ['1.33.2', '1.34.0', '2.0.0rc1'])
    def test_supported_openvc_accepted(self, derived, monkeypatch, version):
        import openvc
        monkeypatch.setattr(openvc, '__version__', version)
        ldp._require_openvc_ecdsa_sd()


class TestEcdsaSdPartialStatus:
    """Selective disclosure lets a holder reveal any subset of what the issuer
    left non-mandatory, and no verifier can count what was withheld. With
    credentialStatus selective, revealing one entry of two (the clear one),
    or an entry without its statusSize, passed the #328 key check and the
    status check. Disclosed lifecycle statements must be mandatory."""

    @pytest.fixture(autouse=True)
    def _sd(self):
        from test_ob3_ldp_ecdsa_sd import _require_ldp_sd
        _require_ldp_sd()

    @staticmethod
    def _issue(credential, selective, lax):
        from test_ob3_ldp_ecdsa_sd import LAX_MANDATORY, _issue_and_derive
        return _issue_and_derive(credential, selective=selective,
                                 mandatory=LAX_MANDATORY if lax else None)

    def test_withheld_status_entry_is_refused(self, ob3_credential, monkeypatch):
        import openvc.proof.ecdsa_sd as sd
        clear = dict(STATUS_ENTRY, id='https://issuer.example/status/1#3',
                     statusListIndex='3')
        revoked = dict(STATUS_ENTRY, id='https://issuer.example/status/2#5',
                       statusListCredential='https://issuer.example/status/2')
        credential = replace(ob3_credential,
                             expiration_date=datetime(2030, 1, 1, tzinfo=UTC),
                             credential_status=[clear, revoked])
        download = _status_lists({clear['statusListCredential']: [],
                                  revoked['statusListCredential']: [5]})
        # control: an issuer that makes status mandatory, so it is all shown
        full, pub, _ = self._issue(credential, [], lax=False)
        assert len(full['credentialStatus']) == 2
        _rejected(full, "'revocation' is set at index 5", OB3LdpVerifier(pubkey_pem=pub),
                  check_status=True, download=download, verify_status_list=False)

        # ecdsa-sd-2023 selects with JSON pointers, array indexes included;
        # openvc's derive helper lacks them, so the holder side is patched
        # (the verifier never sees the pointers).
        original = sd._select_path

        def select(tokens, source, selection):
            if len(tokens) == 2 and tokens[1].isdigit():
                selection.setdefault(tokens[0], []).append(
                    copy.deepcopy(source[tokens[0]][int(tokens[1])]))
                return None
            return original(tokens, source, selection)

        monkeypatch.setattr(sd, '_select_path', select)
        document, pub, _ = self._issue(
            credential, ['/validUntil', '/credentialStatus/0'], lax=True)
        assert [e['id'] for e in document['credentialStatus']] == [clear['id']]
        verify_data_integrity_proof(document, pub)
        for verifier in (OB3LdpVerifier(), OB3LdpVerifier(pubkey_pem=pub)):
            _rejected(document, 'credentialStatus statements its issuer did not '
                      'make mandatory', verifier, check_status=True,
                      download=download, verify_status_list=False)

    def test_withheld_status_size_is_refused(self, ob3_credential):
        entry = dict(STATUS_ENTRY, statusSize=2)
        credential = replace(ob3_credential,
                             expiration_date=datetime(2030, 1, 1, tzinfo=UTC),
                             credential_status=[entry])
        download = _status_lists({entry['statusListCredential']: [10, 11]})
        members = ['/credentialStatus/%s' % member for member in (
            'type', 'statusPurpose', 'statusListIndex', 'statusListCredential')]
        # control: with status mandatory the holder cannot leave statusSize out
        full, pub, _ = self._issue(credential, members, lax=False)
        assert full['credentialStatus']['statusSize'] == 2
        _rejected(full, 'unsupported statusSize', OB3LdpVerifier(pubkey_pem=pub),
                  check_status=True, download=download, verify_status_list=False)

        document, pub, _ = self._issue(credential, ['/validUntil'] + members, lax=True)
        assert 'statusSize' not in document['credentialStatus']
        verify_data_integrity_proof(document, pub)
        for verifier in (OB3LdpVerifier(), OB3LdpVerifier(pubkey_pem=pub)):
            _rejected(document, 'credentialStatus statements its issuer did not '
                      'make mandatory', verifier, check_status=True,
                      download=download, verify_status_list=False)

    def test_mandatory_statements_are_those_openvc_verified(self, ob3_credential):
        # The check indexes the disclosed statements with openvc's own
        # helpers: a view whose non-mandatory count differs from the
        # signatures the delegate verified fails closed.
        from test_ob3_ldp_ecdsa_sd import _lifecycle_credential
        document, _, _ = self._issue(_lifecycle_credential(ob3_credential),
                                     ['/credentialSchema'], lax=False)
        statements, mandatory = ldp._sd_disclosed_statements(document, document['proof'])
        assert mandatory and len(mandatory) < len(statements)
        forged = {k: v for k, v in document.items() if k != 'credentialSchema'}
        with pytest.raises(OB3VerificationError, match='do not match'):
            ldp._sd_disclosed_statements(forged, forged['proof'])

    def test_openvc_without_the_helpers_fails_closed(self, ob3_credential, monkeypatch):
        import openvc.proof.ecdsa_sd as sd
        from test_ob3_ldp_ecdsa_sd import _lifecycle_credential
        document, pub, _ = self._issue(_lifecycle_credential(ob3_credential), [], lax=False)
        OB3LdpVerifier(pubkey_pem=pub).verify(document)
        monkeypatch.delattr(sd, '_relabel')
        with pytest.raises(OB3VerificationError, match='does not expose'):
            ldp._sd_disclosed_statements(document, document['proof'])

    def test_credential_without_an_iri_id_fails_closed(self, ob3_credential, monkeypatch):
        from test_ob3_ldp_ecdsa_sd import _lifecycle_credential
        document, _, _ = self._issue(_lifecycle_credential(ob3_credential), [], lax=False)
        statements, mandatory = ldp._sd_disclosed_statements(document, document['proof'])
        monkeypatch.setattr(ldp, '_sd_disclosed_statements',
                            lambda doc, proof, lines=None: (statements, mandatory))
        doc = dict(document, id='_:b0')
        with pytest.raises(OB3VerificationError, match='cannot find the statements'):
            ldp._reject_selective_sd_lifecycle(doc, doc['proof'])


class TestEcdsaSdBlankNodeIds:
    """openvc-core's derive writes a blank node label on every node of a
    presentation that has no id (criteria, in every one of them), so with
    ecdsa-sd-2023 a label is refused only where OB 3.0 requires an id, the
    credential and the issuer: on a subject or a status entry, whose id is
    optional, it is the delegate's own."""

    @pytest.fixture(autouse=True)
    def _sd(self):
        from test_ob3_ldp_ecdsa_sd import _require_ldp_sd
        _require_ldp_sd()

    @staticmethod
    def _derived(ob3_credential, **fields):
        from test_ob3_ldp_ecdsa_sd import (_issue_and_derive,
                                           _lifecycle_credential)
        return _issue_and_derive(
            replace(_lifecycle_credential(ob3_credential), **fields), selective=[])

    def test_presentation_of_a_status_entry_without_id_verifies(self, ob3_credential):
        document, pub, did = self._derived(
            ob3_credential, credential_status=[dict(UNIDENTIFIED_STATUS)])
        # The premise: if the delegate stops labelling, the exemption can go.
        assert document['credentialStatus']['id'].startswith('_:')
        assert document['credentialSubject']['achievement']['criteria'][
            'id'].startswith('_:')
        for verifier in (OB3LdpVerifier(), OB3LdpVerifier(pubkey_pem=pub)):
            assert verifier.verify(document).issuer.id == did
        # The same JSON under eddsa-rdfc-2022, whose signers write no label.
        with pytest.raises(OB3VerificationError, match='blank node label'):
            cv._reject_blank_node_ids(document, 'credential', False)

    @pytest.mark.parametrize('position', ['credential', 'issuer'])
    def test_label_where_an_id_is_required_is_refused(
            self, ob3_credential, monkeypatch, position):
        document, pub, _ = self._derived(ob3_credential)
        doc = copy.deepcopy(document)
        ID_POSITIONS[position][0](doc)['id'] = '_:b7'

        def delegate(*args, **kwargs):
            raise AssertionError('the delegate must not run')

        monkeypatch.setitem(ldp._CRYPTOSUITES, 'ecdsa-sd-2023', delegate)
        _rejected(doc, "credential has the blank node label '_:b7' %s"
                  % ID_POSITIONS[position][2], OB3LdpVerifier(pubkey_pem=pub))
