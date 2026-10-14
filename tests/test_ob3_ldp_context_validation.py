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
from datetime import datetime, timezone
from pathlib import Path

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
    did:key, or a signer that emits the shape) over an out-of-policy value."""

    SPELLINGS = {
        'iri': (None, lambda field: VC + field),
        'iri-with-vocab': (VC, lambda field: VC + field),
        'vocab-suffix': (VC + 'valid', lambda field: field[len('valid'):]),
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

        vocab, spell = self.SPELLINGS[spelling]
        if vocab:
            body['@context'] = list(body['@context']) + [{'@vocab': vocab}]
        body[spell(field)] = body.pop(field)
        doc = add_data_integrity_proof(body, priv, vm)
        verify_data_integrity_proof(doc, pub)
        with pytest.raises(OB3VerificationError, match='spells a property'):
            _check(doc)                       # the signer guard's check, too
        _rejected(doc, 'credential spells a property', verifier)

    def test_language_tagged_date(self, issuer):
        priv, _, did, vm = issuer
        body = _credential(did, expiration_date=datetime(2021, 1, 1, tzinfo=UTC)).to_vc()
        body[VC + 'validUntil'] = {'@value': body.pop('validUntil'), '@language': 'en'}
        _rejected(add_data_integrity_proof(body, priv, vm), 'spells a property')

    @pytest.mark.parametrize('vocab, key', [
        (None, SEC + 'expiration'),
        (SEC + 'expira', 'tion'),
    ], ids=['iri', 'vocab-suffix'])
    @pytest.mark.parametrize('pinned', [False, True], ids=['did', 'pinned'])
    def test_expired_proof(self, issuer, pinned, vocab, key):
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
        _rejected(doc, 'the proof spells a property', verifier)

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

    def test_nested_context(self, expired):
        doc = self._doc(expired)
        doc['credentialSubject']['@context'] = list(doc['@context'])
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

    def test_relative_inline_vocab(self, expired):
        doc = self._doc(expired)
        doc['@context'] = list(doc['@context']) + [{'@vocab': 'relative/'}]
        _rejected(doc, 'absolute IRI')

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

    def test_inline_absolute_vocab_is_tolerated(self, issuer):
        # An inline {"@vocab": <absolute IRI>} can neither alias, re-map nor
        # drop a defined term, so appending one changes nothing signed.
        priv, _, did, _ = issuer
        doc = OB3LdpSigner(priv).sign(_credential(did))
        doc['@context'] = list(doc['@context']) + [{'@vocab': 'https://example.org/v#'}]
        OB3LdpVerifier().verify(doc)


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

    def test_embedded_credentials_nest_too_deeply(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        holder = doc['issuer']['endorsement'][0]
        for level in range(cv._MAX_EMBEDDED_DEPTH + 1):
            inner = _endorsement(100 + level)
            holder['issuer'] = {
                'id': 'https://accreditor.example/issuers/%d' % level,
                'type': ['Profile'], 'name': 'Accreditor', 'endorsement': [inner]}
            holder = inner
        _rejected(doc, 'nests embedded credentials too deeply', verifier)

    def test_endorsement_literal_entry(self, complete):
        signed, verifier, _ = complete
        doc = copy.deepcopy(signed)
        doc['endorsement'] = ['https://elsewhere.example/endorsement/1']
        _rejected(doc, 'compacted form', verifier)


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
        doc[VC + 'validFrom'] = {'@value': doc.pop('validFrom'),
                                 '@type': XSD_DATETIME}

        def delegate(*args, **kwargs):
            raise AssertionError('the delegate must not run')

        monkeypatch.setitem(ldp._CRYPTOSUITES, 'ecdsa-sd-2023', delegate)
        _rejected(doc, 'not in compacted form', OB3LdpVerifier(pubkey_pem=pub))

    @pytest.mark.parametrize('version', ['1.30.1', '1.29.9', '0.9', 'dev', None])
    def test_old_openvc_fails_closed(self, derived, monkeypatch, version):
        import openvc
        monkeypatch.setattr(openvc, '__version__', version, raising=False)
        with pytest.raises(OB3VerificationError, match=r'openvc-core >= 1\.30\.2'):
            ldp._require_openvc_ecdsa_sd()
        document, pub, _ = derived
        _rejected(document, r'openvc-core >= 1\.30\.2', OB3LdpVerifier(pubkey_pem=pub))

    def test_missing_openvc_version_fails_closed(self, derived, monkeypatch):
        import openvc
        monkeypatch.delattr(openvc, '__version__')
        with pytest.raises(OB3VerificationError, match=r'openvc-core >= 1\.30\.2'):
            ldp._require_openvc_ecdsa_sd()

    @pytest.mark.parametrize('version', ['1.30.2', '1.31.3', '2.0.0rc1'])
    def test_supported_openvc_accepted(self, derived, monkeypatch, version):
        import openvc
        monkeypatch.setattr(openvc, '__version__', version)
        ldp._require_openvc_ecdsa_sd()
