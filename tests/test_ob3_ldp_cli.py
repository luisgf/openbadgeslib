"""End-to-end CLI tests for Data Integrity (LDP) badges — openbadges-verifier.

Signing fixtures need pyld; the extra-absent test at the bottom runs always.
"""
import json
import sys
from unittest.mock import patch

import pytest

from openbadgeslib import openbadges_verifier
from openbadgeslib import baking

from ldp_helpers import b58encode, did_key, sign_ldp

RECIPIENT = 'recipient@example.com'


def _run(argv, capsys):
    with patch.object(sys, 'argv', argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_verifier.main()
    out = capsys.readouterr().out
    return exc.value.code, json.loads(out)


def _ldp_document(ob3_credential, pub_pem):
    doc = ob3_credential.to_vc()
    doc['issuer'] = {'id': did_key(pub_pem), 'type': ['Profile'],
                     'name': 'Test Issuer'}
    return doc


def _bake(tmp_path, document, svg_image, *, fmt='svg', png_image=None):
    text = json.dumps(document)
    if fmt == 'svg':
        baked = baking.bake_svg(svg_image, text,
                                element=baking.SVG_ELEMENT_OB3,
                                namespace=baking.SVG_NS_OB3, as_text=True)
    else:
        baked = baking.bake_png(png_image, text,
                                keyword=baking.ITXT_KEYWORD_OB3)
    badge = tmp_path / ('badge.%s' % fmt)
    badge.write_bytes(baked)
    return badge


@pytest.fixture()
def ldp_badge(tmp_path, ob3_credential, ed25519_keypair, svg_image):
    pytest.importorskip('pyld')
    priv_pem, pub_pem = ed25519_keypair
    signed = sign_ldp(_ldp_document(ob3_credential, pub_pem), priv_pem, pub_pem)
    return _bake(tmp_path, signed, svg_image)


class TestLdpCli:
    def test_pinned_key_valid_and_trusted(self, ldp_badge, tmp_path,
                                          ed25519_pub_pem, capsys):
        pub = tmp_path / 'verify.pem'
        pub.write_bytes(ed25519_pub_pem)
        code, result = _run(['openbadges-verifier', '-i', str(ldp_badge),
                             '-r', RECIPIENT, '-V', '3', '-k', str(pub),
                             '--json'], capsys)
        assert code == 0
        assert result['valid'] is True and result['trusted'] is True
        assert result['proof_format'] == 'ldp'
        assert result['achievement'] == 'Test Achievement'

    def test_png_carrier(self, tmp_path, ob3_credential, ed25519_keypair,
                         png_image, capsys):
        pytest.importorskip('pyld')
        priv_pem, pub_pem = ed25519_keypair
        signed = sign_ldp(_ldp_document(ob3_credential, pub_pem),
                          priv_pem, pub_pem)
        badge = _bake(tmp_path, signed, None, fmt='png', png_image=png_image)
        pub = tmp_path / 'verify.pem'
        pub.write_bytes(pub_pem)
        code, result = _run(['openbadges-verifier', '-i', str(badge),
                             '-r', RECIPIENT, '-V', '3', '-k', str(pub),
                             '--json'], capsys)
        assert code == 0 and result['proof_format'] == 'ldp'

    def test_resolve_did_key_is_untrusted(self, ldp_badge, capsys):
        code, result = _run(['openbadges-verifier', '-i', str(ldp_badge),
                             '-r', RECIPIENT, '-V', '3', '--resolve-did',
                             '--json'], capsys)
        assert code == 2                       # valid but self-asserted key
        assert result['valid'] is True and result['trusted'] is False
        assert result['issuer_did'].startswith('did:key:')
        assert result['proof_format'] == 'ldp'

    def test_tampered_document_fails(self, tmp_path, ob3_credential,
                                     ed25519_keypair, svg_image, capsys):
        pytest.importorskip('pyld')
        priv_pem, pub_pem = ed25519_keypair
        signed = sign_ldp(_ldp_document(ob3_credential, pub_pem),
                          priv_pem, pub_pem)
        signed['credentialSubject']['id'] = 'mailto:attacker@example.com'
        badge = _bake(tmp_path, signed, svg_image)
        pub = tmp_path / 'verify.pem'
        pub.write_bytes(pub_pem)
        code, result = _run(['openbadges-verifier', '-i', str(badge),
                             '-r', 'attacker@example.com', '-V', '3',
                             '-k', str(pub), '--json'], capsys)
        assert code == 1 and result['valid'] is False

    def test_gate_without_key_or_flag(self, ldp_badge, capsys):
        code, result = _run(['openbadges-verifier', '-i', str(ldp_badge),
                             '-r', RECIPIENT, '-V', '3', '--json'], capsys)
        assert code == 1
        assert '--resolve-did' in result['reason']

    def test_jwt_badge_reports_vc_jwt_format(self, tmp_path, rsa_priv_pem,
                                             rsa_pub_pem, svg_image, capsys):
        # Regression: the JWT path must now report its proof_format too.
        from openbadgeslib.ob3 import (Achievement, Issuer, OB3Signer,
                                       OpenBadgeCredential)
        cred = OpenBadgeCredential(
            issuer=Issuer(id='https://example.com/issuer', name='Issuer'),
            recipient_id='mailto:' + RECIPIENT,
            achievement=Achievement(id='https://example.com/a', name='A',
                                    description='d', criteria_narrative='c'))
        signer = OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')
        badge = tmp_path / 'jwt.svg'
        badge.write_bytes(signer.sign_into_svg(cred, svg_image))
        pub = tmp_path / 'verify.pem'
        pub.write_bytes(rsa_pub_pem)
        code, result = _run(['openbadges-verifier', '-i', str(badge),
                             '-r', RECIPIENT, '-V', '3', '-k', str(pub),
                             '--json'], capsys)
        assert code == 0 and result['proof_format'] == 'vc-jwt'


class TestLdpCliExtraAbsent:
    def test_missing_pyld_reports_install_hint(self, tmp_path, svg_image,
                                               ed25519_pub_pem, monkeypatch,
                                               capsys):
        # Hand-built (unverifiable) LDP document: the flow must reach the
        # lazy pyld import and surface the actionable hint — without pyld.
        monkeypatch.setitem(sys.modules, 'pyld', None)
        doc = {'@context': [
                   'https://www.w3.org/ns/credentials/v2',
                   'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'],
               'id': 'urn:uuid:x',
               'type': ['VerifiableCredential', 'OpenBadgeCredential'],
               'issuer': {'id': 'did:web:i.example', 'name': 'I'},
               'validFrom': '2026-01-01T00:00:00Z',
               'credentialSubject': {
                   'id': 'mailto:' + RECIPIENT,
                   'type': ['AchievementSubject'],
                   'achievement': {'id': 'https://a.example/1', 'name': 'A',
                                   'type': ['Achievement'], 'description': 'd',
                                   'criteria': {'narrative': 'c'}}},
               'proof': {'type': 'DataIntegrityProof',
                         'cryptosuite': 'eddsa-rdfc-2022',
                         'proofPurpose': 'assertionMethod',
                         'verificationMethod': 'did:web:i.example#k',
                         'proofValue': 'z' + b58encode(b'\x01' * 64)}}
        badge = _bake(tmp_path, doc, svg_image)
        pub = tmp_path / 'verify.pem'
        pub.write_bytes(ed25519_pub_pem)
        code, result = _run(['openbadges-verifier', '-i', str(badge),
                             '-r', RECIPIENT, '-V', '3', '-k', str(pub),
                             '--json'], capsys)
        assert code == 1
        assert 'pip install openbadgeslib[ldp]' in result['reason']
