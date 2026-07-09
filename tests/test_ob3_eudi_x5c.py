"""Tests for opt-in X.509 / EU Trusted List trust anchoring in
verify_badge_sd_jwt (the EUDI SD-JWT track, #178).

A received third-party badge whose issuer JWT carries an `x5c` chain is verified
by routing through openvc-core's verify_credential pipeline, which path-validates
the chain to the caller's trust anchors (e.g. an EU Trusted List's
TrustAnchorSet.certificates) and binds it to `iss`. The crypto needs the [eudi]
extra and skips without it; the "extra absent" test runs always.
"""
import base64
import datetime as dt
import sys
import time

import pytest

from openbadgeslib.ob3.eudi import (OB3_SD_JWT_VCT, EudiError,
                                    verify_badge_sd_jwt)

ISS = 'https://issuer.example'
_PAST = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
_FUTURE = dt.datetime(2035, 1, 1, tzinfo=dt.timezone.utc)


def _chain():
    """Build a root -> intermediate -> leaf chain (leaf SAN = ISS). Returns the
    x5c list [leaf, inter] (DER-base64), the root cert, and the leaf key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def cert(subject, issuer, issuer_key, subject_key, *, ca, san=None):
        builder = (x509.CertificateBuilder()
                   .subject_name(name(subject)).issuer_name(name(issuer))
                   .public_key(subject_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(_PAST).not_valid_after(_FUTURE)
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                                  critical=True))
        if ca:
            builder = builder.add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
        if san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san), critical=False)
        return builder.sign(issuer_key, hashes.SHA256())

    def der_b64(crt):
        return base64.b64encode(
            crt.public_bytes(serialization.Encoding.DER)).decode('ascii')

    root_key = ec.generate_private_key(ec.SECP256R1())
    root = cert('root', 'root', root_key, root_key, ca=True)
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = cert('inter', 'root', root_key, inter_key, ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = cert('leaf', 'inter', inter_key, leaf_key, ca=False,
                san=[x509.UniformResourceIdentifier(ISS)])
    return [der_b64(leaf), der_b64(inter)], root, leaf_key


def _sd_jwt_with_x5c(leaf_key, x5c, *, iss=ISS, vct=OB3_SD_JWT_VCT):
    """A minimal badge SD-JWT (no disclosures) whose issuer JWT carries *x5c*."""
    from openvc.keys import P256SigningKey
    from openvc.proof._jws import sign_compact
    header = {'alg': 'ES256', 'typ': 'dc+sd-jwt', 'kid': 'leaf',
              'x5c': list(x5c)}
    payload = {'iss': iss, 'vct': vct, 'iat': int(time.time()),
               'name': 'Python 101',
               'achievement': {'id': 'https://ex/b/1', 'name': 'Python 101'}}
    return sign_compact(
        header, payload, signing_key=P256SigningKey(leaf_key, kid='leaf')) + '~'


class TestX5cTrust:
    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip('openvc')

    def test_trusted_anchor_verifies_and_binds_issuer(self):
        x5c, root, leaf_key = _chain()
        result = verify_badge_sd_jwt(
            _sd_jwt_with_x5c(leaf_key, x5c), x5c_trust_anchors=[root])
        assert result.issuer == ISS
        assert result.vct == OB3_SD_JWT_VCT

    def test_untrusted_anchor_rejected(self):
        x5c, _root, leaf_key = _chain()
        unrelated_root = _chain()[1]
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(_sd_jwt_with_x5c(leaf_key, x5c),
                                x5c_trust_anchors=[unrelated_root])

    def test_tampered_signature_rejected(self):
        x5c, root, leaf_key = _chain()
        jwt_part, sep, rest = _sd_jwt_with_x5c(leaf_key, x5c).partition('~')
        head, payload, sig = jwt_part.split('.')
        sig = ('A' if sig[0] != 'A' else 'B') + sig[1:]     # break the signature
        with pytest.raises(EudiError):
            verify_badge_sd_jwt('.'.join([head, payload, sig]) + sep + rest,
                                x5c_trust_anchors=[root])

    def test_neither_pubkey_nor_anchors_is_rejected(self):
        x5c, _root, leaf_key = _chain()
        with pytest.raises(EudiError, match='pubkey_pem'):
            verify_badge_sd_jwt(_sd_jwt_with_x5c(leaf_key, x5c))

    def test_no_x5c_header_rejected_even_with_anchors(self):
        # An attacker omits the x5c header and self-certifies via did:jwk. The
        # x5c anchors must NOT be bypassed by falling back to DID resolution:
        # without this guard the forged badge would verify against its own key.
        import json

        from cryptography.hazmat.primitives.asymmetric import ec
        from openvc.keys import P256SigningKey
        from openvc.proof._jws import sign_compact

        _x5c, root, _leaf = _chain()

        def b64u(b):
            return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

        atk = ec.generate_private_key(ec.SECP256R1())
        nums = atk.public_key().public_numbers()
        jwk = {'kty': 'EC', 'crv': 'P-256',
               'x': b64u(nums.x.to_bytes(32, 'big')),
               'y': b64u(nums.y.to_bytes(32, 'big'))}
        did = 'did:jwk:' + b64u(json.dumps(jwk, separators=(',', ':')).encode())
        header = {'alg': 'ES256', 'typ': 'dc+sd-jwt', 'kid': did + '#0'}  # no x5c
        payload = {'iss': did, 'vct': OB3_SD_JWT_VCT, 'iat': int(time.time()),
                   'name': 'Forged',
                   'achievement': {'id': 'https://ex/x', 'name': 'Forged'}}
        forged = sign_compact(
            header, payload,
            signing_key=P256SigningKey(atk, kid=did + '#0')) + '~'
        with pytest.raises(EudiError, match='x5c'):
            verify_badge_sd_jwt(forged, x5c_trust_anchors=[root])


def test_x5c_path_needs_the_extra(monkeypatch):
    for name in ('openvc', 'openvc.keys', 'openvc.proof.sd_jwt'):
        monkeypatch.setitem(sys.modules, name, None)
    with pytest.raises(EudiError, match=r'openbadgeslib\[eudi\]'):
        verify_badge_sd_jwt('x~', x5c_trust_anchors=['anchor'])
