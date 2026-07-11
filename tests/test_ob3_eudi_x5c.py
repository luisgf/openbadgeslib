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
# Leaf windows that must land on the wrong side of "now" (the boundary tests).
_EXPIRED = dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc)    # not_after in the past
_NOT_YET = dt.datetime(2034, 1, 1, tzinfo=dt.timezone.utc)    # not_before in the future


def _chain(*, leaf_not_before=_PAST, leaf_not_after=_FUTURE, leaf_crldp=False):
    """Build a root -> intermediate -> leaf chain (leaf SAN = ISS). Returns the
    x5c list [leaf, inter] (DER-base64), the root cert, and the leaf key.

    The leaf's validity window and an optional CRL Distribution Point are
    parametrised for the trust-boundary tests (#236)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def cert(subject, issuer, issuer_key, subject_key, *, ca, san=None,
             not_before=_PAST, not_after=_FUTURE, crldp=False):
        builder = (x509.CertificateBuilder()
                   .subject_name(name(subject)).issuer_name(name(issuer))
                   .public_key(subject_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(not_before).not_valid_after(not_after)
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
        if crldp:
            builder = builder.add_extension(x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        'http://crl.example/leaf.crl')],
                    relative_name=None, reasons=None, crl_issuer=None)]),
                critical=False)
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
                san=[x509.UniformResourceIdentifier(ISS)],
                not_before=leaf_not_before, not_after=leaf_not_after,
                crldp=leaf_crldp)
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

    def test_issue_with_x5c_then_verify_closes_the_loop(self):
        # openvc-core >=1.18 lets issue_badge_sd_jwt embed the x5c chain, so a
        # badge is issued anchored on X.509 and verified in one call — the
        # issue-side counterpart of test_trusted_anchor_verifies_and_binds_issuer.
        from cryptography.hazmat.primitives import serialization
        from openbadgeslib.ob3 import (Achievement, Issuer,
                                       OpenBadgeCredential)
        from openbadgeslib.ob3.eudi import (_issuer_jwt_has_x5c,
                                            issue_badge_sd_jwt)
        x5c, root, leaf_key = _chain()
        leaf_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        cred = OpenBadgeCredential(
            issuer=Issuer(id=ISS, name='Issuer'),
            recipient_id='mailto:r@example.com',
            achievement=Achievement(id='https://a.example/1', name='A',
                                    description='d', criteria_narrative='c'))
        token = issue_badge_sd_jwt(cred, privkey_pem=leaf_pem, x5c=x5c)
        assert _issuer_jwt_has_x5c(token)                   # x5c embedded on issue
        result = verify_badge_sd_jwt(token, x5c_trust_anchors=[root])
        assert result.issuer == ISS                         # verified via anchor


class TestX5cTrustBoundary:
    """Pin the X.509 / eIDAS trust decisions openvc-core owns, and document the
    revocation gap (#236). These assertions run against BOTH the pinned floor
    and the latest openvc-core in the `eudi` CI drift job, so a change in the
    delegate's chain-validation behaviour turns that job red. See the
    'X.509 / eIDAS trust boundary' section of verify_badge_sd_jwt's docstring.
    """

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip('openvc')

    def test_expired_leaf_is_rejected(self):
        # Temporal validity IS enforced by openvc-core (cryptography's
        # PolicyBuilder .time()): a leaf whose window has closed is refused.
        x5c, root, leaf_key = _chain(leaf_not_after=_EXPIRED)
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(_sd_jwt_with_x5c(leaf_key, x5c),
                                x5c_trust_anchors=[root])

    def test_not_yet_valid_leaf_is_rejected(self):
        x5c, root, leaf_key = _chain(leaf_not_before=_NOT_YET)
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(_sd_jwt_with_x5c(leaf_key, x5c),
                                x5c_trust_anchors=[root])

    def test_revocation_is_not_consulted(self):
        # KNOWN GAP (#236): certificate revocation (CRL / OCSP) is NOT checked —
        # cryptography's path validation ignores CRL Distribution Points and does
        # no OCSP. A leaf that carries a CRLDP (the marker of a revocable cert),
        # is otherwise valid and still inside its window, therefore VERIFIES.
        # Deployments that must honour revocation obtain it out of band. If a
        # future openvc-core starts enforcing revocation this assertion flips,
        # and the floor/latest drift job surfaces it for a contract/doc update.
        x5c, root, leaf_key = _chain(leaf_crldp=True)
        result = verify_badge_sd_jwt(_sd_jwt_with_x5c(leaf_key, x5c),
                                     x5c_trust_anchors=[root])
        assert result.issuer == ISS   # verified despite the revocation pointer


def test_x5c_path_needs_the_extra(monkeypatch):
    for name in ('openvc', 'openvc.keys', 'openvc.proof.sd_jwt'):
        monkeypatch.setitem(sys.modules, name, None)
    with pytest.raises(EudiError, match=r'openbadgeslib\[eudi\]'):
        verify_badge_sd_jwt('x~', x5c_trust_anchors=['anchor'])
