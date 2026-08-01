"""Tests for the OID4VCI config surface and the identity primitives it needs.

Covers openbadgeslib.confparser.oid4vci_config / oid4vci_formats, plus
ob3.did.did_jwk_from_jwk and ob3.credential.IdentityObject.create — the pieces
that hold a wallet-issued credential's subject binding together.
"""
import base64
import json
import os

import pytest

from openbadgeslib.confparser import (OID4VCIConfig, load_config,
                                      oid4vci_config, oid4vci_formats)
from openbadgeslib.errors import ConfigError
from openbadgeslib.ob3 import IdentityObject
from openbadgeslib.ob3.did import did_jwk_from_jwk
from openbadgeslib.oid4vci import FORMAT_JWT_VC_JSON, FORMAT_SD_JWT_VC

_BASE = """\
[paths]
base = %(base)s

[issuer]
name = Test Issuer
url = https://www.issuer.example
publish_url = https://openbadges.issuer.example/issuer/

[badge_1]
name = Badge 1
description = A badge
badge = https://www.issuer.example/badge_1/badge.json
key_type = %(key_type)s
%(badge_extra)s
%(oid4vci)s
"""


def _config(tmp_path, *, key_type='ED25519', badge_extra='', oid4vci=''):
    text = _BASE % {'base': str(tmp_path), 'key_type': key_type,
                    'badge_extra': badge_extra, 'oid4vci': oid4vci}
    path = tmp_path / 'config.ini'
    path.write_text(text)
    return load_config(str(path))


class TestOID4VCIConfigDefaults:
    def test_absent_section_resolves_entirely_from_issuer(self, tmp_path):
        # The common deployment writes no [oid4vci] keys at all.
        cfg = oid4vci_config(_config(tmp_path))
        assert isinstance(cfg, OID4VCIConfig)
        assert cfg.credential_issuer == 'https://openbadges.issuer.example/issuer/'
        assert cfg.credential_endpoint == \
            'https://openbadges.issuer.example/issuer/credential'
        assert cfg.nonce_endpoint == \
            'https://openbadges.issuer.example/issuer/nonce'
        assert cfg.token_endpoint == \
            'https://openbadges.issuer.example/issuer/token'
        assert cfg.offer_ttl_s == 600
        assert cfg.nonce_ttl_s == 120
        assert cfg.token_ttl_s == 300
        assert cfg.proof_max_age_s == 300
        assert cfg.batch_size == 1
        assert cfg.tx_code_length == 6
        assert cfg.tx_code_input_mode == 'numeric'
        assert cfg.store_path == os.path.join(str(tmp_path), 'oid4vci.sqlite3')

    def test_issuer_without_trailing_slash_still_appends(self, tmp_path):
        # urljoin replaces the last path segment when the base has no trailing
        # slash: an issuer at /vci would otherwise derive /credential.
        conf = _config(tmp_path, oid4vci='[oid4vci]\n'
                       'credential_issuer = https://issuer.example/vci\n')
        cfg = oid4vci_config(conf)
        assert cfg.credential_endpoint == 'https://issuer.example/vci/credential'
        assert cfg.token_endpoint == 'https://issuer.example/vci/token'
        # The identifier itself keeps the operator's exact spelling: it is what
        # wallet key proofs bind their 'aud' to.
        assert cfg.credential_issuer == 'https://issuer.example/vci'

    def test_explicit_endpoints_win_over_derivation(self, tmp_path):
        conf = _config(tmp_path, oid4vci=(
            '[oid4vci]\n'
            'credential_endpoint = https://other.example/c\n'))
        cfg = oid4vci_config(conf)
        assert cfg.credential_endpoint == 'https://other.example/c'
        assert cfg.nonce_endpoint == \
            'https://openbadges.issuer.example/issuer/nonce'

    def test_lifetimes_are_read(self, tmp_path):
        conf = _config(tmp_path, oid4vci=(
            '[oid4vci]\noffer_ttl_s = 60\nnonce_ttl_s = 30\n'
            'token_ttl_s = 45\nproof_max_age_s = 90\nbatch_size = 4\n'
            'tx_code_length = 8\ntx_code_input_mode = text\n'))
        cfg = oid4vci_config(conf)
        assert (cfg.offer_ttl_s, cfg.nonce_ttl_s, cfg.token_ttl_s) == (60, 30, 45)
        assert cfg.proof_max_age_s == 90
        assert cfg.batch_size == 4
        assert (cfg.tx_code_length, cfg.tx_code_input_mode) == (8, 'text')


class TestOID4VCIConfigRejections:
    def test_plaintext_http_issuer_is_refused(self, tmp_path):
        conf = _config(tmp_path, oid4vci='[oid4vci]\n'
                       'credential_issuer = http://issuer.example/\n')
        with pytest.raises(ConfigError, match='must be an https URL'):
            oid4vci_config(conf)

    def test_no_base_to_derive_from_is_refused(self, tmp_path):
        path = tmp_path / 'config.ini'
        path.write_text('[paths]\nbase = %s\n\n[issuer]\nname = X\n'
                        % str(tmp_path))
        with pytest.raises(ConfigError, match='needs a credential_issuer'):
            oid4vci_config(load_config(str(path)))

    @pytest.mark.parametrize('key', ['offer_ttl_s', 'nonce_ttl_s',
                                     'token_ttl_s', 'proof_max_age_s',
                                     'batch_size', 'tx_code_length'])
    def test_non_positive_lifetime_is_refused(self, tmp_path, key):
        conf = _config(tmp_path,
                       oid4vci='[oid4vci]\n%s = 0\n' % key)
        with pytest.raises(ConfigError, match='must be positive'):
            oid4vci_config(conf)

    @pytest.mark.parametrize('key', ['offer_ttl_s', 'batch_size'])
    def test_non_integer_lifetime_is_refused(self, tmp_path, key):
        conf = _config(tmp_path, oid4vci='[oid4vci]\n%s = soon\n' % key)
        with pytest.raises(ConfigError, match='must be an integer'):
            oid4vci_config(conf)

    def test_unknown_tx_code_input_mode_is_refused(self, tmp_path):
        conf = _config(tmp_path,
                       oid4vci='[oid4vci]\ntx_code_input_mode = braille\n')
        with pytest.raises(ConfigError, match='tx_code_input_mode'):
            oid4vci_config(conf)

    def test_userinfo_in_a_published_url_is_refused_at_load(self, tmp_path):
        # [oid4vci] is a _PUBLIC_URL_SECTIONS member: its URLs end up in the
        # issuer metadata every wallet reads, so credentials in them leak.
        path = tmp_path / 'config.ini'
        path.write_text(
            '[paths]\nbase = %s\n\n[issuer]\nname = X\n'
            'publish_url = https://openbadges.issuer.example/issuer/\n\n'
            '[oid4vci]\ncredential_issuer = https://u:p@issuer.example/\n'
            % str(tmp_path))
        with pytest.raises(ValueError):
            load_config(str(path))


class TestOID4VCIFormats:
    def test_absent_key_means_not_offered(self, tmp_path):
        assert oid4vci_formats(_config(tmp_path), 'badge_1') == ()

    def test_formats_are_parsed_in_order_without_duplicates(self, tmp_path):
        conf = _config(tmp_path, badge_extra=(
            'oid4vci_formats = vc+sd-jwt, jwt_vc_json , vc+sd-jwt\n'))
        assert oid4vci_formats(conf, 'badge_1') == \
            (FORMAT_SD_JWT_VC, FORMAT_JWT_VC_JSON)

    def test_unknown_format_is_refused(self, tmp_path):
        conf = _config(tmp_path, badge_extra='oid4vci_formats = ldp_vc\n')
        with pytest.raises(ConfigError, match='unknown format'):
            oid4vci_formats(conf, 'badge_1')

    def test_sd_jwt_on_an_rsa_badge_is_refused(self, tmp_path):
        # SD-JWT VC has no RSA profile, so this pairing could never issue.
        # Catching it at config load beats failing with a wallet waiting.
        conf = _config(tmp_path, key_type='RSA',
                       badge_extra='oid4vci_formats = jwt_vc_json, vc+sd-jwt\n')
        with pytest.raises(ConfigError, match='cannot be signed with an RSA key'):
            oid4vci_formats(conf, 'badge_1')

    def test_jwt_vc_json_on_an_rsa_badge_is_fine(self, tmp_path):
        conf = _config(tmp_path, key_type='RSA',
                       badge_extra='oid4vci_formats = jwt_vc_json\n')
        assert oid4vci_formats(conf, 'badge_1') == (FORMAT_JWT_VC_JSON,)

    def test_ecc_badge_accepts_both(self, tmp_path):
        conf = _config(tmp_path, key_type='ECC',
                       badge_extra='oid4vci_formats = jwt_vc_json, vc+sd-jwt\n')
        assert oid4vci_formats(conf, 'badge_1') == \
            (FORMAT_JWT_VC_JSON, FORMAT_SD_JWT_VC)


class TestDidJwk:
    ED25519_JWK = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'aGVsbG8'}

    def test_round_trips_to_the_same_jwk(self, tmp_path):
        did = did_jwk_from_jwk(self.ED25519_JWK)
        assert did.startswith('did:jwk:')
        encoded = did[len('did:jwk:'):]
        raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
        assert json.loads(raw) == self.ED25519_JWK

    def test_is_unpadded_base64url(self):
        did = did_jwk_from_jwk(self.ED25519_JWK)
        assert '=' not in did
        assert '+' not in did and '/' not in did

    def test_member_order_does_not_change_the_did(self):
        # Canonical serialisation: the same key must always yield the same
        # identifier, whatever order the wallet spelled its JWK in.
        reordered = {'x': 'aGVsbG8', 'kty': 'OKP', 'crv': 'Ed25519'}
        assert did_jwk_from_jwk(reordered) == did_jwk_from_jwk(self.ED25519_JWK)

    @pytest.mark.parametrize('member', ['d', 'k', 'p', 'q', 'dp', 'dq', 'qi',
                                        'priv'])
    def test_private_key_material_is_refused(self, member):
        jwk = dict(self.ED25519_JWK, **{member: 'SECRET'})
        with pytest.raises(ValueError, match='private key material'):
            did_jwk_from_jwk(jwk)

    def test_missing_kty_is_refused(self):
        with pytest.raises(ValueError, match='kty'):
            did_jwk_from_jwk({'crv': 'Ed25519', 'x': 'aGVsbG8'})

    def test_non_object_is_refused(self):
        with pytest.raises(ValueError, match='JWK object'):
            did_jwk_from_jwk('did:jwk:whatever')

    def test_unserialisable_jwk_is_refused(self):
        with pytest.raises(ValueError, match='not JSON-serialisable'):
            did_jwk_from_jwk({'kty': 'OKP', 'x': object()})

    def test_p384_holder_is_accepted(self):
        # The reason did:jwk exists here rather than did:key: a P-384 or RSA
        # wallet key has no multicodec did:key encoding in this library, but is
        # a perfectly valid holder.
        did = did_jwk_from_jwk({'kty': 'EC', 'crv': 'P-384', 'x': 'a', 'y': 'b'})
        assert did.startswith('did:jwk:')


class TestIdentityObjectCreate:
    def test_matches_the_ob2_hash(self):
        from openbadgeslib.ob2.models import hash_identity
        obj = IdentityObject.create('user@example.org', 'salt123')
        assert obj.identity_hash == hash_identity('user@example.org', 'salt123')
        assert obj.hashed is True
        assert obj.salt == 'salt123'
        assert obj.identity_type == 'emailAddress'

    def test_serialises_to_the_schema_shape(self):
        d = IdentityObject.create('user@example.org', 'salt123').to_dict()
        assert d['type'] == 'IdentityObject'
        assert d['identityType'] == 'emailAddress'
        assert d['hashed'] is True
        assert d['identityHash'].startswith('sha256$')
        assert d['salt'] == 'salt123'

    def test_round_trips_through_from_dict(self):
        obj = IdentityObject.create('user@example.org', 'salt123')
        assert IdentityObject.from_dict(obj.to_dict()) == obj

    def test_salt_is_optional(self):
        obj = IdentityObject.create('user@example.org')
        assert obj.salt is None
        assert 'salt' not in obj.to_dict()
        # An unsalted hash is still the plain sha256 of the address, so it must
        # equal the salted form with an empty salt rather than differ subtly.
        assert obj.identity_hash == \
            IdentityObject.create('user@example.org', '').identity_hash

    def test_different_salts_give_different_hashes(self):
        a = IdentityObject.create('user@example.org', 'a')
        b = IdentityObject.create('user@example.org', 'b')
        assert a.identity_hash != b.identity_hash
