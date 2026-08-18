"""Tests for the OID4VCI protocol surface: metadata, offers and the handlers.

The credential-endpoint tests need openvc-core's openid4vci module (the
[oid4vci] extra); everything else runs without it, which is the point of
keeping the error mapping and the discovery documents free of openvc imports.
"""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from openbadgeslib.errors import ConfigError
from openbadgeslib.oid4vci import (FORMAT_JWT_VC_JSON, FORMAT_SD_JWT_VC,
                                   InMemoryOID4VCIStore, NonceIssuer,
                                   build_authorization_server_metadata,
                                   build_credential_offer,
                                   build_issuer_metadata,
                                   credential_configuration_id,
                                   handle_credential_request,
                                   handle_nonce_request, handle_token_request,
                                   offered_badges)
from openbadgeslib.oid4vci.errors import (INVALID_CREDENTIAL_REQUEST,
                                          INVALID_ENCRYPTION_PARAMETERS,
                                          INVALID_GRANT, INVALID_NONCE,
                                          INVALID_PROOF, INVALID_REQUEST,
                                          INVALID_TOKEN, OID4VCIError,
                                          as_oid4vci_error)
from openbadgeslib.oid4vci.metadata import parse_credential_configuration_id
from openbadgeslib.oid4vci.offer import OFFER_SCHEME

TESTS_DIR = Path(__file__).parent
ISSUER = 'https://issuer.example/issuer/'


def _write_conf(tmp_path, *, status=False, formats='jwt_vc_json',
                key_type='RSA', priv='test_sign_rsa.pem',
                pub='test_verify_rsa.pem', oid4vci_extra=''):
    log = tmp_path / 'log'
    log.mkdir(exist_ok=True)
    lines = [
        '[paths]', 'base = %s' % tmp_path, 'base_log = %s' % log,
        'base_image = %s' % (TESTS_DIR / 'images'), '',
        '[logs]', 'general = general.log', 'signer = signer.log', '',
        '[issuer]', 'name = Test Issuer', 'url = https://example.com',
        'publish_url = %s' % ISSUER, '',
        '[oid4vci]', 'credential_issuer = %s' % ISSUER, oid4vci_extra, '',
        '[badge_1]', 'name = Test Badge', 'description = A test badge',
        'local_image = sample1.svg',
        'image = https://example.com/badge.svg',
        'criteria = https://example.com/criteria.html',
        'verify_key = https://example.com/verify.pem',
        'badge = https://example.com/badge.json',
        'crypto_key = https://example.com/key.json',
        'private_key = %s/%s' % (TESTS_DIR, priv),
        'public_key = %s/%s' % (TESTS_DIR, pub),
        'key_type = %s' % key_type,
        'oid4vci_formats = %s' % formats,
    ]
    if status:
        lines.append('status_lists = revocation')
    path = tmp_path / 'cfg.ini'
    path.write_text('\n'.join(lines) + '\n')
    from openbadgeslib.confparser import read_config_or_exit
    return read_config_or_exit(str(path))


@pytest.fixture
def conf(tmp_path):
    return _write_conf(tmp_path)


@pytest.fixture
def store():
    made = InMemoryOID4VCIStore()
    yield made
    made.close()


@pytest.fixture
def nonces(store):
    return NonceIssuer(store, ttl_s=120)


def _holder_key():
    key = ec.generate_private_key(ec.SECP256R1())
    return key, json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))


def _key_proof(nonce, privkey, holder_jwk, *, audience=ISSUER, iat=None,
               typ='openid4vci-proof+jwt', alg='ES256'):
    """A wallet's openid4vci-proof+jwt, as it would arrive at the endpoint."""
    return jwt.encode(
        {'aud': audience, 'iat': iat or int(time.time()), 'nonce': nonce,
         'iss': 'wallet-client-id'},
        privkey, algorithm=alg, headers={'typ': typ, 'jwk': holder_jwk})


class TestIssuerMetadata:
    def test_advertises_the_configured_badge(self, conf):
        meta = build_issuer_metadata(conf)
        assert meta['credential_issuer'] == ISSUER
        assert meta['credential_endpoint'] == ISSUER + 'credential'
        assert meta['nonce_endpoint'] == ISSUER + 'nonce'
        configurations = meta['credential_configurations_supported']
        assert list(configurations) == ['badge_1_jwt_vc_json']
        entry = configurations['badge_1_jwt_vc_json']
        assert entry['format'] == FORMAT_JWT_VC_JSON
        assert entry['cryptographic_binding_methods_supported'] == ['did:jwk']
        assert entry['credential_signing_alg_values_supported'] == ['RS256']
        assert entry['proof_types_supported']['jwt'][
            'proof_signing_alg_values_supported'] == ['ES256', 'ES384', 'EdDSA']
        assert entry['credential_definition']['type'] == [
            'VerifiableCredential', 'OpenBadgeCredential']

    def test_points_wallets_at_the_authorization_server(self, conf):
        # Without this a wallet cannot find the token endpoint and the
        # pre-authorized flow stops before its first request.
        assert build_issuer_metadata(conf)['authorization_servers'] == [ISSUER]

    def test_display_comes_from_the_config(self, conf):
        meta = build_issuer_metadata(conf)
        assert meta['display'][0]['name'] == 'Test Issuer'
        entry = meta['credential_configurations_supported'][
            'badge_1_jwt_vc_json']
        assert entry['display'][0]['name'] == 'Test Badge'
        assert entry['display'][0]['description'] == 'A test badge'
        assert entry['display'][0]['logo']['uri'] == \
            'https://example.com/badge.svg'

    def test_sd_jwt_entry_carries_a_vct_and_a_jwk_binding(self, tmp_path):
        conf = _write_conf(tmp_path, formats='vc+sd-jwt', key_type='ECC',
                           priv='test_sign_ecc.pem', pub='test_verify_ecc.pem')
        entry = build_issuer_metadata(conf)[
            'credential_configurations_supported']['badge_1_vc_sd_jwt']
        assert entry['format'] == FORMAT_SD_JWT_VC
        assert entry['vct']
        assert entry['cryptographic_binding_methods_supported'] == ['jwk']
        assert entry['credential_signing_alg_values_supported'] == ['ES256']
        assert 'credential_definition' not in entry

    def test_never_reads_the_private_key(self, tmp_path):
        # The metadata is public; deriving algorithms from key_type rather than
        # from the key means a missing or unreadable key cannot break it.
        conf = _write_conf(tmp_path)
        conf['badge_1']['private_key'] = str(tmp_path / 'does-not-exist.pem')
        meta = build_issuer_metadata(conf)
        assert meta['credential_configurations_supported'][
            'badge_1_jwt_vc_json']['credential_signing_alg_values_supported']

    def test_batch_is_advertised_only_when_enabled(self, tmp_path):
        assert 'batch_credential_issuance' not in build_issuer_metadata(
            _write_conf(tmp_path))
        conf = _write_conf(tmp_path, oid4vci_extra='batch_size = 5')
        assert build_issuer_metadata(conf)['batch_credential_issuance'] == \
            {'batch_size': 5}

    def test_no_opted_in_badge_is_a_config_error(self, tmp_path):
        conf = _write_conf(tmp_path)
        del conf['badge_1']['oid4vci_formats']
        with pytest.raises(ConfigError, match='no badge section opts into'):
            build_issuer_metadata(conf)

    def test_explicit_badge_without_opt_in_is_refused(self, tmp_path):
        conf = _write_conf(tmp_path)
        del conf['badge_1']['oid4vci_formats']
        with pytest.raises(ConfigError, match='does not opt into'):
            build_issuer_metadata(conf, badges=['badge_1'])


class TestAuthorizationServerMetadata:
    def test_declares_the_pre_authorized_grant(self, conf):
        meta = build_authorization_server_metadata(conf)
        assert meta['issuer'] == ISSUER
        assert meta['token_endpoint'] == ISSUER + 'token'
        assert meta['grant_types_supported'] == [
            'urn:ietf:params:oauth:grant-type:pre-authorized_code']

    def test_allows_anonymous_access(self, conf):
        # Without this flag a conformant wallet looks for a client
        # authentication method, finds none and gives up.
        meta = build_authorization_server_metadata(conf)
        assert meta['pre-authorized_grant_anonymous_access_supported'] is True


class TestConfigurationIds:
    def test_id_is_derived_and_slugged(self):
        assert credential_configuration_id('badge_1', FORMAT_JWT_VC_JSON) == \
            'badge_1_jwt_vc_json'
        # A raw 'vc+sd-jwt' would put a '+' into an id that travels in URLs.
        assert credential_configuration_id('badge_1', FORMAT_SD_JWT_VC) == \
            'badge_1_vc_sd_jwt'

    def test_round_trips_through_the_config(self, conf):
        badge, fmt = parse_credential_configuration_id(
            conf, 'badge_1_jwt_vc_json')
        assert (badge, fmt) == ('badge_1', FORMAT_JWT_VC_JSON)

    def test_an_unoffered_id_is_refused(self, conf):
        with pytest.raises(ConfigError, match='no credential configuration'):
            parse_credential_configuration_id(conf, 'badge_9_jwt_vc_json')

    def test_offered_badges_skips_sections_without_opt_in(self, tmp_path):
        conf = _write_conf(tmp_path)
        assert offered_badges(conf) == ['badge_1']
        del conf['badge_1']['oid4vci_formats']
        assert offered_badges(conf) == []


class TestCredentialOffer:
    def test_offer_document_and_uri(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        assert offer.offer['credential_issuer'] == ISSUER
        assert offer.offer['credential_configuration_ids'] == \
            ['badge_1_jwt_vc_json']
        grant = offer.offer['grants'][
            'urn:ietf:params:oauth:grant-type:pre-authorized_code']
        assert grant['pre-authorized_code'] == offer.pre_authorized_code
        assert 'tx_code' not in grant
        assert offer.uri.startswith(OFFER_SCHEME)
        assert offer.tx_code is None

    def test_uri_carries_the_offer_verbatim(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        query = parse_qs(urlparse(offer.uri).query)
        assert json.loads(query['credential_offer'][0]) == offer.offer

    def test_offer_is_short_enough_to_scan(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        assert offer.fits_in_a_qr_code

    def test_by_reference_form(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        uri = offer.uri_by_reference('https://issuer.example/offers/abc')
        query = parse_qs(urlparse(uri).query)
        assert query['credential_offer_uri'] == \
            ['https://issuer.example/offers/abc']
        assert json.loads(offer.offer_json) == offer.offer

    def test_tx_code_is_returned_once_and_stored_hashed(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, tx_code=True)
        assert offer.tx_code and len(offer.tx_code) == 6
        declared = offer.offer['grants'][
            'urn:ietf:params:oauth:grant-type:pre-authorized_code']['tx_code']
        assert declared['length'] == 6
        assert declared['input_mode'] == 'numeric'
        # The offer document must not leak the PIN it is protected by.
        assert offer.tx_code not in json.dumps(offer.offer)
        stored = store.find_grant(offer.grant_id)
        assert stored.tx_code_digest is not None
        assert offer.tx_code.encode() not in stored.tx_code_digest

    def test_grant_is_persisted_before_the_offer_is_returned(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        stored = store.find_grant(offer.grant_id)
        assert stored is not None
        assert stored.recipient == 'r@example.org'
        assert stored.credential_format == FORMAT_JWT_VC_JSON
        assert stored.credential_id.startswith('urn:uuid:')

    def test_status_slot_is_reserved_at_offer_time(self, tmp_path, store):
        # And under the credential's real id, so the operator can revoke it
        # through the ordinary publish path.
        from openbadgeslib.ob3.status_registry import StatusRegistry
        conf = _write_conf(tmp_path, status=True)
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        assert offer.status_index is not None
        assert offer.notices
        registry = StatusRegistry.load(
            str(tmp_path / 'status' / 'badge_1.json'))
        entries = registry.find(store.find_grant(offer.grant_id).credential_id)
        assert len(entries) == 1
        assert entries[0].index == offer.status_index
        assert entries[0].recipient == 'mailto:r@example.org'

    def test_badge_without_opt_in_is_refused(self, tmp_path, store):
        conf = _write_conf(tmp_path)
        del conf['badge_1']['oid4vci_formats']
        with pytest.raises(ConfigError, match='does not offer OID4VCI'):
            build_credential_offer(conf, 'badge_1', 'r@example.org',
                                   store=store)

    def test_format_the_badge_did_not_offer_is_refused(self, conf, store):
        with pytest.raises(ConfigError, match='does not offer'):
            build_credential_offer(conf, 'badge_1', 'r@example.org',
                                   store=store,
                                   credential_format=FORMAT_SD_JWT_VC)

    def test_revocable_sd_jwt_is_refused_at_offer_time(self, tmp_path, store):
        conf = _write_conf(tmp_path, status=True, formats='vc+sd-jwt',
                           key_type='ECC', priv='test_sign_ecc.pem',
                           pub='test_verify_ecc.pem')
        with pytest.raises(ConfigError, match='irrevocable'):
            build_credential_offer(conf, 'badge_1', 'r@example.org',
                                   store=store)

    def test_revocable_batch_is_refused(self, tmp_path, store):
        # One grant reserves one slot, so a batch would issue credentials that
        # could never be revoked.
        conf = _write_conf(tmp_path, status=True,
                           oid4vci_extra='batch_size = 3')
        with pytest.raises(ConfigError, match='irrevocable'):
            build_credential_offer(conf, 'badge_1', 'r@example.org',
                                   store=store)

    def test_expiry_honours_the_config(self, tmp_path, store):
        conf = _write_conf(tmp_path, oid4vci_extra='offer_ttl_s = 60')
        now = datetime(2026, 7, 25, tzinfo=timezone.utc)
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, now=now)
        assert offer.expires_at == now + timedelta(seconds=60)


class TestTokenEndpoint:
    """Runs without openvc: redeeming a code involves no wallet cryptography."""

    def test_redeems_a_code_for_a_token(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        response = handle_token_request(conf, code=offer.pre_authorized_code,
                                        store=store)
        body = response.to_dict()
        assert body['token_type'] == 'Bearer'
        assert body['expires_in'] == 300
        assert body['access_token']
        assert response.grant.recipient == 'r@example.org'

    def test_token_resolves_to_the_grant(self, conf, store):
        from openbadgeslib.oid4vci.codes import secret_id
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        response = handle_token_request(conf, code=offer.pre_authorized_code,
                                        store=store)
        now = datetime.now(tz=timezone.utc)
        grant = store.grant_for_token(secret_id(response.access_token), now=now)
        assert grant is not None and grant.grant_id == offer.grant_id

    def test_unknown_code_is_invalid_grant(self, conf, store):
        with pytest.raises(OID4VCIError) as caught:
            handle_token_request(conf, code='not-a-real-code', store=store)
        assert caught.value.error == INVALID_GRANT
        assert caught.value.http_status == 400

    def test_expired_code_is_invalid_grant(self, tmp_path, store):
        conf = _write_conf(tmp_path, oid4vci_extra='offer_ttl_s = 60')
        past = datetime.now(tz=timezone.utc) - timedelta(hours=1)
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, now=past)
        with pytest.raises(OID4VCIError) as caught:
            handle_token_request(conf, code=offer.pre_authorized_code,
                                 store=store)
        assert caught.value.error == INVALID_GRANT

    def test_all_rejections_share_one_message(self, conf, store):
        # An endpoint that distinguishes "unknown" from "expired" from "already
        # used" tells an attacker which of their guesses named a real offer.
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        handle_token_request(conf, code=offer.pre_authorized_code, store=store)
        messages = set()
        for code in (offer.pre_authorized_code, 'unknown-code'):
            with pytest.raises(OID4VCIError) as caught:
                handle_token_request(conf, code=code, store=store)
            messages.add(caught.value.description)
        assert len(messages) == 1

    def test_replayed_code_kills_the_grant_and_its_tokens(self, conf, store):
        from openbadgeslib.oid4vci.codes import secret_id
        from openbadgeslib.oid4vci.store import STATE_INVALIDATED
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        first = handle_token_request(conf, code=offer.pre_authorized_code,
                                     store=store)
        with pytest.raises(OID4VCIError):
            handle_token_request(conf, code=offer.pre_authorized_code,
                                 store=store)
        # A second presentation means the offer leaked, so the token handed to
        # whoever went first must stop working too.
        assert store.find_grant(offer.grant_id).state == STATE_INVALIDATED
        now = datetime.now(tz=timezone.utc)
        assert store.grant_for_token(secret_id(first.access_token),
                                     now=now) is None

    def test_correct_tx_code_is_accepted(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, tx_code=True)
        response = handle_token_request(conf, code=offer.pre_authorized_code,
                                        tx_code=offer.tx_code, store=store)
        assert response.access_token

    def test_wrong_tx_code_is_refused_and_counted(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, tx_code=True)
        wrong = '000000' if offer.tx_code != '000000' else '111111'
        with pytest.raises(OID4VCIError) as caught:
            handle_token_request(conf, code=offer.pre_authorized_code,
                                 tx_code=wrong, store=store)
        assert caught.value.error == INVALID_GRANT
        assert store.find_grant(offer.grant_id).tx_code_attempts == 1

    def test_tx_code_attempts_are_capped(self, conf, store):
        from openbadgeslib.oid4vci.store import STATE_INVALIDATED
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, tx_code=True)
        wrong = '000000' if offer.tx_code != '000000' else '111111'
        for _ in range(3):
            with pytest.raises(OID4VCIError):
                handle_token_request(conf, code=offer.pre_authorized_code,
                                     tx_code=wrong, store=store)
        assert store.find_grant(offer.grant_id).state == STATE_INVALIDATED
        # Even the right PIN is useless now.
        with pytest.raises(OID4VCIError):
            handle_token_request(conf, code=offer.pre_authorized_code,
                                 tx_code=offer.tx_code, store=store)

    def test_missing_tx_code_is_invalid_request(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store, tx_code=True)
        with pytest.raises(OID4VCIError) as caught:
            handle_token_request(conf, code=offer.pre_authorized_code,
                                 store=store)
        assert caught.value.error == INVALID_REQUEST

    def test_unexpected_tx_code_is_invalid_request(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        with pytest.raises(OID4VCIError) as caught:
            handle_token_request(conf, code=offer.pre_authorized_code,
                                 tx_code='123456', store=store)
        assert caught.value.error == INVALID_REQUEST

    def test_other_grant_types_are_refused(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        with pytest.raises(OID4VCIError) as caught:
            handle_token_request(conf, code=offer.pre_authorized_code,
                                 store=store, grant_type='authorization_code')
        assert caught.value.error == INVALID_REQUEST

    def test_empty_code_is_refused(self, conf, store):
        with pytest.raises(OID4VCIError) as caught:
            handle_token_request(conf, code='', store=store)
        assert caught.value.error == INVALID_REQUEST


class TestNonceEndpoint:
    def test_returns_a_nonce_and_its_lifetime(self, conf, nonces):
        body = handle_nonce_request(conf, nonces=nonces)
        assert body['c_nonce']
        assert body['c_nonce_expires_in'] == 120

    def test_each_call_is_fresh(self, conf, nonces):
        seen = {handle_nonce_request(conf, nonces=nonces)['c_nonce']
                for _ in range(20)}
        assert len(seen) == 20


class TestErrorMapping:
    @pytest.mark.parametrize('name,expected', [
        ('CredentialRequestMalformed', INVALID_CREDENTIAL_REQUEST),
        ('ProofReplayed', INVALID_NONCE),
        ('UnsupportedProofType', INVALID_PROOF),
        ('SignatureInvalid', INVALID_PROOF),
        ('MalformedToken', INVALID_PROOF),
        ('UnsupportedAlgorithm', INVALID_PROOF),
        ('ClaimsInvalid', INVALID_PROOF),
    ])
    def test_openvc_exceptions_map_to_spec_codes(self, name, expected):
        exc = type(name, (Exception,), {})('boom')
        assert as_oid4vci_error(exc).error == expected

    def test_a_missing_nonce_maps_to_invalid_nonce(self):
        # openvc reports this as a generic ClaimsInvalid, but only
        # invalid_nonce tells the wallet to go and fetch one — the other codes
        # would leave it stuck retrying an unfixable request. Pinned because
        # the distinction rests on openvc's wording.
        exc = type('ClaimsInvalid', (Exception,), {})(
            'key proof is missing the required nonce')
        assert as_oid4vci_error(exc).error == INVALID_NONCE

    def test_an_unknown_exception_still_refuses(self, ):
        exc = type('SomethingNew', (Exception,), {})('boom')
        assert as_oid4vci_error(exc).error == INVALID_CREDENTIAL_REQUEST

    def test_error_body_is_the_wire_shape(self):
        error = OID4VCIError(INVALID_PROOF, 'nope')
        assert error.to_dict() == {'error': 'invalid_proof',
                                   'error_description': 'nope'}
        assert error.http_status == 400

    def test_errors_are_catchable_as_library_exceptions(self):
        from openbadgeslib.errors import LibOpenBadgesException
        assert isinstance(OID4VCIError(INVALID_PROOF, 'x'),
                          LibOpenBadgesException)

    def test_mapping_needs_no_openvc_import(self):
        # errors.py indexes by class name precisely so the whole error surface
        # imports and works without the extra installed. Checked over the parsed
        # imports rather than the text, so prose mentioning openvc is fine.
        import ast
        import openbadgeslib.oid4vci.errors as module
        tree = ast.parse(Path(module.__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not [name for name in imported if name.startswith('openvc')]


class TestCredentialEndpointWithoutTheExtra:
    """What the credential endpoint refuses before any wallet crypto runs.

    These need no openvc: authentication and the size ceiling are checked
    first, on purpose, so an unauthenticated or oversized request is refused
    without importing anything — and an issuer that never installed the extra
    still answers those accurately instead of complaining about packaging.
    """

    def _token(self, conf, store):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        return handle_token_request(conf, code=offer.pre_authorized_code,
                                    store=store).access_token

    def test_no_access_token_is_401(self, conf, store, nonces):
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, {}, access_token=None,
                                      store=store, nonces=nonces)
        assert caught.value.error == INVALID_TOKEN
        assert caught.value.http_status == 401

    def test_unknown_access_token_is_401(self, conf, store, nonces):
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, {}, access_token='nope',
                                      store=store, nonces=nonces)
        assert caught.value.http_status == 401

    def test_oversized_body_is_refused_before_parsing(self, conf, store,
                                                      nonces):
        from openbadgeslib.oid4vci.handler import MAX_REQUEST_BYTES
        token = self._token(conf, store)
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, 'x' * (MAX_REQUEST_BYTES + 1),
                                      access_token=token, store=store,
                                      nonces=nonces)
        assert caught.value.error == INVALID_CREDENTIAL_REQUEST
        assert 'exceeds' in caught.value.description

    def test_non_utf8_body_is_refused(self, conf, store, nonces):
        token = self._token(conf, store)
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, b'\xff\xfe not utf-8',
                                      access_token=token, store=store,
                                      nonces=nonces)
        assert caught.value.error == INVALID_CREDENTIAL_REQUEST
        assert 'UTF-8' in caught.value.description

    def test_bytes_body_is_accepted_and_decoded(self, conf, store, nonces):
        # A framework handing over raw bytes must work; this gets past the
        # decode and fails later (either on the extra or on the empty request).
        token = self._token(conf, store)
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, b'{}', access_token=token,
                                      store=store, nonces=nonces)
        assert 'UTF-8' not in caught.value.description

    def test_missing_extra_gives_an_actionable_message(self, conf, store,
                                                       nonces, monkeypatch):
        import openbadgeslib.oid4vci.handler as module

        def _absent():
            raise OID4VCIError(INVALID_CREDENTIAL_REQUEST,
                               'OID4VCI issuance needs the [oid4vci] extra: '
                               'pip install openbadgeslib[oid4vci]')
        monkeypatch.setattr(module, '_require_openvc', _absent)
        token = self._token(conf, store)
        with pytest.raises(OID4VCIError, match=r'\[oid4vci\] extra'):
            handle_credential_request(conf, {}, access_token=token,
                                      store=store, nonces=nonces)

    def test_the_real_require_openvc_reports_the_extra(self, monkeypatch):
        # Pin the hint itself: an ImportError must become a typed error with
        # an install line, not escape as a bare ImportError from an endpoint.
        import builtins
        import openbadgeslib.oid4vci.handler as module
        real_import = builtins.__import__

        def _blocked(name, *args, **kwargs):
            if name.startswith('openvc'):
                raise ImportError('no openvc here')
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, '__import__', _blocked)
        with pytest.raises(OID4VCIError, match=r'\[oid4vci\] extra'):
            module._require_openvc()


class TestCredentialEndpoint:
    """The full claim path. Needs openvc-core's openid4vci module."""

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        """Require openvc-core's openid4vci module (the [oid4vci] extra).

        Missing it SKIPs, except where the extra is installed on purpose — a CI
        leg that sets ``OPENBADGES_REQUIRE_OID4VCI=1`` — where it FAILs instead.
        Without that, an openvc packaging change would quietly turn the entire
        credential-endpoint suite into skips and the job would still be green,
        which is the failure mode #221 fixed for the ecdsa-sd-2023 suite.
        """
        import importlib
        import os
        try:
            importlib.import_module('openvc.openid4vci')
        except ImportError as exc:
            reason = ('the [oid4vci] extra is required for the credential '
                      'endpoint tests but openvc.openid4vci is not '
                      'importable: %s' % exc)
            if os.environ.get('OPENBADGES_REQUIRE_OID4VCI') == '1':
                pytest.fail(reason, pytrace=False)
            pytest.skip(reason)

    def _claim(self, conf, store, nonces, *, badge='badge_1',
               recipient='r@example.org', holder=None, tx_code=False,
               offer=None, token=None, configuration_id=None, proofs=None):
        offer = offer or build_credential_offer(conf, badge, recipient,
                                                store=store, tx_code=tx_code)
        token = token or handle_token_request(
            conf, code=offer.pre_authorized_code,
            tx_code=offer.tx_code, store=store)
        if proofs is None:
            key, jwk = holder or _holder_key()
            nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
            proofs = [_key_proof(nonce, key, jwk)]
        body = {'credential_configuration_id':
                configuration_id or offer.credential_configuration_ids[0],
                'proofs': {'jwt': proofs}}
        return offer, token, handle_credential_request(
            conf, body, access_token=token.access_token, store=store,
            nonces=nonces)

    def test_issues_a_credential_bound_to_the_holder(self, conf, store, nonces):
        from openbadgeslib.ob3.did import did_jwk_from_jwk
        key, jwk = _holder_key()
        _, _, response = self._claim(conf, store, nonces, holder=(key, jwk))
        assert len(response.credentials) == 1
        claims = jwt.decode(response.credentials[0],
                            options={'verify_signature': False})
        assert claims['sub'] == did_jwk_from_jwk(jwk)
        assert claims['credentialSubject']['identifier'][0]['hashed'] is True

    def test_response_body_is_the_wire_shape(self, conf, store, nonces):
        _, _, response = self._claim(conf, store, nonces)
        body = response.to_dict()
        assert list(body) == ['credentials']
        assert body['credentials'][0]['credential'] == response.credentials[0]

    def test_credential_verifies_against_the_issuer_key(self, conf, store,
                                                        nonces):
        from openbadgeslib.ob3 import OB3Verifier
        _, _, response = self._claim(conf, store, nonces)
        pubkey = (TESTS_DIR / 'test_verify_rsa.pem').read_bytes()
        credential = OB3Verifier(pubkey_pem=pubkey).verify(
            response.credentials[0])
        assert credential.achievement.name == 'Test Badge'

    def test_recipient_comes_from_the_grant_not_the_request(self, conf, store,
                                                            nonces):
        from openbadgeslib.ob2.models import hash_identity
        _, _, response = self._claim(conf, store, nonces,
                                     recipient='learner@example.org')
        identifier = response.issued[0].credential.identifiers[0]
        assert identifier.identity_hash == hash_identity('learner@example.org',
                                                         identifier.salt)

    def test_revocable_badge_uses_the_reserved_slot(self, tmp_path, store,
                                                    nonces):
        conf = _write_conf(tmp_path, status=True)
        offer, _, response = self._claim(conf, store, nonces)
        result = response.issued[0]
        assert result.status_index == offer.status_index
        assert result.jti == store.find_grant(offer.grant_id).credential_id
        entries = result.credential.credential_status
        assert entries[0]['statusListIndex'] == str(offer.status_index)

    def test_a_reused_nonce_is_invalid_nonce(self, conf, store, nonces):
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        proof = _key_proof(nonce, key, jwk)
        offer, token, _ = self._claim(conf, store, nonces, proofs=[proof])
        # A second grant, but the same already-spent nonce.
        offer2 = build_credential_offer(conf, 'badge_1', 'r2@example.org',
                                        store=store)
        token2 = handle_token_request(conf, code=offer2.pre_authorized_code,
                                      store=store)
        body = {'credential_configuration_id':
                offer2.credential_configuration_ids[0],
                'proofs': {'jwt': [proof]}}
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, body,
                                      access_token=token2.access_token,
                                      store=store, nonces=nonces)
        assert caught.value.error == INVALID_NONCE

    def test_a_missing_nonce_is_invalid_nonce(self, conf, store, nonces):
        key, jwk = _holder_key()
        proof = jwt.encode(
            {'aud': ISSUER, 'iat': int(time.time()), 'iss': 'wallet'},
            key, algorithm='ES256',
            headers={'typ': 'openid4vci-proof+jwt', 'jwk': jwk})
        with pytest.raises(OID4VCIError) as caught:
            self._claim(conf, store, nonces, proofs=[proof])
        assert caught.value.error == INVALID_NONCE

    def test_a_proof_for_another_audience_is_refused(self, conf, store,
                                                     nonces):
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        proof = _key_proof(nonce, key, jwk,
                           audience='https://attacker.example/')
        with pytest.raises(OID4VCIError) as caught:
            self._claim(conf, store, nonces, proofs=[proof])
        assert caught.value.error == INVALID_PROOF

    def test_a_stale_proof_is_refused(self, conf, store, nonces):
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        proof = _key_proof(nonce, key, jwk, iat=int(time.time()) - 86400)
        with pytest.raises(OID4VCIError) as caught:
            self._claim(conf, store, nonces, proofs=[proof])
        assert caught.value.error == INVALID_PROOF

    def test_a_future_dated_proof_is_refused(self, conf, store, nonces):
        # Without this direction a wallet signs once with iat far ahead and
        # holds a proof that never goes stale.
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        proof = _key_proof(nonce, key, jwk, iat=int(time.time()) + 86400)
        with pytest.raises(OID4VCIError) as caught:
            self._claim(conf, store, nonces, proofs=[proof])
        assert caught.value.error == INVALID_PROOF

    def test_a_wrong_typ_is_refused(self, conf, store, nonces):
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        proof = _key_proof(nonce, key, jwk, typ='JWT')
        with pytest.raises(OID4VCIError) as caught:
            self._claim(conf, store, nonces, proofs=[proof])
        assert caught.value.error == INVALID_PROOF

    def test_a_second_holder_cannot_claim_the_same_grant(self, conf, store,
                                                         nonces):
        offer, token, _ = self._claim(conf, store, nonces)
        thief, thief_jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        body = {'credential_configuration_id':
                offer.credential_configuration_ids[0],
                'proofs': {'jwt': [_key_proof(nonce, thief, thief_jwk)]}}
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, body,
                                      access_token=token.access_token,
                                      store=store, nonces=nonces)
        assert caught.value.error == INVALID_CREDENTIAL_REQUEST
        assert 'different key' in caught.value.description

    def test_the_same_holder_may_retry(self, conf, store, nonces):
        # A dropped response must not cost the wallet its credential.
        key, jwk = _holder_key()
        offer, token, first = self._claim(conf, store, nonces,
                                          holder=(key, jwk))
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        body = {'credential_configuration_id':
                offer.credential_configuration_ids[0],
                'proofs': {'jwt': [_key_proof(nonce, key, jwk)]}}
        again = handle_credential_request(conf, body,
                                          access_token=token.access_token,
                                          store=store, nonces=nonces)
        assert again.credentials

    def test_an_unoffered_configuration_is_refused(self, conf, store, nonces):
        with pytest.raises(OID4VCIError) as caught:
            self._claim(conf, store, nonces,
                        configuration_id='badge_9_jwt_vc_json')
        assert caught.value.error == INVALID_CREDENTIAL_REQUEST

    def test_no_access_token_is_401(self, conf, store, nonces):
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        body = {'credential_configuration_id': 'badge_1_jwt_vc_json',
                'proofs': {'jwt': [_key_proof(nonce, key, jwk)]}}
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, body, access_token=None,
                                      store=store, nonces=nonces)
        assert caught.value.error == INVALID_TOKEN
        assert caught.value.http_status == 401

    def test_an_unknown_access_token_is_401(self, conf, store, nonces):
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        body = {'credential_configuration_id': 'badge_1_jwt_vc_json',
                'proofs': {'jwt': [_key_proof(nonce, key, jwk)]}}
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, body, access_token='nope',
                                      store=store, nonces=nonces)
        assert caught.value.http_status == 401

    def test_response_encryption_is_refused_not_ignored(self, conf, store,
                                                        nonces):
        # Answering in the clear a request that asked for encryption would let
        # the wallet believe it got what it asked for.
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        token = handle_token_request(conf, code=offer.pre_authorized_code,
                                     store=store)
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        body = {'credential_configuration_id':
                offer.credential_configuration_ids[0],
                'proofs': {'jwt': [_key_proof(nonce, key, jwk)]},
                'credential_response_encryption': {'alg': 'ECDH-ES',
                                                   'enc': 'A128GCM',
                                                   'jwk': jwk}}
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, body,
                                      access_token=token.access_token,
                                      store=store, nonces=nonces)
        assert caught.value.error == INVALID_ENCRYPTION_PARAMETERS

    def test_an_oversized_body_is_refused_before_parsing(self, conf, store,
                                                         nonces):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        token = handle_token_request(conf, code=offer.pre_authorized_code,
                                     store=store)
        from openbadgeslib.oid4vci.handler import MAX_REQUEST_BYTES
        with pytest.raises(OID4VCIError) as caught:
            handle_credential_request(conf, 'x' * (MAX_REQUEST_BYTES + 1),
                                      access_token=token.access_token,
                                      store=store, nonces=nonces)
        assert caught.value.error == INVALID_CREDENTIAL_REQUEST
        assert 'exceeds' in caught.value.description

    def test_a_malformed_body_is_refused(self, conf, store, nonces):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        token = handle_token_request(conf, code=offer.pre_authorized_code,
                                     store=store)
        with pytest.raises(OID4VCIError):
            handle_credential_request(conf, '{not json',
                                      access_token=token.access_token,
                                      store=store, nonces=nonces)

    def test_an_issuer_fault_is_not_dressed_up_as_a_client_error(
            self, tmp_path, store, nonces):
        # A broken issuer must surface as a 500, not as invalid_credential_
        # request — otherwise the wallet retries a request that can never work.
        from openbadgeslib.errors import IssuanceError
        conf = _write_conf(tmp_path)
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        token = handle_token_request(conf, code=offer.pre_authorized_code,
                                     store=store)
        conf['badge_1']['private_key'] = str(tmp_path / 'missing.pem')
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        body = {'credential_configuration_id':
                offer.credential_configuration_ids[0],
                'proofs': {'jwt': [_key_proof(nonce, key, jwk)]}}
        with pytest.raises(IssuanceError):
            handle_credential_request(conf, body,
                                      access_token=token.access_token,
                                      store=store, nonces=nonces)

    def test_sd_jwt_badge_binds_the_holder_through_cnf(self, tmp_path, store,
                                                       nonces):
        conf = _write_conf(tmp_path, formats='vc+sd-jwt', key_type='ECC',
                           priv='test_sign_ecc.pem', pub='test_verify_ecc.pem')
        key, jwk = _holder_key()
        _, _, response = self._claim(conf, store, nonces, holder=(key, jwk))
        from openbadgeslib.ob3.eudi import verify_badge_sd_jwt
        pubkey = (TESTS_DIR / 'test_verify_ecc.pem').read_bytes()
        verified = verify_badge_sd_jwt(response.credentials[0],
                                       pubkey_pem=pubkey)
        assert verified.confirmation['jwk']['x'] == jwk['x']


class TestSelfCheckedDiscovery:
    """The builders pass their output through openvc-core's fail-closed wire
    parsers (1.25, floor 1.26), so a document no wallet would accept is a
    ConfigError at build time — not a wallet that silently never scans.
    These tests need the [oid4vci] extra: without it the builders return
    their output unchecked."""

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip('openvc.openid4vci')

    def test_issuer_metadata_round_trips_through_openvc(self, conf):
        from openvc.openid4vci import parse_credential_issuer_metadata
        parsed = parse_credential_issuer_metadata(build_issuer_metadata(conf))
        assert parsed.credential_issuer == ISSUER
        assert parsed.credential_endpoint == ISSUER + 'credential'
        assert parsed.nonce_endpoint == ISSUER + 'nonce'
        assert parsed.authorization_servers == (ISSUER,)
        assert 'badge_1_jwt_vc_json' in \
            parsed.credential_configurations_supported

    def test_offer_round_trips_through_openvc(self, conf, store):
        from openvc.openid4vci import parse_credential_offer
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        parsed = parse_credential_offer(offer.offer)
        assert parsed.credential_issuer == ISSUER
        assert list(parsed.credential_configuration_ids) == \
            ['badge_1_jwt_vc_json']

    def test_an_invalid_endpoint_url_is_a_config_error(self, conf,
                                                       monkeypatch):
        # The builders compose URLs from configuration, so a composed value
        # that violates the wire contract must surface as ConfigError — the
        # operator's vocabulary — not as openvc's IssuerMetadataMalformed.
        # Patch the openvc symbol (imported lazily inside the validator), so
        # the ConfigError translation under test is the real one.
        from openvc.openid4vci import IssuerMetadataMalformed

        def _refuse(document):
            raise IssuerMetadataMalformed(
                "credential_endpoint must be an absolute https URL, got "
                "'not-a-url'")

        monkeypatch.setattr('openvc.openid4vci.'
                            'parse_credential_issuer_metadata', _refuse)
        with pytest.raises(ConfigError, match='not a valid OID4VCI'):
            build_issuer_metadata(conf)

    def test_the_validator_rejects_what_openvc_rejects(self, conf):
        # The self-check is not decorative: a document openvc's parser refuses
        # is a ConfigError through the module's own validator too.
        from openvc.openid4vci import IssuerMetadataMalformed
        import openbadgeslib.oid4vci.metadata as metadata_module
        with pytest.raises(ConfigError, match='not a valid OID4VCI'):
            metadata_module._validate_issuer_metadata(
                dict(build_issuer_metadata(conf),
                     credential_endpoint='not-a-url'))
        with pytest.raises(IssuerMetadataMalformed):
            # And the poisoned document is genuinely refused upstream — the
            # ConfigError above is openvc's verdict, not a local invention.
            from openvc.openid4vci import parse_credential_issuer_metadata
            parse_credential_issuer_metadata(
                dict(build_issuer_metadata(conf),
                     credential_endpoint='not-a-url'))

    def test_an_invalid_offer_is_a_config_error_and_persists_nothing(
            self, conf, store, monkeypatch):
        from openvc.openid4vci import CredentialOfferMalformed

        def _refuse(document):
            raise CredentialOfferMalformed(
                "credential_issuer must be an absolute https URL, got "
                "'http://plaintext.example/'")

        # Patch the openvc symbol (imported lazily inside the validator), so
        # the ConfigError translation under test is the real one.
        monkeypatch.setattr('openvc.openid4vci.parse_credential_offer',
                            _refuse)
        with pytest.raises(ConfigError, match='not a valid OID4VCI'):
            build_credential_offer(conf, 'badge_1', 'r@example.org',
                                   store=store)
        # The grant must not survive a rejected offer: an offer nobody can use
        # backed by a live pre-authorized code is an orphan worth refusing.
        from openbadgeslib.oid4vci.store import STATE_OFFERED
        assert not [g for g in store._grants.values()
                    if g.state == STATE_OFFERED]

    def test_the_offer_validator_rejects_what_openvc_rejects(self, conf,
                                                             store):
        import openbadgeslib.oid4vci.offer as offer_module
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        poisoned = dict(offer.offer,
                        credential_issuer='http://plaintext.example/')
        with pytest.raises(ConfigError, match='not a valid OID4VCI'):
            offer_module._validate_offer(poisoned)


class TestReceivedCredentialOffers:
    """parse_received_credential_offer: validating third-party offers with
    openvc-core's fail-closed parser. Needs the [oid4vci] extra."""

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip('openvc.openid4vci')

    def test_accepts_a_well_formed_offer(self):
        from openbadgeslib.oid4vci import parse_received_credential_offer
        offer = {
            'credential_issuer': 'https://issuer.example/',
            'credential_configuration_ids': ['badge_1_jwt_vc_json'],
            'grants': {'urn:ietf:params:oauth:grant-type:pre-authorized_code':
                       {'pre-authorized_code': 'abc'}},
            # An extension member the parser does not model must survive.
            'x-issuer-extension': {'anything': True},
        }
        parsed = parse_received_credential_offer(offer)
        assert parsed['credential_issuer'] == 'https://issuer.example/'
        assert parsed['x-issuer-extension'] == {'anything': True}

    def test_accepts_a_json_string(self, conf, store):
        from openbadgeslib.oid4vci import parse_received_credential_offer
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        parsed = parse_received_credential_offer(offer.offer_json)
        assert parsed == json.loads(offer.offer_json)

    def test_an_http_issuer_is_refused(self):
        from openbadgeslib.oid4vci import parse_received_credential_offer
        with pytest.raises(OID4VCIError) as caught:
            parse_received_credential_offer({
                'credential_issuer': 'http://plaintext.example/',
                'credential_configuration_ids': ['x']})
        assert caught.value.error == INVALID_REQUEST

    def test_duplicate_configuration_ids_are_refused(self):
        from openbadgeslib.oid4vci import parse_received_credential_offer
        with pytest.raises(OID4VCIError) as caught:
            parse_received_credential_offer({
                'credential_issuer': 'https://issuer.example/',
                'credential_configuration_ids': ['a', 'a']})
        assert caught.value.error == INVALID_REQUEST

    def test_empty_configuration_ids_are_refused(self):
        from openbadgeslib.oid4vci import parse_received_credential_offer
        with pytest.raises(OID4VCIError):
            parse_received_credential_offer({
                'credential_issuer': 'https://issuer.example/',
                'credential_configuration_ids': []})

    def test_a_by_reference_offer_is_not_dereferenced(self):
        # credential_offer_uri is a fetch this library does not perform: the
        # parser takes the object as-is (and rejects it for lacking the
        # by-value members, which is the fail-closed answer).
        from openbadgeslib.oid4vci import parse_received_credential_offer
        with pytest.raises(OID4VCIError):
            parse_received_credential_offer({
                'credential_issuer': 'https://issuer.example/',
                'credential_offer_uri': 'https://issuer.example/offers/1'})


class TestKeyAttestationProofs:
    """The attested-key proof form ({typ, alg, kid, key_attestation}) an EU
    wallet stack emits, accepted through resolve_proof_key_in_context
    (openvc-core ≥1.24). Needs the [oid4vci] extra."""

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip('openvc.openid4vci')

    def _attested_proof(self, nonce, holder_priv, holder_jwk):
        """A key proof in the App. D form: the key is inside the attestation,
        the header names it only by kid."""
        provider_priv = ec.generate_private_key(ec.SECP256R1())
        provider_jwk = json.loads(
            jwt.algorithms.ECAlgorithm.to_jwk(provider_priv.public_key()))
        attestation = jwt.encode(
            {'attested_keys': [holder_jwk], 'iat': int(time.time()),
             'key_storage': ['iso_18045_moderate']},
            provider_priv, algorithm='ES256',
            headers={'typ': 'key-attestation+jwt', 'jwk': provider_jwk})
        return jwt.encode(
            {'aud': ISSUER, 'iat': int(time.time()), 'nonce': nonce,
             'iss': 'wallet-client-id'},
            holder_priv, algorithm='ES256',
            headers={'typ': 'openid4vci-proof+jwt', 'kid': 'wallet-key-1',
                     'key_attestation': attestation})

    def _request_with_proof(self, conf, store, nonces, proof, **kwargs):
        offer = build_credential_offer(conf, 'badge_1', 'r@example.org',
                                       store=store)
        token = handle_token_request(conf, code=offer.pre_authorized_code,
                                     store=store)
        body = {'credential_configuration_id':
                offer.credential_configuration_ids[0],
                'proofs': {'jwt': [proof]}}
        return handle_credential_request(
            conf, body, access_token=token.access_token, store=store,
            nonces=nonces, **kwargs)

    def test_attested_proof_is_refused_without_a_resolver(self, conf, store,
                                                          nonces):
        # The default stays fail-closed: a kid nobody resolves is a refusal,
        # attestation or no attestation.
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        proof = self._attested_proof(nonce, key, jwk)
        with pytest.raises(OID4VCIError) as caught:
            self._request_with_proof(conf, store, nonces, proof)
        assert caught.value.error == INVALID_PROOF

    def test_attested_proof_issues_through_the_context_resolver(
            self, conf, store, nonces):
        from openbadgeslib.ob3.did import did_jwk_from_jwk
        key, jwk = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        proof = self._attested_proof(nonce, key, jwk)

        seen = []

        def resolver(ctx):
            # What the deployment actually gets: the kid, the alg, and the
            # parsed-but-unverified attestation to apply its own trust rule.
            seen.append(ctx)
            assert ctx.kid == 'wallet-key-1'
            assert ctx.alg == 'ES256'
            assert ctx.key_attestation is not None
            assert ctx.credential_issuer == ISSUER
            return dict(ctx.key_attestation.attested_keys[0])

        response = self._request_with_proof(
            conf, store, nonces, proof, resolve_proof_key_in_context=resolver)
        assert seen, 'the resolver was never called'
        claims = jwt.decode(response.credentials[0],
                            options={'verify_signature': False})
        assert claims['sub'] == did_jwk_from_jwk(jwk)

    def test_a_proof_signed_outside_its_attestation_is_refused(
            self, conf, store, nonces):
        # App. D's MUST: the proof must be signed by one of the attestation's
        # attested_keys. A resolver that hands back a key the wallet never
        # claimed gets the request rejected — the check can only refuse.
        key, jwk = _holder_key()
        other_priv, _ = _holder_key()
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        provider_priv = ec.generate_private_key(ec.SECP256R1())
        provider_jwk = json.loads(
            jwt.algorithms.ECAlgorithm.to_jwk(provider_priv.public_key()))
        # The attestation lists the holder key, but the proof is signed by
        # a different one.
        attestation = jwt.encode(
            {'attested_keys': [jwk], 'iat': int(time.time())},
            provider_priv, algorithm='ES256',
            headers={'typ': 'key-attestation+jwt', 'jwk': provider_jwk})
        proof = jwt.encode(
            {'aud': ISSUER, 'iat': int(time.time()), 'nonce': nonce},
            other_priv, algorithm='ES256',
            headers={'typ': 'openid4vci-proof+jwt', 'kid': 'wallet-key-1',
                     'key_attestation': attestation})
        with pytest.raises(OID4VCIError) as caught:
            self._request_with_proof(
                conf, store, nonces, proof,
                resolve_proof_key_in_context=lambda ctx: jwk)
        assert caught.value.error == INVALID_PROOF

    def test_a_malformed_attestation_is_refused_before_crypto(
            self, conf, store, nonces):
        nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        key, jwk = _holder_key()
        proof = jwt.encode(
            {'aud': ISSUER, 'iat': int(time.time()), 'nonce': nonce},
            key, algorithm='ES256',
            headers={'typ': 'openid4vci-proof+jwt', 'kid': 'wallet-key-1',
                     'key_attestation': 'not-a-jws'})
        with pytest.raises(OID4VCIError) as caught:
            self._request_with_proof(
                conf, store, nonces, proof,
                resolve_proof_key_in_context=lambda ctx: jwk)
        assert caught.value.error in (INVALID_PROOF, INVALID_CREDENTIAL_REQUEST)
