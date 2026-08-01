#!/usr/bin/env python3
"""Issue a badge to a wallet over OID4VCI, end to end, with no web server.

Walks the whole pre-authorized code flow in one process, playing both sides:

  * ISSUER — openbadgeslib builds the discovery documents and the Credential
             Offer, redeems the code, mints nonces, and issues the credential
             bound to the key the wallet proves it holds.
  * WALLET — a few lines of PyJWT standing in for a real wallet: it reads the
             offer, redeems the pre-authorized code with its out-of-band PIN,
             fetches a nonce and signs an `openid4vci-proof+jwt`.

There is deliberately NO HTTP here. openbadgeslib returns response bodies; the
routes are yours to mount. What the wallet would POST is passed straight to the
handler, which is exactly what your framework would do after parsing the body.

The wallet key-proof cryptography is openvc-core's (`openvc.openid4vci`); the
offers, the state and the response bodies are openbadgeslib's. Needs the
[oid4vci] extra:

    pip install "openbadgeslib[oid4vci]"
    python examples/oid4vci_pre_authorized_flow.py
"""

import json
import tempfile
import time
from pathlib import Path


CONFIG = """\
[paths]
base = {base}
base_log = {base}/log
base_image = {images}

[logs]
general = general.log
signer = signer.log

[issuer]
name = Example Issuer
url = https://example.org
publish_url = https://badges.example.org/issuer/

[oid4vci]
credential_issuer = https://badges.example.org/issuer/
offer_ttl_s = 600

[badge_1]
name = Python Wizard
description = Awarded for shipping a wallet integration
local_image = {image}
image = https://badges.example.org/issuer/badge_1/badge.svg
criteria = https://badges.example.org/issuer/badge_1/criteria.html
criteria_narrative = Ship an OID4VCI integration
verify_key = https://badges.example.org/issuer/badge_1/verify.pem
badge = https://badges.example.org/issuer/badge_1/badge.json
crypto_key = https://badges.example.org/issuer/badge_1/key.json
private_key = {base}/keys/sign.pem
public_key = {base}/keys/verify.pem
key_type = ED25519
oid4vci_formats = jwt_vc_json
status_lists = revocation
"""


def main() -> None:
    try:
        import openvc.openid4vci  # noqa: F401
    except ImportError:
        print('This example needs the [oid4vci] extra (openvc-core >= 1.23): '
              'pip install "openbadgeslib[oid4vci]". Skipping.')
        return

    import jwt
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from openbadgeslib.confparser import load_config
    from openbadgeslib.keys import KeyFactory, KeyType
    from openbadgeslib.ob3 import OB3Verifier
    from openbadgeslib.oid4vci import (InMemoryOID4VCIStore, NonceIssuer,
                                       build_authorization_server_metadata,
                                       build_credential_offer,
                                       build_issuer_metadata,
                                       handle_credential_request,
                                       handle_nonce_request,
                                       handle_token_request)

    with tempfile.TemporaryDirectory() as workdir:
        base = Path(workdir)
        (base / 'log').mkdir()
        (base / 'keys').mkdir()
        images = Path(__file__).parent.parent / 'tests' / 'images'

        # A throwaway issuer key, so the example is self-contained.
        priv_pem, pub_pem = KeyFactory(KeyType.ED25519).generate_keypair()
        (base / 'keys' / 'sign.pem').write_bytes(priv_pem)
        (base / 'keys' / 'verify.pem').write_bytes(pub_pem)

        config_path = base / 'config.ini'
        config_path.write_text(CONFIG.format(base=base, images=images,
                                             image='sample1.svg'))
        conf = load_config(str(config_path))

        # State: in memory because this is one process. A real deployment uses
        # SqliteOID4VCIStore — InMemoryOID4VCIStore reports multiprocess_safe
        # = False and loses its atomicity across workers.
        store = InMemoryOID4VCIStore()
        nonces = NonceIssuer(store, ttl_s=120)

        # ── ISSUER: the two documents a wallet reads first ───────────────────
        metadata = build_issuer_metadata(conf)
        as_metadata = build_authorization_server_metadata(conf)
        print('# Discovery')
        print('  credential_issuer :', metadata['credential_issuer'])
        print('  credential_endpoint:', metadata['credential_endpoint'])
        print('  offers            :',
              ', '.join(metadata['credential_configurations_supported']))
        print('  token_endpoint    :', as_metadata['token_endpoint'])

        # ── ISSUER: build an offer for a named learner ───────────────────────
        offer = build_credential_offer(conf, 'badge_1', 'learner@example.org',
                                       store=store, tx_code=True)
        print('\n# Offer')
        print('  QR payload        :', offer.uri[:68] + '...')
        print('  fits in a QR code :', offer.fits_in_a_qr_code)
        print('  tx_code           :', offer.tx_code,
              '(send this by a DIFFERENT channel)')
        print('  status slot       :', offer.status_index, '(reserved)')

        # ── WALLET: read the offer, redeem the code ──────────────────────────
        from urllib.parse import parse_qs, urlparse
        scanned = json.loads(
            parse_qs(urlparse(offer.uri).query)['credential_offer'][0])
        grants = scanned['grants'][
            'urn:ietf:params:oauth:grant-type:pre-authorized_code']
        token = handle_token_request(conf, code=grants['pre-authorized_code'],
                                     tx_code=offer.tx_code, store=store)
        print('\n# Token')
        print('  response          :', json.dumps(token.to_dict())[:64] + '...')

        # ── WALLET: fetch a nonce and prove it holds its key ─────────────────
        c_nonce = handle_nonce_request(conf, nonces=nonces)['c_nonce']
        holder = ed25519.Ed25519PrivateKey.generate()
        holder_jwk = json.loads(
            jwt.algorithms.OKPAlgorithm.to_jwk(holder.public_key()))
        key_proof = jwt.encode(
            {'aud': metadata['credential_issuer'], 'iat': int(time.time()),
             'nonce': c_nonce, 'iss': 'example-wallet'},
            holder, algorithm='EdDSA',
            headers={'typ': 'openid4vci-proof+jwt', 'jwk': holder_jwk})

        # ── ISSUER: verify the proof and issue ───────────────────────────────
        response = handle_credential_request(
            conf,
            {'credential_configuration_id':
                scanned['credential_configuration_ids'][0],
             'proofs': {'jwt': [key_proof]}},
            access_token=token.access_token, store=store, nonces=nonces)
        credential_jwt = response.credentials[0]
        print('\n# Credential')
        print('  body              :',
              json.dumps(response.to_dict())[:64] + '...')

        # ── Anyone: verify what the wallet received ──────────────────────────
        pubkey = (base / 'keys' / 'verify.pem').read_bytes()
        credential = OB3Verifier(pubkey_pem=pubkey).verify(credential_jwt)
        print('  achievement       :', credential.achievement.name)
        print('  bound to holder   :', credential.recipient_id[:44] + '...')
        print('  recipient (hashed):',
              credential.identifiers[0].identity_hash[:24] + '...')
        print('  revocable         :',
              bool(credential.credential_status))

        # ── The replay defences, demonstrated ────────────────────────────────
        from openbadgeslib.oid4vci.errors import OID4VCIError
        print('\n# Replay defences')
        for label, call in (
            ('reuse the nonce',
             lambda: handle_credential_request(
                 conf,
                 {'credential_configuration_id':
                     scanned['credential_configuration_ids'][0],
                  'proofs': {'jwt': [key_proof]}},
                 access_token=token.access_token, store=store, nonces=nonces)),
            ('reuse the code',
             lambda: handle_token_request(
                 conf, code=grants['pre-authorized_code'],
                 tx_code=offer.tx_code, store=store)),
        ):
            try:
                call()
                print('  %-18s NOT REFUSED' % label)
            except OID4VCIError as exc:
                print('  %-18s refused: %s (HTTP %d)'
                      % (label, exc.error, exc.http_status))

        store.close()


if __name__ == '__main__':
    main()
