#!/usr/bin/env python3
"""Issue and verify an OpenBadges 3.0 credential as a compact JWT-VC.

The core OB 3.0 flow, end to end and self-contained (it generates its own key):
build a credential from your domain data, sign it, and verify it on the
receiving side. Run it with:

    python examples/ob3_jwt_vc.py

See the "Library Integration Tutorial" wiki page for the narrative.
"""
from openbadgeslib.keys import KeyFactory, KeyType
from openbadgeslib.ob3 import (Achievement, Issuer, OB3Signer, OB3Verifier,
                               OpenBadgeCredential)


def main() -> None:
    # 1. A signing key. Ed25519 here; RSA and ECC (P-256) work too — the signer
    #    picks the JWS algorithm from the key type.
    priv_pem, pub_pem = KeyFactory(KeyType.ED25519).generate_keypair()

    # 2. Build the credential from your application's data.
    credential = OpenBadgeCredential(
        issuer=Issuer(id='https://issuer.example/organization.json',
                      name='Example University'),
        recipient_id='mailto:learner@example.com',
        achievement=Achievement(
            id='https://issuer.example/badges/python-101',
            name='Python 101',
            description='Completed the introductory Python course.',
            criteria_narrative='Passed all assignments and the final project.'))

    # 3. Sign it into a compact JWT-VC string (what you deliver to the learner).
    token = OB3Signer(privkey_pem=priv_pem, algorithm='EdDSA').sign(credential)
    print('Issued a JWT-VC (%d chars).' % len(token))

    # 4. Verify on the receiving side. Pin the issuer's public key out-of-band
    #    and bind the credential to the expected recipient.
    verified = OB3Verifier(pubkey_pem=pub_pem).verify(
        token, expected_recipient='learner@example.com')
    print('Verified "%s" issued by "%s" to %s.'
          % (verified.achievement.name, verified.issuer.name,
             verified.recipient_id))

    assert verified.achievement.name == 'Python 101'


if __name__ == '__main__':
    main()
