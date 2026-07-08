#!/usr/bin/env python3
"""Issue an OpenBadges 3.0 credential with an embedded W3C Data Integrity proof
(eddsa-rdfc-2022) and verify it.

Unlike the JWT-VC form, the credential is a self-contained JSON-LD document
carrying its own `proof`. This needs the [ldp] extra (a JSON-LD processor):

    pip install "openbadgeslib[ldp]"
    python examples/ob3_data_integrity.py

The issuer here is a did:key derived from the signing key (self-asserted); for a
trusted issuer publish a did:web with openbadges-publish. See the "Library
Integration Tutorial" and "Signing and Verification" wiki pages.
"""


def main() -> None:
    try:
        import pyld  # noqa: F401
    except ImportError:
        print('This example needs the [ldp] extra: '
              'pip install "openbadgeslib[ldp]". Skipping.')
        return

    from openbadgeslib.keys import KeyFactory, KeyType
    from openbadgeslib.ob3 import (Achievement, Issuer, OB3LdpVerifier,
                                   OpenBadgeCredential, add_data_integrity_proof)
    from openbadgeslib.ob3.did import did_key_from_pem

    # A did:key IS the signing key, so the proof's verificationMethod is derived
    # from it and the issuer id is that same did:key.
    priv_pem, pub_pem = KeyFactory(KeyType.ED25519).generate_keypair()
    did = did_key_from_pem(pub_pem)
    verification_method = '%s#%s' % (did, did[len('did:key:'):])

    credential = OpenBadgeCredential(
        issuer=Issuer(id=did, name='Example University'),
        recipient_id='mailto:learner@example.com',
        achievement=Achievement(
            id='https://issuer.example/badges/python-101', name='Python 101',
            description='Completed the introductory Python course.',
            criteria_narrative='Passed all assignments and the final project.'))

    # Sign: add a Data Integrity proof to the bare VC document.
    signed_document = add_data_integrity_proof(
        credential.to_vc(), priv_pem, verification_method)
    print('Signed with proof:', signed_document['proof']['cryptosuite'])

    # Verify the embedded proof (pin the public key).
    verified = OB3LdpVerifier(pubkey_pem=pub_pem).verify(
        signed_document, expected_recipient='learner@example.com')
    print('Verified "%s" (Data Integrity).' % verified.achievement.name)

    assert verified.achievement.name == 'Python 101'


if __name__ == '__main__':
    main()
