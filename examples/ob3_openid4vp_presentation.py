#!/usr/bin/env python3
"""Present an OpenBadges 3.0 Data Integrity badge over OpenID4VP, and verify it.

Three roles, one clean split of responsibilities:

  * ISSUER   — openbadgeslib issues the badge as an OB 3.0 Data Integrity
               credential (eddsa-rdfc-2022). Issuing credentials is this
               library's job.
  * HOLDER   — a wallet wraps the badge in a W3C Verifiable Presentation and
               signs a Data Integrity ``authentication`` proof bound to the
               verifier's request (challenge = nonce, domain = client_id).
  * VERIFIER — a relying party verifies the OpenID4VP ``vp_token`` against its
               DCQL query and that request binding.

The wallet-exchange rail (building the VP, ``verify_vp_token``) lives in
openvc-core, not here: openbadgeslib mints the credential, openvc-core carries
it over OpenID4VP 1.0. That is the delegation boundary the Certification
Cookbook describes. Needs the [ldp-sd] extra (openvc-core + a JSON-LD
processor):

    pip install "openbadgeslib[ldp-sd]"
    python examples/ob3_openid4vp_presentation.py
"""

from datetime import datetime, timezone


def main() -> None:
    try:
        import pyld  # noqa: F401
        from openvc.keys import Ed25519SigningKey
        from openvc.openid4vp import verify_vp_token
        from openvc.proof.data_integrity import DataIntegrityProofSuite
    except ImportError:
        print('This example needs the [ldp-sd] extra (openvc-core + pyld): '
              'pip install "openbadgeslib[ldp-sd]". Skipping.')
        return

    from openbadgeslib.keys import KeyFactory, KeyType
    from openbadgeslib.ob3 import (Achievement, Issuer, OB3LdpSigner,
                                   OpenBadgeCredential)
    from openbadgeslib.ob3.contexts import bundled_contexts
    from openbadgeslib.ob3.did import did_key_from_pem

    # openvc-core canonicalizes with its own engine, which does not bundle the
    # OB 3.0 (imsglobal) @context — hand it openbadgeslib's pinned, fail-closed
    # set so the badge inside the VP resolves without touching the network.
    ob3_contexts = bundled_contexts()

    def did_and_vm(pub_pem: bytes) -> tuple[str, str]:
        did = did_key_from_pem(pub_pem)
        return did, '%s#%s' % (did, did[len('did:key:'):])

    # ── HOLDER: a wallet key and its did:key identity ────────────────────────
    holder_priv, holder_pub = KeyFactory(KeyType.ED25519).generate_keypair()
    holder_did, holder_vm = did_and_vm(holder_pub)

    # ── ISSUER (openbadgeslib): issue the badge TO the holder ────────────────
    issuer_priv, issuer_pub = KeyFactory(KeyType.ED25519).generate_keypair()
    issuer_did, issuer_vm = did_and_vm(issuer_pub)
    badge = OpenBadgeCredential(
        issuer=Issuer(id=issuer_did, name='Example University'),
        recipient_id=holder_did,                  # subject == the wallet holder
        achievement=Achievement(
            id='https://issuer.example/badges/python-101', name='Python 101',
            description='Completed the introductory Python course.',
            criteria_narrative='Passed all assignments and the final project.'),
        issuance_date=datetime(2026, 1, 1, tzinfo=timezone.utc))
    secured_badge = OB3LdpSigner(issuer_priv, issuer_vm).sign(badge)
    print('Issuer minted an OB 3.0 Data Integrity badge "%s" for the holder.'
          % secured_badge['credentialSubject']['achievement']['name'])

    # ── VERIFIER: the OpenID4VP request the holder is answering ──────────────
    nonce = 'n-0S6_WzA2Mj'                         # per-session, from the request
    client_id = 'x509_san_dns:verifier.example'    # the full, prefixed Client ID
    dcql_query = {'credentials': [{'id': 'c1', 'format': 'ldp_vc'}]}

    # ── HOLDER (openvc-core): wrap the badge in a VP, bind it to the request ──
    presentation = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        'type': ['VerifiablePresentation'],
        'holder': holder_did,
        'verifiableCredential': [secured_badge],
    }
    holder_key = Ed25519SigningKey.from_pem(holder_priv, kid=holder_vm)
    vp = DataIntegrityProofSuite().add_proof(
        presentation, signing_key=holder_key, verification_method=holder_vm,
        proof_purpose='authentication', challenge=nonce, domain=client_id,
        extra_contexts=ob3_contexts)
    print('Holder presented it as an ldp_vc VP (authentication proof; '
          'challenge=nonce, domain=client_id).')

    # ── VERIFIER (openvc-core): verify the vp_token, bound to the request ────
    result = verify_vp_token(
        {'c1': [vp]}, dcql_query=dcql_query, nonce=nonce, client_id=client_id,
        extra_contexts=ob3_contexts,
        require_holder_binding=True)               # subject must equal the holder
    (p,) = result.presentations
    print('Verifier accepted the vp_token: format=%s, authenticated holder=%s'
          % (p.format, p.holder))
    print('  embedded badge issuer=%s' % p.credentials[0].issuer)
    print('  subject == authenticated holder: %s'
          % (p.credentials[0].subject == p.holder))

    assert p.format == 'ldp_vc'
    assert p.holder == holder_did
    assert p.credentials[0].subject == holder_did          # recipient-bound


if __name__ == '__main__':
    main()
