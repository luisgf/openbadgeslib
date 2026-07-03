"""Test-only helpers to produce eddsa-rdfc-2022 signed credentials.

The library is deliberately verify-only for Data Integrity; tests need a
signer to build fixtures, so a ~30-line one lives here (mirroring the W3C
vc-di-eddsa signing algorithm) and is shared by the library and CLI suites.
"""
import copy
import hashlib

from cryptography.hazmat.primitives import serialization as ser

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    out = ''
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b'\x00'))
    return '1' * pad + out


def did_key(pub_pem: bytes) -> str:
    pub = ser.load_pem_public_key(pub_pem)
    raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return 'did:key:z' + b58encode(b'\xed\x01' + raw)


def sign_ldp(document: dict, priv_pem: bytes, pub_pem: bytes, *,
             purpose: str = 'assertionMethod', extra_contexts=None) -> dict:
    """Sign *document* with an eddsa-rdfc-2022 Data Integrity proof."""
    from openbadgeslib.ob3.contexts import document_loader
    from openbadgeslib.ob3.ldp import _canonize
    did = did_key(pub_pem)
    proof = {
        'type': 'DataIntegrityProof',
        'cryptosuite': 'eddsa-rdfc-2022',
        'created': '2026-07-03T00:00:00Z',
        'verificationMethod': '%s#%s' % (did, did[len('did:key:'):]),
        'proofPurpose': purpose,
    }
    loader = document_loader(extra_contexts)
    config = dict(proof)
    config['@context'] = document['@context']
    cfg_hash = hashlib.sha256(_canonize(config, loader).encode()).digest()
    doc_hash = hashlib.sha256(_canonize(document, loader).encode()).digest()
    priv = ser.load_pem_private_key(priv_pem, password=None)
    signature = priv.sign(cfg_hash + doc_hash)
    signed = copy.deepcopy(document)
    signed['proof'] = dict(proof, proofValue='z' + b58encode(signature))
    return signed
