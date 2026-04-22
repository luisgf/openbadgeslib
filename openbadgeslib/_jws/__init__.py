"""JWS sign/verify backed by PyJWT algorithm implementations (RS256/384/512, ES256/384/512)."""

from . import utils
from .exceptions import SignatureError, MissingKey, MissingSigner, MissingVerifier, RouteMissingError

from jwt.algorithms import RSAAlgorithm, ECAlgorithm
from jwt.exceptions import InvalidKeyError

_ALGORITHMS = {
    'RS256': (RSAAlgorithm, RSAAlgorithm.SHA256),
    'RS384': (RSAAlgorithm, RSAAlgorithm.SHA384),
    'RS512': (RSAAlgorithm, RSAAlgorithm.SHA512),
    'ES256': (ECAlgorithm,  ECAlgorithm.SHA256),
    'ES384': (ECAlgorithm,  ECAlgorithm.SHA384),
    'ES512': (ECAlgorithm,  ECAlgorithm.SHA512),
}


def _key_to_pem(key):
    """Convert a pycryptodome or ecdsa key object to PEM bytes; pass through bytes/str."""
    from Crypto.PublicKey import RSA as _RSA
    from ecdsa import SigningKey as _SK, VerifyingKey as _VK
    if isinstance(key, _RSA.RsaKey):
        return key.export_key('PEM')
    if isinstance(key, (_SK, _VK)):
        return key.to_pem()
    if isinstance(key, (bytes, str)):
        return key
    raise ValueError(f"Unsupported key type: {type(key)}")


def _algo_for(alg_name):
    entry = _ALGORITHMS.get(alg_name)
    if entry is None:
        raise RouteMissingError(f"Algorithm {alg_name!r} is not supported")
    cls, hash_id = entry
    return cls(hash_id)


def sign(header_dict, payload_dict, key):
    """Sign header+payload dicts and return raw signature bytes."""
    if key is None:
        raise MissingKey("No signing key provided")
    alg_name = header_dict.get('alg')
    if not alg_name:
        raise MissingSigner("Header is missing 'alg'")

    signing_input = utils.encode(header_dict) + b'.' + utils.encode(payload_dict)
    algo = _algo_for(alg_name)
    try:
        prepared = algo.prepare_key(_key_to_pem(key))
        return algo.sign(signing_input, prepared)
    except (InvalidKeyError, ValueError) as exc:
        raise SignatureError(str(exc)) from exc


def verify_block(msg, key=None):
    """Verify a JWS compact serialization (bytes or str). Returns True or raises SignatureError."""
    if isinstance(msg, str):
        msg = msg.encode('utf-8')

    try:
        head_b64, payload_b64, sig_b64 = msg.split(b'.')
    except ValueError:
        raise SignatureError("Malformed JWS: expected header.payload.signature")

    if key is None:
        raise MissingKey("No verification key provided")

    header = utils.decode(head_b64)
    alg_name = header.get('alg')
    if not alg_name:
        raise MissingVerifier("JWS header is missing 'alg'")

    signing_input = head_b64 + b'.' + payload_b64
    raw_sig = utils.from_base64(sig_b64)

    algo = _algo_for(alg_name)
    try:
        prepared = algo.prepare_key(_key_to_pem(key))
        valid = algo.verify(signing_input, prepared, raw_sig)
    except (InvalidKeyError, ValueError) as exc:
        raise SignatureError(str(exc)) from exc

    if not valid:
        raise SignatureError("Signature verification failed")

    return True
