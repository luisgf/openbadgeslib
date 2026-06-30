"""JWS sign/verify backed by PyJWT algorithm implementations (RS256/384/512, ES256/384/512)."""

from typing import Any, Dict, Optional, Set, Union

from . import utils
from .exceptions import SignatureError, MissingKey, MissingSigner, MissingVerifier, RouteMissingError

from jwt.algorithms import RSAAlgorithm, ECAlgorithm
from jwt.exceptions import InvalidKeyError

from ..keys import KeyType, detect_key_type, key_to_pem
from ..errors import UnknownKeyType

_ALGORITHMS = {
    'RS256': (RSAAlgorithm, RSAAlgorithm.SHA256),
    'RS384': (RSAAlgorithm, RSAAlgorithm.SHA384),
    'RS512': (RSAAlgorithm, RSAAlgorithm.SHA512),
    'ES256': (ECAlgorithm,  ECAlgorithm.SHA256),
    'ES384': (ECAlgorithm,  ECAlgorithm.SHA384),
    'ES512': (ECAlgorithm,  ECAlgorithm.SHA512),
}


def _algo_for(alg_name: str) -> Any:
    entry = _ALGORITHMS.get(alg_name)
    if entry is None:
        raise RouteMissingError(f"Algorithm {alg_name!r} is not supported")
    cls, hash_id = entry
    return cls(hash_id)


def _allowed_algs_for_key(key: Any) -> Set[str]:
    """Signature algorithms permitted for a verification key, bound to its type.

    Binding the accepted algorithm to the key type stops a forged JWS header
    from dictating the algorithm (cross-type confusion, and—were a symmetric
    entry ever added to _ALGORITHMS—the classic RS256->HS256 downgrade).
    """
    try:
        key_type = detect_key_type(key_to_pem(key))
    except UnknownKeyType:
        return set()
    if key_type is KeyType.RSA:
        return {'RS256', 'RS384', 'RS512'}
    if key_type is KeyType.ECC:
        return {'ES256', 'ES384', 'ES512'}
    return set()


def sign(header_dict: Dict[str, Any], payload_dict: Dict[str, Any], key: Any) -> bytes:
    """Sign header+payload dicts and return raw signature bytes."""
    if key is None:
        raise MissingKey("No signing key provided")
    alg_name = header_dict.get('alg')
    if not alg_name:
        raise MissingSigner("Header is missing 'alg'")

    signing_input = utils.encode(header_dict) + b'.' + utils.encode(payload_dict)
    algo = _algo_for(alg_name)
    try:
        prepared = algo.prepare_key(key_to_pem(key))
        return algo.sign(signing_input, prepared)
    except (InvalidKeyError, ValueError) as exc:
        raise SignatureError(str(exc)) from exc


def verify_block(msg: Union[str, bytes], key: Optional[Any] = None) -> bool:
    """Verify a JWS compact serialization (bytes or str). Returns True or raises SignatureError."""
    if isinstance(msg, str):
        msg = msg.encode('utf-8')

    try:
        head_b64, payload_b64, sig_b64 = msg.split(b'.')
    except ValueError:
        raise SignatureError("Malformed JWS: expected header.payload.signature")

    if key is None:
        raise MissingKey("No verification key provided")

    try:
        header = utils.decode(head_b64)
    except (ValueError, TypeError) as exc:
        raise SignatureError("Malformed JWS header") from exc
    if not isinstance(header, dict):
        raise SignatureError("Malformed JWS header")

    alg_name = header.get('alg')
    if not alg_name:
        raise MissingVerifier("JWS header is missing 'alg'")

    allowed = _allowed_algs_for_key(key)
    if allowed and alg_name not in allowed:
        raise SignatureError(
            "Algorithm %r in JWS header is not allowed for this key type"
            % alg_name)

    signing_input = head_b64 + b'.' + payload_b64
    raw_sig = utils.from_base64(sig_b64)

    algo = _algo_for(alg_name)
    try:
        prepared = algo.prepare_key(key_to_pem(key))
        valid = algo.verify(signing_input, prepared, raw_sig)
    except (InvalidKeyError, ValueError) as exc:
        raise SignatureError(str(exc)) from exc

    if not valid:
        raise SignatureError("Signature verification failed")

    return True
