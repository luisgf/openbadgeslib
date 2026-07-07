"""JWS sign/verify backed by PyJWT algorithm implementations (RS256/384/512, ES256/384/512)."""

from typing import Any, Dict, Optional, Set, Union, cast

from . import utils
from .exceptions import SignatureError, MissingKey, MissingSigner, MissingVerifier, RouteMissingError

from jwt.algorithms import RSAAlgorithm, ECAlgorithm, OKPAlgorithm
from jwt.exceptions import InvalidKeyError

from ..keys import KeyType, detect_key_type, key_to_pem
from ..errors import UnknownKeyType

# Each entry is (algorithm class, hash id). EdDSA's OKPAlgorithm takes no hash
# argument — its hash id is None and _algo_for constructs it with no args.
_ALGORITHMS = {
    'RS256': (RSAAlgorithm, RSAAlgorithm.SHA256),
    'RS384': (RSAAlgorithm, RSAAlgorithm.SHA384),
    'RS512': (RSAAlgorithm, RSAAlgorithm.SHA512),
    'ES256': (ECAlgorithm,  ECAlgorithm.SHA256),
    'ES384': (ECAlgorithm,  ECAlgorithm.SHA384),
    'ES512': (ECAlgorithm,  ECAlgorithm.SHA512),
    'EdDSA': (OKPAlgorithm,  None),
}


def _algo_for(alg_name: str) -> Any:
    entry = _ALGORITHMS.get(alg_name)
    if entry is None:
        raise RouteMissingError(f"Algorithm {alg_name!r} is not supported")
    cls, hash_id = entry
    if hash_id is None:
        return cls()
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
    if key_type is KeyType.ED25519:
        return {'EdDSA'}
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
        return cast(bytes, algo.sign(signing_input, prepared))
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
    if not isinstance(alg_name, str) or not alg_name:
        # A non-string 'alg' (JSON array/object) is truthy but unhashable, so
        # it would raise a raw TypeError at the `not in allowed` membership
        # test below. Reject any non-string/empty alg here as a clean JWSException.
        raise MissingVerifier("JWS header 'alg' is missing or not a string")

    allowed = _allowed_algs_for_key(key)
    if not allowed:
        # Fail closed: if the key type cannot be classified we cannot pin the
        # algorithm to it, so refuse rather than let the header's 'alg' dictate
        # verification. Skipping the check here would reopen the cross-type
        # confusion / RS256->HS256 downgrade this guard exists to stop, were a
        # key type ever added without a matching branch in _allowed_algs_for_key.
        raise SignatureError(
            "Cannot determine the verification key type; refusing to verify a "
            "JWS whose algorithm cannot be pinned to the key")
    if alg_name not in allowed:
        raise SignatureError(
            "Algorithm %r in JWS header is not allowed for this key type"
            % alg_name)

    signing_input = head_b64 + b'.' + payload_b64
    try:
        raw_sig = utils.from_base64(sig_b64)
    except (ValueError, TypeError) as exc:
        raise SignatureError("Malformed JWS signature") from exc

    algo = _algo_for(alg_name)
    try:
        prepared = algo.prepare_key(key_to_pem(key))
        valid = algo.verify(signing_input, prepared, raw_sig)
    except (InvalidKeyError, ValueError, AttributeError, TypeError) as exc:
        # A private key served where a public key is expected reaches
        # RSAAlgorithm.verify() as an RSAPrivateKey, which has no .verify()
        # method — PyJWT lets the resulting AttributeError escape. Treat any
        # such key/algorithm mismatch as a failed signature, never a crash.
        raise SignatureError(str(exc)) from exc

    if not valid:
        raise SignatureError("Signature verification failed")

    return True
