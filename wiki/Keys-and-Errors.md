This page documents the key abstractions in `openbadgeslib.keys` and the full exception hierarchy you can catch. Keys describe *how* badges are signed (RSA, ECC, or Ed25519); errors tell you *why* an operation failed. For where these types are used see [[Python API OB2]] and [[Python API OB3]].

## Keys

Everything lives in `openbadgeslib.keys`. The library supports three key types, all backed by [`cryptography`](https://cryptography.io/) (already pulled in by `PyJWT[crypto]`): RSA, ECC on the NIST P-256 curve, and Ed25519. Signing and verification run through PyJWT; `keys.py` only generates and parses the key material.

### KeyType and the JWS algorithm

`KeyType` is an `enum.Enum` with three members:

```python
from openbadgeslib.keys import KeyType, alg_for_key_type

KeyType.RSA          # value: 'RSA 2048'
KeyType.ECC          # value: 'ECC NIST256p'
KeyType.ED25519      # value: 'Ed25519'

alg_for_key_type(KeyType.RSA)       # -> 'RS256'
alg_for_key_type(KeyType.ECC)       # -> 'ES256'
alg_for_key_type(KeyType.ED25519)   # -> 'EdDSA'
```

`alg_for_key_type(key_type)` returns the JWS algorithm the library signs with for a given key type. An unknown type raises `UnknownKeyType`.

### KeyFactory and the key classes

`KeyFactory(key_type=KeyType.RSA)` returns a fresh key object for the requested type. It returns a `KeyECC` for `KeyType.ECC`, a `KeyRSA` for `KeyType.RSA`, a `KeyEd25519` for `KeyType.ED25519`, and raises `UnknownKeyType` for anything else.

```python
from openbadgeslib.keys import KeyFactory, KeyType

key = KeyFactory(KeyType.ECC)        # -> KeyECC instance
priv_pem, pub_pem = key.generate_keypair()
```

`KeyRSA`, `KeyECC`, and `KeyEd25519` derive from `KeyBase` and share the same interface:

| Method | Purpose |
| --- | --- |
| `generate_keypair()` | Generate a new keypair; returns `(priv_key_pem, pub_key_pem)` |
| `read_private_key(key_pem=...)` | Load a private key from PEM |
| `read_public_key(key_pem=...)` | Load a public key from PEM |
| `get_priv_key_pem()` | Export the loaded/generated private key as PEM |
| `get_pub_key_pem()` | Export the loaded/generated public key as PEM |
| `get_priv_key()` | Return the underlying crypto object |
| `get_pub_key()` | Return the underlying crypto object |

`KeyRSA(key_size=2048)` defaults to a 2048-bit modulus; `KeyECC(key_curve=NIST256p)` defaults to the NIST256p curve; `KeyEd25519()` takes no parameters (the curve is fixed).

```python
from openbadgeslib.keys import KeyFactory, KeyType

# Generate
key = KeyFactory(KeyType.RSA)
priv_pem, pub_pem = key.generate_keypair()

# Load back later
key2 = KeyFactory(KeyType.RSA)
key2.read_private_key(key_pem=priv_pem)
key2.read_public_key(key_pem=pub_pem)
assert key2.get_priv_key_pem() == priv_pem
```

### Helper functions

`detect_key_type(pem_data)` guesses the `KeyType` from PEM bytes/str by probing Ed25519 first (the `ecdsa` library would otherwise misread an Ed25519 PEM as ECC), then trying to import it as RSA, then as an ECC verifying key, then as an ECC signing key. It raises `UnknownKeyType('Unable to guess Key type')` if none match.

```python
from openbadgeslib.keys import detect_key_type, KeyType

detect_key_type(priv_pem)   # -> KeyType.RSA, KeyType.ECC, or KeyType.ED25519
```

`key_to_pem(key)` normalises any supported key into PEM. It exports `cryptography` key objects (RSA, EC and Ed25519, public or private) — what the library now produces — passes `bytes`/`str` through unchanged, and still accepts a live `pycryptodome`/`python-ecdsa` object via a soft import (for a caller predating the 3.7 port). It raises `UnknownKeyType` for anything else. It is the single shared implementation used by the OB2 JWS layer and both OB3 signer/verifier.

```python
from openbadgeslib.keys import key_to_pem

pem = key_to_pem(key.get_priv_key())   # works for RSA, ECC, Ed25519, or raw PEM
```

## Errors

All library-level exceptions in `openbadgeslib.errors` inherit from a single root, so you can catch everything the library raises with one `except`.

### The hierarchy

```text
LibOpenBadgesException
├── KeyGenExceptions
│   ├── GenPrivateKeyError
│   ├── GenPublicKeyError
│   ├── PrivateKeySaveError
│   ├── PublicKeySaveError
│   ├── PrivateKeyReadError
│   ├── PublicKeyReadError
│   └── UnknownKeyType
├── SignerExceptions
│   └── ErrorSigningFile
├── VerifierExceptions
│   ├── AssertionFormatIncorrect
│   ├── NotIdentityInAssertion
│   └── ErrorParsingFile
├── BadgeImgFormatUnsupported
└── StatusError
    ├── StatusListFull
    ├── UnknownCredential
    ├── AmbiguousCredential
    ├── AlreadyRevoked
    ├── AlreadySuspended
    ├── NotSuspended
    └── RegistryCorrupt
```

`KeyGenExceptions`, `SignerExceptions`, `VerifierExceptions`, and `StatusError` are intermediate base classes; the leaves under each are the concrete errors raised in practice. `StatusError` groups the issuer-side credential-status (revocation/suspension) errors. `BadgeImgFormatUnsupported` hangs directly off `LibOpenBadgesException` (it is neither key, signer, verifier, nor status specific).

`UnknownKeyType` is the one you will see most when working with `openbadgeslib.keys` — `KeyFactory`, `alg_for_key_type`, `key_to_pem`, and `detect_key_type` all raise it.

### OB3 verification errors

OB3 verification raises `OB3VerificationError`, which **also** inherits from `LibOpenBadgesException`. That means a single broad `except LibOpenBadgesException` still catches OB3 failures alongside OB2 ones.

### What to catch

```python
from openbadgeslib.errors import (
    LibOpenBadgesException,    # catch-all root
    KeyGenExceptions,          # key generation / load / save
    SignerExceptions,          # signing
    VerifierExceptions,        # OB2 verification
    UnknownKeyType,            # bad / unrecognised key
)

try:
    # generate, sign, or verify ...
    ...
except VerifierExceptions:
    ...        # OB2 verification specifically failed
except LibOpenBadgesException:
    ...        # anything else from the library, including OB3VerificationError
```

Catch the most specific class you can act on; fall back to `LibOpenBadgesException` for a single safety net.

### Low-level JWS exceptions

The bundled JWS implementation in `openbadgeslib._jws` has its own small set of exceptions in `openbadgeslib._jws.exceptions`, all under a `JWSException` base, which **does** inherit from `LibOpenBadgesException`. A single `except LibOpenBadgesException` catches these too, alongside the OB2/OB3 errors above.

```text
LibOpenBadgesException
└── JWSException
    ├── MissingKey
    ├── MissingSigner
    ├── MissingVerifier
    ├── SignatureError
    └── RouteMissingError
```

| Exception | Meaning |
| --- | --- |
| `MissingKey` | No key was provided to the JWS operation |
| `MissingSigner` | No signer configured |
| `MissingVerifier` | No verifier configured |
| `SignatureError` | The JWS signature is invalid |
| `RouteMissingError` | No route registered for the operation |

These are internal plumbing; most code should catch the higher-level errors above. If you call into `_jws` directly, catch them explicitly (or catch the `JWSException` base for all of them at once):

```python
from openbadgeslib._jws.exceptions import SignatureError, MissingKey

try:
    ...
except SignatureError:
    ...        # raised on an invalid/forged JWS signature
```

See [[Python API OB2]] for where signer/verifier exceptions surface in OB2 workflows, and [[Python API OB3]] for `OB3VerificationError`.
