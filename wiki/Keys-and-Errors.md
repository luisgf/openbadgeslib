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

`key_to_pem(key)` normalises any supported key into PEM. It exports `cryptography` key objects (RSA, EC and Ed25519, public or private) — what the library produces — and passes `bytes`/`str` through unchanged. It raises `UnknownKeyType` for anything else; since 4.0.0 that includes a live `pycryptodome`/`python-ecdsa` key object (the soft-import shim was removed — pass a `cryptography` key object or PEM instead). It is the single shared implementation used by the OB2 JWS layer and both OB3 signer/verifier.

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
│   ├── ErrorSigningFile
│   └── UnsupportedAlgorithm      (also a ValueError)
├── VerifierExceptions
│   ├── AssertionFormatIncorrect
│   ├── NotIdentityInAssertion
│   └── ErrorParsingFile
├── BadgeImgFormatUnsupported
├── ConfigError                   (also a ValueError)
├── IssuanceError
├── DecompressionLimitExceeded
├── StatusError
│   ├── StatusListFull
│   ├── UnknownCredential
│   ├── AlreadyRevoked
│   ├── AlreadySuspended
│   ├── NotSuspended
│   └── RegistryCorrupt
├── PublishError                  (openbadgeslib.ob3.publish)
│   ├── CredentialNotFound
│   └── AmbiguousCredential
├── OB2VerificationError          (openbadgeslib.ob2.verifier)
└── OB3VerificationError          (openbadgeslib.ob3.verifier)
```

`KeyGenExceptions`, `SignerExceptions`, `VerifierExceptions`, `StatusError`, and `PublishError` are intermediate base classes; the leaves under each are the concrete errors raised in practice. `StatusError` groups the issuer-side credential-status (revocation/suspension) errors. `PublishError` (raised by `openbadgeslib.ob3.publish` / `openbadges-publish`) groups OB3 publication and status-operation failures — note that `CredentialNotFound` and `AmbiguousCredential` are `PublishError`s, **not** `StatusError`s, so a caller handling "the revoke/suspend identifier matched several credentials (or none)" must catch `PublishError` (or the `LibOpenBadgesException` root), not `StatusError`. `BadgeImgFormatUnsupported`, `ConfigError`, `IssuanceError` and `DecompressionLimitExceeded` hang directly off `LibOpenBadgesException` (none is key, signer, verifier or status specific). `ConfigError` and `UnsupportedAlgorithm` **also** inherit `ValueError`, so code that historically caught a bare `ValueError` from the config helpers or a signer constructor keeps working. The same map lives in the `LibOpenBadgesException` docstring, so `help(openbadgeslib.errors.LibOpenBadgesException)` and this page agree.

`UnknownKeyType` is the one you will see most when working with `openbadgeslib.keys` — `KeyFactory`, `alg_for_key_type`, `key_to_pem`, and `detect_key_type` all raise it.

### OB2 and OB3 verification errors

> **`OB2VerificationError` is NOT a `VerifierExceptions`.** Both verification errors hang **directly** off `LibOpenBadgesException` (see the tree above), so `except VerifierExceptions` does *not* catch a failed OB 2.0 or OB 3.0 verdict — it catches the parse/identity family (`AssertionFormatIncorrect`, `NotIdentityInAssertion`, `ErrorParsingFile`), which is what the OB 1.0 reader and the OB2/OB3 token extractors raise. Catch `OB2VerificationError` / `OB3VerificationError` by name, or fall back to `LibOpenBadgesException`.

### What to catch

```python
from openbadgeslib.errors import (
    LibOpenBadgesException,    # catch-all root
    KeyGenExceptions,          # key generation / load / save
    SignerExceptions,          # signing
    VerifierExceptions,        # image/assertion parsing and identity binding
    ConfigError,               # missing / malformed config.ini
    UnknownKeyType,            # bad / unrecognised key
)
from openbadgeslib.ob2 import OB2VerificationError
from openbadgeslib.ob3 import OB3VerificationError

try:
    # generate, sign, or verify ...
    ...
except (OB2VerificationError, OB3VerificationError):
    ...        # the badge did not verify (bad signature, expired, revoked, ...)
except VerifierExceptions:
    ...        # the badge could not even be read (malformed image / assertion)
except ConfigError:
    ...        # config.ini is missing, empty or malformed
except LibOpenBadgesException:
    ...        # anything else from the library
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
