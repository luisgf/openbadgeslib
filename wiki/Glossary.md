A reference of the terms, standards, file formats, and crypto primitives used across openbadgeslib. For how these pieces fit together, see [[OB2 vs OB3]] and [[Signing and Verification]].

## A

### Achievement
The thing a badge certifies (a skill, course, or accomplishment). In OB3 this is the `Achievement` object inside the credential; in OB2 the equivalent role is played by the [BadgeClass](#badgeclass).

### Apache
Open-source HTTP server. Mentioned as one option for publicly hosting issued badges and key/verification files. See [[Guides]].

### Assertion
An Open Badges document describing a badge award: who earned it, when, under what criteria, and how to verify the issuer's signature. In OB2 signed badges the assertion is serialised as a [JWS](#jws) token and baked into the badge image (SVG/PNG). See [[Signing and Verification]].

## B

### Badge
The end artifact: an image (SVG or PNG) with a signed assertion embedded in it (OB2), or a Verifiable Credential document (OB3). The [[Quick Start]] walks through producing one.

### BadgeClass
The OB2 definition of a badge type: its name, description, criteria, image, and issuer. Each [Assertion](#assertion) references the BadgeClass it instantiates.

### BSD 2-Clause
The BSD 2-Clause License, under which the openbadgeslib command-line wrapper tools are released. See [[Authors License and FAQ]].

## C

### Credential
General term for a signed claim about a subject. In OB3 the concrete type is the `OpenBadgeCredential`, a [Verifiable Credential](#verifiable-credential) signed as [JWT-VC](#jwt-vc). See [[Python API OB3]].

## E

### ECC
Elliptic Curve Cryptography. This library uses the NIST P-256 curve with ECDSA and SHA-256 (algorithm identifier `ES256`). See [[Security Model]].

### ecdsa
A pure-Python implementation of ECDSA cryptography. Used by this library for ECC key generation, loading, and PEM serialisation.

### Ed25519
An Edwards-curve digital signature scheme (EdDSA over Curve25519). This library supports it via the `cryptography` package (JWS algorithm identifier `EdDSA`). See [[Security Model]].

## I

### IIS
Internet Information Services, the web server bundled with Microsoft Windows Server. One hosting option for published badge files.

### Issuer
The entity awarding the badge. Its identity and public key let a verifier confirm the signature. Configured under the issuer section of `config.ini`; see [[Configuration]].

## J

### JWS
JSON Web Signature (RFC 7515): content secured with a digital signature in a JSON-based structure. openbadgeslib uses the compact serialisation `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`. This is the proof format baked into OB2 badges.

### JWT
JSON Web Token (RFC 7519): an application of [JWS](#jws) whose payload is a JSON object of claims. [PyJWT](#pyjwt) implements the signing and verification algorithms used here.

### JWT-VC
A [JWT](#jwt) used as a W3C Verifiable Credential proof format. The payload carries standard claims (`iss`, `sub`, `jti`, `iat`, `exp`) plus a `vc` claim holding the full credential object. OB3 uses JWT-VC to sign `OpenBadgeCredential` documents. See [[OB2 vs OB3]].

## L

### LGPL3
The GNU Lesser General Public License v3, under which the openbadgeslib core library is released. See [[Authors License and FAQ]].

## M

### Metadata
Data embedded in a file that describes its content. In Open Badges, the [Assertion](#assertion) is metadata embedded in the badge image.

## N

### Nginx
A lightweight HTTP server and reverse proxy. One option for hosting published badge and verification files.

## O

### OpenBadge / Open Badges
The IMS Global Open Badges specification: a standard for digital badges carrying verifiable metadata and cryptographic proofs of achievement. Originally created by Mozilla, now maintained by the IMS Global Learning Consortium. This library supports strict OB 2.0 and OB 3.0, plus a frozen OB 1.0 legacy format — see [[OB2 vs OB3]].

### OpenBadgeCredential
The OB3 credential type produced by this library — a [Verifiable Credential](#verifiable-credential) describing an [Achievement](#achievement), signed as [JWT-VC](#jwt-vc).

## P

### PEM
Privacy-Enhanced Mail encoding: the Base64 text format (with `-----BEGIN ...-----` delimiters) used to store the RSA/ECC keys this library generates. Keys live as `.pem` files; see [[Keys and Errors]].

### PEP8
PEP 8 — Style Guide for Python Code, the coding conventions followed by this project. See [[Contributing]].

### PNG
Portable Network Graphics, a raster image format with lossless compression. One of the two image formats openbadgeslib can bake an OB2 assertion into.

### pycryptodome
A self-contained Python package of low-level cryptographic primitives (a maintained fork of `pycrypto`). Used for RSA key generation and PEM serialisation (ECC is handled by `ecdsa`, Ed25519 by `cryptography`).

### PyJWT
A Python library for encoding/decoding JSON Web Tokens. openbadgeslib uses `jwt.algorithms.RSAAlgorithm`, `jwt.algorithms.ECAlgorithm`, and `jwt.algorithms.OKPAlgorithm` (Ed25519/EdDSA) for JWS signing and verification; requires the `cryptography` package (installed via `PyJWT[crypto]`). See [[Installation]].

### pypng
A pure-Python library for reading and writing PNG image files.

### Python
A high-level, general-purpose programming language emphasising code readability. openbadgeslib targets Python 3 — see [[Installation]].

## R

### Recipient
The person being awarded the badge, identified by email (typically hashed with a [salt](#salt) for privacy). Supplied when signing; see [[CLI Reference]].

### revocationList
A list, published by the issuer, of assertions/credentials that have been revoked. A verifier consults it to reject badges the issuer has withdrawn. See [[Security Model]].

### RSA
A widely used public-key cryptosystem. This library uses RSA 2048-bit keys with PKCS#1 v1.5 padding and SHA-256 (algorithm identifier `RS256`).

## S

### salt
A random value combined with the recipient's email before hashing, so the same email does not always produce the same identity hash. Protects recipient privacy in published badges.

### SVG
Scalable Vector Graphics, an XML-based vector image format. One of the two image formats openbadgeslib can bake an OB2 assertion into.

## V

### Verifiable Credential
A W3C data-model standard for tamper-evident, cryptographically verifiable claims about a subject. OB3 expresses badges as Verifiable Credentials signed via [JWT-VC](#jwt-vc). See [[OB2 vs OB3]].

## See also

- [[Signing and Verification]] — how assertions and credentials are produced and checked
- [[Security Model]] — key handling, algorithms, and revocation
- [[CLI Reference]] — the five `openbadges-*` commands
