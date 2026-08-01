"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es

        All rights reserved.

        This library is free software; you can redistribute it and/or
        modify it under the terms of the GNU Lesser General Public
        License as published by the Free Software Foundation; either
        version 3.0 of the License, or (at your option) any later version.

        This library is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
        Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public
        License along with this library.
"""

# OpenID for Verifiable Credential Issuance (OID4VCI 1.0), issuer side,
# pre-authorized code flow.
#
# WHAT THIS IS. Everything an issuer needs to hand a badge to a wallet: build a
# Credential Offer, redeem its pre-authorized code, mint and consume nonces,
# verify the wallet's key proof and issue the credential bound to the key that
# proof demonstrated. It returns dicts and dataclasses.
#
# WHAT THIS IS NOT: a server. There are no routes, no framework, no TLS and no
# HTTP dependency — the caller owns those. That is not an omission but the
# boundary this library keeps everywhere else too (openbadges-publish writes
# files for the operator to serve; it does not serve them). Every error this
# package raises maps to HTTP 400 with a `Cache-Control: no-store` header,
# which is the whole of what an integrator needs to know to wire it up.
#
# THE SPLIT WITH openvc-core. The cryptography that runs over attacker-supplied
# bytes — verifying the wallet's `openid4vci-proof+jwt`, and validating the
# Credential Request's shape — lives in openvc.openid4vci and is reached
# through the [oid4vci] extra. That code has to sit at openvc's raw-JWS layer,
# and reimplementing it here would mean a second signature check that could
# drift from the first. What openvc refuses to hold is anything with a
# lifetime: the nonce store, the offer lifecycle, the codes and the tokens.
# Those are this package's job, and the security property they carry — never
# issuing a credential to a key that did not prove possession of it — is ours,
# not openvc's.
#
# WHAT IS NOT SUPPORTED, and must not be claimed:
#   * No DPoP, no key attestation verification, no client authentication, and
#     no authorization code flow. HAIP requires all four, so **this is not a
#     HAIP-conformant issuer** and nothing built on it may say otherwise.
#   * Access tokens are bearer tokens (RFC 6750): within their short lifetime a
#     stolen token is replayable.
#   * `vc+sd-jwt` badges are irrevocable (#226).
#   * No rate limiting, no TLS, no request-size ceiling above what the handlers
#     check — the integrator owns the edge.

from .errors import OID4VCIError
from .formats import (EC_ONLY_FORMATS, FORMAT_JWT_VC_JSON, FORMAT_SD_JWT_VC,
                      OID4VCI_FORMATS, REVOCABLE_FORMATS)
from .handler import (CredentialResponse, TokenResponse,
                      handle_credential_request, handle_nonce_request,
                      handle_token_request)
from .memory_store import InMemoryOID4VCIStore
from .metadata import (build_authorization_server_metadata,
                       build_issuer_metadata, credential_configuration_id,
                       offered_badges)
from .nonce import NonceIssuer
from .offer import CredentialOffer, build_credential_offer
from .reconcile import ReconcileResult, reconcile_reservations
from .sqlite_store import SqliteOID4VCIStore
from .store import (OID4VCIStore, OID4VCIStoreError, PreAuthorizedGrant,
                    PurgeStats, issuance_fingerprint)

__all__ = [
    # Credential-format vocabulary.
    'EC_ONLY_FORMATS',
    'FORMAT_JWT_VC_JSON',
    'FORMAT_SD_JWT_VC',
    'OID4VCI_FORMATS',
    'REVOCABLE_FORMATS',
    # Discovery documents.
    'build_authorization_server_metadata',
    'build_issuer_metadata',
    'credential_configuration_id',
    'offered_badges',
    # Offers.
    'CredentialOffer',
    'build_credential_offer',
    # Reconciling unclaimed status-list reservations (offline).
    'ReconcileResult',
    'reconcile_reservations',
    # Request handlers.
    'CredentialResponse',
    'TokenResponse',
    'handle_credential_request',
    'handle_nonce_request',
    'handle_token_request',
    # Errors.
    'OID4VCIError',
    'OID4VCIStoreError',
    # State: the Protocol, its two implementations, and the nonce machinery.
    'InMemoryOID4VCIStore',
    'NonceIssuer',
    'OID4VCIStore',
    'PreAuthorizedGrant',
    'PurgeStats',
    'SqliteOID4VCIStore',
    'issuance_fingerprint',
]
