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

# Protocol-level failures, carrying the error code OID4VCI defines for them.
#
# Everything raised here is the CLIENT's fault and maps to HTTP 400 with
# `Cache-Control: no-store`. That uniformity is deliberate: it is the whole of
# what an integrator needs to know to wire these into a framework, and it means
# this module never has to learn what HTTP is.
#
# An issuer-side failure — a broken config, an unreadable key, a full status
# list — is NOT translated. It stays an IssuanceError and reaches the caller as
# a 500, because telling a wallet its request was invalid when the issuer is
# the one that is broken makes the wallet retry a request that can never
# succeed.

from typing import Dict

from ..errors import LibOpenBadgesException


class OID4VCIError(LibOpenBadgesException):
    """A client-attributable failure at an OID4VCI endpoint.

    ``error`` is the code from the spec, ``description`` the human-readable
    detail, and :meth:`to_dict` the JSON error body verbatim. ``http_status``
    is the status to serve it with — 400 for everything except a bad access
    token, which OAuth 2.0 requires be a 401. Carrying the number here rather
    than making the integrator memorise the exception is the difference
    between a two-line handler and a table they have to keep in step with us.

    Serve every one of these with ``Cache-Control: no-store``.
    """

    def __init__(self, error: str, description: str,
                 http_status: int = 400) -> None:
        self.error = error
        self.description = description
        self.http_status = http_status
        super().__init__('%s: %s' % (error, description))

    def to_dict(self) -> Dict[str, str]:
        return {'error': self.error, 'error_description': self.description}


# ── the error codes this package can emit ────────────────────────────────────

#: The Credential Request was malformed or asked for something not granted.
INVALID_CREDENTIAL_REQUEST = 'invalid_credential_request'
#: A key proof failed to verify. The wallet must fix its proof.
INVALID_PROOF = 'invalid_proof'
#: The nonce was missing, unknown, expired or already spent. The wallet must
#: fetch a fresh one from the nonce endpoint and retry — which is why getting
#: this code right matters more than it looks: the other codes carry no such
#: instruction, so a misrouted nonce failure leaves the wallet stuck.
INVALID_NONCE = 'invalid_nonce'
#: Response encryption was requested; this issuer does not implement it.
INVALID_ENCRYPTION_PARAMETERS = 'invalid_encryption_parameters'
#: The pre-authorized code was unknown, expired, already redeemed or killed.
INVALID_GRANT = 'invalid_grant'
#: The token request itself was malformed (missing tx_code, bad grant type).
INVALID_REQUEST = 'invalid_request'
#: The access token was missing, unknown or expired. Served as HTTP 401 with a
#: ``WWW-Authenticate: Bearer`` header, per RFC 6750 — not 400.
INVALID_TOKEN = 'invalid_token'

#: openvc exception class name -> OID4VCI error code.
#:
#: Indexed by CLASS NAME rather than by the imported class on purpose: it keeps
#: this module free of any openvc import, even a lazy one, so the whole error
#: surface is importable and testable without the [oid4vci] extra installed.
_ERROR_CODES: Dict[str, str] = {
    'CredentialRequestMalformed': INVALID_CREDENTIAL_REQUEST,
    'ProofReplayed': INVALID_NONCE,
    'UnsupportedProofType': INVALID_PROOF,
    'SignatureInvalid': INVALID_PROOF,
    'MalformedToken': INVALID_PROOF,
    'UnsupportedAlgorithm': INVALID_PROOF,
    'ClaimsInvalid': INVALID_PROOF,
}

#: openvc reports a proof with no nonce as a generic ClaimsInvalid rather than
#: a dedicated type, so the class name alone cannot distinguish "your proof is
#: wrong" from "you forgot the nonce" — and those two need different codes,
#: because only invalid_nonce tells the wallet to go and fetch one. Matching
#: openvc's own wording is narrow and slightly brittle, so it is pinned by a
#: test; the clean fix is a dedicated exception type upstream.
_MISSING_NONCE_MARKER = 'missing the required nonce'


def as_oid4vci_error(exc: BaseException) -> OID4VCIError:
    """Translate an exception from openvc into a typed protocol error.

    Anything unrecognised becomes ``invalid_credential_request`` rather than
    escaping: an unknown verification failure must still be a refusal, never a
    success and never a traceback out of an endpoint.
    """
    name = type(exc).__name__
    message = str(exc)
    if name == 'ClaimsInvalid' and _MISSING_NONCE_MARKER in message:
        return OID4VCIError(INVALID_NONCE, message)
    return OID4VCIError(_ERROR_CODES.get(name, INVALID_CREDENTIAL_REQUEST),
                        message)


__all__ = [
    'INVALID_CREDENTIAL_REQUEST', 'INVALID_ENCRYPTION_PARAMETERS',
    'INVALID_GRANT', 'INVALID_NONCE', 'INVALID_PROOF', 'INVALID_REQUEST',
    'INVALID_TOKEN', 'OID4VCIError', 'as_oid4vci_error',
]
