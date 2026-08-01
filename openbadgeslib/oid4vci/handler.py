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

# The three request handlers: token, nonce and credential.
#
# Each takes what a request carries and returns what the response body should
# be. They never see a socket, a header or a status code — the integrator maps
# OID4VCIError.http_status and mounts the routes. Wiring one up is two lines:
#
#     try:
#         return 200, handle_credential_request(conf, body, ...).to_dict()
#     except OID4VCIError as exc:
#         return exc.http_status, exc.to_dict()
#
# WHAT DECIDES WHAT GETS ISSUED. Not the request. The access token resolves to
# a grant, and the grant already fixed the badge, the recipient, the format and
# the status slot when the offer was built. The wallet's Credential Request can
# only be checked against that — its credential_configuration_id must MATCH, it
# cannot select — and the only thing it genuinely contributes is the holder key
# its proof demonstrates possession of. That is the shape of "no wrong-issue":
# there is no code path where a request parameter widens what is issued.

import configparser
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Union

from ..confparser import oid4vci_config
from ..issue import CredentialResult, issue_credential_from_conf
from .codes import (dummy_tx_verification, new_secret, secret_id,
                    verify_tx_code)
from .errors import (INVALID_CREDENTIAL_REQUEST,
                     INVALID_ENCRYPTION_PARAMETERS, INVALID_GRANT,
                     INVALID_REQUEST, INVALID_TOKEN, OID4VCIError,
                     as_oid4vci_error)
from .metadata import PRE_AUTHORIZED_GRANT, parse_credential_configuration_id
from .nonce import NonceIssuer
from .store import (CLAIM_CONFLICT, CLAIM_GONE, OID4VCIStoreError,
                    PreAuthorizedGrant, STATE_OFFERED, issuance_fingerprint)

_INSTALL_HINT = (
    'OID4VCI issuance needs the [oid4vci] extra: pip install '
    'openbadgeslib[oid4vci]')

#: A Credential Request body larger than this is refused before it is parsed.
#: The same posture util.MAX_DOWNLOAD_SIZE takes for outbound fetches, applied
#: to what arrives: a hostile body must not make us allocate first and think
#: later. Generous next to a batch of key proofs, which are small JWSs.
MAX_REQUEST_BYTES = 128 * 1024


def _require_openvc() -> Any:
    """Import the openvc-core OID4VCI pieces, or raise with an actionable hint."""
    try:
        from openvc.openid4vci import (parse_credential_request,
                                       verify_credential_request_proofs)
    except ImportError as exc:
        raise OID4VCIError(INVALID_CREDENTIAL_REQUEST, _INSTALL_HINT) from exc
    return parse_credential_request, verify_credential_request_proofs


@dataclass
class TokenResponse:
    """The token endpoint's answer: an access token bound to one grant."""

    access_token: str
    expires_in: int
    grant: PreAuthorizedGrant
    token_type: str = 'Bearer'

    def to_dict(self) -> Dict[str, Any]:
        return {'access_token': self.access_token,
                'token_type': self.token_type,
                'expires_in': self.expires_in}


@dataclass
class CredentialResponse:
    """The credential endpoint's answer, plus what the issuer should log.

    ``to_dict`` is the wire body. ``issued`` carries the
    :class:`~openbadgeslib.issue.CredentialResult` per credential so the caller
    can write its audit line without re-parsing tokens it just produced.
    """

    credentials: List[str]
    credential_configuration_id: str
    credential_format: str
    issued: List[CredentialResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {'credentials': [{'credential': token}
                                for token in self.credentials]}


def handle_token_request(conf: configparser.ConfigParser, *, code: str,
                         tx_code: Optional[str] = None, store: Any,
                         grant_type: str = PRE_AUTHORIZED_GRANT,
                         now: Optional[datetime] = None) -> TokenResponse:
    """Exchange a pre-authorized code for an access token.

    Mints the token and binds it to the grant, so the caller does not have to
    invent a session mechanism — the mapping from token to grant is the state
    this library already keeps, and asking every integrator to rebuild it is
    asking them to rebuild the part that is easy to get wrong.

    Raises :class:`OID4VCIError`. Unknown, expired, already-redeemed and
    invalidated codes all produce the SAME ``invalid_grant`` with the same
    message and, by way of :func:`~openbadgeslib.oid4vci.codes.
    dummy_tx_verification`, in the same time — otherwise the endpoint becomes
    an oracle for which codes exist.
    """
    moment = now or datetime.now(tz=timezone.utc)
    cfg = oid4vci_config(conf)
    if grant_type != PRE_AUTHORIZED_GRANT:
        raise OID4VCIError(
            INVALID_REQUEST,
            'this issuer only supports the pre-authorized code grant')
    if not code or not isinstance(code, str):
        raise OID4VCIError(INVALID_REQUEST,
                           'the pre-authorized_code parameter is required')

    grant = store.find_grant_by_code(secret_id(code), now=moment)
    if grant is None:
        # Burn the same work a real tx_code check costs, so "no such code" and
        # "wrong PIN" are indistinguishable by response time.
        dummy_tx_verification()
        raise OID4VCIError(INVALID_GRANT, _GRANT_REJECTED)

    if grant.state != STATE_OFFERED:
        # The code was already spent, or the grant was killed. A pre-authorized
        # code is a bearer secret used exactly once, so a second presentation
        # means a copy is in circulation — and the holder of that copy may be
        # the one who already redeemed it. Revoke the grant and every token
        # issued against it rather than let either party keep the credential
        # (OAuth 2.1 §4.1.3 code-reuse handling).
        dummy_tx_verification()
        store.invalidate_grant(grant.grant_id)
        raise OID4VCIError(INVALID_GRANT, _GRANT_REJECTED)

    if grant.requires_tx_code:
        if not tx_code:
            raise OID4VCIError(INVALID_REQUEST,
                               'this offer requires a tx_code')
        assert grant.tx_code_kdf is not None
        assert grant.tx_code_salt is not None and grant.tx_code_digest is not None
        if not verify_tx_code(tx_code, grant.tx_code_kdf, grant.tx_code_salt,
                              grant.tx_code_digest):
            store.record_tx_failure(grant.grant_id)
            raise OID4VCIError(INVALID_GRANT, _GRANT_REJECTED)
    elif tx_code:
        raise OID4VCIError(INVALID_REQUEST,
                           'this offer does not use a tx_code')

    if not store.redeem_grant(grant.grant_id, now=moment):
        # The state check above passed but the CAS lost, so two requests
        # presented the same code simultaneously — same conclusion, and this is
        # the path that catches it when the two are truly concurrent.
        store.invalidate_grant(grant.grant_id)
        raise OID4VCIError(INVALID_GRANT, _GRANT_REJECTED)

    access_token = new_secret()
    store.mint_token(secret_id(access_token), grant.grant_id,
                     expires_at=moment + timedelta(seconds=cfg.token_ttl_s))
    return TokenResponse(access_token=access_token,
                         expires_in=cfg.token_ttl_s, grant=grant)


#: One message for every rejection at the token endpoint. Distinguishing
#: "unknown code" from "expired" from "already used" would tell an attacker
#: which of their guesses named a real offer.
_GRANT_REJECTED = ('the pre-authorized code is not valid, has expired, or has '
                   'already been used')


def handle_nonce_request(conf: configparser.ConfigParser, *,
                         nonces: NonceIssuer) -> Dict[str, Any]:
    """Issue a ``c_nonce`` for a wallet to embed in its next key proof.

    Serve with ``Cache-Control: no-store``. This endpoint is unauthenticated by
    design — a wallet needs a nonce before it has anything to authenticate
    with — which is exactly why minting one writes nothing (see
    :mod:`~openbadgeslib.oid4vci.nonce`).
    """
    return {'c_nonce': nonces.mint(), 'c_nonce_expires_in': nonces.ttl_s}


def handle_credential_request(conf: configparser.ConfigParser,
                              body: Union[Mapping[str, Any], str, bytes], *,
                              access_token: Optional[str], store: Any,
                              nonces: NonceIssuer,
                              now: Optional[datetime] = None
                              ) -> CredentialResponse:
    """Verify a Credential Request and issue what its grant authorises.

    *body* is the raw request body (a parsed mapping, or the unparsed JSON).
    *access_token* is the bearer token from the Authorization header, which
    this function looks up rather than trusts.

    Raises :class:`OID4VCIError` for anything the wallet did wrong, and lets
    :class:`~openbadgeslib.errors.IssuanceError` through untouched for anything
    the ISSUER did wrong (broken config, unreadable key, exhausted status
    list). That distinction is load-bearing: dressing an issuer fault up as
    ``invalid_credential_request`` would have the wallet retry a request that
    can never succeed, forever.
    """
    moment = now or datetime.now(tz=timezone.utc)
    cfg = oid4vci_config(conf)

    # Authentication and the size ceiling come first, and deliberately before
    # _require_openvc(): they need no wallet cryptography, so an unauthenticated
    # or oversized request is refused without importing anything — and, on an
    # issuer that never installed the extra, it gets the accurate answer rather
    # than a packaging complaint about a request that was invalid anyway.
    if not access_token:
        raise OID4VCIError(INVALID_TOKEN, 'an access token is required',
                           http_status=401)
    grant = store.grant_for_token(secret_id(access_token), now=moment)
    if grant is None:
        raise OID4VCIError(INVALID_TOKEN,
                           'the access token is not valid or has expired',
                           http_status=401)

    payload = _bounded_body(body)
    parse_credential_request, verify_proofs = _require_openvc()

    try:
        request = parse_credential_request(
            payload, batch_size=grant.max_proofs,
            # The grant's id, not the issuer's catalogue: a wallet must not be
            # able to name a badge it was never offered.
            supported_configuration_ids=[grant.credential_configuration_id])
    except Exception as exc:                       # noqa: BLE001 - mapped below
        raise as_oid4vci_error(exc) from exc

    if request.response_encryption is not None:
        # Answering in the clear a request that asked for encryption would be
        # worse than refusing it: the wallet would believe it got what it
        # asked for.
        raise OID4VCIError(
            INVALID_ENCRYPTION_PARAMETERS,
            'this issuer does not support encrypted credential responses')
    if request.credential_identifier is not None:
        raise OID4VCIError(
            INVALID_CREDENTIAL_REQUEST,
            'this issuer does not use credential_identifier; send a '
            'credential_configuration_id')

    try:
        proofs = verify_proofs(
            request,
            credential_issuer=cfg.credential_issuer,
            # Wired to True and never configurable: replay is the whole reason
            # a key proof exists, and an issuer that can switch the check off
            # is an issuer that eventually ships with it off.
            check_nonce=nonces.consume, require_nonce=True,
            # No kid resolver and no trust anchors, so only proofs that carry
            # their key inline are accepted. Fail closed: resolving a kid or
            # anchoring an x5c is a deployment decision nobody has asked for.
            resolve_proof_key=None, trust_anchors=None,
            max_age_s=cfg.proof_max_age_s, now=moment,
            batch_size=grant.max_proofs)
    except OID4VCIStoreError:
        # The nonce store failed. Not the wallet's fault and not a refusal:
        # let it surface as a server error rather than telling the wallet its
        # perfectly good proof was invalid.
        raise
    except Exception as exc:                       # noqa: BLE001 - mapped below
        raise as_oid4vci_error(exc) from exc

    fingerprint = issuance_fingerprint(grant.credential_configuration_id,
                                       [proof.thumbprint for proof in proofs])
    claim = store.claim_issuance(grant.grant_id, fingerprint, now=moment)
    if claim == CLAIM_CONFLICT:
        raise OID4VCIError(
            INVALID_CREDENTIAL_REQUEST,
            'this grant has already issued a credential to a different key')
    if claim == CLAIM_GONE:
        raise OID4VCIError(INVALID_GRANT, _GRANT_REJECTED)

    badge, credential_format = parse_credential_configuration_id(
        conf, grant.credential_configuration_id)

    if grant.status_index is not None and len(proofs) > 1:
        # One grant reserves one status-list slot, so a batch would leave every
        # credential after the first with no way to be revoked. Refusing beats
        # issuing N badges of which N-1 are silently permanent. build_
        # credential_offer already rejects this pairing; this is the backstop
        # for a grant that reached the store some other way.
        raise OID4VCIError(
            INVALID_CREDENTIAL_REQUEST,
            'this credential is revocable, so it cannot be issued as a batch: '
            'send a single key proof')

    issued: List[CredentialResult] = []
    for index, proof in enumerate(proofs):
        result = issue_credential_from_conf(
            conf, badge, grant.recipient,
            credential_format=credential_format,
            holder_jwk=proof.public_jwk,
            status_index=grant.status_index if index == 0 else None,
            credential_id=grant.credential_id if index == 0 else None)
        issued.append(result)

    return CredentialResponse(
        credentials=[result.token for result in issued],
        credential_configuration_id=grant.credential_configuration_id,
        credential_format=credential_format, issued=issued)


def _bounded_body(body: Union[Mapping[str, Any], str, bytes]
                  ) -> Union[Mapping[str, Any], str]:
    """Reject an oversized body before anything tries to parse it."""
    if isinstance(body, (str, bytes)):
        if len(body) > MAX_REQUEST_BYTES:
            raise OID4VCIError(
                INVALID_CREDENTIAL_REQUEST,
                'the Credential Request exceeds %d bytes' % MAX_REQUEST_BYTES)
        if isinstance(body, bytes):
            try:
                return body.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise OID4VCIError(INVALID_CREDENTIAL_REQUEST,
                                   'the Credential Request is not UTF-8') from exc
    return body


__all__ = ['CredentialResponse', 'MAX_REQUEST_BYTES', 'TokenResponse',
           'handle_credential_request', 'handle_nonce_request',
           'handle_token_request']
