"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014-2026, Jesús Cea Avión, jcea@jcea.es

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

from .credential import (Achievement, Alignment, Evidence, IdentityObject,
                         Issuer, OpenBadgeCredential, Result, ResultDescription)
from .signer import OB3Signer
from .verifier import (OB3VerificationError, OB3Verifier,
                       verify_endorsement_jwt)
from .ldp import (OB3LdpSigner, OB3LdpVerifier, add_data_integrity_proof,
                  verify_data_integrity_proof)
from .status import check_credential_status
from .status_list import (build_status_list_credential, encode_bitstring,
                          sign_status_list_credential, status_entry)
from .status_registry import StatusRegistry
from .did import (build_did_document, did_key_from_pem, did_web_from_url,
                  multikey_from_pem, resolve_did, resolve_verification_method)
from ..util import CachingDownloader

__all__ = [
    'Achievement',
    'CachingDownloader',
    'Alignment',
    'Evidence',
    'IdentityObject',
    'Issuer',
    'OpenBadgeCredential',
    'Result',
    'ResultDescription',
    'OB3LdpSigner',
    'OB3LdpVerifier',
    'OB3Signer',
    'OB3Verifier',
    'OB3VerificationError',
    'add_data_integrity_proof',
    'verify_data_integrity_proof',
    'StatusRegistry',
    'build_did_document',
    'build_status_list_credential',
    'check_credential_status',
    'did_key_from_pem',
    'did_web_from_url',
    'encode_bitstring',
    'multikey_from_pem',
    'resolve_did',
    'resolve_verification_method',
    'sign_status_list_credential',
    'status_entry',
    'verify_endorsement_jwt',
]
