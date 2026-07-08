"""OpenBadges 1.0 (legacy) signer — compatibility shim, re-exports from openbadgeslib.ob1."""
import warnings

from .ob1.signer import Signer

warnings.warn(
    'openbadgeslib.signer is a legacy OpenBadges 1.0 compatibility shim; prefer '
    'openbadgeslib.ob2.OB2Signer or openbadgeslib.ob3.OB3Signer for new work. '
    'OpenBadges 1.0 remains supported (no removal planned). See the '
    '"OpenBadges 1.0 lifecycle" wiki page.',
    DeprecationWarning, stacklevel=2)

__all__ = ['Signer']
