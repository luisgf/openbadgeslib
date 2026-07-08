"""OpenBadges 1.0 (legacy) verifier — compatibility shim, re-exports from openbadgeslib.ob1."""
import warnings

from .ob1.verifier import Verifier, VerifyInfo

warnings.warn(
    'openbadgeslib.verifier is a legacy OpenBadges 1.0 compatibility shim; '
    'prefer openbadgeslib.ob2.OB2Verifier or openbadgeslib.ob3.OB3Verifier for '
    'new work. OpenBadges 1.0 remains supported (no removal planned). See the '
    '"OpenBadges 1.0 lifecycle" wiki page.',
    DeprecationWarning, stacklevel=2)

__all__ = ['Verifier', 'VerifyInfo']
