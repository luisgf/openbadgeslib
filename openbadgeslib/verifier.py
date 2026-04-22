"""OpenBadges 2.0 verifier — compatibility shim, re-exports from openbadgeslib.ob2."""
from .ob2.verifier import Verifier, VerifyInfo

__all__ = ['Verifier', 'VerifyInfo']
