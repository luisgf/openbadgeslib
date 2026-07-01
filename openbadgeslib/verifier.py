"""OpenBadges 1.0 (legacy) verifier — compatibility shim, re-exports from openbadgeslib.ob1."""
from .ob1.verifier import Verifier, VerifyInfo

__all__ = ['Verifier', 'VerifyInfo']
