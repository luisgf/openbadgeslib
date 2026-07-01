"""OpenBadges 1.0 (legacy) signer — compatibility shim, re-exports from openbadgeslib.ob1."""
from .ob1.signer import Signer

__all__ = ['Signer']
