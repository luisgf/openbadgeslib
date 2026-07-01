"""OpenBadges 1.0 (legacy) badge objects — compatibility shim, re-exports from openbadgeslib.ob1."""
from .ob1.badge import (
    BadgeStatus, BadgeImgType, BadgeType,
    Assertion, Badge, BadgeSigned,
    extract_svg_assertion, extract_png_assertion,
)

__all__ = [
    'BadgeStatus', 'BadgeImgType', 'BadgeType',
    'Assertion', 'Badge', 'BadgeSigned',
    'extract_svg_assertion', 'extract_png_assertion',
]
