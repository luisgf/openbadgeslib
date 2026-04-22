"""OpenBadges 2.0 badge objects — compatibility shim, re-exports from openbadgeslib.ob2."""
from .ob2.badge import (
    BadgeStatus, BadgeImgType, BadgeType,
    Assertion, Badge, BadgeSigned,
    extract_svg_assertion, extract_png_assertion,
)

__all__ = [
    'BadgeStatus', 'BadgeImgType', 'BadgeType',
    'Assertion', 'Badge', 'BadgeSigned',
    'extract_svg_assertion', 'extract_png_assertion',
]
