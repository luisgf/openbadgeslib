"""OpenBadges 1.0 (legacy) badge objects — compatibility shim, re-exports from openbadgeslib.ob1."""
import warnings

from .ob1.badge import (
    BadgeStatus, BadgeImgType, BadgeType,
    Assertion, Badge, BadgeSigned,
    extract_svg_assertion, extract_png_assertion,
)

warnings.warn(
    'openbadgeslib.badge is a legacy OpenBadges 1.0 compatibility shim and is '
    'deprecated; it will be removed in openbadgeslib 4.0.0. Import from '
    'openbadgeslib.ob2 (strict OB 2.0) or openbadgeslib.ob3 (OB 3.0) instead. '
    'See the "OpenBadges 1.0 lifecycle" wiki page.',
    DeprecationWarning, stacklevel=2)

__all__ = [
    'BadgeStatus', 'BadgeImgType', 'BadgeType',
    'Assertion', 'Badge', 'BadgeSigned',
    'extract_svg_assertion', 'extract_png_assertion',
]
