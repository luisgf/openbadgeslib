from ..errors import LibOpenBadgesException


class JWSException(LibOpenBadgesException):
    pass


class MissingKey(JWSException):
    pass


class MissingSigner(JWSException):
    pass


class MissingVerifier(JWSException):
    pass


class SignatureError(JWSException):
    pass


class RouteMissingError(JWSException):
    pass
