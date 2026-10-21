"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es

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

# Parsing JSON that an attacker controls: a token header or payload, a baked
# assertion, a document a remote host serves. json.loads accepts what nothing
# downstream can handle, and each of those shapes surfaced later as a bare
# RecursionError, UnicodeEncodeError or OverflowError out of a verify() that
# promises a typed failure:
#
# * nesting: json.loads recurses to the interpreter's limit (about 1000 levels
#   up to Python 3.13; a C stack budget, around 100 000 levels, from 3.14), and
#   everything after it -- repr() in an error message, copy.deepcopy, json.dumps,
#   a recursive walk -- stops sooner, so a document the parser accepted turned
#   into a RecursionError at the next statement, or into CPU (a walk that
#   rebuilds an O(depth) path per node is quadratic);
# * a lone surrogate (a "\ud800" escape in an ASCII document) is a str that
#   cannot be encoded to UTF-8, so hashing, canonicalizing or printing it
#   raises UnicodeEncodeError;
# * a number past the range of a float (1e999 is Infinity; Infinity and NaN are
#   not JSON but Python's parser takes them) makes int() and float() raise
#   OverflowError, and json.dumps print a token that is not JSON.
#
# They are refused here, once, as a ValueError, which every caller that parses
# untrusted JSON already maps to its own typed error. No credential, token or
# status document legitimately contains any of them.

import json
import math

from typing import Any, Union


#: Containers nested more than this deep are refused. A badge nests a handful
#: of levels; the most the library itself admits is a chain of
#: ob3/_context_validation.py's _MAX_EMBEDDED_DEPTH embedded credentials, each
#: a few containers deep.
MAX_JSON_DEPTH = 128


class UntrustedJSONError(ValueError):
    """Untrusted JSON the library refuses to process. The message never quotes
    the offending value: formatting it is what failed in the first place."""


class JSONTooDeepError(UntrustedJSONError):
    """Containers nested deeper than the caller's bound."""


def check(value: Any, limit: int = MAX_JSON_DEPTH, *,
          scalars: bool = True) -> None:
    """Raise :class:`UntrustedJSONError` unless *value* (parsed JSON, or a dict
    a caller hands in) is nested at most *limit* containers deep, holds no
    string that cannot be UTF-8 encoded (key or value) and no non-finite float.
    ``scalars=False`` checks the depth alone.

    Iterative: the point is to survive input a recursive walk would not, and a
    self-referencing structure ends at the depth bound."""
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
            if scalars:
                for key in node:
                    _check_scalar(key)
        elif isinstance(node, (list, tuple)):
            children = node
        else:
            if scalars:
                _check_scalar(node)
            continue
        if depth > limit:
            raise JSONTooDeepError(
                "JSON is nested more than %d levels deep" % limit)
        for child in children:
            if isinstance(child, (dict, list, tuple)):
                stack.append((child, depth + 1))
            elif scalars:
                _check_scalar(child)


def nested_deeper_than(value: Any, limit: int) -> bool:
    """True if *value* (parsed JSON) has containers nested more than *limit*
    deep. For a caller that applies its own bound, with its own message."""
    try:
        check(value, limit, scalars=False)
    except JSONTooDeepError:
        return True
    return False


def _check_scalar(node: Any) -> None:
    if isinstance(node, str):
        if not node.isascii():
            try:
                node.encode('utf-8')
            except UnicodeEncodeError:
                raise UntrustedJSONError(
                    "JSON holds a string with an unpaired surrogate "
                    "(not valid Unicode)") from None
    elif isinstance(node, float) and not math.isfinite(node):
        raise UntrustedJSONError("JSON holds a number that is not finite")


def loads(data: Union[str, bytes, bytearray]) -> Any:
    """json.loads of untrusted *data*, then :func:`check` of the result.

    Raises :class:`UntrustedJSONError` (a ValueError, as is the JSONDecodeError
    and the UnicodeDecodeError of malformed input) for a document nested past
    what the parser or :data:`MAX_JSON_DEPTH` allows, and for the rest of what
    :func:`check` refuses."""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode('utf-8')
    try:
        value = json.loads(data)
    except RecursionError:
        raise JSONTooDeepError(
            "JSON is nested more than %d levels deep" % MAX_JSON_DEPTH) from None
    check(value)
    return value
