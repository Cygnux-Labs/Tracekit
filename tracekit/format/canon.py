"""Canonical JSON for evidence format v2: JCS (RFC 8785) and a strict parser.

v1 keeps `tracekit.core.canon`; nothing here is used to verify v1 bundles.
"""
import hashlib
import json
import math

import rfc8785

MAX_SAFE_INT = 2 ** 53 - 1


class StrictJSONError(ValueError):
    """`code` is one of: invalid_utf8, syntax, duplicate_key, non_finite, int_range, lone_surrogate."""

    def __init__(self, code, msg):
        super().__init__(f"{code}: {msg}")
        self.code = code


def canonical(obj):
    """JCS bytes of a JSON value; raises rfc8785.CanonicalizationError for anything JCS can't encode."""
    try:
        return rfc8785.dumps(obj)
    except (UnicodeEncodeError, RecursionError) as e:   # lone-surrogate key; nesting deeper than the stack
        raise rfc8785.CanonicalizationError(str(e)) from None


def event_hash(event):
    return "sha256:" + hashlib.sha256(canonical(event)).hexdigest()


def _object(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise StrictJSONError("duplicate_key", repr(k))
        d[k] = v
    return d


def _constant(s):
    raise StrictJSONError("non_finite", s)


def _float(s):
    f = float(s)
    if not math.isfinite(f):
        raise StrictJSONError("non_finite", s)
    return f


def _int(s):
    # integer tokens only (no '.' or exponent); the length check keeps int() off huge digit strings
    if len(s.lstrip("-")) > 16 or abs(int(s)) > MAX_SAFE_INT:
        raise StrictJSONError("int_range", s)
    return int(s)


def _check_strings(v):
    stack = [v]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            stack.extend(v)
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, str):
            try:
                v.encode("utf-8")
            except UnicodeEncodeError:
                raise StrictJSONError("lone_surrogate", repr(v)) from None


def loads_strict(text):
    """Parse JSON text (str or UTF-8 bytes), rejecting anything JCS can't hash the same way everywhere."""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError as e:
            raise StrictJSONError("invalid_utf8", str(e)) from None
    try:
        v = json.loads(text, object_pairs_hook=_object, parse_constant=_constant, parse_float=_float, parse_int=_int)
    except (json.JSONDecodeError, RecursionError) as e:
        raise StrictJSONError("syntax", str(e)) from None
    _check_strings(v)
    return v
