"""Canonical JSON for evidence format v2: JCS (RFC 8785) and a strict parser.

v1 keeps `tracekit.core.canon`; nothing here is used to verify v1 bundles.
"""
import hashlib
import json
import math

MAX_SAFE_INT = 2 ** 53 - 1

try:
    import rfc8785
    CanonicalizationError, _dumps = rfc8785.CanonicalizationError, rfc8785.dumps
except ImportError:   # `pip install --no-deps tracekit-ai`: the verifier runs on the standard library alone
    class CanonicalizationError(ValueError):
        pass

    def _number(f):
        """ECMA-262 Number::toString of a finite float, as RFC 8785 3.2.2.3 asks."""
        if f == 0:
            return "0"
        mant, _, exp = repr(abs(f)).partition("e")
        whole, _, frac = mant.partition(".")
        digits = (whole + frac).lstrip("0")
        n = len(whole) + int(exp or 0) - (len(whole + frac) - len(digits))   # f = 0.<digits> * 10**n
        digits, sign = digits.rstrip("0"), "-" if f < 0 else ""
        if len(digits) <= n <= 21:
            return sign + digits + "0" * (n - len(digits))
        if 0 < n <= 21:
            return sign + digits[:n] + "." + digits[n:]
        if -6 < n <= 0:
            return sign + "0." + "0" * -n + digits
        e = n - 1
        return sign + digits[0] + ("." + digits[1:] if len(digits) > 1 else "") + ("e+" if e > 0 else "e-") + str(abs(e))

    def _jcs(v):
        if v is None or isinstance(v, (bool, str)):
            return json.dumps(v, ensure_ascii=False)
        if isinstance(v, int):
            if abs(v) > MAX_SAFE_INT:
                raise CanonicalizationError(f"{v} exceeds safe integer domain for JSON floats")
            return str(int(v))
        if isinstance(v, float):
            if not math.isfinite(v):
                raise CanonicalizationError(f"{v} is not representable in JCS")
            return _number(v)
        if isinstance(v, (list, tuple)):
            return "[" + ",".join(map(_jcs, v)) + "]"
        if isinstance(v, dict):
            if not all(isinstance(k, str) for k in v):
                raise CanonicalizationError("object keys must be strings")
            items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16be", "surrogatepass"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(x) for k, x in items) + "}"
        raise CanonicalizationError(f"unsupported type: {type(v)}")

    def _dumps(obj):
        return _jcs(obj).encode("utf-8")


class StrictJSONError(ValueError):
    """`code` is one of: invalid_utf8, syntax, duplicate_key, non_finite, int_range, lone_surrogate."""

    def __init__(self, code, msg):
        super().__init__(f"{code}: {msg}")
        self.code = code


def canonical(obj):
    """JCS bytes of a JSON value; raises CanonicalizationError for anything JCS can't encode."""
    try:
        return _dumps(obj)
    except (UnicodeEncodeError, RecursionError) as e:   # lone surrogate; nesting deeper than the stack
        raise CanonicalizationError(str(e)) from None


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
