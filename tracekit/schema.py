"""Validate events against tracekit/schema/tracekit.event.v1.json or .v2.json (picked by `schema_version`) with a
small, dependency-free JSON Schema subset (type, const, enum, required, properties, additionalProperties, items,
oneOf, allOf, if/then, $ref to #/$defs, pattern, minimum, maximum, minLength, maxLength, maxItems). Any other keyword
raises, so a typo in a schema cannot silently drop a check.

v2 patterns must match the whole value with ASCII semantics. v1 keeps its original semantics (`re.search`, Unicode
classes) and reports values that pass only that way as warnings."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
V1 = "tracekit.event.v1"
V2 = "tracekit.event.v2"
_SCHEMAS = {}

_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}
KEYWORDS = {"type", "const", "enum", "required", "properties", "additionalProperties", "items", "oneOf", "allOf",
            "if", "then", "$ref", "pattern", "minimum", "maximum", "minLength", "maxLength", "maxItems",
            "$schema", "$id", "$defs", "title", "description"}


def schema(version=V1):
    if version not in _SCHEMAS:
        name = f"schema/{version}.json"
        try:
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                _SCHEMAS[version] = json.load(f)
        except OSError:  # imported from a zip archive: read the packaged copy
            import pkgutil
            _SCHEMAS[version] = json.loads(pkgutil.get_data(__package__, name).decode("utf-8"))
    return _SCHEMAS[version]


def _is_type(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, _TYPES[t])


def _check(v, s, root, path, errs, warns=None, strict=False):
    unknown = s.keys() - KEYWORDS
    if unknown:
        raise ValueError(f"unknown schema keyword(s) {sorted(unknown)} at {path}")
    if "$ref" in s:
        ref = s["$ref"]
        assert ref.startswith("#/$defs/"), ref
        return _check(v, root["$defs"][ref[8:]], root, path, errs, warns, strict)
    if "type" in s:
        ts = s["type"] if isinstance(s["type"], list) else [s["type"]]
        if not any(_is_type(v, t) for t in ts):
            errs.append(f"{path}: expected {'/'.join(ts)}, got {type(v).__name__}")
            return
    if "const" in s and v != s["const"]:
        errs.append(f"{path}: must be {s['const']!r}")
    if "enum" in s and v not in s["enum"]:
        errs.append(f"{path}: {v!r} not in {s['enum']}")
    if isinstance(v, str):
        if "pattern" in s:
            full = re.fullmatch(s["pattern"], v, re.ASCII)
            if not (full if strict else re.search(s["pattern"], v)):
                errs.append(f"{path}: does not match {s['pattern']}")
            elif not full and warns is not None:
                warns.append(f"{path}: non-canonical value for {s['pattern']}")
        if "minLength" in s and len(v) < s["minLength"]:
            errs.append(f"{path}: shorter than {s['minLength']}")
        if "maxLength" in s and len(v) > s["maxLength"]:
            errs.append(f"{path}: longer than {s['maxLength']}")
    if _is_type(v, "number") and "minimum" in s and v < s["minimum"]:
        errs.append(f"{path}: below {s['minimum']}")
    if _is_type(v, "number") and "maximum" in s and v > s["maximum"]:
        errs.append(f"{path}: above {s['maximum']}")
    if isinstance(v, list) and "maxItems" in s and len(v) > s["maxItems"]:
        errs.append(f"{path}: more than {s['maxItems']} items")
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append(f"{path}: missing required '{k}'")
        props = s.get("properties", {})
        ap = s.get("additionalProperties", True)
        for k, val in v.items():
            if k in props:
                _check(val, props[k], root, f"{path}.{k}", errs, warns, strict)
            elif ap is False:
                errs.append(f"{path}: unexpected field '{k}'")
            elif isinstance(ap, dict):
                _check(val, ap, root, f"{path}.{k}", errs, warns, strict)
    if isinstance(v, list) and "items" in s:
        for i, it in enumerate(v):
            _check(it, s["items"], root, f"{path}[{i}]", errs, warns, strict)
    if "oneOf" in s:
        matched = []
        for sub in s["oneOf"]:
            e, w = [], []
            _check(v, sub, root, path, e, w, strict)
            if not e:
                matched.append(w)
        if len(matched) != 1:
            errs.append(f"{path}: must match exactly one alternative (matched {len(matched)})")
        elif warns is not None:
            warns.extend(matched[0])
    for sub in s.get("allOf", []):
        _check(v, sub, root, path, errs, warns, strict)
    if "if" in s:
        e = []
        _check(v, s["if"], root, path, e, None, strict)
        if not e and "then" in s:
            _check(v, s["then"], root, path, errs, warns, strict)


def validate(event, warnings=None):
    """Return a list of error strings (empty when valid). v1 warnings are appended to `warnings` when given."""
    errs = []
    v2 = isinstance(event, dict) and event.get("schema_version") == V2
    root = schema(V2 if v2 else V1)
    _check(event, root, root, "event", errs, None if v2 else warnings, v2)
    return errs
