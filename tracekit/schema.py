"""Validate events against tracekit/schema/tracekit.event.v1.json with a small, dependency-free
JSON Schema subset (type, const, enum, required, properties, additionalProperties, items,
oneOf, allOf, if/then, $ref to #/$defs, pattern, minimum, minLength, maxLength)."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "schema", "tracekit.event.v1.json")
_SCHEMA = None

_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def schema():
    global _SCHEMA
    if _SCHEMA is None:
        try:
            with open(SCHEMA_PATH, encoding="utf-8") as f:
                _SCHEMA = json.load(f)
        except OSError:  # imported from a zip archive: read the packaged copy
            import pkgutil
            _SCHEMA = json.loads(pkgutil.get_data(__package__, "schema/tracekit.event.v1.json").decode("utf-8"))
    return _SCHEMA


def _is_type(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, _TYPES[t])


def _check(v, s, root, path, errs):
    if "$ref" in s:
        ref = s["$ref"]
        assert ref.startswith("#/$defs/"), ref
        return _check(v, root["$defs"][ref[8:]], root, path, errs)
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
        if "pattern" in s and not re.search(s["pattern"], v):
            errs.append(f"{path}: does not match {s['pattern']}")
        if "minLength" in s and len(v) < s["minLength"]:
            errs.append(f"{path}: shorter than {s['minLength']}")
        if "maxLength" in s and len(v) > s["maxLength"]:
            errs.append(f"{path}: longer than {s['maxLength']}")
    if _is_type(v, "number") and "minimum" in s and v < s["minimum"]:
        errs.append(f"{path}: below {s['minimum']}")
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append(f"{path}: missing required '{k}'")
        props = s.get("properties", {})
        ap = s.get("additionalProperties", True)
        for k, val in v.items():
            if k in props:
                _check(val, props[k], root, f"{path}.{k}", errs)
            elif ap is False:
                errs.append(f"{path}: unexpected field '{k}'")
            elif isinstance(ap, dict):
                _check(val, ap, root, f"{path}.{k}", errs)
    if isinstance(v, list) and "items" in s:
        for i, it in enumerate(v):
            _check(it, s["items"], root, f"{path}[{i}]", errs)
    if "oneOf" in s:
        ok = 0
        for sub in s["oneOf"]:
            e = []
            _check(v, sub, root, path, e)
            ok += not e
        if ok != 1:
            errs.append(f"{path}: must match exactly one alternative (matched {ok})")
    for sub in s.get("allOf", []):
        _check(v, sub, root, path, errs)
    if "if" in s:
        e = []
        _check(v, s["if"], root, path, e)
        if not e and "then" in s:
            _check(v, s["then"], root, path, errs)


def validate(event):
    """Return a list of error strings (empty when valid)."""
    errs = []
    root = schema()
    _check(event, root, root, "event", errs)
    return errs
