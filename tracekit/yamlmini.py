"""A small YAML-subset parser so policy files need no dependency (PyYAML is used when present;
tests check both give the same result for the shipped policies).

Supported: block mappings and lists (indentation), `- key: value` list items, comments,
single-quoted (backslashes literal, '' for a quote) and double-quoted (JSON escapes) strings,
plain scalars (true/false/null/~, ints, floats, strings), flow lists `[a, 'b']` and `{}`.
Not supported (rejected, not guessed): anchors, tags, block scalars (| >), multi-doc.
"""
import json
import re


class YAMLError(ValueError):
    pass


_INT = re.compile(r"^[-+]?\d+$")
_FLOAT = re.compile(r"^[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?$")


def _strip_comment(line):
    out, q = [], None
    i = 0
    while i < len(line):
        c = line[i]
        if q:
            out.append(c)
            if q == "'" and c == "'":
                if i + 1 < len(line) and line[i + 1] == "'":
                    out.append("'"); i += 1
                else:
                    q = None
            elif q == '"' and c == "\\":
                if i + 1 < len(line):
                    out.append(line[i + 1]); i += 1
            elif q == '"' and c == '"':
                q = None
        else:
            if c == "#" and (i == 0 or line[i - 1] in " \t"):
                break
            if c in "'\"" and (not out or "".join(out).rstrip()[-1:] in ("", ":", "-", "[", ",", "{") ):
                q = c
            out.append(c)
        i += 1
    return "".join(out).rstrip()


def _scalar(tok, lineno):
    t = tok.strip()
    if t == "":
        return None
    if t[0] == "'":
        if len(t) < 2 or t[-1] != "'":
            raise YAMLError(f"line {lineno}: unterminated single-quoted string")
        return t[1:-1].replace("''", "'")
    if t[0] == '"':
        try:
            return json.loads(t)
        except ValueError as e:
            raise YAMLError(f"line {lineno}: bad double-quoted string: {e}") from e
    if t[0] in "&*!|>%@`":
        raise YAMLError(f"line {lineno}: unsupported YAML feature {t[0]!r}")
    if t[0] == "[":
        if t[-1] != "]":
            raise YAMLError(f"line {lineno}: unterminated flow list")
        inner = t[1:-1].strip()
        return [] if not inner else [_scalar(x, lineno) for x in _split_flow(inner, lineno)]
    if t == "{}":
        return {}
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if t in ("null", "~", "Null", "NULL"):
        return None
    if _INT.match(t):
        return int(t)
    if _FLOAT.match(t):
        return float(t)
    return t


def _split_flow(s, lineno):
    parts, cur, q = [], [], None
    for c in s:
        if q:
            cur.append(c)
            if c == q:
                q = None
        elif c in "'\"":
            q = c; cur.append(c)
        elif c == ",":
            parts.append("".join(cur)); cur = []
        else:
            cur.append(c)
    if q:
        raise YAMLError(f"line {lineno}: unterminated string in flow list")
    parts.append("".join(cur))
    return parts


def _split_key(text, lineno):
    """'key: value' -> (key, value_text) or None if not a mapping entry."""
    if text[:1] in "'\"":
        end = text.find(text[0], 1)
        if end < 0:
            raise YAMLError(f"line {lineno}: unterminated key")
        key, rest = text[1:end], text[end + 1:]
        if not rest.startswith(":"):
            return None
        return key, rest[1:]
    m = re.match(r"^([^:#'\"\[\]{},][^:#]*?)\s*:(\s+|$)(.*)$", text)
    if not m:
        return None
    return m.group(1), m.group(3)


def loads(text):
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[:len(raw) - len(raw.lstrip())]:
            raise YAMLError(f"line {n}: tabs are not allowed for indentation")
        s = _strip_comment(raw)
        if s.strip() in ("", "---"):
            continue
        lines.append((len(s) - len(s.lstrip()), s.strip(), n))
    if not lines:
        return None
    val, i = _block(lines, 0, lines[0][0])
    if i != len(lines):
        raise YAMLError(f"line {lines[i][2]}: unexpected indentation")
    return val


def _block(lines, i, indent):
    if lines[i][1].startswith("- ") or lines[i][1] == "-":
        return _list(lines, i, indent)
    return _map(lines, i, indent)


def _map(lines, i, indent, first=None):
    out = {}
    while i < len(lines):
        ind, text, n = lines[i]
        if first is not None:
            ind, text, n = first
            first = None
        elif ind < indent:
            break
        elif ind > indent:
            raise YAMLError(f"line {n}: unexpected indentation")
        if text.startswith("- "):
            break
        kv = _split_key(text, n)
        if kv is None:
            raise YAMLError(f"line {n}: expected 'key: value'")
        k, v = kv
        if k in out:
            raise YAMLError(f"line {n}: duplicate key {k!r}")
        i += 1
        if v.strip() == "":
            if i < len(lines) and (lines[i][0] > indent or (lines[i][0] == indent and lines[i][1].startswith("- "))):
                out[k], i = _block(lines, i, lines[i][0])
            else:
                out[k] = None
        else:
            out[k] = _scalar(v, n)
    return out, i


def _list(lines, i, indent):
    out = []
    while i < len(lines):
        ind, text, n = lines[i]
        if ind < indent or not (text.startswith("- ") or text == "-"):
            if ind > indent:
                raise YAMLError(f"line {n}: unexpected indentation")
            break
        if ind > indent:
            raise YAMLError(f"line {n}: unexpected indentation")
        rest = text[1:].strip()
        i += 1
        if rest == "":
            if i < len(lines) and lines[i][0] > indent:
                v, i = _block(lines, i, lines[i][0])
            else:
                v = None
            out.append(v)
            continue
        kv = _split_key(rest, n)
        if kv is not None:
            item_indent = ind + (len(text) - len(rest))
            v, i = _map_from_item(lines, i, item_indent, (item_indent, rest, n))
            out.append(v)
        else:
            out.append(_scalar(rest, n))
    return out, i


def _map_from_item(lines, i, indent, first):
    # the first key sits on the "- " line; the rest are indented to line up with it
    out = {}
    ind, text, n = first
    k, v = _split_key(text, n)
    if v.strip() == "":
        if i < len(lines) and lines[i][0] > indent:
            out[k], i = _block(lines, i, lines[i][0])
        else:
            out[k] = None
    else:
        out[k] = _scalar(v, n)
    if i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("- "):
        more, i = _map(lines, i, indent)
        for mk in more:
            if mk in out:
                raise YAMLError(f"duplicate key {mk!r}")
        out.update(more)
    return out, i


def load_any(text):
    """PyYAML's safe_load when installed, else this parser."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return loads(text)
    return yaml.safe_load(text)
