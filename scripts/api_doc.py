#!/usr/bin/env python3
"""Write the signer RPC field tables of docs/api.md from the contract in tracekit/signer/rpc_schema.py.

Each RPC's tables sit between a pair of marker comments in the page; everything between a pair is rewritten, and
everything outside is hand-written and left alone:

    <!-- api-doc:begin content_get -->
    <!-- api-doc:end content_get -->

    python scripts/api_doc.py                # rewrite the tables in docs/api.md
    python scripts/api_doc.py --check        # write nothing: fail if docs/api.md differs from the contract
    python scripts/api_doc.py --show NAME    # print one RPC's tables, write nothing
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)   # this checkout's tracekit, installed or not

from tracekit.signer import rpc_schema   # noqa: E402

PAGE = os.path.join(ROOT, "docs", "api.md")
MARKED = re.compile(r"(<!-- api-doc:begin (\S+) -->\n)(.*?)(<!-- api-doc:end \2 -->)", re.S)


NAMES = {"string": "text", "integer": "whole number", "number": "number",
         "boolean": "true or false", "null": "nothing", "object": "object", "array": "list"}


def kind(schema):
    """A short, readable type for one field."""
    if "const" in schema:
        return "always `%s`" % json.dumps(schema["const"])
    if "enum" in schema:
        return "one of " + ", ".join("`%s`" % v for v in schema["enum"])
    t = schema.get("type")
    if isinstance(t, list):
        return " or ".join(NAMES.get(x, x) for x in t)
    if t == "array":
        inner = schema.get("items", {})
        if not inner:
            return "list"
        item = kind(inner)
        if " or " in item or item.startswith(("one of", "always")):
            return "list of (%s)" % item
        return "list of " + item + ("" if item.endswith("s") or item == "any value" else "s")
    if t == "object":
        return "object"
    if t is None:
        for key in ("anyOf", "oneOf"):
            if key in schema:
                return " or ".join(dict.fromkeys(kind(x) for x in schema[key]))
        return "any value"
    return NAMES.get(t, str(t))


def limits(schema):
    """The plain limits on one schema, as a list of phrases."""
    out = []
    if "minLength" in schema or "maxLength" in schema:
        lo, hi = schema.get("minLength"), schema.get("maxLength")
        if lo is not None and hi is not None:
            out.append("%d to %d characters" % (lo, hi))
        elif hi is not None:
            out.append("up to %d characters" % hi)
        else:
            out.append("at least %d characters" % lo)
    if "minItems" in schema or "maxItems" in schema:
        lo, hi = schema.get("minItems"), schema.get("maxItems")
        if lo is not None and lo == hi:
            out.append("exactly %d items" % lo)
        elif lo is not None and hi is not None:
            out.append("%d to %d items" % (lo, hi))
        elif hi is not None:
            out.append("up to %d items" % hi)
        else:
            out.append("at least %d items" % lo)
    # 2 ** 53 - 1, the largest whole number JSON holds exactly, caps every whole number: the page says it once
    top = schema.get("maximum")
    top = None if top == 2 ** 53 - 1 else top
    if "minimum" in schema and (schema["minimum"] != 0 or top is not None):
        out.append("at least %s" % schema["minimum"])
    if top is not None:
        out.append("at most %s" % top)
    if "pattern" in schema:
        out.append("matches `%s`" % schema["pattern"])
    return out


def shape(branch):
    """One oneOf branch that has no type of its own, in words: the value that selects it and what it requires."""
    props = branch.get("properties", {})
    when = " and ".join("`%s` is `%s`" % (k, json.dumps(v["const"])) for k, v in props.items() if "const" in v)
    parts = []
    if branch.get("required"):
        parts.append("requires " + " and ".join("`%s`" % r for r in branch["required"]))
    if branch.get("additionalProperties") is False and props:
        parts.append("allows only " + ", ".join("`%s`" % k for k in props))
    return "(%s%s)" % ("when %s: " % when if when else "", ", ".join(parts) or "no further fields required")


def is_shape(branch):
    return branch.get("type") != "object" and ("required" in branch or "properties" in branch)


def notes_list(schema):
    out = limits(schema)
    values = schema.get("additionalProperties")
    if isinstance(values, dict):   # a map: its keys are free, its values are held to a schema
        out.append("each value: " + "; ".join([kind(values)] + notes_list(values)))
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        each = notes_list(schema["items"])
        if each:
            out.append("each item: " + "; ".join(each))
    shapes = [b for b in schema.get("oneOf", ()) if is_shape(b)]
    if shapes:
        out.append("one of " + " or ".join(shape(b) for b in shapes))
    scalars = [(b, notes_list(b)) for b in schema.get("oneOf", ()) if "type" in b and b["type"] != "object"]
    scalars = [(b, n) for b, n in scalars if n]
    for b, n in scalars:   # a field that is text or nothing: the limits are the text's
        out.append(("%s: " % kind(b) if len(scalars) > 1 else "") + "; ".join(n))
    return out


def notes(schema):
    """The limits on a field, in words."""
    return "; ".join(notes_list(schema))


def conditions(schema):
    """The limits an `if`/`then` pair puts on a field, by field name: the then-part applies when the if-part's values match."""
    if "if" not in schema:
        return {}
    when = " and ".join("`%s` is `%s`" % (k, json.dumps(v["const"])) for k, v in schema["if"]["properties"].items())
    return {k: "when %s: %s" % (when, "; ".join([kind(v)] + notes_list(v))) for k, v in schema["then"]["properties"].items()}


def rows(schema, prefix=""):
    """One (name, type, required, notes) row per field, nested fields included."""
    result = []
    required = set(schema.get("required", []))
    # a field some shapes of the object require and others don't
    sometimes = {r for b in schema.get("oneOf", ()) if is_shape(b) for r in b.get("required", ())} - required
    when = conditions(schema)
    for name, sub in schema.get("properties", {}).items():
        path = prefix + name
        note = "; ".join(x for x in (notes(sub), when.get(name)) if x)
        result.append((path, kind(sub), "yes" if name in required else "depends" if name in sometimes else "no", note))
        inner = sub["items"] if sub.get("type") == "array" and "items" in sub else sub
        base = path + "[]" if inner is not sub else path
        if inner.get("type") == "object":
            result += rows(inner, base + ".")
        branches = [b for b in inner.get("oneOf", ()) if b.get("type") == "object"]
        for i, branch in enumerate(branches, 1):   # one row per branch, then its fields: they differ by `kind`
            const = branch["properties"].get("kind", {}).get("const")
            label = "%s (%s)" % (base, "kind " + const if const else "variant %d" % i)
            result.append((label, "object", "no", ""))
            result += rows(branch, label + ".")
    return result


def table(schema):
    lines = ["| Field | Type | Required | Notes |", "|---|---|---|---|"]
    for name, typ, req, note in rows(schema):
        lines.append("| `%s` | %s | %s | %s |" % tuple(c.replace("|", "\\|") for c in (name, typ, req, note)))
    return "\n".join(lines)


def block(name):
    """What goes between one RPC's markers: its two tables, folded away so the page reads as prose first."""
    return "\n".join([
        "<details>", "<summary>Request and answer fields</summary>", "",
        "**Request**", "", table(rpc_schema.REQUESTS[name]), "",
        "**Answer**", "", table(rpc_schema.RESPONSES[name]), "",
        "</details>", ""])


def render(text):
    """The page with every marked pair filled from the contract. Raises ValueError on a marker that names no RPC."""
    def fill(m):
        if m.group(2) not in rpc_schema.REQUESTS:
            raise ValueError("docs/api.md has a marker for %r, which is not an RPC in rpc_schema.py" % m.group(2))
        return m.group(1) + block(m.group(2)) + m.group(4)
    return MARKED.sub(fill, text)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="write nothing; exit 1 if docs/api.md is out of date")
    ap.add_argument("--show", metavar="NAME", help="print one RPC's tables; write nothing")
    a = ap.parse_args()
    if a.show:
        if a.show not in rpc_schema.REQUESTS:
            print("no RPC named %r; the RPCs are: %s" % (a.show, ", ".join(rpc_schema.REQUESTS)))
            return 1
        print(block(a.show))
        return 0
    with open(PAGE, encoding="utf-8") as f:
        old = f.read()
    try:
        new = render(old)
    except ValueError as e:
        print(e)
        return 1
    if a.check:
        if new != old:
            print("docs/api.md is out of date with tracekit/signer/rpc_schema.py: run python scripts/api_doc.py")
            return 1
        print("docs/api.md is up to date (contract version %d)" % rpc_schema.RPC_VERSION)
        return 0
    if new != old:
        with open(PAGE, "w", encoding="utf-8") as f:
            f.write(new)
    print("docs/api.md: %d RPC tables written (contract version %d)" % (len(MARKED.findall(new)), rpc_schema.RPC_VERSION))
    return 0


if __name__ == "__main__":
    sys.exit(main())
