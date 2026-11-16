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
        return "always `%s`" % str(schema["const"]).lower()
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


def notes(schema):
    """The limits on a field, in words."""
    out = []
    if "minLength" in schema or "maxLength" in schema:
        lo, hi = schema.get("minLength"), schema.get("maxLength")
        if lo is not None and hi is not None:
            out.append("%d to %d characters" % (lo, hi))
        elif hi is not None:
            out.append("up to %d characters" % hi)
        else:
            out.append("at least %d characters" % lo)
    if "maxItems" in schema:
        out.append("up to %d items" % schema["maxItems"])
    if "minimum" in schema and schema.get("minimum") != 0:
        out.append("at least %s" % schema["minimum"])
    if "pattern" in schema:
        out.append("matches `%s`" % schema["pattern"])
    return "; ".join(out)


def rows(schema, prefix=""):
    """One (name, type, required, notes) row per field, nested fields included."""
    result = []
    required = set(schema.get("required", []))
    for name, sub in schema.get("properties", {}).items():
        path = prefix + name
        result.append((path, kind(sub), "yes" if name in required else "no", notes(sub)))
        if sub.get("type") == "object":
            result += rows(sub, path + ".")
        elif sub.get("type") == "array" and sub.get("items", {}).get("type") == "object":
            result += rows(sub["items"], path + "[].")
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
