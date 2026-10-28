"""Generate Tracekit's GitHub wiki from docs/. The wiki is a view of the docs: edit docs/, never the wiki.

    python scripts/wiki.py OUT_DIR [--ref TAG_OR_SHA]
    python scripts/wiki.py --map      # {docs path: wiki URL} as JSON, for links kept outside this repository

Run it in a checkout of REF (default main). OUT_DIR must be empty or absent. It gets one page per docs page (named by
tracekit.wiki.page_name, the one mapping), Home.md, _Sidebar.md (SECTIONS), _Footer.md and the images the pages show,
under images/. Links between docs pages become wiki links with their #anchors, links to anything else in the
repository become github.com URLs at REF. A link or anchor that resolves to nothing, or a docs page in no section, is an error and nothing is written. The
same tree and REF give the same bytes. Publishing: docs/RELEASING.md.
"""
import argparse
import fnmatch
import glob
import itertools
import json
import os
import posixpath
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)   # this checkout's tracekit, not an installed one
from tracekit.wiki import page_name, wiki_url  # noqa: E402
REPO = "https://github.com/Cygnux-Labs/Tracekit"

# docs pages that aren't user docs
EXCLUDED = {
    "RELEASING.md": "the maintainers' release procedure",
    "launch-checklist.md": "the 1.0 launch's internal checklist",
}
# the sidebar: docs paths in order; a glob adds the pages it matches that no earlier entry placed, sorted
SECTIONS = [
    ("Get started", ["quickstart-v2.md", "quickstarts/README.md", "quickstarts/*.md", "coding-agents.md", "doctor.md",
                     "walkthrough.md"]),
    ("How it works", ["concepts/README.md", "concepts/overview.md", "concepts/tool-call-lifecycle.md",
                      "concepts/evidence-format.md", "concepts/verification.md", "concepts/witnesses-and-monitoring.md",
                      "concepts/policy.md", "concepts/approvals.md", "concepts/containment.md",
                      "concepts/capture-and-completeness.md", "concepts/custody.md", "concepts/provenance-and-why.md",
                      "concepts/deployment.md", "concepts/storage-and-performance.md", "concepts/integrations.md",
                      "concepts/security-model.md", "architecture.md", "why-architecture.md"]),
    ("Integrations", ["integrations.md", "adapters.md", "otel.md", "remote-ingest.md", "integrations/*.md"]),
    ("Policy and approvals", ["policy-v2.md", "approvals.md", "pcm.md", "findings.md", "reasoning.md", "incidents.md",
                              "webhooks.md"]),
    ("Deploy and operate", ["deploy.md", "deploy-container.md", "deploy-kubernetes.md", "deploy-compose.md",
                            "identity.md", "executor.md", "a2a.md", "c2c.md", "mcp-gateway.md", "gateway.md", "egress.md", "witnesses.md",
                            "monitor.md", "issuer.md", "observability.md", "viewer.md", "viewer-1.4.md", "why.md",
                            "migration.md", "portability.md"]),
    ("Verify the evidence", ["for-auditors.md", "verdicts.md", "format-v2.md", "auditor-guide.md", "sample/README.md",
                             "signing.md", "graph.md", "guarantees.md"]),
    ("Security and privacy", ["threat-model-server.md", "threat-model-laptop.md", "security-checklist.md",
                              "review-packet.md", "privacy.md", "limits.md", "support.md"]),
    ("Compliance", ["compliance/README.md", "compliance/*.md"]),
    ("Evaluation", ["evaluation.md", "case-study-oss-agents.md"]),
    ("Demos", ["demos/README.md", "demos/*/README.md"]),
    ("Help", ["faq.md"]),
]
HOME = """# Tracekit

Tracekit records what an AI agent does as evidence that people who weren't there can check.
A signer the agent can't control decides each tool call against your policy, then signs the call, the decision and the
result into a hash-chained log that independent witnesses cosign.
Each run exports as one `.tkb` bundle that anyone can verify offline, against keys they chose to trust.

## Start here

"""
START = [
    ("quickstart-v2.md", "a signed, verified run in a few minutes"),
    ("coding-agents.md", "Codex, Cursor and Gemini CLI; Claude Code is in the quickstart"),
    ("concepts/README.md", "the design, one concept per page, in reading order"),
    ("integrations.md", "frameworks, sandboxes and gateways"),
    ("verdicts.md", "what each line of `tracekit verify` means"),
    ("deploy.md", "a signer the agent can't reach"),
    ("faq.md", "what a verified run proves, and what it doesn't"),
]
FOOTER = "Generated from [docs/]({repo}/tree/{ref}/docs) at {ref}. Edit the docs in the repository, not here.\n"

FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$")
LINK = re.compile(r"(!?)\[((?:[^\[\]]|\[[^\]]*\])*)\]\(([^)\s]+)\)")
ANCHOR = re.compile(r'<a (?:id|name)="([^"]+)"')
SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)


def prose(text):
    """Each line of `text` with True where it is outside a fenced code block."""
    fence = None
    for line in text.split("\n"):
        m = FENCE.match(line)
        if m and (fence is None or (m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence))):
            fence = m.group(1) if fence is None else None
            yield line, False
        else:
            yield line, fence is None


def paragraphs(text):
    """`text` as runs of lines, each with True where it is a paragraph outside fenced code: a link's text may wrap
    within a paragraph, never across a blank line or a fence."""
    for outside, run in itertools.groupby(prose(text), lambda lo: lo[1] and lo[0].strip() != ""):
        yield "\n".join(line for line, _ in run), outside


def slug(heading):
    """GitHub's anchor for a heading: its rendered text, lowercased, without punctuation, spaces as hyphens."""
    text = re.sub(r"!?\[((?:[^\[\]]|\[[^\]]*\])*)\]\([^)]*\)", r"\1", heading)
    text = re.sub(r"<[^>]+>", "", text)
    return "".join(c for c in text.lower() if c.isalnum() or c in " -_").replace(" ", "-")


def anchors(text):
    """Every anchor of a page: its <a id> and its headings', a repeated one with -1, -2, ... as on GitHub."""
    seen = {}
    out = set()
    for line, outside in prose(text):
        out.update(ANCHOR.findall(line) if outside else ())
        m = outside and HEADING.match(line)
        if m:
            s = slug(m.group(1))
            out.add(f"{s}-{seen[s]}" if s in seen else s)
            seen[s] = seen.get(s, 0) + 1
    return out


def title(text, name):
    """A page's H1 without code marks or a trailing parenthesis: the sidebar's label."""
    h1 = re.search(r"^# (.+)$", text, re.M)
    return re.sub(r"\s*\([^)]*\)$", "", h1.group(1).replace("`", "")) if h1 else name.replace("-", " ")


def sidebar_pages(pages):
    """[(section, [docs path, ...])] from SECTIONS, and the errors: a page placed twice, in no section, or missing."""
    sections, placed, errors = [], [], []
    for section, entries in SECTIONS:
        paths = []
        for entry in entries:
            hits = sorted(p for p in pages if fnmatch.fnmatchcase(p, entry)) if "*" in entry else [entry]
            for p in hits:
                if "*" in entry and p in placed:
                    continue
                if p in placed:
                    errors.append(f"docs/{p}: in the sidebar twice")
                if p not in pages:
                    errors.append(f"docs/{p}: in the sidebar but not a docs page")
                placed.append(p)
                paths.append(p)
        sections.append((section, paths))
    errors += [f"docs/{p}: not in the sidebar; add it to SECTIONS (or EXCLUDED) in scripts/wiki.py"
               for p in sorted(set(pages) - set(placed))]
    return sections, errors


def pages(root=ROOT):
    """The wiki's pages: every page under docs/ but EXCLUDED, as its path under docs/, sorted."""
    docs = os.path.join(root, "docs")
    found = (os.path.relpath(p, docs).replace(os.sep, "/")
             for p in glob.glob(os.path.join(docs, "**", "*.md"), recursive=True))
    return sorted(p for p in found if p not in EXCLUDED)


def build(ref, root=ROOT):
    """The wiki as {path in OUT_DIR: text, or the source file of an image}. Exits listing every error."""
    texts = {}
    for p in pages(root):
        with open(os.path.join(root, "docs", p), encoding="utf-8") as f:
            texts[p] = f.read()
    names = {p: page_name(p) for p in texts}
    sections, errors = sidebar_pages(texts)
    clash = {}
    for p, n in names.items():
        clash.setdefault(n.lower(), []).append(p)
    errors += [f"pages named alike: {', '.join(ps)}" for ps in clash.values() if len(ps) > 1]
    marks = {p: anchors(t) for p, t in texts.items()}
    out = {}

    def relink(page, m):
        bang, label, target = m.groups()
        if SCHEME.match(target):
            return m.group(0)
        path, _, anchor = target.partition("#")
        dest = posixpath.normpath(posixpath.join(posixpath.dirname("docs/" + page), path)) if path else "docs/" + page
        doc = dest[len("docs/"):] if dest.startswith("docs/") else None
        if doc and doc + "/README.md" in texts:
            doc += "/README.md"
        if doc in texts:
            if anchor and anchor not in marks[doc]:
                errors.append(f"docs/{page}: ({target}): docs/{doc} has no heading #{anchor}")
            return f"{bang}[{label}]({names[doc] if path else ''}{'#' + anchor if anchor else ''})"
        if dest.startswith("../") or dest == ".." or not os.path.exists(os.path.join(root, dest)):
            errors.append(f"docs/{page}: ({target}) resolves to nothing")
            return m.group(0)
        if bang:
            image = "images/" + (doc or dest)
            out[image] = os.path.join(root, dest)
            return f"![{label}]({image})"
        kind = "tree" if os.path.isdir(os.path.join(root, dest)) else "blob"
        return f"[{label}]({REPO}/{kind}/{ref}/{dest}{'#' + anchor if anchor else ''})"

    for p, text in texts.items():
        out[names[p] + ".md"] = "\n".join(LINK.sub(lambda m: relink(p, m), run) if outside else run
                                          for run, outside in paragraphs(text))
    for p, _ in START:
        if p not in texts:
            errors.append(f"docs/{p}: on Home but not a docs page")
    if errors:
        raise SystemExit("wiki: nothing written:\n  " + "\n  ".join(errors))
    label = {p: title(texts[p], names[p]) for p in texts}
    out["Home.md"] = HOME + "".join(f"- [{label[p]}]({names[p]}): {why}\n" for p, why in START)
    out["_Sidebar.md"] = "**[Home](Home)**\n" + "".join(
        f"\n**{section}**\n\n" + "".join(f"- [{label[p]}]({names[p]})\n" for p in paths) for section, paths in sections)
    out["_Footer.md"] = FOOTER.format(repo=REPO, ref=ref)
    return out


def write(out, out_dir):
    if os.path.exists(out_dir) and os.listdir(out_dir):
        raise SystemExit(f"wiki: {out_dir} is not empty")
    for rel, value in sorted(out.items()):
        path = os.path.join(out_dir, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if rel.startswith("images/"):
            shutil.copyfile(value, path)
        else:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(value)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("out_dir", nargs="?")
    ap.add_argument("--ref", default="main", help="the tag or commit the pages' repository links point at")
    ap.add_argument("--map", action="store_true", help="print {docs path: wiki URL} as JSON and write nothing")
    args = ap.parse_args(argv)
    if args.map:
        print(json.dumps({f"docs/{p}": wiki_url(f"docs/{p}") for p in pages()}, indent=2))
        return
    if not args.out_dir:
        ap.error("OUT_DIR is required without --map")
    out = build(args.ref)
    write(out, args.out_dir)
    n = sum(1 for rel in out if rel.endswith(".md") and not rel.startswith("_"))
    print(f"wiki: {n} pages, {len(out) - n - 2} images in {args.out_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
