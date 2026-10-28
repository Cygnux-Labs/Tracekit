import glob
import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("wiki", os.path.join(ROOT, "scripts", "wiki.py"))
wiki = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wiki)
from tracekit.wiki import WIKI  # noqa: E402  (scripts/wiki.py put this checkout first on sys.path)
REF = "v9.9.9"
# what sends people to the docs from outside docs/: these files and everything under tracekit/
OUTSIDE = ["README.md", "plugin/README.md", "pyproject.toml", "plugin/.claude-plugin/plugin.json", "server.json"]
WIKI_LINK = re.compile(re.escape(WIKI) + r"(?:/([A-Za-z0-9-]+))?(?:#([\w-]+))?")
WIKI_CALL = re.compile(r"""wiki_url\(\s*['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?\s*\)""")
DOCS_ON_GITHUB = re.compile(r"github\.com/Cygnux-Labs/Tracekit/(?:blob|tree)/[^/\s]+/docs/[^)\s\"'#]+\.md")


def outside_docs():
    """{path: text} of every file outside docs/ that links to the docs."""
    paths = OUTSIDE + [os.path.relpath(p, ROOT) for ext in ("py", "html", "yaml", "json")
                       for p in glob.glob(os.path.join(ROOT, "tracekit", "**", f"*.{ext}"), recursive=True)]
    texts = {}
    for p in paths:
        with open(os.path.join(ROOT, p), encoding="utf-8") as f:
            texts[p.replace(os.sep, "/")] = f.read()
    return texts


def generate():
    d = tempfile.mkdtemp()
    wiki.main([d, "--ref", REF])
    out = {}
    for base, _, files in os.walk(d):
        for f in files:
            with open(os.path.join(base, f), "rb") as fh:
                out[os.path.relpath(os.path.join(base, f), d).replace(os.sep, "/")] = fh.read()
    shutil.rmtree(d)
    return out


def links(text):
    return [m.group(3) for run, outside in wiki.paragraphs(text) if outside for m in wiki.LINK.finditer(run)]


class Wiki(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = generate()
        cls.pages = {k[:-3]: v.decode() for k, v in cls.out.items() if k.endswith(".md")}

    def test_every_docs_page_is_one_page_and_one_sidebar_entry(self):
        docs = os.path.join(ROOT, "docs")
        paths = [os.path.relpath(p, docs).replace(os.sep, "/") for p in glob.glob(os.path.join(docs, "**", "*.md"), recursive=True)]
        names = sorted(wiki.page_name(p) for p in paths if p not in wiki.EXCLUDED)
        self.assertIn("Integrations-OpenShell", names)
        self.assertIn("A2A", names)
        self.assertIn("C2C", names)
        self.assertNotIn("RELEASING", self.pages)
        entries = [t for t in links(self.pages["_Sidebar"]) if t != "Home"]
        self.assertEqual(sorted(entries), names)
        self.assertEqual(sorted(set(self.pages) - {"Home", "_Sidebar", "_Footer"}), names)

    def test_every_internal_link_and_anchor_resolves(self):
        repo = re.compile(re.escape(wiki.REPO) + rf"/(?:blob|tree)/{REF}/([^#]+)")
        broken = []
        for page, text in self.pages.items():
            for target in links(text):
                m = repo.match(target)
                if m:
                    ok = os.path.exists(os.path.join(ROOT, m.group(1)))
                elif wiki.SCHEME.match(target):
                    continue
                elif target.startswith("images/"):
                    ok = target in self.out
                else:
                    name, _, anchor = target.partition("#")
                    dest = self.pages.get(name or page)
                    ok = dest is not None and (not anchor or anchor in wiki.anchors(dest))
                if not ok:
                    broken.append(f"{page}: {target}")
        self.assertEqual(broken, [])
        self.assertIn(f"/blob/{REF}/", self.pages["Concepts-Evidence-Format"])
        self.assertIn(f" at {REF}.", self.pages["_Footer"])

    def test_no_page_links_to_a_docs_file(self):
        """Links whose text wrapped a line were never rewritten: pages linked to .md files and ../ paths."""
        left = re.compile(r"\]\((?![a-z][a-z0-9+.-]*:)[^)\s]*\.md[#)]|\]\(\.\./")
        self.assertEqual([f"{p}: {m}" for p, t in self.pages.items() for m in left.findall(t)], [])

    def test_links_from_outside_docs_name_wiki_pages_and_anchors(self):
        bad, seen = [], 0
        for path, text in outside_docs().items():
            found = [(page or "Home", anchor) for page, anchor in WIKI_LINK.findall(text)]
            found += [(wiki.page_name(doc[len("docs/"):]) if doc.startswith("docs/") else doc, anchor)
                      for doc, anchor in WIKI_CALL.findall(text)]
            for page, anchor in found:
                seen += 1
                if page not in self.pages or (anchor and anchor not in wiki.anchors(self.pages[page])):
                    bad.append(f"{path}: {page}#{anchor}")
        self.assertEqual(bad, [])
        self.assertGreater(seen, 100)

    def test_nothing_outside_docs_links_to_a_docs_page_on_github(self):
        self.assertEqual([f"{p}: {m}" for p, t in outside_docs().items() for m in DOCS_ON_GITHUB.findall(t)], [])

    def test_map(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            wiki.main(["--map"])
        mapping = json.loads(out.getvalue())
        self.assertEqual(len(mapping), len(self.pages) - 3)   # Home, _Sidebar and _Footer aren't docs pages
        self.assertEqual(mapping["docs/integrations/openshell.md"], wiki.wiki_url("docs/integrations/openshell.md"))
        self.assertTrue(mapping["docs/integrations/openshell.md"].endswith("/wiki/Integrations-OpenShell"))

    def test_output_is_deterministic(self):
        self.assertEqual(generate(), self.out)

    def test_github_slugs(self):
        self.assertEqual(wiki.slug("Provenance and `tracekit why`"), "provenance-and-tracekit-why")
        self.assertEqual(wiki.slug("E1: tamper [detection](x.md), **v2**"), "e1-tamper-detection-v2")
        self.assertEqual(wiki.anchors('# A\n## A\n```\n# B\n```\n<a id="c"></a>'), {"a", "a-1", "c"})

    def test_a_page_missing_from_the_sidebar_fails(self):
        sections = [(s, [p for p in paths if p != "faq.md"]) for s, paths in wiki.SECTIONS]
        with mock.patch.object(wiki, "SECTIONS", sections), self.assertRaises(SystemExit) as e:
            wiki.build("main")
        self.assertIn("docs/faq.md: not in the sidebar", str(e.exception))

    def test_a_link_to_nothing_fails(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.mkdir(os.path.join(root, "docs"))
        with open(os.path.join(root, "docs", "faq.md"), "w", encoding="utf-8") as f:
            f.write("# FAQ\n\n[a](gone.md) [b](#nowhere) [c](faq.md#faq)\n")
        with mock.patch.object(wiki, "SECTIONS", [("Help", ["faq.md"])]), self.assertRaises(SystemExit) as e:
            wiki.build("main", root)
        self.assertIn("docs/faq.md: (gone.md) resolves to nothing", str(e.exception))
        self.assertIn("docs/faq.md: (#nowhere): docs/faq.md has no heading #nowhere", str(e.exception))
        self.assertNotIn("faq.md#faq", str(e.exception))
