import glob
import importlib.util
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
REF = "v9.9.9"


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
    return [m.group(3) for line, outside in wiki.prose(text) if outside for m in wiki.LINK.finditer(line)]


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
