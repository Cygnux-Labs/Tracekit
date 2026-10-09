import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK = re.compile(r"\]\(([^)\s]+)\)")


class DocLinks(unittest.TestCase):
    def test_relative_links_resolve(self):
        files = [os.path.join(ROOT, "README.md")] + glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True)
        broken = []
        for path in files:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for target in LINK.findall(text):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                rel = target.split("#", 1)[0]
                if not os.path.exists(os.path.join(os.path.dirname(path), rel)):
                    broken.append(f"{os.path.relpath(path, ROOT)}: {target}")
        self.assertEqual(broken, [])
