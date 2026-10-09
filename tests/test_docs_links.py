import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK = re.compile(r"\]\(([^)\s]+)\)")
SKIP = ("paper/", "planning/", "node_modules/", ".agent-flow", ".worktrees/")


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, ".git")), "docs link across the repository; an sdist ships only part of it")
class DocLinks(unittest.TestCase):
    def test_relative_links_resolve(self):
        tracked = subprocess.run(["git", "ls-files", "-z", "--", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        files = [f for f in tracked.split("\0") if f and not f.startswith(SKIP) and "/node_modules/" not in f]
        self.assertIn("README.md", files)
        broken = []
        for rel_path in files:
            path = os.path.join(ROOT, rel_path)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for target in LINK.findall(text):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                rel = target.split("#", 1)[0]
                if not os.path.exists(os.path.join(os.path.dirname(path), rel)):
                    broken.append(f"{rel_path}: {target}")
        self.assertEqual(broken, [])
