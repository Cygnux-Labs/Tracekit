import os
import re
import shlex
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCK = re.compile(r"^```(?:bash|sh)\n(.*?)^```", re.M | re.S)
EXIT = re.compile(r"^(tracekit [^#]*?)\s*# exit (\d+)$")
SAFE = {"demo", "--version", "verify"}  # need no network or root


def readme_commands():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        blocks = BLOCK.findall(f.read())
    return [line.strip() for b in blocks for line in b.splitlines()
            if line.strip().startswith(("tracekit", "pip install"))]


class Readme(unittest.TestCase):
    def test_shell_blocks_listed(self):
        cmds = readme_commands()
        for prefix in ("pip install tracekit-ai", "tracekit last", "tracekit demo --server", "tracekit init --dev --v2", "tracekit verify docs/sample/"):
            self.assertTrue(any(c.startswith(prefix) for c in cmds), prefix)

    def test_annotated_commands_exit_as_stated(self):
        runs = [m.groups() for m in map(EXIT.match, readme_commands()) if m]
        self.assertGreaterEqual(len(runs), 3)
        for cmd, code in runs:
            argv = shlex.split(cmd)[1:]
            self.assertIn(argv[0], SAFE, cmd)
            p = subprocess.run([sys.executable, "-m", "tracekit", *argv], cwd=ROOT, capture_output=True, text=True,
                               timeout=300)
            self.assertEqual(p.returncode, int(code), f"{cmd}\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")

    def test_version(self):
        p = subprocess.run([sys.executable, "-m", "tracekit", "--version"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        self.assertTrue(p.stdout.startswith("tracekit "))

    def test_hero_is_the_reproducible_observer_video(self):
        with open(os.path.join(ROOT, "docs", "demo", "record_observer.mjs"), encoding="utf-8") as f:
            self.assertIn('"observer.gif"', f.read())
        self.assertTrue(os.path.exists(os.path.join(ROOT, "docs", "demo", "observer_scene.py")))
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            self.assertIn('src="https://raw.githubusercontent.com/Cygnux-Labs/Tracekit/main/docs/demo/observer.gif"', f.read())

    def test_repo_links_point_at_existing_files(self):
        # README links are absolute so they work on PyPI too; each must still name a file in this repository
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            paths = re.findall(r"https://github\.com/Cygnux-Labs/Tracekit/(?:blob|tree)/main/([^)#\s\"]+)", f.read())
        self.assertTrue(paths)
        self.assertEqual([p for p in paths if not os.path.exists(os.path.join(ROOT, p))], [])
