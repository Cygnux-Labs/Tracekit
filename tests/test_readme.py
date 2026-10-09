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
        for prefix in ("pip install tracekit-ai", "tracekit demo", "tracekit init --dev", "tracekit verify docs/sample/"):
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

    def test_demo_tape_renders_the_embedded_gif(self):
        with open(os.path.join(ROOT, "docs", "demo", "demo.tape"), encoding="utf-8") as f:
            tape = f.read()
        self.assertIn("Output docs/demo/demo.gif", tape)
        self.assertIn('Type "tracekit demo"', tape)
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            self.assertIn('src="docs/demo/demo.gif"', f.read())
