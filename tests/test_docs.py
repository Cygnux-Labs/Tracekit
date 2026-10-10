import argparse
import contextlib
import glob
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

from tracekit import cli
from tracekit.signer import service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK = re.compile(r"\]\(([^)\s]+)\)")
SKIP = ("paper/", "planning/", "node_modules/", ".agent-flow", ".worktrees/")
FENCE = re.compile(r"^```(\w*)\n(.*?)^```", re.M | re.S)
COMMAND = re.compile(r"(?:^|(?<=\s))tracekit ([a-z][\w-]*)", re.M)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def cli_commands():
    """The subcommand names of `tracekit`'s parser."""
    names = {}

    def grab(parser, *a, **k):
        names.update(next(x for x in parser._actions if isinstance(x, argparse._SubParsersAction)).choices)
        raise SystemExit(0)

    with mock.patch.object(argparse.ArgumentParser, "parse_args", grab), contextlib.suppress(SystemExit):
        cli.main(["--version"])
    return set(names)


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, ".git")), "docs link across the repository; an sdist ships only part of it")
class DocLinks(unittest.TestCase):
    def test_relative_links_resolve(self):
        tracked = subprocess.run(["git", "ls-files", "-z", "--", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        files = [f for f in tracked.split("\0") if f and not f.startswith(SKIP) and "/node_modules/" not in f]
        self.assertIn("README.md", files)
        broken = []
        for rel_path in files:
            path = os.path.join(ROOT, rel_path)
            for target in LINK.findall(read(path)):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                rel = target.split("#", 1)[0]
                if not os.path.exists(os.path.join(os.path.dirname(path), rel)):
                    broken.append(f"{rel_path}: {target}")
        self.assertEqual(broken, [])


class DocCommands(unittest.TestCase):
    def test_every_tracekit_command_in_a_code_block_exists(self):
        known = cli_commands()
        self.assertIn("verify", known)
        pages = [os.path.join(ROOT, "README.md")] + glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True)
        unknown = [f"{os.path.relpath(p, ROOT)}: tracekit {m}" for p in pages for _, block in FENCE.findall(read(p))
                   for m in COMMAND.findall(block) if m not in known]
        self.assertEqual(unknown, [])

    def test_signer_yaml_snippets_in_deploy_guide_load(self):
        blocks = [b for lang, b in FENCE.findall(read(os.path.join(ROOT, "docs", "deploy.md")))
                  if lang == "yaml" and b.startswith("# signer.yaml")]
        self.assertGreaterEqual(len(blocks), 2)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "signer.yaml")
        # the TLS files and service-account CA the snippets name exist only where the signer is deployed
        with mock.patch.object(ssl.SSLContext, "load_cert_chain"), mock.patch("ssl.create_default_context"):
            for i, block in enumerate(blocks):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(block)
                for blocked in (False, True):
                    with self.subTest(block=i, pyyaml_blocked=blocked), \
                            mock.patch.dict("sys.modules", {"yaml": None} if blocked else {}):
                        self.assertIn("data_dir", service.load_config(path))
