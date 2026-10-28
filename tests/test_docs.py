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

import yaml

from tracekit import cli
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
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


class DocTables(unittest.TestCase):
    def test_every_table_has_one_header_and_no_row_outside_it(self):
        """why.md's API table had its header twice, and two command rows sat after a paragraph, outside any table."""
        sep, bad = re.compile(r"^\|(?: *:?-+:? *\|)+$"), []
        for path in sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True)):
            lines = FENCE.sub(lambda m: "\n" * m.group(0).count("\n"), read(path)).split("\n")
            for i, line in enumerate(lines):
                first = line.startswith("|") and not (i and lines[i - 1].startswith("|"))
                if first and not sep.match(lines[i + 1] if i + 1 < len(lines) else "") or \
                        sep.match(line) and i > 1 and lines[i - 2].startswith("|"):
                    bad.append(f"{os.path.relpath(path, ROOT)}:{i + 1}")
        self.assertEqual(bad, [])


def documented_authorize():
    """(where, its `authorize` mapping) for every signer config the docs and deploy examples give."""
    for page in ("docs/deploy.md", "docs/remote-ingest.md", "docs/identity.md"):
        for lang, block in FENCE.findall(read(os.path.join(ROOT, page))):
            if lang == "yaml" and re.search(r"^authorize:", block, re.M):
                yield page, yaml.safe_load(block)["authorize"]
    example = read(os.path.join(ROOT, "deploy", "docker", "signer.yaml.example"))   # the central block, commented out
    yield "signer.yaml.example", yaml.safe_load(re.search(r"^# (authorize: .*)", example, re.M).group(1))["authorize"]
    with open(os.path.join(ROOT, "examples", "v2", "agent_sandbox", "signer.yaml"), encoding="utf-8") as f:
        config = next(o for o in yaml.safe_load_all(f) if o["kind"] == "ConfigMap")["data"]["signer.yaml"]
    yield "agent_sandbox/signer.yaml", yaml.safe_load(config)["authorize"]


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, ".git")), "reads deploy/ and examples/, which an sdist leaves out")
class DocumentedGrants(unittest.TestCase):
    def test_every_documented_agent_grant_list_lets_an_adapter_run_a_call(self):
        """The lists lacked approval_consume, which the adapters call after every allow: each allowed call was blocked."""
        agent, call = CallerIdentity("token", "agent", True), {"tool_call_id": "t1", "tool": "Read",
                                                                "args_source": "parsed", "args": {"file_path": "a"}}
        lists = [(where, who, grants) for where, authorize in documented_authorize()
                 for who, grants in authorize.items() if "register_run" in grants]
        self.assertGreaterEqual(len(lists), 6)
        for where, who, grants in lists:
            with self.subTest(where=where, who=who):
                d = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, d, True)
                s = service.SignerService(d, authorize={"token:agent": grants})
                self.addCleanup(s.close)
                run = s.call(agent, "register_run", {"request_id": "r0", "agent": {"name": "a"}})
                ids = {"run_id": run["run_id"], "run_token": run["run_token"]}
                d = s.call(agent, "decide", {"request_id": "r1", **ids, "stream": "s", "client_seq": 0, **call})
                self.assertEqual(d["decision"], "allow")
                self.assertTrue(s.call(agent, "approval_consume", {"request_id": "r2", **ids, **call})["ok"])
                s.call(agent, "complete", {"request_id": "r3", **ids, "stream": "s", "client_seq": 1, "status": "ok",
                                           "tool_call_id": "t1", "decision_id": d["decision_id"],
                                           "args_digest": event_hash({"tool": "Read", "args": call["args"]})})
                s.call(agent, "status", {})   # the content vault's limit, for what the model said
                if who.startswith("token:"):   # a coding-agent hook's identity on a remote signer: each prompt
                    s.call(agent, "constraint_add", {"request_id": "r5", **ids, "constraint": {"kind": "no_push"}})
                    s.call(agent, "observe", {"request_id": "r6", **ids, "stream": "s", "client_seq": 2,
                                              "source": "claude-code:UserPromptSubmit", "trust": "trusted",
                                              "value": "don't push"})
                s.call(agent, "close_run", {"request_id": "r4", **ids})


class LimitsIndex(unittest.TestCase):
    def test_every_doc_with_a_limits_section_is_linked_from_limits_md(self):
        limits = os.path.join(ROOT, "docs", "limits.md")
        linked = {os.path.normpath(os.path.join(ROOT, "docs", t.split("#", 1)[0])) for t in LINK.findall(read(limits))}
        section = re.compile(r"(?:\A|\n\n)(?:#+ [^\n]*\blimits\b|\**limits\b)", re.I)
        pages = glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True)
        with_limits = [p for p in pages if p != limits and section.search(read(p))]
        self.assertIn(os.path.join(ROOT, "docs", "issuer.md"), with_limits)
        self.assertEqual([os.path.relpath(p, ROOT) for p in with_limits if os.path.normpath(p) not in linked], [])


class DocCommands(unittest.TestCase):
    def test_every_tracekit_command_in_a_code_block_exists(self):
        known = cli_commands()
        self.assertIn("verify", known)
        pages = [os.path.join(ROOT, "README.md")] + glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True)
        unknown = [f"{os.path.relpath(p, ROOT)}: tracekit {m}" for p in pages for _, block in FENCE.findall(read(p))
                   for m in COMMAND.findall(block) if m not in known]
        self.assertEqual(unknown, [])

    def test_no_system_mode_command_needs_tracekit_on_roots_path(self):
        """System-mode init installs Tracekit only into /opt/tracekit (install._install_venv) and puts no `tracekit`
        command on root's PATH, so `sudo tracekit ...` finds none there. `tracekit deploy compose` isn't system mode."""
        pages = [os.path.join(ROOT, "README.md"), os.path.join(ROOT, "tracekit_sdk.py")] + [
            p for pattern in ("docs/**/*.md", "plugin/**/*.md", "tracekit/**/*.py", "tracekit/**/*.yaml", "eval/*.py",
                              "eval/*.yaml")
            for p in glob.glob(os.path.join(ROOT, pattern), recursive=True)]
        hits = [f"{os.path.relpath(p, ROOT)}:{n}" for p in pages for n, line in enumerate(read(p).splitlines(), 1)
                if re.search(r"sudo tracekit (?!deploy )", line)]
        self.assertEqual(hits, [])

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
