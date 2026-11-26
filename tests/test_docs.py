import argparse
import contextlib
import glob
import hashlib
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

from tracekit import agent_hooks, cli, install, privacy, report
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.policy2 import compile as pc
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

    def test_kilo_and_opencode_rows_name_only_the_tools_still_unread(self):
        # #988: Kilo's browser_open, repo_clone and kilo_memory_save are decided by what they do, and an http(s) image
        # of OpenCode's experimental_image_generate by the fetch rules
        text = read(os.path.join(ROOT, "docs", "limits.md"))
        kilo = next(r for r in text.splitlines() if r.startswith("| Kilo's own tools that Tracekit doesn't map"))
        self.assertIn("Among them: `agent_manager`", kilo)
        self.assertIn("`browser_open` and `repo_clone` are decided as a `WebFetch`", kilo)
        self.assertIn("`kilo_memory_save` is decided as a `Write`", kilo)
        self.assertNotIn("is decided as a path, not by the fetch rules", text)

    def test_a_rule_the_docs_call_flagged_held_or_denied_decides_so_in_a_shipped_pack(self):
        # limits.md once called TK-F009 and TK-F015 "flagged" after they had become holds in every pack
        sections = {}
        for pack in ("coding", "dev", "server", "strict"):
            policy = pc.build(os.path.join(ROOT, "tracekit", "policy2", "packs", pack + ".yaml"))[0]
            for sec in ("deny", "ask", "flag"):
                for r in policy.get(sec, []):
                    sections.setdefault(r["id"], set()).add(sec)
        verb = {"flagged": "flag", "held": "ask", "denied": "deny"}
        named = re.compile(r"\b(flagged|held|denied)\s*\(((?:`TK-[A-Z0-9-]+`(?:,\s*|\s+and\s+|\s+or\s+)?)+)\)")
        pages = [os.path.join(ROOT, "README.md")] + glob.glob(os.path.join(ROOT, "docs", "**", "*.md"), recursive=True)
        wrong = [f"{os.path.relpath(p, ROOT)}: {said} ({rid}), but it is {sorted(sections[rid])}"
                 for p in pages for said, ids in named.findall(read(p)) for rid in re.findall(r"TK-[A-Z0-9-]+", ids)
                 if rid in sections and verb[said] not in sections[rid]]
        self.assertEqual(wrong, [])


class DocCommands(unittest.TestCase):
    def test_system_mode_upgrade_docs_include_macos_signer_label(self):
        """The macOS upgrade commands must use the launchd label configured by init."""
        upgrade = read(os.path.join(ROOT, "docs", "deploy.md")).split("To upgrade:", 1)[1]
        self.assertIn(f"sudo launchctl bootout system/{install.V2_LABEL}", upgrade)

    def test_every_tracekit_command_in_a_code_block_exists(self):
        known = cli_commands()
        self.assertIn("verify", known)
        pages = [os.path.join(ROOT, "README.md")] + [p for d in ("docs", "plugin") for p in glob.glob(
            os.path.join(ROOT, d, "**", "*.md"), recursive=True)]
        unknown = [f"{os.path.relpath(p, ROOT)}: tracekit {m}" for p in pages for _, block in FENCE.findall(read(p))
                   for m in COMMAND.findall(block) if m not in known]
        self.assertEqual(unknown, [])

    def test_the_agent_lists_name_every_coding_agent(self):
        # the README's `--agent` list, deploy.md's (once 8 of them) and coding-agents.md's v1 one (once without kiro and
        # interpreter)
        readme = re.search(r"add `--agent codex`, (.*?) for the others", read(os.path.join(ROOT, "README.md")), re.S)
        deploy = re.search(r"own hook with `--agent` \((.*?); \[coding agents\]", read(os.path.join(ROOT, "docs", "deploy.md")),
                           re.S)
        v1 = re.search(r"tracekit init --dev --agent codex +# v1; or (.*)", read(os.path.join(ROOT, "docs", "coding-agents.md")))
        self.assertEqual({"codex", *re.findall(r"`([a-z]+)`", readme.group(1))}, set(agent_hooks.HARNESSES))
        self.assertEqual(set(re.findall(r"`([a-z]+)`", deploy.group(1))), set(agent_hooks.HARNESSES))
        self.assertEqual({"codex", *re.findall(r"[a-z]+", v1.group(1))}, set(agent_hooks.HARNESSES))

    def test_field_reports_md_names_every_agent_a_shared_report_prints(self):
        # what `audit --share` reveals: the page once listed 12 of the 22 names report.AGENTS prints
        text = read(os.path.join(ROOT, "docs", "field-reports.md"))
        listed = re.search(r"An agent name is printed only when it is one Tracekit's own hooks and tools give a run \((.*?)\)",
                           text, re.S)
        self.assertEqual(set(re.findall(r"`([a-z-]+)`", listed.group(1))), report.AGENTS)

    def test_privacy_md_names_every_tool_call_field_kept_in_clear(self):
        # it once left out `commands`, `paths` and `urls`
        row = next(r for r in read(os.path.join(ROOT, "docs", "privacy.md")).splitlines()
                   if r.startswith("| `tool.call` | `command`"))
        self.assertEqual(set(re.findall(r"`([a-z_]+)`", row.split("|")[2])), privacy.ALWAYS_CLEAR)

    def test_no_command_needs_tracekit_on_roots_path(self):
        """System-mode init installs Tracekit only into /opt/tracekit (install._install_venv) and puts no `tracekit`
        command on root's PATH, so `sudo tracekit ...` finds none there. Nor does `deploy compose` from a checkout's or a
        venv's Tracekit, which docs/deploy-compose.md gave as `sudo tracekit deploy compose` (#464)."""
        pages = [os.path.join(ROOT, "README.md"), os.path.join(ROOT, "tracekit_sdk.py")] + [
            p for pattern in ("docs/**/*.md", "plugin/**/*.md", "tracekit/**/*.py", "tracekit/**/*.yaml", "eval/*.py",
                              "eval/*.yaml")
            for p in glob.glob(os.path.join(ROOT, pattern), recursive=True)]
        hits = [f"{os.path.relpath(p, ROOT)}:{n}" for p in pages for n, line in enumerate(read(p).splitlines(), 1)
                if "sudo tracekit " in line]
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


class PluginSkills(unittest.TestCase):
    def test_every_skill_states_the_fixed_rule(self):
        """A harness loads each skill on its own, so each says it: the agent never answers a hold or changes Tracekit,
        and gives the person the approve command to run. Each is named as its folder, as Agent Skills requires."""
        skills = glob.glob(os.path.join(ROOT, "plugin", "skills", "*", "SKILL.md"))
        self.assertGreaterEqual(len(skills), 4)
        for path in skills:
            text = read(path)
            words = " ".join(text.split())
            with self.subTest(skill=os.path.basename(os.path.dirname(path))):
                self.assertTrue(text.startswith(f"---\nname: {os.path.basename(os.path.dirname(path))}\n"))
                self.assertIn("change Tracekit's policy, signer, hooks or files", words)
                self.assertIn("`tracekit approvals approve", words)
                # what the policy does, as it does it (the plugin review: "blocks any change to its files" wasn't so
                # for the hooks and plugins, which TK-F009 and TK-F015 hold)
                if "**The fixed rule.**" in text:
                    self.assertIn("blocks an agent's own approval (TK-D012) and changes to Tracekit's own files "
                                  "(TK-D007, TK-D013), and holds changes to the agent's hooks and plugins, Tracekit's "
                                  "among them, for a person (TK-F009, TK-F015)", words)

    def test_the_setup_skill_knows_where_the_plugins_hooks_run_and_what_it_installs(self):
        """The plugin review: the setup skill told Codex, Copilot CLI and Cursor plugin users to run init with
        --no-hooks and to discount doctor's D-HOOKS-PRESENT, which left the agent unguarded on native Windows, where
        the plugin's POSIX shell hooks don't run; its "came from the plugin" check (a skills/ folder next to any hooks/
        folder) matched a standalone install beside a user's own hooks, so init ran with --no-hooks and none ran; and
        it installed whatever tracekit-ai the index or uv's cache gave, which can be older than the plugin's hooks."""
        text = read(os.path.join(ROOT, "plugin", "skills", "tracekit-setup", "SKILL.md"))
        words = " ".join(text.split())
        self.assertIn("On native Windows (not WSL), the plugin's hooks don't run", words)
        self.assertIn("run `tracekit init --dev --v2 --agent <name>` without `--no-hooks`", words)
        self.assertIn("On native Windows, where init wrote the hooks, a `D-HOOKS-PRESENT` warning is real", words)
        self.assertIn("both the plugin's `hooks/<agent>.json`", words)
        self.assertIn("and `scripts/tracekit-hook` are there", words)
        installs = re.findall(r"(?:install|--from)\s+'?(tracekit-ai[^\s']*)", text)
        self.assertEqual(len(installs), 3)   # uvx --from, uv tool install, pip install
        self.assertEqual(set(installs), {"tracekit-ai>=1.7.0"})

    def test_the_plugins_setup_skill_is_the_public_one(self):
        """The plugin ships Cygnux-Labs/tracekit-skills' skills/tracekit-setup/SKILL.md byte for byte, so skill indexes
        find one text. Change it there first, copy it here, then pin its git blob id: `git rev-parse
        main:skills/tracekit-setup/SKILL.md` in that repository."""
        data = read(os.path.join(ROOT, "plugin", "skills", "tracekit-setup", "SKILL.md")).encode("utf-8")
        self.assertEqual(hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(),
                         "a792c2ddc745f83318e438814e8dec430cf0c920")   # the plugin's skills, for every agent


class DocTableCells(unittest.TestCase):
    def test_every_table_row_has_as_many_cells_as_its_header(self):
        """#644: a bare | inside a code span splits the cell on GitHub, so the row shows more cells than its header. An
        escaped \\| is no border; fenced blocks are left out, kept as blank lines so line numbers stay true."""
        sep = re.compile(r"^\|(\s*:?-+:?\s*\|)+$")

        def cells(line):
            return len(re.findall(r"(?<!\\)\|", line))
        bad = []
        for path in sorted([os.path.join(ROOT, "README.md")] + glob.glob(os.path.join(ROOT, "docs", "**", "*.md"),
                                                                        recursive=True)):
            lines = FENCE.sub(lambda m: "\n" * m.group(0).count("\n"), read(path)).splitlines()
            for i in range(len(lines) - 1):
                if lines[i].startswith("|") and sep.match(lines[i + 1].strip()):
                    j = i + 2
                    while j < len(lines) and lines[j].startswith("|"):
                        if cells(lines[j]) != cells(lines[i]):
                            bad.append(f"{os.path.relpath(path, ROOT)}:{j + 1}")
                        j += 1
        self.assertEqual(bad, [])


class VaultDocs(unittest.TestCase):
    def test_the_docs_do_not_ask_for_a_restart_after_a_vault_change(self):
        """#986: the gateway re-reads the vault's state every interval, so the restart these pages asked for is no
        longer what an operator has to do."""
        self.assertNotIn("Restart the gateway after you turn the vault on",
                         read(os.path.join(ROOT, "docs", "gateway.md")))
        rows = [line for line in read(os.path.join(ROOT, "docs", "limits.md")).splitlines()
                if "not_retained" in line and "`status`" in line]
        self.assertEqual(len(rows), 1)
        self.assertNotIn("restart it after turning the vault on or off", rows[0])
        self.assertIn("minute", rows[0])   # and says what an operator should allow instead


class ReadmePromises(unittest.TestCase):
    def test_the_readme_names_the_verdict_a_tampered_bundle_gets(self):
        """The README promised `FAILED` for a tampered bundle; the verifier prints `TAMPERED at event N`."""
        row = next(line for line in read(os.path.join(ROOT, "README.md")).splitlines() if line.startswith("| **Prove**"))
        self.assertIn("`TAMPERED at event N`", row)
        self.assertNotIn("FAILED", row)
