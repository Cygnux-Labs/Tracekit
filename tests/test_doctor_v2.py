"""`tracekit doctor` for the v2 signer: every check's ok path (the clean E16 layout) and fail path (its E16 case),
setup detection, --json and the exit codes. The v1 doctor's own tests are in tests/test_system_install.py."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

from tracekit import cli, client, doctor, install

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("e16_doctor", os.path.join(HERE, "..", "eval", "e16_doctor.py"))
e16 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e16)


@unittest.skipIf(os.name == "nt", "POSIX ownership and modes")
class E16(unittest.TestCase):
    def test_clean_layout_passes_every_check(self):
        results = e16.run_case(None)
        self.assertEqual([r for r in results if r["status"] != "ok"], [])
        self.assertEqual({r["id"] for r in results}, {want for _, want, _ in e16.CASES})

    def test_every_misconfiguration_is_flagged(self):
        self.assertGreaterEqual(len(e16.CASES), 20)
        for name, want, mutate in e16.CASES:
            if name in e16.ROOT_ONLY and not e16.IS_ROOT:
                continue
            with self.subTest(name), contextlib.redirect_stdout(io.StringIO()):
                got = {r["id"]: r["status"] for r in e16.run_case(mutate)}
                self.assertIn(got.get(want), ("warn", "fail"), name)

    def test_malformed_agent_settings_are_results_not_crashes(self):
        def bad(shape):
            def mutate(L):
                with open(L.settings) as f:
                    s = json.load(f)
                shape(s)
                with open(L.settings, "w") as f:
                    json.dump(s, f)
            return mutate
        for name, shape, want in (
                ("timeout", lambda s: s["hooks"]["PreToolUse"][0]["hooks"][0].update(timeout="600"), "D-HOOKS-TIMEOUT"),
                ("env", lambda s: s.update(env=["x"]), "D-SIGNER-ENV"),
                ("hooks", lambda s: s["hooks"]["PreToolUse"][0].update(hooks=5), "D-HOOKS-PRESENT"),
                ("entry", lambda s: s["hooks"]["PreToolUse"][0]["hooks"].append("x"), "D-HOOKS-PRESENT")):
            with self.subTest(name), contextlib.redirect_stdout(io.StringIO()):
                got = {r["id"]: r["status"] for r in e16.run_case(bad(shape))}
                self.assertIn(want, got)

    def test_hooks_installed_before_1_2_only_need_init_again(self):
        got = {r["id"]: r["status"] for r in e16.run_case(e16._unnamed)}
        self.assertEqual((got["D-HOOKS-EVENT"], got["D-HOOKS-VENV"]), ("warn", "ok"))

    def test_data_dir_of_the_agents_user_fails_the_boundary(self):
        def agent_is_me(L):
            L.kw["agent"] = types.SimpleNamespace(**dict(vars(e16.AGENT), pw_uid=os.getuid()))
        got = {r["id"]: r for r in e16.run_case(agent_is_me)}
        self.assertEqual(got["D-PROCESS-BOUNDARY"]["status"], "fail")


class CodingAgentHooks(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def installed(self, harness):
        from tracekit import agent_hooks
        path = os.path.join(self.d, harness, "hooks.json")
        with contextlib.redirect_stdout(io.StringIO()):
            agent_hooks.install(harness, path=path, v2=True)
        with open(path) as f:
            return path, json.load(f)

    def check(self, harness, path, settings):
        with open(path, "w") as f:
            json.dump(settings, f)
        return {r["id"]: r for r in doctor.v2_checks({"data_dir": self.d}, "dev", harnesses={harness: path})}

    def entries(self, settings):
        return [(ev, h) for ev, groups in settings["hooks"].items() for group in groups
                for h in (group["hooks"] if "hooks" in group else [group])]

    def test_installed_hooks_name_their_event_and_wait_for_approval(self):
        for harness in ("codex", "cursor", "gemini", "goose", "qwen"):
            with self.subTest(harness=harness):
                path, settings = self.installed(harness)
                got = self.check(harness, path, settings)
                for rid in ("D-HOOKS-EVENT", "D-HOOKS-TIMEOUT"):
                    self.assertIn(rid, got)
                    self.assertEqual(got[rid]["status"], "ok")
                    self.assertIn(harness, got[rid]["detail"])
                    self.assertIn(path, got[rid]["detail"])

    def test_a_command_without_its_event_warns(self):
        for harness in ("codex", "cursor", "gemini", "goose", "qwen"):
            with self.subTest(harness=harness):
                path, settings = self.installed(harness)
                ev, h = self.entries(settings)[0]
                h["command"] = h["command"].replace(ev, "")
                got = self.check(harness, path, settings)
                self.assertIn("D-HOOKS-EVENT", got)
                self.assertEqual(got["D-HOOKS-EVENT"]["status"], "warn")
                self.assertIn(ev, got["D-HOOKS-EVENT"]["detail"])
                self.assertIn(path, got["D-HOOKS-EVENT"]["detail"])
                self.assertEqual(got["D-HOOKS-EVENT"]["fix"], f"tracekit init --dev --v2 --agent {harness}")

    def test_production_hook_advice_uses_system_init_for_the_harness(self):
        harness = "codex"
        path, settings = self.installed(harness)
        ev, hook = self.entries(settings)[0]
        hook["command"] = hook["command"].replace(ev, "")
        with open(path, "w") as f:
            json.dump(settings, f)
        got = {r["id"]: r for r in doctor.v2_checks(
            {"data_dir": self.d}, "production", harnesses={harness: path})}
        self.assertEqual(got["D-HOOKS-EVENT"]["fix"], doctor.REINIT + f" --agent {harness}")

    def test_cursor_fail_closed_on_an_event_but_a_tool_call_warns(self):
        # Cursor blocks the event when a failClosed hook can't run: a person's prompt (beforeSubmitPrompt) too
        path, settings = self.installed("cursor")
        settings["hooks"]["beforeSubmitPrompt"][0]["failClosed"] = True
        got = self.check("cursor", path, settings)["D-HOOKS-EVENT"]
        self.assertEqual(got["status"], "warn")
        self.assertIn("beforeSubmitPrompt", got["detail"])
        self.assertEqual(got["fix"], "tracekit init --dev --v2 --agent cursor")

    def test_a_short_pre_tool_timeout_warns_in_the_harness_unit(self):
        from tracekit import agent_hooks
        for harness in ("codex", "cursor", "gemini", "goose", "qwen"):
            with self.subTest(harness=harness):
                path, settings = self.installed(harness)
                for ev, h in self.entries(settings):
                    if ev in agent_hooks.PRE:
                        h["timeout"] = 539_999 if harness in ("gemini", "qwen") else 539
                got = self.check(harness, path, settings)
                self.assertIn("D-HOOKS-TIMEOUT", got)
                self.assertEqual(got["D-HOOKS-TIMEOUT"]["status"], "warn")
                self.assertIn(path, got["D-HOOKS-TIMEOUT"]["detail"])
                self.assertEqual(got["D-HOOKS-TIMEOUT"]["fix"], f"tracekit init --dev --v2 --agent {harness}")

    def test_only_v2_tracekit_commands_are_checked_even_in_a_shared_group(self):
        from tracekit import agent_hooks
        for harness in ("codex", "cursor", "gemini", "goose", "qwen"):
            with self.subTest(harness=harness):
                path, settings = self.installed(harness)
                ev = next(ev for ev in settings["hooks"] if ev in agent_hooks.PRE)
                unrelated = [{"command": "echo unrelated", "timeout": 1},
                             {"command": "python -m tracekit.agent_hooks " + harness, "timeout": 1}]
                if harness == "cursor":
                    settings["hooks"][ev].extend(unrelated)
                else:
                    settings["hooks"][ev][0]["hooks"].extend(unrelated)
                got = self.check(harness, path, settings)
                self.assertEqual(got["D-HOOKS-EVENT"]["status"], "ok")
                self.assertEqual(got["D-HOOKS-TIMEOUT"]["status"], "ok")

    def test_missing_invalid_and_boundary_timeouts(self):
        from tracekit import agent_hooks
        from tracekit.integrations.claude_code import APPROVAL_WAIT_S
        for harness in ("codex", "cursor", "gemini", "goose", "qwen"):
            scale = 1000 if harness in ("gemini", "qwen") else 1
            for value in (None, "600000", False, -1, float("nan"), APPROVAL_WAIT_S * scale):
                with self.subTest(harness=harness, timeout=value):
                    path, settings = self.installed(harness)
                    for ev, h in self.entries(settings):
                        if ev in agent_hooks.PRE:
                            if value is None:
                                h.pop("timeout")
                            else:
                                h["timeout"] = value
                    got = self.check(harness, path, settings)["D-HOOKS-TIMEOUT"]
                    self.assertEqual(got["status"], "ok" if value == APPROVAL_WAIT_S * scale else "warn")

    def test_a_missing_pre_tool_timeout_is_read_as_the_harness_default(self):
        # agy waits 30 s for a hook that sets no timeout, not the 60 s the others wait: the warning states agy's wait
        from tracekit import agent_hooks
        for harness, says in (("antigravity", "30 s"), ("codex", "60 s")):
            with self.subTest(harness=harness):
                path, settings = self.installed(harness)
                hooks = settings[agent_hooks.AGY_HOOK] if harness == "antigravity" else settings["hooks"]
                for ev, h in self.entries({"hooks": hooks}):
                    if ev in agent_hooks.PRE:
                        h.pop("timeout")
                got = self.check(harness, path, settings)["D-HOOKS-TIMEOUT"]
                self.assertEqual(got["status"], "warn")
                self.assertIn(f"{harness} pre-tool timeout {says} in {path}", got["detail"])

    def test_a_wrong_event_and_an_event_missing_from_a_post_hook_warn(self):
        for harness in ("codex", "cursor", "gemini", "goose", "qwen"):
            for replacement in ("", "AnotherEvent"):
                with self.subTest(harness=harness, replacement=replacement):
                    path, settings = self.installed(harness)
                    ev, h = self.entries(settings)[1]
                    h["command"] = h["command"].replace(ev, replacement)
                    got = self.check(harness, path, settings)["D-HOOKS-EVENT"]
                    self.assertEqual(got["status"], "warn")
                    self.assertIn(ev, got["detail"])

    def test_each_agents_results_name_its_file(self):
        harnesses = {}
        for harness in ("codex", "gemini"):
            path, settings = self.installed(harness)
            harnesses[harness] = path
        got = doctor.v2_checks({"data_dir": self.d}, "dev", harnesses=harnesses)
        for rid in ("D-HOOKS-EVENT", "D-HOOKS-TIMEOUT"):
            checks = [r for r in got if r["id"] == rid]
            self.assertEqual(len(checks), 2)
            self.assertTrue(all(r["status"] == "ok" for r in checks))
            for harness, path in harnesses.items():
                self.assertEqual(sum(harness in r["detail"] and path in r["detail"] for r in checks), 1)

    def test_an_unreadable_or_malformed_file_warns_instead_of_passing(self):
        for text in ("not json", "[]", '{"hooks": {"PreToolUse": 5}}'):
            with self.subTest(text=text):
                path = os.path.join(self.d, "hooks.json")
                with open(path, "w") as f:
                    f.write(text)
                got = doctor.v2_checks({"data_dir": self.d}, "dev", harnesses={"codex": path})
                checks = [r for r in got if r["id"] == "D-HOOKS-EVENT"]
                self.assertEqual(len(checks), 1)
                self.assertEqual(checks[0]["status"], "warn")
                self.assertIn(path, checks[0]["detail"])
                os.unlink(path)
                got = doctor.v2_checks({"data_dir": self.d}, "dev", harnesses={"codex": path})
                self.assertEqual(next(r for r in got if r["id"] == "D-HOOKS-EVENT")["status"], "warn")

    def test_opencode_is_not_read_as_a_hook_config(self):
        path = os.path.join(self.d, "tracekit.js")
        got = doctor.v2_checks({"data_dir": self.d}, "dev", harnesses={"opencode": path})
        self.assertFalse(any(r["id"] in ("D-HOOKS-EVENT", "D-HOOKS-TIMEOUT") for r in got))

    def test_installer_commands_with_windows_and_posix_quoting_pass(self):
        for platform, python in (("nt", r"C:\Program Files\Python\python.exe"),
                                 ("posix", "/opt/tracekit env/bin/python")):
            for harness in ("codex", "cursor", "gemini", "goose", "qwen"):
                with self.subTest(platform=platform, harness=harness):
                    with mock.patch.object(os, "name", platform), mock.patch.object(sys, "executable", python):
                        path, settings = self.installed(harness)
                    got = self.check(harness, path, settings)
                    self.assertEqual(got["D-HOOKS-EVENT"]["status"], "ok")
                    self.assertEqual(got["D-HOOKS-TIMEOUT"]["status"], "ok")


@unittest.skipUnless(os.name == "posix", "a POSIX shell wraps the hook")
class HooksBefore13(unittest.TestCase):
    def test_hooks_that_block_every_event_warn_until_init_runs_again(self):
        # init before 1.3 wrapped every event's command to fail closed: a hook that can't start blocked each prompt
        from tracekit import agent_hooks
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        old = install._blocking
        for harness in ("claude", "codex", "cursor", "gemini", "goose", "qwen", "droid"):
            path = os.path.join(d, harness, "hooks.json")

            def init():
                with contextlib.redirect_stdout(io.StringIO()):
                    if harness == "claude":
                        install.install_hooks(path, module=install.V2_HOOK)
                    else:
                        agent_hooks.install(harness, v2=True, path=path)

            def row():
                kw = {"settings": path} if harness == "claude" else {"harnesses": {harness: path}}
                return next(r for r in doctor.v2_checks({"data_dir": d}, "dev", **kw) if r["id"] == "D-HOOKS-EVENT")
            with self.subTest(harness=harness):
                with mock.patch.object(install, "_blocking", lambda run, unless="", pre=True, json_deny=False: old(run, unless, json_deny=json_deny)):
                    init()   # as init before 1.3 wrote it
                got = row()
                self.assertEqual(got["status"], "warn", got)
                self.assertIn("block", got["detail"])
                self.assertEqual(got["fix"], "tracekit init --dev --v2" + ("" if harness == "claude" else f" --agent {harness}"))
                init()
                self.assertEqual(row()["status"], "ok")


class DroidHooks(unittest.TestCase):
    def test_droid_flat_configs_are_discovered_and_checked_without_reading_metadata_as_hooks(self):
        from tracekit import agent_hooks
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d}), \
                mock.patch("os.getcwd", return_value=d):
            path = agent_hooks.config_path("droid", d)
            agent_hooks.install("droid", d, v2=True)
            with open(path) as f:
                config = json.load(f)
            config.update(theme="dark", metadata={"source": "mine"}, revision=3)
            with open(path, "w") as f:
                json.dump(config, f)
            self.assertEqual(doctor._dev_harnesses()["droid"], path)
            rows = doctor.v2_checks({"data_dir": d}, "dev", harnesses={"droid": path})
            for rid in ("D-HOOKS-EVENT", "D-HOOKS-TIMEOUT"):
                row = next(r for r in rows if r["id"] == rid)
                self.assertEqual(row["status"], "ok", row)
                self.assertIn(path, row["detail"])
            for ev in agent_hooks.DROID_EVENTS:
                action = config[ev][0]["hooks"][0]
                original = action["command"]
                action["command"] = original.replace(ev, "WrongEvent")
                with open(path, "w") as f:
                    json.dump(config, f)
                row = next(r for r in doctor.v2_checks({"data_dir": d}, "dev", harnesses={"droid": path})
                           if r["id"] == "D-HOOKS-EVENT")
                self.assertEqual(row["status"], "warn", ev)
                self.assertIn(ev, row["detail"])
                self.assertEqual(row["fix"], "tracekit init --dev --v2 --agent droid")
                action["command"] = original
            config["PreToolUse"][0]["hooks"][0]["timeout"] = 60
            with open(path, "w") as f:
                json.dump(config, f)
            row = next(r for r in doctor.v2_checks({"data_dir": d}, "dev", harnesses={"droid": path})
                       if r["id"] == "D-HOOKS-TIMEOUT")
            self.assertEqual(row["status"], "warn")
            self.assertIn("60 s", row["detail"])


class AntigravityHooks(unittest.TestCase):
    def test_agy_hooks_under_tracekits_hook_name_are_found_and_checked_in_seconds(self):
        # agy's hooks.json maps each hook's name to its events: Tracekit's are under AGY_HOOK, not `hooks`, and an
        # agy-only setup must not be told to install Claude Code's hooks
        from tracekit import agent_hooks
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "XDG_CONFIG_HOME": os.path.join(d, ".config")}), \
                mock.patch("os.getcwd", return_value=d), contextlib.redirect_stdout(io.StringIO()):
            path = agent_hooks.install("antigravity", v2=True)
            self.assertEqual(path, os.path.join(d, ".gemini", "config", "hooks.json"))
            harnesses = doctor._dev_harnesses()
            self.assertEqual(harnesses, {"antigravity": path})

            def rows():
                return {r["id"]: r for r in doctor.v2_checks({"data_dir": d}, "dev", settings=os.path.join(d, "none.json"),
                                                             harnesses=harnesses)}
            got = rows()
            self.assertEqual(got["D-HOOKS-PRESENT"]["status"], "ok", got["D-HOOKS-PRESENT"])
            self.assertIn(f"antigravity in {path}", got["D-HOOKS-PRESENT"]["detail"])
            for rid in ("D-HOOKS-EVENT", "D-HOOKS-TIMEOUT"):
                self.assertEqual(got[rid]["status"], "ok", got[rid])
                self.assertIn(path, got[rid]["detail"])
            with open(path) as f:
                config = json.load(f)
            config[agent_hooks.AGY_HOOK]["PreToolUse"][0]["hooks"][0]["timeout"] = 539
            with open(path, "w") as f:
                json.dump(config, f)
            row = rows()["D-HOOKS-TIMEOUT"]
            self.assertEqual(row["status"], "warn")
            self.assertIn("539 s", row["detail"])
            self.assertEqual(row["fix"], "tracekit init --dev --v2 --agent antigravity")
            self.assertEqual(got["D-AGY-HOOKS-RUN"]["status"], "ok", got["D-AGY-HOOKS-RUN"])

    def test_agy_sign_ins_and_a_disabled_hook_that_run_no_hook_are_warned_about(self):
        # agy loads its hooks and never runs them when signed in with a Gemini API key (antigravity-cli#893) or
        # Application Default Credentials (#1310), or when the named hook is disabled: a run with no record at all
        from tracekit import agent_hooks
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {"HOME": d, "USERPROFILE": d, "XDG_CONFIG_HOME": os.path.join(d, ".config")}), \
                mock.patch("os.getcwd", return_value=d), contextlib.redirect_stdout(io.StringIO()):
            os.environ.pop("AGY_ADC_AUTH", None)
            path = agent_hooks.install("antigravity", v2=True)
            settings, app = (os.path.join(d, ".gemini", *p) for p in (("antigravity-cli", "settings.json"),
                                                                       ("config", "config.json")))
            workspace = agent_hooks.config_path("antigravity", d)

            def write(p, cfg):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    json.dump(cfg, f)

            def row():
                rows = {r["id"]: r for r in doctor.v2_checks({"data_dir": d}, "dev", settings=os.path.join(d, "none.json"),
                                                             harnesses=doctor._dev_harnesses())}
                return rows["D-AGY-HOOKS-RUN"]
            with open(path) as f:
                hooks = json.load(f)
            for change, says in ((lambda: write(settings, {"modelProvider": "gemini"}), "antigravity-cli#893"),
                                 (lambda: write(app, {"userSettings": {"enableAdc": True}}), "enableAdc"),
                                 (lambda: os.environ.update(AGY_ADC_AUTH="true"), "AGY_ADC_AUTH=true"),
                                 (lambda: write(path, {agent_hooks.AGY_HOOK: {**hooks[agent_hooks.AGY_HOOK],
                                                                              "enabled": False}}), '"enabled": false'),
                                 # a workspace's hooks.json can turn off Tracekit's hook of the same name
                                 (lambda: write(workspace, {agent_hooks.AGY_HOOK: {"enabled": False}}),
                                  f'"enabled": false in {workspace}')):
                with self.subTest(says=says):
                    change()
                    got = row()
                    self.assertEqual(got["status"], "warn", got)
                    self.assertIn(says, got["detail"])
                    self.assertIn("Google account", got["fix"])
                    self.assertEqual(f"from {workspace}" in got["fix"], workspace in says)
                    for f in (settings, app, workspace):
                        if os.path.exists(f):
                            os.unlink(f)
                    os.environ.pop("AGY_ADC_AUTH", None)
                    write(path, hooks)
            self.assertEqual(row()["status"], "ok")


class DevFresh(unittest.TestCase):
    def test_a_dev_signer_that_never_started_gets_dev_advice(self):
        """On a fresh home doctor said "run doctor as root" for the missing keys and "add a witness in signer.yaml" at
        assurance "local", none of which fits a dev signer: it has no keys until `tracekit up` and takes no witnesses."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        got = {r["id"]: r for r in doctor.v2_checks({"data_dir": d}, "dev")}
        self.assertEqual(got["D-KEYS-MODE"]["fix"], "start the dev signer: tracekit up")
        self.assertIn("assurance stays dev", got["D-WITNESS-CONFIGURED"]["detail"])
        self.assertIn("the dev signer takes no witnesses", got["D-WITNESS-CONFIGURED"]["fix"])

    def test_without_witnesses_assurance_is_local_only_with_an_anchor(self):
        """A production signer with no witness said assurance stays local; the verifier says dev without an anchor."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for cfg, level in (({}, "dev"), ({"anchors": {"rekor": {"url": "https://rekor.example"}}}, "local")):
            got = {r["id"]: r for r in doctor.v2_checks({"data_dir": d, **cfg})}
            self.assertIn(f"assurance stays {level}", got["D-WITNESS-CONFIGURED"]["detail"])


class Reinit(unittest.TestCase):
    def test_the_reinit_fix_runs_on_this_platform(self):
        """On macOS init refuses system mode without --experimental-macos, which the fix left out."""
        self.assertEqual(doctor.REINIT.endswith(" --experimental-macos"), sys.platform == "darwin")


class K8s(unittest.TestCase):
    def test_clean_deployment_passes_every_check(self):
        results = e16.run_k8s_case(None)
        self.assertEqual([r for r in results if r["status"] != "ok"], [])
        self.assertEqual({r["id"] for r in results}, {want for _, want, _ in e16.K8S_CASES})

    def test_every_misconfiguration_is_flagged(self):
        self.assertGreaterEqual(len(e16.K8S_CASES), 10)
        for name, want, mutate in e16.K8S_CASES:
            with self.subTest(name):
                got = {r["id"]: r["status"] for r in e16.run_k8s_case(mutate)}
                self.assertIn(got.get(want), ("warn", "fail"), name)

    def test_a_token_with_cloud_identity_fails_without_it_warns(self):
        token = e16._set(e16._pod, automountServiceAccountToken=True)
        gke = e16._sa_note("iam.gke.io/gcp-service-account", "s@p.iam.gserviceaccount.com")
        for mutate, want in ((token, "warn"), (lambda d: (token(d), gke(d)), "fail")):
            got = {r["id"]: r["status"] for r in e16.run_k8s_case(mutate)}
            self.assertEqual(got["D-K8S-SA-TOKEN"], want)

    def test_central_signer_with_cloud_identity_and_a_sidecar_passes(self):
        def central(docs):
            e16._sa_note("eks.amazonaws.com/role-arn", "arn:aws:iam::111122223333:role/tracekit-kms")(docs)
            e16._pod(docs)["containers"] = [{"name": "istio-proxy", "image": "istio/proxyv2:1.22",
                                             "securityContext": dict(e16.HARDENED, runAsUser=1337)}]
        self.assertEqual([r for r in e16.run_k8s_case(central) if r["status"] != "ok"], [])

    def test_block_yaml_lists_cronjobs_and_json_files(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "a.yaml"), "w") as f:
            f.write("# rendered\n---\napiVersion: v1\nkind: List\nitems:\n  - kind: Pod\n    metadata:\n      name: p\n"
                    "    spec:\n      hostNetwork: true\n      containers:\n        - name: s\n"
                    "          args: [signer, serve]\n---\n")
        with open(os.path.join(d, "b.json"), "w") as f:
            json.dump({"kind": "CronJob", "metadata": {"name": "c"}, "spec": {"jobTemplate": {"spec": {"template": {
                "spec": {"hostPID": True, "containers": [{"name": "a", "env": [{"name": "TRACEKIT_SIGNER"}]}]}}}}}}, f)
        docs, bad = doctor.load_manifests(d)
        self.assertEqual(bad, [])
        got = {r["id"]: r for r in doctor.k8s_checks(docs)}
        self.assertEqual(got["D-K8S-HOST-ACCESS"]["detail"], "Pod/p: hostNetwork; CronJob/c: hostPID")

    def test_in_pod_reads_its_pod_and_service_account(self):
        docs = e16.k8s_clean()
        pod = {"kind": "Pod", "metadata": {"name": "agent-1", "namespace": "acme"}, "spec": e16._pod(docs)}
        sa = dict(docs[0], metadata=dict(docs[0]["metadata"], annotations={"eks.amazonaws.com/role-arn": "arn"}))
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for n, text in (("namespace", "acme"), ("token", "t0k"), ("ca.crt", "")):
            with open(os.path.join(d, n), "w") as f:
                f.write(text)
        urls = []

        def urlopen(req, **kw):
            urls.append((req.full_url, req.headers["Authorization"]))
            return io.BytesIO(json.dumps(pod if "/pods/" in req.full_url else sa).encode())
        with mock.patch.dict(os.environ, {"KUBERNETES_SERVICE_HOST": "10.0.0.1", "HOSTNAME": "agent-1"}), \
                mock.patch.object(doctor, "SA_DIR", d), mock.patch("ssl.create_default_context"), \
                mock.patch("urllib.request.urlopen", urlopen):
            got = {r["id"]: r["status"] for r in doctor.in_pod()}
        self.assertEqual(urls, [("https://10.0.0.1:443/api/v1/namespaces/acme/pods/agent-1", "Bearer t0k"),
                                ("https://10.0.0.1:443/api/v1/namespaces/acme/serviceaccounts/agent", "Bearer t0k")])
        self.assertEqual(got["D-K8S-WORKLOAD-IDENTITY"], "fail")

    def test_outside_a_pod_it_warns(self):
        with mock.patch.dict(os.environ, clear=True):
            self.assertEqual([(r["id"], r["status"]) for r in doctor.in_pod()], [("D-K8S-WORKLOADS", "warn")])


class Postgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin, cls.cluster = e16.pg_admin()
        if not cls.admin:
            raise unittest.SkipTest(cls.cluster)

    @classmethod
    def tearDownClass(cls):
        e16.pg_stop(cls.cluster)

    def test_signer_with_postgres_grants_passes(self):
        self.assertEqual([r["status"] for r in e16.run_pg_case(self.admin, None)], ["ok", "ok"])

    def test_extra_grants_are_flagged(self):
        for name, want, sql in e16.PG_CASES:
            with self.subTest(name):
                got = {r["id"]: r["status"] for r in e16.run_pg_case(self.admin, sql)}
                self.assertEqual(got[want], "fail", name)


class Kms(unittest.TestCase):
    def setUp(self):
        from test_signer_kms import FakeKms
        self.kms = FakeKms()
        self.issuer = None   # the error code Sign with DryRun raises on the issuer key

        def sign(**req):
            if req.get("DryRun"):
                e = Exception(self.issuer)
                e.response = {"Error": {"Code": self.issuer}}
                raise e
            return FakeKms.sign(self.kms, **req)
        self.kms.sign = sign
        boto3 = types.SimpleNamespace(client=lambda name, region_name: self.kms)
        patcher = mock.patch.dict("sys.modules", boto3=boto3)
        patcher.start()
        self.addCleanup(patcher.stop)

    def check(self, issuer_key=None):
        return {r["id"]: r for r in doctor.kms_checks({"key_id": "alias/log", "region": "eu-west-1"}, issuer_key)}

    def test_log_key_spec_and_usage(self):
        self.assertEqual(self.check()["D-KMS-LOG-KEY"]["status"], "ok")
        self.kms.spec = "ECC_NIST_P256"
        self.assertEqual(self.check()["D-KMS-LOG-KEY"]["status"], "fail")

    def test_issuer_key_must_not_be_signable(self):
        for code, want in (("DryRunOperationException", "fail"), ("AccessDeniedException", "ok"),
                           ("NotFoundException", "warn")):
            self.issuer = code
            with self.subTest(code):
                self.assertEqual(self.check("alias/issuer-ca")["D-KMS-ISSUER-SIGN"]["status"], want)
        self.assertNotIn("D-KMS-ISSUER-SIGN", self.check())

    def test_skipped_with_the_reason_without_boto3_or_credentials(self):
        with mock.patch.dict("sys.modules", boto3=None):
            self.assertEqual(self.check()["D-KMS-LOG-KEY"]["detail"], "not checked: no boto3")
        self.kms.get_public_key = mock.Mock(side_effect=type("NoCredentialsError", (Exception,), {})("no creds"))
        self.assertEqual(self.check()["D-KMS-LOG-KEY"]["status"], "warn")

    @unittest.skipIf(os.name == "nt", "the E16 layout is a POSIX system mode install")
    def test_signer_yaml_with_kms_and_postgres_runs_both(self):
        def mutate(L):
            L.signer_yaml(log_key={"aws_kms": {"key_id": "alias/log", "region": "eu-west-1"}},
                          storage={"postgres": {"dsn_file": "pg.dsn"}})
        with mock.patch.object(doctor, "pg_checks", return_value=[doctor.result("D-PG-SIGNER-ROLE", "ok", "")]) as pg:
            got = {r["id"] for r in e16.run_case(mutate)}
        self.assertTrue({"D-KMS-LOG-KEY", "D-PG-SIGNER-ROLE"} <= got)
        self.assertTrue(pg.call_args.args[0]["dsn_file"].endswith("pg.dsn"))


class Probe(unittest.TestCase):
    agent = types.SimpleNamespace(pw_name="agent", pw_uid=64101, pw_gid=64101)

    @unittest.skipIf(os.name == "nt", "POSIX uids")
    def test_not_probed_unless_root_or_the_agent(self):
        with mock.patch.object(doctor.os, "geteuid", return_value=1000):
            self.assertIsNone(doctor.agent_access(self.agent, [["/", "read"]]))

    @unittest.skipIf(os.name == "nt", "POSIX uids")
    def test_root_probes_in_a_child_dropped_to_the_agent(self):
        with mock.patch.object(doctor.os, "geteuid", return_value=0), \
                mock.patch.object(doctor.files, "as_user", return_value=[["/k", "read"]]) as as_user:
            self.assertEqual(doctor.agent_access(self.agent, [["/k", "read"]]), [["/k", "read"]])
        as_user.assert_called_once_with(self.agent, doctor._access, [["/k", "read"]])

    def test_access_reports_only_what_succeeds(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        missing = os.path.join(d, "missing")
        self.assertEqual(doctor._access([[d, "read"], [missing, "write"]]), [[d, "read"]])


@unittest.skipIf(os.name == "nt", "mount table parsing is POSIX-only")
class FileSystem(unittest.TestCase):
    def test_longest_mount_wins(self):
        with mock.patch.object(doctor, "_mounts", return_value=[("/", "ext4"), ("/srv", "nfs4"), ("/srv/a", "xfs")]):
            self.assertEqual(doctor.fs_type("/srv/data"), "nfs4")
            self.assertEqual(doctor.fs_type("/srv/a/b"), "xfs")
            self.assertEqual(doctor.fs_type("/srvx"), "ext4")


class Report(unittest.TestCase):
    def run_report(self, statuses, as_json=False):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = doctor.report([doctor.result(f"D-{i}", s, "detail", "fix it") for i, s in enumerate(statuses)],
                                 as_json)
        return code, out.getvalue()

    def test_exit_codes(self):
        self.assertEqual(self.run_report(["ok", "ok"])[0], 0)
        self.assertEqual(self.run_report(["ok", "warn"])[0], 2)
        self.assertEqual(self.run_report(["warn", "fail"])[0], 1)

    def test_json_lists_id_status_detail_fix(self):
        code, out = self.run_report(["ok", "fail"], as_json=True)
        self.assertEqual(json.loads(out), [{"id": "D-0", "status": "ok", "detail": "detail", "fix": ""},
                                           {"id": "D-1", "status": "fail", "detail": "detail", "fix": "fix it"}])

    def test_cli_passes_config_and_json(self):
        with mock.patch.object(doctor, "main", return_value=2) as main:
            self.assertEqual(cli.main(["doctor", "--json", "--config", "/etc/x.yaml"]), 2)
            cli.main(["doctor", "--k8s", "--manifests", "/m", "--issuer-key", "alias/ca"])
        self.assertEqual(main.call_args_list, [mock.call("/etc/x.yaml", True, False, None, None),
                                               mock.call(None, False, True, "/m", "alias/ca")])


class Detect(unittest.TestCase):
    def collect(self, sc, config=None):
        with mock.patch.object(doctor.client, "system_config", return_value=sc), \
                mock.patch.object(install, "v1_results", return_value=[doctor.result("D-V1-X", "ok", "v1")]), \
                mock.patch.object(doctor, "v2_checks", return_value=[doctor.result("D-V2", "ok", "v2")]) as v2:
            return [r["id"] for r in doctor.collect(config)], v2

    def test_v1_system_mode(self):
        self.assertEqual(self.collect({"socket": "/var/lib/tracekit/tracekitd.sock"})[0], ["D-V1-X"])

    def test_v2_system_mode(self):
        ids, v2 = self.collect({"signer": "/run/tracekit-signer/signer.sock", "hooks": {"user": "nobody-e16"}})
        self.assertEqual(ids, ["D-V2"])
        self.assertEqual(v2.call_args.args[0], install.V2_CONFIG)
        self.assertEqual(v2.call_args.kwargs["signer"], "/run/tracekit-signer/signer.sock")

    def test_both_system_modes(self):
        self.assertEqual(self.collect({"socket": "/s", "signer": "/t"})[0], ["D-V1-X", "D-V2"])

    def test_the_sandbox_settings_read_are_the_ones_claude_code_ranks(self):
        """With CLAUDE_CONFIG_DIR set, an old ~/.claude/settings.json read after it made a sandbox that falls back to
        running unsandboxed look fail-closed: only the user settings file Claude Code reads counts."""
        project = os.path.join(os.getcwd(), ".claude")
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/work/claude"}):
            self.assertEqual(self.collect(None)[1].call_args.kwargs["sandbox_settings"],
                             [os.path.join("/work/claude", "settings.json"), os.path.join(project, "settings.json"),
                              os.path.join(project, "settings.local.json"), doctor._managed()])
        v2 = self.collect({"signer": "/t", "hooks": {"user": "nobody-e16", "settings": "/home/a/.claude/settings.json"}})[1]
        self.assertEqual(v2.call_args.kwargs["sandbox_settings"], ["/home/a/.claude/settings.json", doctor._managed()])
        # hooks in a project file (init --project): the agent's own user settings are read first
        with mock.patch.object(doctor, "_user", return_value=types.SimpleNamespace(pw_dir="/home/a")), \
                mock.patch.object(install, "plugin_enabled", return_value=None):
            v2 = self.collect({"signer": "/t", "hooks": {"user": "a", "settings": "/srv/app/.claude/settings.json"}})[1]
        self.assertEqual(v2.call_args.kwargs["sandbox_settings"],
                         [os.path.join("/home/a", ".claude", "settings.json"), "/srv/app/.claude/settings.json",
                          doctor._managed()])

    def test_the_gemini_settings_read_are_the_ones_gemini_ranks(self):
        d = {"darwin": "/Library/Application Support/GeminiCli", "win32": r"C:\ProgramData\gemini-cli"}.get(
            sys.platform, "/etc/gemini-cli")
        defaults, system = os.path.join(d, "system-defaults.json"), os.path.join(d, "settings.json")
        self.assertEqual(self.collect(None)[1].call_args.kwargs["gemini_settings"],
                         [defaults, os.path.join(os.path.expanduser("~"), ".gemini", "settings.json"),
                          os.path.join(os.getcwd(), ".gemini", "settings.json"), system])
        with mock.patch.object(doctor, "_user", return_value=types.SimpleNamespace(pw_dir="/home/a")), \
                mock.patch.object(install, "plugin_enabled", return_value=None):
            v2 = self.collect({"signer": "/t", "hooks": {"user": "a", "agent": "gemini",
                                                         "settings": "/srv/app/.gemini/settings.json"}})[1]
        self.assertEqual(v2.call_args.kwargs["gemini_settings"],
                         [defaults, os.path.join("/home/a", ".gemini", "settings.json"), "/srv/app/.gemini/settings.json",
                          system])

    def test_gemini_system_settings_on_windows_and_where_its_variables_move_them(self):
        """Windows looked in /etc/gemini-cli; Gemini CLI reads C:\\ProgramData\\gemini-cli there, and the system
        files from GEMINI_CLI_SYSTEM_SETTINGS_PATH and GEMINI_CLI_SYSTEM_DEFAULTS_PATH on any platform."""
        d = r"C:\ProgramData\gemini-cli"
        with mock.patch.object(doctor.sys, "platform", "win32"), mock.patch.dict(os.environ, clear=True):
            self.assertEqual(doctor._gemini(None, None),
                             [os.path.join(d, "system-defaults.json"), os.path.join(d, "settings.json")])
        with mock.patch.dict(os.environ, {"GEMINI_CLI_SYSTEM_SETTINGS_PATH": "/opt/g/settings.json"}, clear=True):
            self.assertEqual(doctor._gemini(None, None),
                             [os.path.join("/opt/g", "system-defaults.json"), "/opt/g/settings.json"])
        with mock.patch.dict(os.environ, {"GEMINI_CLI_SYSTEM_SETTINGS_PATH": "/opt/g/settings.json",
                                          "GEMINI_CLI_SYSTEM_DEFAULTS_PATH": "/opt/d.json"}, clear=True):
            self.assertEqual(doctor._gemini(None, None), ["/opt/d.json", "/opt/g/settings.json"])

    def test_config_flag(self):
        ids, v2 = self.collect(None, "/etc/other.yaml")
        self.assertEqual((ids, v2.call_args.args[0]), (["D-V2"], "/etc/other.yaml"))

    def test_dev_signer(self):
        ids, v2 = self.collect(None)
        self.assertEqual(v2.call_args.args[1], "dev")
        # the dev signer keeps content (1.2.2): doctor checks the vault it runs, not one that is off
        self.assertTrue(v2.call_args.args[0]["content"]["retain"])
        with mock.patch.dict(os.environ, {"TRACEKIT_DEV_CONTENT": "0"}):
            self.assertIsNone(self.collect(None)[1].call_args.args[0]["content"])

    def test_dev_signer_finds_the_hooks_in_any_settings_file_init_writes(self):
        """Dev doctor read only $CLAUDE_CONFIG_DIR's (or ~/.claude's) settings: hooks in the other one, or in the
        project's, were reported missing."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        home, config, project = (os.path.join(d, n) for n in ("home", "config", "project"))
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        for settings, env in ((os.path.join(home, ".claude", "settings.json"), {"CLAUDE_CONFIG_DIR": config}),
                              (os.path.join(project, ".claude", "settings.json"), {})):
            os.makedirs(project, exist_ok=True)
            os.chdir(project)
            with contextlib.redirect_stdout(io.StringIO()):
                install.install_hooks(settings, module=install.V2_HOOK)
            with mock.patch.dict(os.environ, {"HOME": home, "USERPROFILE": home, **env}), \
                    mock.patch.object(install.client, "client_config", return_value={}):
                _, v2 = self.collect(None)
            self.assertEqual(os.path.realpath(v2.call_args.kwargs["settings"]), os.path.realpath(settings))
            install.install_hooks(settings, uninstall=True)

    def test_untrusted_system_config_fails(self):
        with mock.patch.object(doctor.client, "system_config", side_effect=client.SystemConfigError("not root-owned")):
            self.assertEqual([(r["id"], r["status"]) for r in doctor.collect()], [("D-SYSTEM-CONFIG", "fail")])


class ClaudeSandbox(unittest.TestCase):
    """D-CLAUDE-SANDBOX: a sandbox that falls back to running commands unsandboxed, or whose allowlist a custom proxy
    port switched off, looked the same as a sandbox that holds."""
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def check(self, *layers):
        paths = []
        for i, layer in enumerate(layers):
            paths.append(os.path.join(self.d, f"{i}.json"))
            with open(paths[-1], "w") as f:
                json.dump(layer, f)
        paths.append(os.path.join(self.d, "missing.json"))
        return {r["id"]: r for r in doctor.v2_checks({"data_dir": self.d}, "dev",
                                                     sandbox_settings=paths)}.get("D-CLAUDE-SANDBOX")

    def test_shown_only_when_the_sandbox_is_on(self):
        self.assertIsNone(self.check({}, {"sandbox": {"enabled": False}}, ["not settings"], {"sandbox": "on"}))
        self.assertEqual(doctor._sandbox([["client.json's settings, not a path"]]), {"network": {}})
        self.assertIsNone(self.check({"sandbox": {"enabled": True, "failIfUnavailable": True}},
                                     {"sandbox": {"enabled": False}}))

    def test_a_fallback_or_a_custom_proxy_warns(self):
        got = self.check({"sandbox": {"enabled": True}})
        self.assertEqual(got["status"], "warn")
        self.assertIn("runs commands unsandboxed", got["detail"])
        self.assertIn('"failIfUnavailable": true', got["fix"])
        got = self.check({"sandbox": {"enabled": True, "failIfUnavailable": True, "network": {"httpProxyPort": 8080}}})
        self.assertEqual(got["status"], "warn")
        self.assertIn("httpProxyPort set: Claude Code's network allowlist stops applying", got["detail"])
        self.assertNotIn("failIfUnavailable", got["fix"])

    def test_a_sandbox_that_fails_closed_is_ok_and_says_who_holds_retries(self):
        got = self.check({"sandbox": {"enabled": True, "failIfUnavailable": True}})
        self.assertEqual((got["status"], got["fix"]), ("ok", ""))
        self.assertIn("TK-A003 holds each one", got["detail"])
        got = self.check({"sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False}})
        self.assertIn("retries off", got["detail"])

    def test_a_later_file_wins_each_key_and_network_keys_merge(self):
        got = self.check({"sandbox": {"enabled": True, "network": {"socksProxyPort": 1080}}},
                         {"sandbox": {"failIfUnavailable": True, "network": {"allowedDomains": ["example.org"]}}})
        self.assertEqual(got["status"], "warn")
        self.assertEqual(got["detail"].split(":")[0], "socksProxyPort set")


class GeminiSandbox(unittest.TestCase):
    """D-GEMINI-SANDBOX: Gemini's whole-CLI sandbox runs its hooks in the box too (a container without them, Seatbelt
    with no place for their state), so a sandboxed Gemini looked traced when nothing was recorded."""
    HOOKS = {"hooks": {"BeforeTool": [{"matcher": "*", "hooks": [
        {"type": "command", "command": "/v/python -I -m tracekit.integrations.harness_hooks gemini BeforeTool"}]}]}}

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def check(self, *layers):
        paths = []
        for i, layer in enumerate(layers):
            paths.append(os.path.join(self.d, f"{i}.json"))
            with open(paths[-1], "w") as f:
                json.dump(layer, f)
        return {r["id"]: r for r in doctor.v2_checks({"data_dir": self.d}, "dev",
                                                     gemini_settings=paths)}.get("D-GEMINI-SANDBOX")

    def test_shown_only_with_tracekits_hooks_and_a_sandbox_on(self):
        self.assertIsNone(self.check({"tools": {"sandbox": "docker"}}))
        for off in ({}, {"tools": {"sandbox": "false"}, "security": {"toolSandboxing": "true"}},
                    {"tools": {"sandbox": {"enabled": False, "command": "docker"}}}, {"tools": {"sandbox": 0}}):
            self.assertIsNone(self.check(self.HOOKS, off), off)

    def test_the_whole_cli_sandbox_warns(self):
        for box in (True, "1", "docker", "sandbox-exec", {"enabled": True}):
            got = self.check(self.HOOKS, {"tools": {"sandbox": box}, "security": {"toolSandboxing": True}})
            self.assertEqual(got["status"], "warn", box)
        self.assertIn("nothing is recorded", got["detail"])
        self.assertIn('"toolSandboxing": true', got["fix"])

    def test_the_tool_sandbox_is_ok_and_says_who_holds_expansions(self):
        got = self.check(self.HOOKS, {"security": {"toolSandboxing": True}})
        self.assertEqual((got["status"], got["fix"]), ("ok", ""))
        self.assertIn("TK-A004 holds", got["detail"])

    def test_a_later_file_wins_each_key(self):
        got = self.check({"tools": {"sandbox": "docker"}, "security": {"toolSandboxing": True}}, self.HOOKS,
                         {"tools": {"sandbox": False}})
        self.assertEqual(got["status"], "ok")


class PluginHooks(unittest.TestCase):
    """The Claude Code plugin's hooks are init's: doctor told plugin users `fix: tracekit init --dev --v2`, after which
    every call was decided twice and every approved call blocked."""
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.settings, self.plugin = os.path.join(self.d, "settings.json"), os.path.join(self.d, "user.json")

    def hooks_present(self, settings, plugin):
        return {r["id"]: r for r in doctor.v2_checks({"data_dir": self.d}, "dev", settings=settings,
                                                     plugin=plugin)}["D-HOOKS-PRESENT"]

    def test_the_plugins_hooks_count_and_init_is_not_suggested(self):
        for settings in (self.settings, None):   # dev mode; system mode with no hooks recorded in client.json
            got = self.hooks_present(settings, (self.plugin, install.PLUGIN))
            self.assertEqual((got["status"], got["fix"]), ("ok", ""), settings)
            self.assertIn("Claude Code plugin", got["detail"])
        self.assertIn("tracekit init --dev --v2", self.hooks_present(self.settings, None)["fix"])

    def test_the_plugin_with_inits_hooks_is_flagged(self):
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(self.settings, module=install.V2_HOOK)
        got = self.hooks_present(self.settings, (self.plugin, "tracekit@community"))
        self.assertEqual(got["status"], "warn")
        self.assertIn("every approved call is blocked", got["detail"])
        self.assertIn("/plugin disable tracekit@community", got["fix"])
        self.assertEqual(self.hooks_present(self.settings, None)["status"], "ok")

    def test_collect_reads_enabled_plugins(self):
        home = os.path.join(self.d, "home")
        os.makedirs(os.path.join(home, ".claude"))
        with open(os.path.join(home, ".claude", "settings.json"), "w") as f:
            json.dump({"enabledPlugins": {install.PLUGIN: True}}, f)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.d)
        with mock.patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}), \
                mock.patch.object(install.client, "client_config", return_value={}), \
                mock.patch.object(doctor.client, "system_config", return_value=None), \
                mock.patch.object(doctor, "v2_checks", return_value=[]) as v2:
            doctor.collect()
        self.assertEqual(v2.call_args.kwargs["plugin"], (os.path.join(home, ".claude", "settings.json"),
                                                          install.PLUGIN))


class ThinkingSummaries(unittest.TestCase):
    """D-THINKING-SUMMARIES: with Claude Code's hooks and the content vault on, thinking summaries off leave every
    transcript's reasoning sealed, so `tracekit analyze --v2` can't check it."""

    def check(self, settings_extra, vault=True):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        settings = os.path.join(d, "settings.json")
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(settings, module=install.V2_HOOK)
        with open(settings) as f:
            s = json.load(f)
        with open(settings, "w") as f:
            json.dump(dict(s, **settings_extra), f)
        cfg = {"data_dir": d, "content": {"retain": True} if vault else None}
        with mock.patch.object(install, "user_settings", return_value=os.path.join(d, "none.json")):
            return {r["id"]: r for r in doctor.v2_checks(cfg, "dev", settings=settings)}["D-THINKING-SUMMARIES"]

    def test_off_with_the_vault_warns_and_names_the_setting_and_the_headless_flag(self):
        got = self.check({})
        self.assertEqual(got["status"], "warn")
        self.assertIn('"showThinkingSummaries": true', got["fix"])
        self.assertIn("claude -p --thinking-display summarized", got["fix"])
        self.assertEqual(self.check({"showThinkingSummaries": False})["status"], "warn")

    def test_on_or_without_the_vault_is_ok(self):
        self.assertEqual(self.check({"showThinkingSummaries": True})["status"], "ok")
        self.assertEqual(self.check({}, vault=False)["status"], "ok")

    def test_not_checked_without_claude_codes_hooks(self):
        """A Codex- or Gemini-only user got a warning whose fix installs Claude Code's hooks."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cfg = {"data_dir": d, "content": {"retain": True}}
        got = {r["id"]: r for r in doctor.v2_checks(cfg, "dev", settings=os.path.join(d, "none.json"),
                                                    harnesses={"gemini": os.path.join(d, "gemini.json")})}
        self.assertNotIn("D-THINKING-SUMMARIES", got)
        self.assertEqual(got["D-HOOKS-PRESENT"]["status"], "ok")
        self.assertIn("v2 hooks for gemini", got["D-HOOKS-PRESENT"]["detail"])

    def test_the_last_settings_file_that_sets_it_wins(self):
        """A true in the user's file passed although the project's false wins in Claude Code; a true in
        settings.local.json still warned."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        user, project, local = (os.path.join(d, n) for n in ("user.json", "project.json", "local.json"))
        with contextlib.redirect_stdout(io.StringIO()):
            install.install_hooks(user, module=install.V2_HOOK)
        cfg = {"data_dir": d, "content": {"retain": True}}
        for layers, want in (({user: True, project: False}, "warn"), ({user: False, local: True}, "ok"),
                             ({project: True, local: None}, "ok")):
            for p in (project, local):
                with open(p, "w") as f:
                    json.dump({}, f)
            for p, v in layers.items():
                with open(p) as f:
                    s = json.load(f)
                with open(p, "w") as f:
                    json.dump(dict(s, showThinkingSummaries=v) if v is not None else s, f)
            got = {r["id"]: r for r in doctor.v2_checks(cfg, "dev", settings=user, sandbox_settings=[
                user, project, local, os.path.join(d, "managed.json")])}["D-THINKING-SUMMARIES"]
            self.assertEqual(got["status"], want, layers)
        self.assertEqual(self.check({"showThinkingSummaries": True})["status"], "ok")


@unittest.skipIf(not hasattr(os, "mkfifo"), "FIFOs")
class HostileSettings(unittest.TestCase):
    def test_a_fifo_or_a_device_as_the_agents_settings_doesnt_hang_doctor(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        fifo, dev = os.path.join(d, "fifo.json"), os.path.join(d, "zero.json")
        os.mkfifo(fifo)
        os.symlink(os.devnull, dev)
        for p in (fifo, dev):
            with self.assertRaises(OSError):
                install.agent_file(p)
        out = []
        with mock.patch.object(install, "user_settings", return_value=dev):
            t = threading.Thread(target=lambda: out.extend(doctor.v2_checks(
                {"data_dir": d, "content": {"retain": True}}, "dev", settings=fifo, sandbox_settings=[fifo, dev],
                plugin=(dev, install.PLUGIN),
                gemini_settings=[fifo, dev], harnesses={"codex": os.path.join(d, "hooks.json"),
                                                        "gemini": fifo})), daemon=True)
            t.start()
            t.join(5)
        self.assertFalse(t.is_alive(), "doctor blocked on the FIFO")
        got = {r["id"]: r for r in out}
        self.assertEqual(got["D-HOOKS-PRESENT"]["status"], "warn")
        self.assertIn("not a regular file", got["D-HOOKS-PRESENT"]["detail"])


class CodingAgentReasoning(unittest.TestCase):
    """D-CODEX-REASONING and D-GEMINI-THOUGHTS: with an agent's v2 hooks installed and the content vault on, a setting
    that keeps its reasoning unreadable is a warning naming the exact fix."""

    def check(self, harness, files, vault=True):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name, text in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        hooks = os.path.join(d, "settings.json" if harness == "gemini" else "hooks.json")
        cfg = {"data_dir": d, "content": {"retain": True} if vault else None}
        rid = "D-CODEX-REASONING" if harness == "codex" else "D-GEMINI-THOUGHTS"
        return {r["id"]: r for r in doctor.v2_checks(cfg, "dev", harnesses={harness: hooks})}[rid]

    def test_codex_summaries_unset_or_none_warn_with_the_line_to_add(self):
        for files in ({}, {"config.toml": 'model_reasoning_summary = "none"\n'}):
            got = self.check("codex", files)
            self.assertEqual(got["status"], "warn")
            self.assertIn('model_reasoning_summary = "auto"', got["fix"])
            self.assertIn("tracekit init --dev --v2 --agent codex", got["fix"])
        self.assertEqual(self.check("codex", {"config.toml": 'model_reasoning_summary = "auto"\n'})["status"], "ok")
        self.assertEqual(self.check("codex", {}, vault=False)["status"], "ok")

    def test_gemini_thoughts_turned_off_in_model_configs_warn(self):
        off = {"modelConfigs": {"overrides": [{"match": {"model": "gemini-3-pro"}, "modelConfig": {
            "generateContentConfig": {"thinkingConfig": {"includeThoughts": False}}}}]}}
        got = self.check("gemini", {"settings.json": json.dumps(off)})
        self.assertEqual(got["status"], "warn")
        self.assertIn("includeThoughts: false", got["fix"])
        self.assertEqual(self.check("gemini", {"settings.json": "{}"})["status"], "ok")

    def test_dev_doctor_finds_the_agents_with_v2_hooks(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        from tracekit import agent_hooks
        config_path = agent_hooks.config_path
        def isolated_config_path(harness, project=None):
            return config_path(harness, project or d)
        with mock.patch.dict(os.environ, {"HOME": d, "XDG_CONFIG_HOME": os.path.join(d, ".config")}), \
                mock.patch("os.getcwd", return_value=d), mock.patch.object(agent_hooks, "config_path", isolated_config_path), \
                contextlib.redirect_stdout(io.StringIO()):
            agent_hooks.install("codex", v2=True)
            agent_hooks.install("gemini")   # v1: not checked
            self.assertEqual(doctor._dev_harnesses(), {"codex": agent_hooks.config_path("codex")})
            agent_hooks.install("opencode", v2=True)   # a JavaScript plugin, read as one
            self.assertEqual(doctor._dev_harnesses(), {"codex": agent_hooks.config_path("codex"),
                                                       "opencode": agent_hooks.config_path("opencode")})
            agent_hooks.install("qwen", v2=True)
            self.assertEqual(doctor._dev_harnesses()["qwen"], agent_hooks.config_path("qwen"))


@unittest.skipIf(os.name == "nt", "POSIX modes")
class DevProfile(unittest.TestCase):
    def test_dev_signer_warns_instead_of_failing(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, 0o700)
        got = {r["id"]: r["status"] for r in doctor.v2_checks({"data_dir": d}, "dev", settings=os.path.join(d, "none"))}
        self.assertEqual(got["D-PROCESS-BOUNDARY"], "warn")
        self.assertEqual(got["D-WITNESS-CONFIGURED"], "warn")
        self.assertEqual(got["D-HOOKS-PRESENT"], "warn")
        self.assertEqual(got["D-DURABILITY"], "ok")
        self.assertNotIn("D-AGENT-PRIV", got)


if __name__ == "__main__":
    unittest.main()
