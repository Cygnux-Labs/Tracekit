"""Spellings past a rule that already holds a command (the reviews of 1.7.3 and #1137, #1138, #1141): each is decided on
every shipped pack the rule is in and on both engines, beside a harmless twin that stays allowed."""
import importlib.util
import os
import shutil
import tempfile
import unittest

from tracekit.policy2 import compile as pc
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc

PACKS = os.path.dirname(svc.DEFAULT_POLICY)
ENGINES = ("re2", "regex") if importlib.util.find_spec("re2") is not None else ("regex",)
_BUILT = {}


def engines(packs=("coding.yaml", "dev.yaml", "server.yaml", "strict.yaml")):
    """(pack, engine name, engine) for each of `packs` on each engine, each built once per run."""
    for pack in packs:
        for name in ENGINES:
            if (pack, name) not in _BUILT:
                _BUILT[pack, name] = Engine(pc.build(os.path.join(PACKS, pack))[0], name)
            yield pack, name, _BUILT[pack, name]


class Spellings(unittest.TestCase):
    def held(self, rule, verdict, commands, packs=("coding.yaml", "dev.yaml", "server.yaml", "strict.yaml")):
        for pack, name, e in engines(packs):
            for command in commands:
                with self.subTest(pack=pack, engine=name, command=command):
                    d = e.decide("Bash", {"command": command})
                    self.assertEqual((d["verdict"], rule in d["rule_ids"]), (verdict, True), d)

    def kept(self, rule, commands, packs=("coding.yaml", "dev.yaml", "server.yaml", "strict.yaml")):
        for pack, name, e in engines(packs):
            for command in commands:
                with self.subTest(pack=pack, engine=name, command=command):
                    self.assertNotIn(rule, e.decide("Bash", {"command": command})["rule_ids"])

    def test_signer_imports_are_read_however_python_spells_them(self):
        """TK-D007 read an import of the signer only first in its list and its dotted name only without blanks, and
        took neither sys.modules nor a module loaded from its file for a look-up: `import os, tracekit.signer.service`,
        `import tracekit . signer . service`, `from tracekit import signer`, `sys.modules['tracekit.signer…']` (also
        through `from sys import modules`) and `imp.load_source` of the signer's file were allowed."""
        self.held("TK-D007", "deny", [
            'python3 -c "import os, tracekit.signer.service as x; x.main()"',
            'python3 -c "import os, tracekit.signer.service"', 'python3 -c "import json,tracekit.signer"',
            'python3 -c "import tracekit . signer . service"', 'python3 -c "import tracekit .signer. service as x; x.main()"',
            'python3 -c "import tracekit.\\\\\nsigner.service"',
            'python3 -c "from tracekit . signer . service import main; main()"',
            'python3 -c "from tracekit import signer"', 'python3 -c "from tracekit import (sdk,\n  daemon)"',
            'python3 -c "from tracekit import sdk, signer as s"',
            "python3 -c \"import sys; sys.modules['tracekit.signer.service'].main()\"",
            "python3 -c \"from sys import modules; modules['tracekit.signer.service'].main()\"",
            "python3 -c \"from sys import modules as m; m['tracekit.signer.pipeline']\"",
            "python3 -c \"import imp; imp.load_source('s', '/x/tracekit/signer/service.py').main()\"",
            "python3 -c \"from importlib.machinery import SourceFileLoader as L; L('s', 'tracekit/signer/service.py').load_module()\""])
        self.kept("TK-D007", [
            'python3 -c "import os, tracekit.sdk"', 'python3 -c "import tracekit . sdk as t; t.RunHandle"',
            'python3 -c "from tracekit import instrument; getattr(instrument, \'__doc__\')"',
            "python3 -c \"import sys; print(sys.modules['os'])\"", "python3 -c \"import imp; imp.load_source('s', 'x.py')\"",
            'python3 -c "from tracekit.signer.rpc_schema import REQUESTS; print(len(REQUESTS))"',
            'python3 -c "import os, tracekit.signer.rpc_schema as r; print(r.RPC_VERSION)"'])

    def test_more_runners_and_wrappers_run_what_they_name(self):
        """cross-env, env-cmd, envchain, dotenvx run, teller run, tox exec and nvm exec ran their command unread, and
        `bun x -p <package> <command>` was read as bun's own -p (print) of code: bunx's run of the command wasn't."""
        a = "tracekit approve apr-" + "0123456789abcdef" * 2
        self.held("TK-D012", "deny", [
            f"cross-env NODE_ENV=production {a}", f"env-cmd -f .env.prod {a}", f"env-cmd {a}", f"envchain aws {a}",
            f"dotenvx run -- {a}", f"dotenvx run -f .env.prod -- {a}", f"teller run -- {a}",
            f"tox exec -e py312 -- {a}", f"nvm exec 20 {a}", f"bun x -p tracekit-ai {a}", f"bun x --bun -p x {a}"])
        self.kept("TK-D012", ["cross-env NODE_ENV=production node app.js", "env-cmd -f .env npm start",
                              "dotenvx run -- npm test", "tox exec -e py312 -- pytest -q", "nvm exec 20 node -v",
                              "bun x -p prettier prettier --check ."])

    def test_kubectl_through_a_distribution_or_wrapper_and_its_raw_view(self):
        """`microk8s kubectl`, `k3s kubectl`, `minikube kubectl --`, microk8s.kubectl and kubecolor ran kubectl unread
        by every kubectl rule (TK-A021, TK-A052, TK-A056); `config view` with `--flatten` (which skips the redaction
        as --raw does), with --raw before `view`, or after more than sixteen of view's options, was allowed; and so
        were gcloud's tokens on the alpha or beta track and `gcloud config config-helper`, whose default output holds
        the access token."""
        self.held("TK-A021", "ask", [
            "microk8s kubectl config view --raw", "microk8s.kubectl config view --raw", "k3s kubectl config view --raw",
            "k0s kubectl config view --raw", "minikube kubectl -- config view --raw",
            "minikube -p dev kubectl -- --context x config view --raw", "kubecolor config view --raw",
            "kubectl config view --minify --flatten", "kubectl --raw config view", "kubectl config --raw view",
            "kubectl config view " + "-v1 " * 17 + "--raw", "kubectl config view " + "--flatten " * 17 + "--raw",
            "gcloud beta auth print-access-token", "gcloud alpha auth print-identity-token",
            "gcloud --project p beta auth print-access-token", "gcloud beta --project p auth print-access-token",
            "gcloud beta auth application-default print-access-token", "gcloud config config-helper",
            "gcloud config config-helper --format='value(credential.access_token)'",
            "gcloud --format=json config config-helper"])
        self.held("TK-A052", "ask", ["microk8s kubectl get secret db -o yaml", "k3s kubectl get secrets -o json",
                                     "minikube kubectl -- get secret db -o jsonpath='{.data}'"])
        self.kept("TK-A021", ["microk8s kubectl config view", "kubectl config view --raw=false",
                              "minikube kubectl -- get pods", "gcloud beta auth list", "gcloud config list",
                              "gcloud config get-value project", "microk8s status"])

    def test_a_shell_call_is_read_in_its_own_working_directory_and_environment_on_every_reading(self):
        """The signer read a shell call's working directory only under the tool's own name: an MCP server's shell tool
        (mcp__srv__shell, read as `shell` by its bare name), a class hint of shell, and the spellings workingDirectory,
        dir and cd were read without it; and a call's own `env` (BASH_ENV, HOME, CDPATH) not at all."""
        live = "/var/lib/tracekit-signer"
        held = [("Bash", {"command": "cat keys/log.key", k: live}, "TK-D007") for k in ("workingDirectory", "dir", "cd")]
        held += [(t, {"command": "cat keys/log.key", k: live}, "TK-D007") for t, k in (
            ("mcp__srv__shell", "cwd"), ("mcp__srv__terminal", "workdir"), ("mcp__srv__run_shell_command", "dir_path"),
            ("mcp:srv/shell", "cwd"), ("mcp__srv_shell", "cwd"))]
        held += [("Bash", {"command": "cat ~/keys/log.key", "env": {"HOME": live}}, "TK-D007"),
                 ("local_shell", {"command": ["cat", "keys/log.key"], "env": {"CDPATH": live}}, "TK-D007"),
                 ("Bash", {"command": "ls", "env": {"BASH_ENV": "/tmp/x.sh"}}, "TK-F011"),
                 ("Bash", {"command": "ls", "env": {"BASH_FUNC_ls%%": "() { id; }"}}, "TK-SHELL-PARSE"),
                 ("Bash", {"command": "ls", "env": ["BASH_ENV=/tmp/x.sh"]}, "TK-SHELL-PARSE")]
        for pack, name, e in engines():
            for tool, args, rule in held:
                with self.subTest(pack=pack, engine=name, tool=tool, args=args):
                    self.assertIn(rule, svc.evaluate(e, tool, args)[0]["rule_ids"])
            with self.subTest(pack=pack, engine=name, hint="shell"):
                d = svc.evaluate(e, "run_it", {"command": "cat keys/log.key", "cwd": live}, hint="shell")[0]
                self.assertIn("TK-D007", d["rule_ids"])
            for tool, args in (("Bash", {"command": "ls", "cwd": "/tmp"}), ("Bash", {"command": "ls", "env": {"X": "1"}}),
                               ("mcp__srv__shell", {"command": "ls", "dir": "/tmp"})):
                with self.subTest(pack=pack, engine=name, tool=tool, args=args):
                    self.assertFalse({"TK-D007", "TK-F011", "TK-SHELL-PARSE"} & set(svc.evaluate(e, tool, args)[0]["rule_ids"]))
        # a deployment's own shell tool by its MCP name, whose bare name its policy maps to another class
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(os.path.join(PACKS, "coding.yaml"), d)
            with open(os.path.join(d, "own.yaml"), "w") as f:
                f.write("extends: coding.yaml\nversion: own-1\ntools:\n  'mcp:srv/query': shell\n  query: sql\n")
            for name in ENGINES:
                e = Engine(pc.build(os.path.join(d, "own.yaml"))[0], name)
                with self.subTest(engine=name, tool="mcp__srv__query"):
                    d2 = svc.evaluate(e, "mcp__srv__query", {"command": "cat keys/log.key", "cwd": live})[0]
                    self.assertIn("TK-D007", d2["rule_ids"])


if __name__ == "__main__":
    unittest.main()
