"""Fail-closed classes (policy2/failclosed.py): with no signer answering and a fail mode that lets a call run, a hook
still blocks secrets, deploys, payments and pushes to main, by class first (in code, whatever a pack says), then by the
policy it can read (the operator's, else the shipped dev pack), and never allows one of them for want of a policy."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from tracekit.policy2 import failclosed

PUSH_MAIN = "git push origin " + "main"
CLASSED = [
    ("Bash", {"command": "aws secretsmanager get-secret-value --secret-id prod/db"}, "secrets"),
    ("Bash", {"command": "cd x && gcloud secrets versions access latest --secret s"}, "secrets"),
    ("Bash", {"command": "kubectl get secret db -o yaml"}, "secrets"),
    ("Bash", {"command": "cat ~/.aws/credentials"}, "secrets"),
    ("Read", {"file_path": "/repo/.env"}, "secrets"),
    ("Read", {"file_path": "/home/u/.ssh/id_ed25519"}, "secrets"),
    ("mcp__vault__get_secret", {"name": "db"}, "secrets"),
    ("Bash", {"command": "npm publish"}, "deploys"),
    ("Bash", {"command": "terraform apply -auto-approve"}, "deploys"),
    ("Bash", {"command": "gh release create v1"}, "deploys"),
    ("Bash", {"command": "gcloud run deploy svc --image i"}, "deploys"),
    ("Bash", {"command": "kubectl -n prod apply -f k8s/"}, "deploys"),
    ("Bash", {"command": "docker push org/app:1"}, "deploys"),
    ("Bash", {"command": "stripe refunds create --charge ch_1"}, "payments"),
    ("Bash", {"command": "curl https://api.stripe.com/v1/refunds -d charge=ch_1"}, "payments"),
    ("mcp__stripe__create_refund", {"charge": "ch_1"}, "payments"),
    ("WebFetch", {"url": "https://api.stripe.com/v1/payouts"}, "payments"),
    ("Bash", {"command": PUSH_MAIN}, "pushes to main"),
    ("Bash", {"command": "git push"}, "pushes to main"),   # push.default picks the branch
    ("Bash", {"command": "gh pr merge 12 --squash"}, "pushes to main"),
    ("mcp__aws__call_aws", {"cli_command": "aws secretsmanager get-secret-value --secret-id x"}, "secrets"),
    ("Bash", {"command": "$TOOL push origin main"}, "unreadable"),
    # a line typed into a terminal, and text written into a process, are read as the commands they run
    ("Bash", {"command": "t push origin main\n", "typed_line": PUSH_MAIN + "\n"}, "pushes to main"),
    ("process_manage", {"action": "submit", "data": "npm publish"}, "deploys"),
    # the CLIs' own credential printers
    ("Bash", {"command": "aws configure export-credentials --profile p"}, "secrets"),
    ("Bash", {"command": "gcloud auth print-access-token"}, "secrets"),
    ("Bash", {"command": "kubectl config view --raw"}, "secrets"),
    ("Bash", {"command": "printf 'host=github.com' | git credential fill"}, "secrets"),
    # globs and URIs that name a credential file, and capturing a payment
    ("Grep", {"pattern": "KEY", "path": "/repo", "glob": ".env*"}, "secrets"),
    ("Glob", {"pattern": "**/.aws/*"}, "secrets"),
    ("mcp__fs__read", {"uri": "file:///repo/.env"}, "secrets"),
    ("mcp__fs__read", {"target": "/h/.netrc"}, "secrets"),
    ("mcp__paypal__capture_order", {"id": "o1"}, "payments"),
    # more deploys and pushes TK-A056 holds
    ("Bash", {"command": "gh release new v1"}, "deploys"),
    ("Bash", {"command": "docker buildx build --push -t ghcr.io/o/a:1 ."}, "deploys"),
    ("Bash", {"command": "gcloud run services update-traffic svc --to-latest"}, "deploys"),
    ("Bash", {"command": "git subtree push --prefix=docs origin main"}, "pushes to main"),
]
# a listed CLI whose subcommand the line can't tell is in that CLI's class (a push before a publish, a payment, a
# secret), and each push or publish the engine reads per command in its own (an image or a release: a deploy)
UNTOLD = [("Bash", {"command": "git $X origin main"}, "pushes to main"),
          ("Bash", {"command": 'set -- push origin main; git "$@"'}, "pushes to main"),
          ("Bash", {"command": "npm $CMD"}, "deploys"), ("Bash", {"command": "stripe $OP"}, "payments"),
          ("Bash", {"command": "aws --region r $SVC get-secret-value"}, "deploys"),
          ("Bash", {"command": "op $V op://vault/item"}, "secrets"),
          ("Bash", {"command": "docker buildx bake --push"}, "deploys"),
          ("Bash", {"command": "docker compose push"}, "deploys"),
          ("Bash", {"command": "gh api repos/o/r/releases -f tag_name=v1"}, "deploys"),
          ("Bash", {"command": "git config remote.origin.push refs/heads/feature:refs/heads/main"}, "pushes to main"),
          # round 5: a word xargs or parallel fills in where the subcommand goes (F2), a switch before an expansion
          # (F5), a draft value that isn't true (F3), more image pushes, releases, tags and push settings (F1, F9)
          ("Bash", {"command": "echo push | xargs -I{} git {} origin main"}, "pushes to main"),
          ("Bash", {"command": "parallel git {} origin main ::: push"}, "pushes to main"),
          ("Bash", {"command": "echo publish | xargs -I{} npm {}"}, "deploys"),
          ("Bash", {"command": "cat ops.txt | xargs -I{} stripe {} ch_1"}, "payments"),
          ("Bash", {"command": "cat ops.txt | xargs -I% vault % secret/prod"}, "secrets"),
          ("Bash", {"command": 'npm -s "$X"'}, "deploys"), ("Bash", {"command": "helm --debug $X"}, "deploys"),
          ("Bash", {"command": 'cargo +nightly --locked "$X"'}, "deploys"),
          ("Bash", {"command": 'gh release edit v1 --draft="$D"'}, "deploys"),
          ("Bash", {"command": "hub release edit --draft=false v1"}, "deploys"),
          ("Bash", {"command": "goreleaser release --clean"}, "deploys"),
          ("Bash", {"command": "crane push img.tar reg/x"}, "deploys"),
          ("Bash", {"command": "skopeo copy docker-archive:x.tar docker://reg/x"}, "deploys"),
          ("Bash", {"command": "docker manifest push reg/x"}, "deploys"),
          ("Bash", {"command": "gh workflow run deploy.yml"}, "deploys"), ("Bash", {"command": "npm publis"}, "deploys"),
          ("Bash", {"command": "gh api repos/o/r/git/refs -f ref=refs/tags/v1 -f sha=x"}, "pushes to main"),
          ("Bash", {"command": "GIT_EDITOR='tee -a' git config --edit"}, "pushes to main"),
          ("Bash", {"command": "git --git-dir=/tmp/e.git push origin feature"}, "pushes to main")]
ROUTINE = [("Bash", {"command": "ls -la"}), ("Bash", {"command": "git status && git diff"}),
           ("Bash", {"command": "git push origin feature/x"}), ("Bash", {"command": "npm test"}),
           ("Bash", {"command": "terraform plan"}), ("Read", {"file_path": "/repo/.env.example"}),
           ("Read", {"file_path": "/repo/README.md"}), ("Bash", {"command": "gh pr list"}),
           ("Bash", {"command": "kubectl get pods"}), ("Grep", {"pattern": "TODO", "glob": "*.py"}),
           ("Glob", {"pattern": "src/**/*.ts"}), ("Bash", {"command": "kubectl config view"}),
           ("process_manage", {"action": "submit", "data": "ls"})]


class Classes(unittest.TestCase):
    def test_each_class_by_what_the_call_names(self):
        for tool, args, want in CLASSED:
            self.assertEqual(failclosed.classify(tool, args), want, (tool, args))
        for tool, args in ROUTINE:
            self.assertIsNone(failclosed.classify(tool, args), (tool, args))

    def test_the_spellings_the_packs_hold_are_in_their_class(self):
        """The 1.8 parsing review: oc (OpenShift's kubectl), a raw API path to secrets, kubectl through a distribution
        or wrapper, a config view with --flatten, gcloud's config-helper and ECR's login password, a monorepo release
        however its tool is run, glab's token, and gcloud's, Azure's, Postgres's and Vault's credential files were in no
        class."""
        for command, want in (
                ("oc get secret db -o yaml", "secrets"), ("oc apply -f k8s/", "deploys"),
                ("kubectl get --raw '/api/v1/secrets?limit=500'", "secrets"),
                ("oc get --raw /api/v1/namespaces/prod/secrets#x", "secrets"), ("kubectl get secret/db -o yaml", "secrets"),
                ("microk8s kubectl get secrets -o json", "secrets"), ("k3s kubectl config view --raw", "secrets"),
                ("minikube kubectl -- config view --raw", "secrets"), ("kubectl config view --flatten", "secrets"),
                ("kubectl config view --raw=true", "secrets"), ("gcloud config config-helper", "secrets"),
                ("aws ecr get-login-password --region eu-west-1", "secrets"), ("lerna publish", "deploys"),
                ("npx changeset publish", "deploys"), ("nx release publish", "deploys"),
                ("yarn lerna publish", "deploys"), ("cat ~/.config/gcloud/application_default_credentials.json", "secrets"),
                ("cat ~/.pgpass", "secrets"), ("cat ~/.vault-token", "secrets"),
                ("cat ~/.azure/msal_token_cache.json", "secrets"), ("glab auth status -t", "secrets"),
                ("glab config get token", "secrets")):
            self.assertEqual(failclosed.classify("Bash", {"command": command}), want, command)
        self.assertEqual(failclosed.classify("Read", {"file_path": "/h/.config/gcloud/credentials.db"}), "secrets")
        self.assertEqual(failclosed.classify("Glob", {"pattern": "**/.pgpass"}), "secrets")
        for command in ("oc get pods", "kubectl config view --raw=false", "kubectl get secret-reader-role",
                        "nx release version", "gcloud config list", "aws ecr describe-repositories"):
            self.assertIsNone(failclosed.classify("Bash", {"command": command}), command)

    def test_an_untold_subcommand_and_the_per_command_pushes(self):
        for tool, args, want in UNTOLD:
            self.assertEqual(failclosed.classify(tool, args), want, (tool, args))
        for line in ("git log $REF", 'git -C "$DIR" status', "kubectl get pods -n $NS", "X=status; git $X",
                     'yarn --cwd "$DIR" build', "echo a | xargs -I{} git add {}", "npm -s test", "crane ls reg/x"):
            self.assertIsNone(failclosed.classify("Bash", {"command": line}), line)


class Typed(unittest.TestCase):
    def test_typed_text_runs_only_where_it_ends_its_line(self):
        # with no signer answering, a fragment a later call could finish into a class command doesn't run (the
        # hook's typed_text: the call's own text)
        for text, runs in (("gi", False), ("ls\ngit pu", False), ("\x1b[A", False), ("", False),
                           ("ls\n", True), ("\x03", True), ("\x1b[A\x03", True)):
            self.assertEqual(failclosed.decide("Bash", {"command": text}, None, text)[0], not runs, repr(text))
        self.assertEqual(failclosed.decide("Bash", {"command": "t push origin main\n",
                                                    "typed_line": PUSH_MAIN + "\n"}, None, "t push origin main\n"),
                         (True, "pushes to main"))


class Decide(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        failclosed._engine.cache_clear()
        self.addCleanup(failclosed._engine.cache_clear)
        # a pack edited to allow everything: it maps the tools and has no rule
        self.open_pack = os.path.join(self.dir, "open.yaml")
        with open(self.open_pack, "w") as f:
            f.write("version: 1\ntools:\n  Bash: shell\n  Read: fs\n  WebFetch: http\n")
        self.hold = ("Bash", {"command": "rm -rf ~/"})   # held by the dev pack, in none of the classes

    def blocked(self, call, policy):
        return failclosed.decide(*call, policy)[0]

    def test_the_classes_block_whatever_the_pack_says(self):
        with mock.patch.object(failclosed, "DEV_PACK", self.open_pack):
            for tool, args, want in CLASSED:
                self.assertEqual(failclosed.decide(tool, args, self.open_pack),
                                 (True, "a command the hook can't read" if want == "unreadable" else want), tool)
            self.assertFalse(self.blocked(self.hold, self.open_pack))   # (the edited pack holds nothing else)
            for call in ROUTINE:
                self.assertFalse(self.blocked(call, self.open_pack), call)

    def test_an_unreadable_policy_reads_the_dev_pack(self):
        root_only = os.path.join(self.dir, "operator.yaml")
        shutil.copy(failclosed.DEV_PACK, root_only)
        os.chmod(root_only, 0)
        if os.access(root_only, os.R_OK):
            self.skipTest("root reads any file")
        blocked, why = failclosed.decide(*self.hold, root_only)
        self.assertTrue(blocked)
        self.assertRegex(why, r"^TK-")
        self.assertFalse(self.blocked(ROUTINE[0], root_only))
        self.classes_block(root_only)

    def test_a_policy_that_fails_to_compile_reads_the_dev_pack(self):
        broken = os.path.join(self.dir, "broken.yaml")
        with open(broken, "w") as f:
            f.write("version: 1\ndeny:\n  - id: X\n    pattern: '('\n")
        self.assertTrue(self.blocked(self.hold, broken))
        self.assertFalse(self.blocked(ROUTINE[0], broken))
        self.classes_block(broken)

    def classes_block(self, policy):
        """The four classes block by class, before any policy is read: with the dev pack, an edited one, or none."""
        for dev in (failclosed.DEV_PACK, self.open_pack, os.path.join(self.dir, "missing.yaml")):
            with mock.patch.object(failclosed, "DEV_PACK", dev):
                for tool, args, want in CLASSED:
                    self.assertEqual(failclosed.decide(tool, args, policy)[1],
                                     "a command the hook can't read" if want == "unreadable" else want, (dev, tool))

    def test_the_policy_reads_a_call_as_the_signer_does(self):
        # service.evaluate: a file tool by another harness's name, an MCP tool's mcp:<server>/<tool> mapping, a line
        # typed into a terminal; each one the dev signer holds, the hook blocks
        for tool, args in (("mcp__postgres__query", {"sql": "DROP TABLE users"}),
                           ("write_file", {"path": "/home/u/.zshrc", "content": "x"}),
                           ("Bash", {"command": "echo hi", "typed_line": self.hold[1]["command"]})):
            self.assertTrue(self.blocked((tool, args), None), tool)

    def test_a_policy_that_fails_on_a_call_blocks_it(self):
        from tracekit.signer import service
        with mock.patch.object(service, "evaluate", side_effect=RuntimeError("a bug the call reaches")):
            self.assertEqual(failclosed.decide("Bash", {"command": "ls"}, None),
                             (True, "the policy failed on this call"))
        with mock.patch.object(failclosed.Engine, "decide", side_effect=RuntimeError("engine")):
            self.assertEqual(failclosed.decide("Bash", {"command": "ls"}, None), (True, "TK-ENGINE-ERROR"))

    def test_with_no_policy_that_loads_the_classes_still_block(self):
        with mock.patch.object(failclosed, "DEV_PACK", os.path.join(self.dir, "missing.yaml")):
            for tool, args, _ in CLASSED:
                self.assertTrue(self.blocked((tool, args), None), tool)
            self.assertFalse(self.blocked(self.hold, None))   # routine work runs: the fail mode said so
            self.assertFalse(self.blocked(ROUTINE[0], None))

    def test_doctor_says_which_hooks_keep_the_classes_closed(self):
        """The review's B2: doctor said the four classes still fail closed while the SDK integrations fail open by
        fail_modes alone; it names the coding agents' hooks as the ones that block them."""
        from tracekit import doctor
        os.chmod(self.dir, 0o700)
        got = doctor.v2_checks({"data_dir": self.dir, "fail_modes": {"fs": "open"}}, "dev",
                               settings=os.path.join(self.dir, "none"))
        detail = next(r["detail"] for r in got if r["id"] == "D-FAIL-MODES")
        self.assertIn("the coding-agent hooks still block secrets, deploys, payments and pushes to main", detail)
        self.assertIn("the SDK and framework integrations fail open by class alone", detail)
