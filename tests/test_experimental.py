"""Experimental servers (ingest gateway, model proxy, OTLP receiver) are off unless --experimental is given.
python3 -m pytest tests/test_experimental.py -q"""
import contextlib
import io
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import cli  # noqa: E402
from tracekit.wiki import wiki_url  # noqa: E402


class Experimental(unittest.TestCase):
    def run_cli(self, argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, err.getvalue()

    def test_refused_without_the_flag(self):
        for argv in (["ingest", "serve", "--home", "/nonexistent"], ["otel", "serve"], ["proxy", "--home", "/nonexistent"],
                     ["init", "--dev", "--home", "/nonexistent", "--proxy"]):
            code, err = self.run_cli(argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("pass --experimental", err, argv)

    def test_flag_lets_it_through_with_a_warning(self):
        # with the flag, ingest serve gets past the gate and stops at its next check (no client tokens)
        code, err = self.run_cli(["ingest", "serve", "--experimental", "--home", "/nonexistent"])
        self.assertEqual(code, 2)
        self.assertIn("experimental and being rebuilt", err)
        self.assertIn("no client tokens", err)

    def test_proxy_port_zero_is_passed_on(self):
        with mock.patch("tracekit.proxy.main", return_value=0) as m:
            self.run_cli(["proxy", "--experimental", "--home", "/nonexistent", "--port", "0"])
        self.assertEqual(m.call_args[0][0][-2:], ["--port", "0"])

    def test_experimental_commands_say_so_once_and_stable_ones_do_not(self):
        for cmd, module, says in (("monitor", "tracekit.monitor.main", True), ("why", "tracekit.why.cli.main", True),
                                  ("view", "tracekit.view.main", False)):
            with mock.patch(module, return_value=0):
                code, err = self.run_cli([cmd])
            self.assertEqual(code, 0)
            self.assertEqual(err.count("is experimental: it works and is tested, but may change "
                                       f"({wiki_url('docs/support.md')})"), int(says), cmd)

    def test_help_is_not_said_to_be_experimental_twice(self):
        """`tracekit pcm --help` printed the experimental banner above a help that says (experimental) itself: the
        banner is for running the command, and help is not a run."""
        for argv in (["pcm", "--help"], ["pcm", "verify", "-h"], ["graph", "--help"]):
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit) as cm:
                cli.main(argv)
            self.assertEqual((cm.exception.code, err.getvalue()), (0, ""), argv)
            self.assertIn("usage: tracekit ", out.getvalue())
        with mock.patch("tracekit.pcm.cli.main", return_value=0):
            self.assertEqual(self.run_cli(["pcm", "demo"])[1].count("tracekit pcm is experimental"), 1)

    def test_the_signer_names_the_experimental_settings_it_was_given(self):
        from tracekit.signer import service as svc
        for cfg, want in (({"data_dir": "/nonexistent"}, None),
                          ({"data_dir": "/nonexistent", "storage": {"postgres": {}}, "approvals": {"agents": {"a": {}}}},
                           "the signer's storage, approvals.agents setting(s) are experimental")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err), mock.patch.object(svc, "load_config", return_value=cfg), \
                    mock.patch.object(svc.logkey, "harden"), mock.patch.object(svc, "open_service", side_effect=OSError):
                self.assertEqual(svc.main(["serve", "--config", "signer.yaml"]), 1)
            self.assertEqual("experimental" in err.getvalue(), want is not None, err.getvalue())
            if want:
                self.assertIn(want, err.getvalue())

    def test_a_malformed_approvals_section_is_refused_cleanly_not_a_traceback(self):
        from tracekit.signer import service as svc
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch.object(svc, "load_config", return_value={
                "data_dir": "/nonexistent", "approvals": [1, 2]}), mock.patch.object(svc.logkey, "harden"), \
                mock.patch.object(svc, "open_service", side_effect=OSError):
            self.assertEqual(svc.main(["serve", "--config", "signer.yaml"]), 1)

    def test_view_says_so_for_why_logs_and_the_v1_ledger_only(self):
        from tracekit import view
        for argv, says in ((["--why", "/nonexistent"], "tracekit why (tracekit view --why)"),
                           (["--ledger"], "the v1 ledger"), (["--bundle", "x.tkb"], "the v1 ledger"), ([], None)):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):   # --tls-cert without --tls-key: refused right after the notice
                self.assertEqual(view.main(argv + ["--tls-cert", "c.pem"]), 2)
            self.assertEqual(says is not None, "is experimental" in err.getvalue(), argv)
            if says:
                self.assertIn(says, err.getvalue())


if __name__ == "__main__":
    unittest.main()
