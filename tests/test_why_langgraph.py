"""tracekit.why.langgraph: fork replay of a recorded LangGraph thread (examples/v2/langchain/injection.py) names the
fetched page as the cause and rules out the benign tool result, without running a tool, calling the signer or touching
the recorded thread."""
import contextlib
import io
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    sys.path.insert(0, os.path.join(ROOT, "examples", "v2", "langchain"))
    import injection as inj
    from tracekit.testing import FakeSigner
    from tracekit.why.cli import main
    from tracekit.why.langgraph import attribute_thread, fork_replay
except ImportError:   # optional: the dev extra installs them
    HAVE_LG = False
else:
    HAVE_LG = True


@unittest.skipUnless(HAVE_LG, "langchain>=1 / langgraph not installed")
class ForkReplay(unittest.TestCase):
    def setUp(self):
        inj.SAVER.delete_thread(inj.THREAD["configurable"]["thread_id"])
        self.signer = FakeSigner(lambda tool, args: ("allow", []))
        r = self.signer.register_run({"request_id": "reg", "agent": {"name": "test"}})
        self.run = {"run_id": r["run_id"], "run_token": r["run_token"]}
        out = inj.record(inj.graph_factory(self.signer, r))
        self.page, self.weather = [m.tool_call_id for m in out["messages"] if m.type == "tool"][:2]
        self.graph = inj.graph_factory()

    def events(self):
        return self.signer.read({**self.run, "limit": 1000})["events"]

    def test_names_the_page_and_rules_out_the_benign_input(self):
        before, history = len(self.events()), len(list(self.graph.get_state_history(inj.THREAD)))
        calls = []
        real = inj.send_email.func
        inj.send_email.func = lambda **kw: calls.append(kw) or real(**kw)
        self.addCleanup(setattr, inj.send_email, "func", real)
        r = attribute_thread(self.graph, inj.THREAD, inj.TARGET, n=80, n_max=160)
        self.assertEqual(r["suspects"], [self.page, self.weather])
        self.assertEqual([c["intervention"] for c in r["causes"]], [self.page])
        self.assertEqual(r["causes"][0]["role"], "primary")
        weather = next(t for t in r["tests"] if t["intervention"] == self.weather)
        self.assertEqual(weather["verdict"], "ruled-out")
        self.assertEqual({(t["rung"], t["off_tape_actions"]) for t in r["tests"]}, {(3, 0)})
        self.assertEqual(r["fork"]["as_node"], "tools")
        self.assertEqual(calls, [])                         # no real tool ran
        self.assertEqual(len(self.events()), before)        # nothing reached the signer
        self.assertEqual(len(list(self.graph.get_state_history(inj.THREAD))), history)   # the thread is untouched

    def test_a_call_the_run_never_made_is_stubbed_and_counted(self):
        real = inj.model

        def other_body(state, config):   # in the branches the email has other arguments than the recorded one
            out = real(state, config)
            for tc in out["messages"][0].tool_calls:
                if tc["name"] == "send_email":
                    tc["args"] = {**tc["args"], "body": "something else"}
            return out

        inj.model = other_body
        self.addCleanup(setattr, inj, "model", real)
        r = fork_replay(inj.graph_factory(), inj.THREAD, None, self.weather, inj.TARGET, n=20)
        self.assertEqual(r["rung"], 3)
        self.assertGreater(r["off_tape_actions"], 0)

    def test_a_checkpoint_before_the_message_has_nothing_to_remove(self):
        early = list(self.graph.get_state_history(inj.THREAD))[-2].config["configurable"]["checkpoint_id"]
        with self.assertRaisesRegex(ValueError, "no message or tool call"):
            fork_replay(self.graph, inj.THREAD, early, self.page, inj.TARGET, n=2)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["attribute", "--langgraph", "injection:graph_factory", "--thread", "injection",
                  "--target", inj.TARGET, "--suspect", self.page, "--json"])
        r = json.loads(out.getvalue())
        self.assertEqual((r["rung"], r["causes"][0]["intervention"]), (3, self.page))


if __name__ == "__main__":
    unittest.main()
