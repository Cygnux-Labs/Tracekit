"""SQL over the ledger (#8): incremental index, chain-link checks, rebuild on rewrite, read-only queries, MCP.
python3 -m pytest contrib/query/tests -q"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [ROOT, HERE]
import tracekit_query as query  # noqa: E402
from tracekit import install  # noqa: E402
from tracekit.agent_sdk import Tracer  # noqa: E402

_SAVED = {}


def setUpModule():
    _SAVED["policy"] = os.environ.pop("TRACEKIT_POLICY", None)


def tearDownModule():
    if _SAVED.get("policy") is not None:
        os.environ["TRACEKIT_POLICY"] = _SAVED["policy"]


class SQL(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        install.init_dev(self.home, [], start=True)
        self.idx = query.Index(self.home, os.path.join(self.d, "idx.sqlite"))

    def tearDown(self):
        install.stop_dev_daemon(self.home)
        if self.old is None:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)
        else:
            os.environ["TRACEKIT_CLIENT_HOME"] = self.old
        shutil.rmtree(self.d, ignore_errors=True)

    def run_agent(self, sid, n=3):
        with Tracer(agent="bot", session_id=sid, cwd=self.d) as t:
            for i in range(n):
                with t.tool("Bash", {"command": f"echo {i}"}) as c:
                    c.result("ok")
            try:
                with t.tool("Bash", {"command": "sudo id"}):
                    pass
            except PermissionError:
                pass

    def test_views_and_incremental_refresh(self):
        self.run_agent("a")
        first = self.idx.refresh()
        self.assertGreater(first, 0)
        self.assertEqual(self.idx.refresh(), 0)  # nothing new
        self.run_agent("b", 2)
        self.assertGreater(self.idx.refresh(), 0)
        cols, rows, _ = self.idx.query("SELECT run_id, tool_calls, denied FROM runs ORDER BY run_id")
        self.assertEqual(rows, [("a", 4, 1), ("b", 3, 1)])
        cols, rows, _ = self.idx.query("SELECT command, decision, ok FROM tool_calls WHERE run_id='a' ORDER BY seq")
        self.assertEqual(rows[-1], ("sudo id", "deny", None))
        self.assertEqual(rows[0], ("echo 0", "allow", 1))
        self.assertEqual(self.idx.query("SELECT count(*) FROM events WHERE chain_ok=0")[1], [(0,)])
        self.assertEqual(self.idx.notes, [])

    def test_read_only_and_errors(self):
        self.run_agent("a")
        self.idx.refresh()
        import sqlite3
        for bad in ("DELETE FROM events", "DROP TABLE events", "INSERT INTO meta VALUES ('x','y')", "PRAGMA query_only=0; DELETE FROM events"):
            with self.assertRaises((sqlite3.Error, sqlite3.Warning)):
                self.idx.query(bad)
        self.assertGreater(self.idx.query("SELECT count(*) FROM events")[1][0][0], 0)

    def test_runaway_query_is_stopped(self):
        self.run_agent("a")
        self.idx.refresh()
        with self.assertRaises(TimeoutError):
            self.idx.query("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c", budget_s=0.3)

    def test_rewritten_ledger_triggers_rebuild(self):
        self.run_agent("a")
        self.idx.refresh()
        led = os.path.join(self.home, "ledger", "ledger.jsonl")
        install.stop_dev_daemon(self.home)
        lines = open(led).read().splitlines()
        r = json.loads(lines[2])
        r["hash"] = "f" * 64
        lines[2] = json.dumps(r)
        open(led, "w").write("\n".join(lines) + "\n")
        self.idx.refresh()
        self.assertTrue(any("rebuilt" in n for n in self.idx.notes), self.idx.notes)
        self.assertGreater(self.idx.query("SELECT count(*) FROM events WHERE chain_ok=0")[1][0][0], 0)  # the broken link is visible
        install.init_dev(self.home, [], start=True)

    def test_mcp_round_trip(self):
        self.run_agent("a")
        reqs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "tracekit_sql",
                                                                              "arguments": {"query": "SELECT name, decision FROM tool_calls WHERE decision='deny'"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "tracekit_sql", "arguments": {"query": "DELETE FROM events"}}},
                {"jsonrpc": "2.0", "id": 5, "method": "nope"}]
        out = io.StringIO()
        query.mcp_serve(self.idx, io.StringIO("\n".join(json.dumps(r) for r in reqs) + "\n"), out)
        resp = {r["id"]: r for r in map(json.loads, out.getvalue().splitlines())}
        self.assertEqual(resp[1]["result"]["serverInfo"]["name"], "tracekit")
        self.assertEqual({t["name"] for t in resp[2]["result"]["tools"]}, {"tracekit_sql", "tracekit_schema"})
        self.assertEqual(json.loads(resp[3]["result"]["content"][0]["text"]), [{"name": "Bash", "decision": "deny"}])
        self.assertTrue(resp[4]["result"]["isError"])
        self.assertEqual(resp[5]["error"]["code"], -32601)
        self.assertNotIn(None, resp)  # the notification got no reply

    def test_model_exchange_tokens(self):
        u = {"input_tokens": 10, "cache_read_tokens": 5, "cache_write_tokens": 1, "output_tokens": 3}
        self.assertEqual(query._columns("model.exchange", {"model": "m", "usage": u}), ("m", None, None, 16, 3))

    def test_cli(self):
        import subprocess
        self.run_agent("a")
        p = subprocess.run([sys.executable, "-m", "tracekit_query", "--home", self.home, "--index", self.idx.path, "--format", "csv",
                            "SELECT run_id, tool_calls FROM runs"], capture_output=True, text=True, cwd=HERE, env=dict(os.environ, PYTHONPATH=ROOT))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split(), ["run_id,tool_calls", "a,4"])


if __name__ == "__main__":
    unittest.main()
