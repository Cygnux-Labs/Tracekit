"""SQL over the signed ledger, with no dependencies (sqlite3 from the standard library).

    tracekit sql "SELECT name, count(*) FROM tool_calls GROUP BY name ORDER BY 2 DESC"
    tracekit sql --schema
    tracekit sql --format json "SELECT * FROM findings WHERE severity IN ('high','critical')"
    tracekit sql --mcp            # MCP server on stdio: coding agents can query traces (tools: tracekit_sql, tracekit_schema)

The ledger stays the source of truth. The index is a derived cache (default ~/.cache/tracekit/index-<id>.sqlite) that is
never treated as evidence, can be deleted at any time, and is rebuilt from the ledger when needed. It is refreshed
incrementally before every query: new records are appended after checking that each one links to the previous record's
hash. If a record already in the index no longer matches the ledger (the ledger was rewritten), the index is rebuilt
and the query result says so. Signatures are not re-checked here: use `tracekit verify` for that.

Queries run on a read-only connection with a time budget, so a query cannot change the index or hang the caller."""
import argparse
import csv
import hashlib
import io
import json
import os
import sqlite3
import sys
import time

INDEX_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY, hash TEXT NOT NULL, prev_hash TEXT NOT NULL, ts TEXT, ts_signed TEXT, run_id TEXT, agent_id TEXT,
  parent_id TEXT, source TEXT, type TEXT, data TEXT, chain_ok INTEGER NOT NULL, tool_use_id TEXT, phase TEXT);
CREATE INDEX IF NOT EXISTS ev_run ON events(run_id, type);
CREATE INDEX IF NOT EXISTS ev_type ON events(type);
CREATE INDEX IF NOT EXISTS ev_tool ON events(tool_use_id, type, run_id);

CREATE VIEW IF NOT EXISTS tool_calls AS
SELECT c.run_id, c.agent_id, c.seq, c.tool_use_id, json_extract(c.data,'$.name') AS name,
       json_extract(c.data,'$.input.command.value') AS command, json_extract(c.data,'$.input.file_path.value') AS file_path,
       json_extract(c.data,'$.input.url.value') AS url, json_extract(d.data,'$.decision') AS decision,
       json_extract(d.data,'$.rule_ids') AS rule_ids, json_extract(r.data,'$.ok') AS ok,
       json_extract(r.data,'$.duration_ms') AS duration_ms, json_extract(r.data,'$.output.redacted') AS output_redacted,
       c.ts AS started, r.ts AS finished, c.source, c.hash AS call_hash, r.hash AS result_hash
FROM events c
LEFT JOIN events d ON d.tool_use_id=c.tool_use_id AND d.type='policy.decision' AND d.run_id=c.run_id
LEFT JOIN events r ON r.tool_use_id=c.tool_use_id AND r.type='tool.result' AND r.run_id=c.run_id
WHERE c.type='tool.call';

CREATE VIEW IF NOT EXISTS model_exchanges AS
SELECT run_id, agent_id, seq, json_extract(data,'$.exchange_id') AS exchange_id, json_extract(data,'$.model') AS model,
       json_extract(data,'$.upstream') AS upstream, json_extract(data,'$.stop_reason') AS stop_reason,
       json_extract(data,'$.status') AS status, json_extract(data,'$.duration_ms') AS duration_ms,
       json_extract(data,'$.first_byte_ms') AS first_byte_ms, json_extract(data,'$.streamed') AS streamed,
       json_extract(data,'$.error') AS error, json_extract(data,'$.tool_uses') AS tool_uses, source, ts, hash
FROM events WHERE type='model.exchange' AND phase='response';

CREATE VIEW IF NOT EXISTS findings AS
SELECT json_extract(data,'$.verdict.run_id') AS run_id, seq, json_extract(data,'$.verdict.rule') AS rule,
       json_extract(data,'$.verdict.severity') AS severity, json_extract(data,'$.verdict.title') AS title,
       json_extract(data,'$.verdict.detail') AS detail, json_extract(data,'$.verdict.evidence') AS evidence,
       json_extract(data,'$.reviewer') AS detector, ts, hash
FROM events WHERE type='review' AND run_id LIKE 'findings:%';

CREATE VIEW IF NOT EXISTS gaps AS
SELECT seq, run_id, json_extract(data,'$.kind') AS kind, json_extract(data,'$.reason') AS reason, ts FROM events WHERE type='capture.gap'
UNION ALL
SELECT seq, run_id, 'trace.tamper:' || json_extract(data,'$.kind'), json_extract(data,'$.path'), ts FROM events WHERE type='trace.tamper';

CREATE VIEW IF NOT EXISTS runs AS
SELECT e.run_id,
  max(CASE WHEN e.type='run.start' THEN json_extract(e.data,'$.agent.name') END) AS agent,
  max(CASE WHEN e.type='run.start' THEN json_extract(e.data,'$.model') END) AS model,
  max(CASE WHEN e.type='run.start' THEN json_extract(e.data,'$.content_capture') END) AS content_capture,
  min(e.ts) AS started, max(CASE WHEN e.type='run.end' THEN e.ts END) AS ended,
  count(*) AS events, sum(e.type='tool.call') AS tool_calls, sum(e.type='model.exchange' AND e.phase='response') AS model_calls,
  sum(e.type='policy.decision' AND json_extract(e.data,'$.decision')='deny') AS denied,
  sum(e.type='policy.decision' AND json_extract(e.data,'$.decision')='flag') AS flagged,
  sum(e.type='tool.result' AND json_extract(e.data,'$.ok')=0) AS failed_tools,
  (SELECT count(*) FROM events f WHERE f.run_id='findings:' || e.run_id) AS findings,
  (SELECT count(*) FROM events g WHERE g.run_id=e.run_id AND g.type IN ('capture.gap','trace.tamper')) AS gaps,
  group_concat(DISTINCT e.source) AS sources
FROM events e WHERE e.run_id NOT LIKE '\\_%' ESCAPE '\\' AND e.run_id NOT LIKE 'findings:%' GROUP BY e.run_id;
"""

DOC = {
    "events": "every ledger record: seq, hash, prev_hash, ts, ts_signed, run_id, agent_id, parent_id, source, type, data (JSON), chain_ok",
    "runs": "one row per run: agent, model, content_capture, started, ended, events, tool_calls, model_calls, denied, flagged, "
            "failed_tools, findings, gaps, sources",
    "tool_calls": "tool call + policy decision + result: run_id, agent_id, seq, tool_use_id, name, command, file_path, url, decision, "
                  "rule_ids, ok, duration_ms, output_redacted, started, finished, source, call_hash, result_hash",
    "model_exchanges": "model responses: run_id, seq, exchange_id, model, upstream, stop_reason, status, duration_ms, first_byte_ms, "
                       "streamed, error, tool_uses (JSON), source, ts, hash",
    "findings": "signed analyzer findings: run_id, seq, rule, severity, title, detail, evidence (JSON), detector, ts, hash",
    "gaps": "capture gaps and trace tampering: seq, run_id, kind, reason, ts",
}


def default_index(home):
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    hid = hashlib.sha256(os.path.abspath(home).encode()).hexdigest()[:16]
    return os.path.join(base, "tracekit", f"index-{hid}.sqlite")


class Index:
    def __init__(self, home, path=None):
        self.home = home
        self.ledger = os.path.join(home, "ledger", "ledger.jsonl")
        self.path = path or default_index(home)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.notes = []

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def _reset(self, db):
        db.executescript("DROP VIEW IF EXISTS runs; DROP VIEW IF EXISTS gaps; DROP VIEW IF EXISTS findings; "
                         "DROP VIEW IF EXISTS model_exchanges; DROP VIEW IF EXISTS tool_calls; DROP TABLE IF EXISTS events; "
                         "DROP TABLE IF EXISTS meta;")
        db.executescript(SCHEMA)
        db.execute("INSERT INTO meta VALUES ('version', ?)", (str(INDEX_VERSION),))

    def refresh(self):
        """Bring the index up to date with the ledger. -> number of records added.

        Only the ledger's new tail is parsed. The bytes already indexed are re-hashed (fast, no parsing) and compared with
        the digest stored at the last refresh; any change before the stored offset means the ledger was rewritten, and the
        index is rebuilt from scratch."""
        from .core import GENESIS
        db = self._connect()
        try:
            have = db.execute("SELECT name FROM sqlite_master WHERE name='meta'").fetchone()
            ver = db.execute("SELECT v FROM meta WHERE k='version'").fetchone() if have else None
            if not ver or ver[0] != str(INDEX_VERSION):
                self._reset(db)
            if not os.path.exists(self.ledger):
                raise FileNotFoundError(f"no ledger at {self.ledger}")
            meta = dict(db.execute("SELECT k, v FROM meta").fetchall())
            offset = int(meta.get("offset", 0))
            size = os.path.getsize(self.ledger)
            with open(self.ledger, "rb") as f:
                if offset:
                    h = hashlib.sha256()
                    left = offset
                    while left > 0:
                        chunk = f.read(min(left, 1 << 20))
                        if not chunk:
                            break
                        h.update(chunk)
                        left -= len(chunk)
                    if size < offset or left or h.hexdigest() != meta.get("prefix_sha256"):
                        self.notes.append("ledger changed before the indexed position (rewritten, truncated or replaced): index rebuilt")
                        self._reset(db)
                        offset = 0
                        f.seek(0)
                        h = hashlib.sha256()
                else:
                    h = hashlib.sha256()
                last = db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
                prev, want = (last[1], last[0] + 1) if last else (GENESIS, 0)
                rows, consumed = [], offset
                for raw in f:
                    if not raw.endswith(b"\n"):
                        break  # a line still being written: pick it up next time
                    consumed += len(raw)
                    h.update(raw)
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except ValueError:
                        self.notes.append(f"unparseable ledger line at byte {consumed - len(raw)}")
                        continue
                    ev = {"seq": r.get("seq"), "prev_hash": r.get("prev_hash", "")} if r.get("elided") else (r.get("event") or {})
                    seq = ev.get("seq")
                    ok = int(ev.get("prev_hash") == prev and seq == want)
                    if not ok:
                        self.notes.append(f"seq {seq}: does not link to the previous record (run `tracekit verify` on an export)")
                    d = ev.get("data") if isinstance(ev.get("data"), dict) else {}
                    rows.append((seq, r.get("hash"), ev.get("prev_hash", ""), ev.get("ts"), ev.get("ts_signed"), ev.get("run_id"),
                                 ev.get("agent_id"), ev.get("parent_id"), ev.get("source"), ev.get("type"),
                                 json.dumps(ev.get("data"), ensure_ascii=False) if "data" in ev else None, ok,
                                 d.get("tool_use_id"), d.get("phase")))
                    prev, want = r.get("hash"), (seq + 1 if isinstance(seq, int) else want + 1)
            with db:
                db.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                db.execute("INSERT OR REPLACE INTO meta VALUES ('offset', ?)", (str(consumed),))
                db.execute("INSERT OR REPLACE INTO meta VALUES ('prefix_sha256', ?)", (h.hexdigest(),))
            return len(rows)
        finally:
            db.close()

    def query(self, sql, params=(), limit=10_000, budget_s=10.0):
        """Run one read-only statement. -> (columns, rows, truncated)."""
        db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=30)
        try:
            db.execute("PRAGMA query_only=1")
            deadline = time.monotonic() + budget_s
            db.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
            try:
                cur = db.execute(sql, params)
            except sqlite3.OperationalError as e:
                if "interrupted" in str(e):
                    raise TimeoutError(f"query exceeded {budget_s:.0f}s") from e
                raise
            cols = [d[0] for d in cur.description or []]
            rows = cur.fetchmany(limit + 1)
            return cols, rows[:limit], len(rows) > limit
        finally:
            db.close()


def render(cols, rows, fmt="table", truncated=False):
    if fmt == "json":
        return json.dumps([dict(zip(cols, r)) for r in rows], indent=2, ensure_ascii=False, default=str)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        w.writerows(rows)
        return buf.getvalue()
    cells = [[("" if v is None else str(v)).replace("\n", " ")[:80] for v in r] for r in rows]
    widths = [max([len(c)] + [len(r[i]) for r in cells]) for i, c in enumerate(cols)]
    line = "  ".join(c.ljust(w) for c, w in zip(cols, widths))
    out = [line, "  ".join("-" * w for w in widths)] + ["  ".join(v.ljust(w) for v, w in zip(r, widths)) for r in cells]
    out.append(f"({len(rows)} row{'s' if len(rows) != 1 else ''}{', truncated' if truncated else ''})")
    return "\n".join(out)


def schema_text():
    return "\n".join(f"{k}: {v}" for k, v in DOC.items())


# ---------------------------------------------------------------- MCP (stdio, JSON-RPC 2.0, newline-delimited)

MCP_TOOLS = [
    {"name": "tracekit_sql", "description": "Run a read-only SQL (SQLite) query over the Tracekit signed ledger of AI agent activity. "
                                            "Tables/views: " + "; ".join(f"{k}({v.split(':', 1)[-1].strip()[:160]})" for k, v in DOC.items()),
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "one SELECT statement"},
                                                      "limit": {"type": "integer", "default": 200}}, "required": ["query"]}},
    {"name": "tracekit_schema", "description": "Describe the tables and views available to tracekit_sql.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def mcp_serve(idx, stdin=None, stdout=None):
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout

    def send(obj):
        stdout.write(json.dumps(obj) + "\n")
        stdout.flush()

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:  # notification (e.g. notifications/initialized)
            continue
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-06-18"),
                                                          "capabilities": {"tools": {}},
                                                          "serverInfo": {"name": "tracekit", "version": "0.2"}}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": MCP_TOOLS}})
        elif method == "tools/call":
            p = msg.get("params") or {}
            name, args = p.get("name"), p.get("arguments") or {}
            try:
                if name == "tracekit_schema":
                    text = schema_text()
                elif name == "tracekit_sql":
                    idx.notes.clear()
                    idx.refresh()
                    cols, rows, trunc = idx.query(str(args.get("query", "")), limit=max(1, min(int(args.get("limit", 200)), 5000)))
                    text = render(cols, rows, "json", trunc) + ("\nnotes: " + "; ".join(idx.notes) if idx.notes else "")
                else:
                    raise ValueError(f"unknown tool {name!r}")
                send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}], "isError": False}})
            except Exception as e:
                send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
        else:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}})


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit sql", description="Read-only SQL over the signed ledger.")
    ap.add_argument("query", nargs="?")
    ap.add_argument("--home", help="signer home (default: from the client config)")
    ap.add_argument("--index", help="index file (default: ~/.cache/tracekit/index-<id>.sqlite)")
    ap.add_argument("--format", choices=("table", "json", "csv"), default="table")
    ap.add_argument("--limit", type=int, default=10_000)
    ap.add_argument("--rebuild", action="store_true", help="drop the index and rebuild it from the ledger")
    ap.add_argument("--schema", action="store_true", help="list tables and views")
    ap.add_argument("--mcp", action="store_true", help="serve tracekit_sql / tracekit_schema over MCP (stdio)")
    a = ap.parse_args(argv)
    from . import client
    home = a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"
    idx = Index(home, a.index)
    if a.schema:
        print(schema_text())
        return 0
    if a.rebuild and os.path.exists(idx.path):
        os.remove(idx.path)
    if a.mcp:
        mcp_serve(idx)
        return 0
    if not a.query:
        ap.error("give a query, --schema or --mcp")
    try:
        idx.refresh()
        cols, rows, trunc = idx.query(a.query, limit=a.limit)
    except (sqlite3.Error, FileNotFoundError, TimeoutError) as e:
        print(f"tracekit sql: {e}", file=sys.stderr)
        return 2
    for n in idx.notes:
        print(f"tracekit sql: note: {n}", file=sys.stderr)
    print(render(cols, rows, a.format, trunc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
