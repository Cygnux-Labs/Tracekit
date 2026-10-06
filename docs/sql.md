# SQL over the ledger

```bash
tracekit sql --schema
tracekit sql "SELECT name, count(*) FROM tool_calls GROUP BY name ORDER BY 2 DESC"
tracekit sql --format json "SELECT * FROM findings WHERE severity IN ('high','critical')"
tracekit sql --format csv "SELECT * FROM runs" > runs.csv
tracekit sql --mcp     # MCP server on stdio for coding agents: tools tracekit_sql, tracekit_schema
```

No dependencies: the index is SQLite from the Python standard library. It lives in `~/.cache/tracekit/` and is a derived
cache, never evidence. Before every query it reads only the ledger's new tail, checking that each record links to the
previous record's hash (`events.chain_ok`). The bytes already indexed are re-hashed and compared with the digest from
the last refresh, so if anything earlier in the ledger changed the index is rebuilt and the command says so.
Signatures are not re-checked here; `tracekit verify` does that.

Queries run on a read-only connection with a time budget (default 10 s).

| View | Columns |
|---|---|
| `runs` | run_id, agent, model, content_capture, started, ended, events, tool_calls, model_calls, denied, flagged, failed_tools, findings, gaps, sources |
| `tool_calls` | run_id, agent_id, seq, tool_use_id, name, command, file_path, url, decision, rule_ids, ok, duration_ms, output_redacted, started, finished, source, call_hash, result_hash |
| `model_exchanges` | run_id, seq, exchange_id, model, upstream, stop_reason, status, duration_ms, first_byte_ms, streamed, error, tool_uses, source, ts, hash |
| `findings` | run_id, seq, rule, severity, title, detail, evidence, detector, ts, hash |
| `gaps` | seq, run_id, kind, reason, ts |
| `events` | every record: seq, hash, prev_hash, ts, ts_signed, run_id, agent_id, parent_id, source, type, data (JSON), chain_ok |

Every row carries the record hash, so any answer can be traced back to signed evidence.

**Scale** (synthetic 300,000-record ledger, 139 MB, one laptop-class core): first index build 10 s; refresh with
nothing new 0.4 s; `GROUP BY` over all 100,000 tool calls 0.3 s; per-run queries under 10 ms; the `runs` rollup 0.7 s.
