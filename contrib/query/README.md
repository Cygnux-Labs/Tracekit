# SQL over the ledger

```bash
tracekit-sql --schema
tracekit-sql "SELECT name, count(*) FROM tool_calls GROUP BY name ORDER BY 2 DESC"
tracekit-sql --format json "SELECT * FROM findings WHERE severity IN ('high','critical')"
tracekit-sql --format csv "SELECT * FROM runs" > runs.csv
tracekit-sql --mcp     # MCP server on stdio for coding agents: tools tracekit_sql, tracekit_schema
```

No dependencies: the index is SQLite from the Python standard library. It lives in `~/.cache/tracekit/` and is a derived
cache, never evidence. Before every query it reads only the ledger's new tail, checking that each record links to the
previous record's hash (`events.chain_ok`). The bytes already indexed are re-hashed and compared with the digest from
the last refresh, so if anything earlier in the ledger changed the index is rebuilt and the command says so.
Signatures are not re-checked here; `tracekit verify` does that.

Queries run on a read-only connection with a time budget (default 10 s).

| View | Columns |
|---|---|
| `runs` | run_id, agent, model, content_capture, started, ended, events, tool_calls, model_calls, tokens_in, tokens_out, denied, flagged, failed_tools, findings, gaps, sources |
| `tool_calls` | run_id, agent_id, seq, tool_use_id, name, command, file_path, url, decision, rule_ids, ok, duration_ms, output_redacted, started, finished, source, call_hash, result_hash |
| `model_exchanges` | run_id, seq, exchange_id, model, upstream, stop_reason, status, duration_ms, first_byte_ms, streamed, error, tool_uses, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, reasoning_tokens, source, ts, hash |
| `findings` | run_id, seq, rule, severity, title, detail, evidence, detector, ts, hash |
| `gaps` | seq, run_id, kind, reason, ts |
| `events` | every record: seq, hash, prev_hash, ts, ts_signed, run_id, agent_id, parent_id, source, type, data (JSON), chain_ok |

Every row carries the record hash, so any answer can be traced back to signed evidence.

## Tokens and cost

```bash
tracekit cost                                   # tokens per run
tracekit cost --by model --prices prices.json   # adds cost
```

`input_tokens` excludes cache reads, so input, cache read and cache write add up without double counting;
`reasoning_tokens` is part of `output_tokens`. Prices change, so Tracekit ships none: `prices.json` is yours
(`{"per": 1000000, "models": {"gpt-4o*": {"input": 2.5, "output": 10, "cache_read": 1.25}}}`; exact names first, then the
longest matching glob). A model without a price shows `-`, never a guess.

**Scale** (E7, `eval/e7_sql_scale.py`: synthetic 1,000,001-event ledger, 604 MB, 2 vCPUs): index build 36.2 s; refresh with nothing new 0.55 s; every typical query (rollups over all runs, tool calls grouped by name with their decisions, tokens by model, per-run lookups) under 1 s, per-run lookups about 1 ms. See [evaluation](evaluation.md#e7-sql-index-at-a-million-events).