Two Qwen Code 0.27.4 sessions, recorded on GitHub Actions (ubuntu-latest, Node 22) with a scripted model, for
`tracekit audit`'s Qwen Code reader (#869). They're the files Qwen Code wrote under `~/.qwen/projects/`, trimmed: each
keeps its `user`, `assistant` and `tool_result` records and every `qwen-code.tool_call` telemetry record, plus one
`attribution_snapshot` and one `api_response` record (the rest of the telemetry and the memory catalog are dropped).
Nothing private: the paths are the runner's.

- `992a9d3d-….jsonl`: `write_file`, `read_file`, `edit` and `run_shell_command`; then three calls by Qwen Code's
  background memory extractor (`write_file`, `read_file`, `edit`, which Qwen Code's permission rules denied), held
  only in telemetry records, which reached the PreToolUse hook; then `qwen --continue` and one more
  `run_shell_command`, appended to the same file.
- `39e5e1e8-….jsonl`: a second session in the same project, one `run_shell_command`.
