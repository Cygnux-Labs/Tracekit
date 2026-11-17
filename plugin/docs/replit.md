# Tracekit in Replit

Replit Agent has no hooks Tracekit can attach to, so Tracekit can't check or record its tool calls there.

What does work is reading Tracekit's records. In the Agent's Skills tab, import from GitHub,
`https://github.com/Cygnux-Labs/tracekit-plugin`, and pick **tracekit-explain** (and **tracekit-graph** if
you use `tracekit graph`). Bring a bundle and its trust file from a machine where Tracekit runs, then ask the agent
"Is this record intact?" or "What happened in this run?". It answers with read-only commands such as:

```bash
tracekit verify run.tkb --trust run.trust.json
```

Skip tracekit-setup and tracekit-connect in Replit: with no hooks there is nothing to set up.
