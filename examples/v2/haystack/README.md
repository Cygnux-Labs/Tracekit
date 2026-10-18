# A Haystack agent on the v2 signer

Runs offline: Haystack's `MockChatGenerator` stands in for the model, so there is no API key and no network (the example
also turns Haystack's usage telemetry off). `ls` is allowed, `sudo rm -rf /` is denied (TK-D001: the model reads why
and the run goes on), and `echo "unterminated` waits for an approval (TK-SHELL-PARSE). Then the run is exported and
verified.

How: `hooks={"before_tool": [tk], "after_tool": [tk]}` on the agent, with `tk = Tracekit(run)`. At `before_tool` it
decides each call before it runs; at `after_tool` it records the outcome
([the integration page](../../../docs/integrations/haystack.md)).

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install tracekit-ai "haystack-ai>=3.4,<3.5"   # from a checkout: pip install .
python examples/v2/haystack/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands. It writes `trust.json` and `<run id>.tkb` to the
current directory and prints the `tracekit verify` report.
