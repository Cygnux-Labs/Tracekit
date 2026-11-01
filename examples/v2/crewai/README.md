# A CrewAI crew on the v2 signer

Runs offline: a scripted `BaseLLM` stands in for the model, so there is no API key and no network. `ls` is allowed,
`sudo rm -rf /` is denied (TK-D001: the model reads why and the run goes on), and `echo "unterminated` waits for an
approval (TK-SHELL-PARSE). Then the run is exported and verified.

How: `hooks(run)` from the integration, registered with CrewAI's `register_before_tool_call_hook` and
`register_after_tool_call_hook`. The before hook decides each call before it runs and the after hook records the
outcome ([the integration page](../../../docs/integrations/crewai.md)).

Path: the scripted model returns `False` from `supports_function_calling()`, so CrewAI doesn't use native tool calls
for it (`Agent._supports_native_tool_calling` is false) and drives it through its text/ReAct path (`Action:` /
`Action Input:`). The before hook fires for all three calls.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install tracekit-ai "crewai>=1.15.27,<1.16"   # from a checkout: pip install .
python examples/v2/crewai/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands. It writes `trust.json` and `<run id>.tkb` to the
current directory and prints the `tracekit verify` report.
