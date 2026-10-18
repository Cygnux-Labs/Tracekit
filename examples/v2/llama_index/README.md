# A LlamaIndex AgentWorkflow on the v2 signer

Runs offline: scripted `MockFunctionCallingLLM`s from `llama_index.core` stand in for the models, so there is no API key
and no network. The triage agent hands off to the ops agent (the handoff is decided too), which asks for three
commands: `ls` is allowed, `sudo rm -rf /` is denied (TK-D001: the model reads why and the run goes on), and
`echo "unterminated` waits for an approval (TK-SHELL-PARSE). Then the run is exported and verified.

How: `Tracekit(run).gate(workflow)` on the `AgentWorkflow`. It overrides the workflow's `call_tool` step, which runs
every agent's tools: each call is decided before it runs and its outcome recorded after
([the integration page](../../../docs/integrations/llamaindex.md)).

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install tracekit-ai "llama-index-core>=0.14.25,<0.15"   # from a checkout: pip install .
python examples/v2/llama_index/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands. It writes `trust.json` and `<run id>.tkb` to the
current directory and prints the `tracekit verify` report.
