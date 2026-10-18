# A Pydantic AI agent on the v2 signer

Runs offline: a `FunctionModel` stands in for the model, so there is no API key and no network. `ls` is allowed,
`sudo rm -rf /` is denied (TK-D001: the model reads why and the run goes on), and `echo "unterminated` waits for an
approval (TK-SHELL-PARSE). Then the run is exported and verified.

How: `capabilities=[Tracekit(run)]` on the agent. Its `wrap_tool_execute` hook decides each call before it runs and
records the outcome after ([the integration page](../../../docs/integrations/pydantic-ai.md)).

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install tracekit-ai "pydantic-ai-slim>=2.57,<2.58"   # from a checkout: pip install .
python examples/v2/pydantic_ai/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands. It writes `trust.json` and `<run id>.tkb` to the
current directory and prints the `tracekit verify` report.
