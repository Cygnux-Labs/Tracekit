# A Microsoft Agent Framework agent on the v2 signer

Runs offline: a scripted chat client stands in for the model, so there is no API key and no network. `ls` is allowed,
`sudo rm -rf /` is denied (TK-D001: the model reads why and the run goes on), and `echo "unterminated` waits for an
approval (TK-SHELL-PARSE). Then the run is exported and verified.

How: `middleware=[Tracekit(run)]` on the agent. Its `process` decides each function call before it runs and records
the outcome after ([the integration page](../../../docs/integrations/microsoft-agent-framework.md)).

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install tracekit-ai "agent-framework-core>=1.22,<1.23"   # from a checkout: pip install .
python examples/v2/agent_framework/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands. It writes `trust.json` and `<run id>.tkb` to the
current directory and prints the `tracekit verify` report.
