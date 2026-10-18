# A Strands agent on the v2 signer

Runs offline: a scripted `Model` stands in for the model, so there is no API key and no network. `ls` is allowed,
`sudo rm -rf /` is denied (TK-D001: the model reads why as an error tool result and the run goes on), and
`echo "unterminated` waits for an approval (TK-SHELL-PARSE). Then the run is exported and verified.

How: `hooks=[Tracekit(run)]` on the agent. Its `BeforeToolCallEvent` callbacks decide each call before it runs and its
`AfterToolCallEvent` callback records the outcome after ([the integration page](../../../docs/integrations/strands.md)).

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install tracekit-ai "strands-agents>=1.61,<1.62"   # from a checkout: pip install .
python examples/v2/strands/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands. It writes `trust.json` and `<run id>.tkb` to the
current directory and prints the `tracekit verify` report.
