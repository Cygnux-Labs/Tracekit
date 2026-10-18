# A Google ADK agent on the v2 signer

Runs offline: a scripted `BaseLlm` stands in for the model, so there is no API key and no network. `ls` is allowed,
`sudo rm -rf /` is denied (TK-D001: the model reads why and the run goes on), and `echo "unterminated` waits for an
approval (TK-SHELL-PARSE). Then the run is exported and verified.

How: `plugins=[Tracekit(run)]` on the ADK `App`. Its `before_tool_callback` decides each call before it runs and its
`after_tool_callback` records the outcome ([the integration page](../../../docs/integrations/google-adk.md)).

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install tracekit-ai "google-adk>=2.12,<2.13"   # from a checkout: pip install .
python examples/v2/google_adk/agent.py --scripted
```

`--scripted` approves the held call from a second process (`tracekit approvals approve`). Without it, approve it
yourself from another terminal; the example prints the commands. It writes `trust.json` and `<run id>.tkb` to the
current directory and prints the `tracekit verify` report.
