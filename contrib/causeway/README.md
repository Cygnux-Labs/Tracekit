# tracekit-causeway

[Causeway](https://github.com/Cygnux-Labs/Causeway) records causal logs of multi-agent runs and tests which input made
an action happen by replaying without it. Its events are hash-chained but not signed. Tracekit closes that (`pip install ./contrib/causeway`):

```bash
tracekit-causeway anchor runs/demo-seed0          # check the chain, sign + checkpoint its head, blob set and test results
tracekit-causeway verify runs/demo-seed0          # OK only if nothing changed since the latest anchor
tracekit-causeway import-tests runs/demo-seed0    # counterfactual verdicts -> signed findings citing the anchor
tracekit export --run anchors:causeway:demo-seed0 -o cw.tkb && tracekit verify cw.tkb
tracekit-causeway export --run R -o runs/         # a Tracekit run in Causeway's format, for its lineage and graph views
```

- **Anchors** are signed `review` records in `anchors:causeway:<run>`. Editing any event (even with the chain rebuilt),
  removing events, or changing blobs or test results after anchoring makes `verify` fail; events appended later are
  reported as an unanchored tail. A run whose chain is already broken is refused, not anchored.
- **Imported verdicts** become findings TK-C001 (confirmed cause), TK-C002 (suppressive), TK-C003 (ruled out) and
  TK-C004 (intervention never applied), with the effect, confidence interval, sample size and method. Importing requires
  a current anchor, so every imported result is covered by a signed record.
- **Export** writes a valid Causeway run (`causeway verify` accepts it) and `tracekit-map.json`, mapping each Causeway
  event to the signed Tracekit record it came from. Tracekit does not record exactly what each model call saw, so
  decision context is reconstructed (every earlier input and tool result of the same agent) and the run's metadata says
  so. Counterfactual replay needs a Causeway program and is not available for exported runs.

On a multi-agent run (`examples/custom_agent.py`: a coordinator and two parallel workers) the export passes Causeway's
verifier, and `causeway graph` / `causeway view` draw the causal graph for any action; the graph view lives in
Causeway, not in Tracekit's observer. `contrib/causeway/tests/test_causeway.py` also runs Causeway's own three-agent demo end to end:
anchor, import the counterfactual verdicts as signed findings, verify.
