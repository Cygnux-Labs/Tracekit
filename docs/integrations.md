# Integrations

## Causeway

[Causeway](https://github.com/Cygnux-Labs/Causeway) records causal logs of multi-agent runs and tests which input made
an action happen by replaying without it. Its events are hash-chained but not signed. Tracekit closes that:

```bash
tracekit causeway anchor runs/demo-seed0          # check the chain, sign + checkpoint its head, blob set and test results
tracekit causeway verify runs/demo-seed0          # OK only if nothing changed since the latest anchor
tracekit causeway import-tests runs/demo-seed0    # counterfactual verdicts -> signed findings citing the anchor
tracekit export --run anchors:causeway:demo-seed0 -o cw.tkb && tracekit verify cw.tkb
tracekit causeway export --run R -o runs/         # a Tracekit run in Causeway's format, for its lineage and graph views
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
Causeway, not in Tracekit's observer. `tests/test_causeway.py` also runs Causeway's own three-agent demo end to end:
anchor, import the counterfactual verdicts as signed findings, verify.

## Onchain agents: transaction guards

```python
from tracekit.adapters.onchain import guarded_tx
receipt = guarded_tx(tracer, guard, calls, send=lambda calls, post: wallet.execute_checked(calls, post), chain_id=1)
```

`guard` is anything with `check(calls) -> {"allow", "reasons", "post"}`, the interface of Proof-Gated Signing's
`pgs.guard.Guard`. The order is fixed: the call is recorded and passes Tracekit's own policy, the guard runs and its
verdict is signed (allow or deny, reasons, a hash of the compiled post-conditions, latency), and only then is `send`
called. A denied transaction never reaches `send`; a guard that raises counts as a deny. The transaction hash and
status are recorded afterwards, and an on-chain revert (for example a post-condition failing after state drift) raises.

`tracekit analyze` adds TK-X006 (transaction signed without a guard verdict), TK-X007 (executed although the guard
denied it) and TK-X008 (blocked by the guard). The adapter is tested with a stand-in guard implementing the same
interface in the default test suite.

**End to end with PGS on a local chain** (`examples/pgs_onchain_demo.py`; needs the PGS repository, `web3`, `z3-solver`
and a Hardhat node, see the script's header). Run on a local Hardhat chain (id 31337, October 2026, PGS's own world and
scenarios):

```
B4_pay_alice                 tx0: signed and executed (tx 3c0d167f4a8c67fe2c…, gas 106694)
B1_swap_usdc_weth            tx0: signed and executed (tx bb923bd31cccdde36c…, gas 130959)
H3_approve_claim_drainer     tx0: BLOCKED by the guard, never signed: tx-guard blocked the transaction: eoa-recipient-not-allowlisted:…
H1_direct_transfer           tx0: BLOCKED by the guard, never signed: tx-guard blocked the transaction: eoa-recipient-not-allowlisted:…
H7_proxy_upgrade_toctou      tx0: signed, REVERTED on-chain by the post-conditions (guard:balance): the drift could not take funds

attacker gain over the session: 0.00 tokens
```

"Never signed" is checked on-chain, not taken from the log: the agent account's nonce does not move for a blocked
transaction. The ledger holds each guard verdict before the matching send, `tracekit analyze` signs a TK-X008 finding
per blocked transaction, and the exported bundle verifies. With `TRACEKIT_PGS=<repo>` and the node running,
`tests/test_examples.py` runs this too. It is a local chain, not a public testnet: the guard and wallet contract are
the same, but there is no real mempool or other traffic.

## MCP clients

`tracekit.adapters.mcp.traced_session(session, tracer, server="github")` wraps an MCP `ClientSession`: each
`call_tool` passes the policy gate as `mcp__<server>__<tool>` before it is sent, and its result is recorded. MCP tool
errors stay results for the caller (as the protocol intends) and are recorded as failed calls.

## Vercel AI SDK

With `experimental_telemetry` enabled, the AI SDK's spans go to `tracekit otel serve --experimental` unchanged: provider calls
(`ai.*.doGenerate`, `ai.*.doStream`) become model exchanges with the tool calls they requested and token usage, and
`ai.toolCall` spans become tool calls with their arguments and results.
