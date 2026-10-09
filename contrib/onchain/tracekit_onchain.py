"""Guarded onchain transactions: a transaction guard's verdict is signed into the ledger before the wallet signs anything.

    from tracekit_onchain import guarded_tx
    receipt = guarded_tx(tracer, guard, calls, send=lambda calls, post: wallet.execute_checked(calls, post), chain_id=1)

``guard`` is anything with ``check(calls) -> {"allow": bool, "reasons": [...], "post": <post-conditions or None>, ...}``,
the interface of Proof-Gated Signing's ``pgs.guard.Guard`` (simulate, extract effects, prove the policy with Z3, compile
post-conditions enforced on-chain). The order is fixed:

1. ``tool.call`` OnchainTx (calls summarised: target, value, selector, calldata hash) and Tracekit's own policy gate;
2. the guard runs; its verdict is recorded as a signed ``review`` (reviewer ``tx-guard``): allow/deny, reasons, a hash of
   the compiled post-conditions, latency;
3. denied: ``send`` is never called, the call is recorded as failed with the guard's reasons, ``PermissionError`` raised;
4. allowed: ``send(calls, post)`` signs and submits; the tx hash and status are recorded.

So a blocked transaction is never signed through this path, and every signed one has a guard verdict before it in the
ledger. ``analyze(records, run_id)`` flags any OnchainTx without one (TK-X006), executed despite a deny (TK-X007) or
blocked by the guard (TK-X008)."""
import hashlib
import json
import time

from tracekit import findings

TOOL = "OnchainTx"


def _bytes(data):
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    s = str(data or "")
    s = s[2:] if s.startswith("0x") else s
    try:
        return bytes.fromhex(s)
    except ValueError:
        return s.encode()


def _summary(calls, chain_id):
    out = []
    for c in calls or []:
        if isinstance(c, dict):
            to, value, data = c.get("to", c.get("target")), c.get("value", 0), c.get("data")  # PGS calls use "target"
        else:  # (to, value, data) tuples, as PGS uses
            to, value, data = (list(c) + [None, 0, b""])[:3]
        raw = _bytes(data)
        out.append({"to": str(to), "value": str(value), "selector": "0x" + raw[:4].hex() if raw else None,
                    "calldata_sha256": hashlib.sha256(raw).hexdigest(), "calldata_bytes": len(raw)})
    return {"chain_id": chain_id, "calls": out}


def _digest(obj):
    return "sha256:" + hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def guarded_tx(tracer, guard, calls, send, chain_id=None, guard_name="tx-guard"):
    summary = _summary(calls, chain_id)
    with tracer.tool(TOOL, {"command": json.dumps(summary, sort_keys=True), **summary}) as call:  # Tracekit's policy first
        t0 = time.monotonic()
        try:
            dec = guard.check(calls)
        except Exception as e:  # a guard that cannot decide must not let the transaction through
            dec = {"allow": False, "reasons": [f"guard error: {e!r}"[:300]], "post": None}
        allow = bool(dec.get("allow"))
        verdict = {"kind": "tx_guard", "allow": allow, "reasons": [str(r)[:300] for r in dec.get("reasons") or []][:50],
                   "postconditions_sha256": _digest(dec.get("post")) if dec.get("post") is not None else None,
                   "guard": guard_name, "latency_ms": int((time.monotonic() - t0) * 1000), "tool_use_id": call.tool_use_id,
                   "tx": summary}
        tracer._send(tracer._event("review", {"reviewer": guard_name, "verdict": verdict}))
        if not allow:
            call.result({"blocked_by": guard_name, "reasons": verdict["reasons"], "signed": False})
            raise PermissionError(f"{guard_name} blocked the transaction: " + "; ".join(verdict["reasons"][:5]))
        receipt = send(calls, dec.get("post"))
        get = (lambda k: receipt.get(k)) if isinstance(receipt, dict) else (lambda k: getattr(receipt, k, None))
        tx_hash, status = get("transactionHash"), get("status")
        if tx_hash is None and isinstance(receipt, (str, bytes)):
            tx_hash = receipt
        if isinstance(tx_hash, (bytes, bytearray)):
            tx_hash = "0x" + bytes(tx_hash).hex()
        elif tx_hash is not None and not isinstance(tx_hash, str) and hasattr(tx_hash, "hex"):
            tx_hash = tx_hash.hex()
        call.result({"signed": True, "tx_hash": str(tx_hash) if tx_hash is not None else None, "status": status,
                     "postconditions_sha256": verdict["postconditions_sha256"]})
        if status == 0:
            raise RuntimeError(f"transaction {tx_hash} reverted on-chain (post-conditions or execution failed)")
        return receipt


def analyze(records, run_id):
    """TK-X006..X008 for run_id over ledger records, as finding verdicts in tracekit.findings' format."""
    recs = sorted(((r["event"], r["hash"]) for r in records if r and not r.get("elided") and r["event"]["run_id"] == run_id),
                  key=lambda x: x[0]["seq"])
    ctx = findings._Ctx(run_id, recs)
    calls = {e["data"]["tool_use_id"]: (e, h) for e, h in recs if e["type"] == "tool.call"}
    results = {e["data"]["tool_use_id"]: (e, h) for e, h in recs if e["type"] == "tool.result"}
    guard = {}
    for e, h in recs:
        v = (e["data"].get("verdict") or {}) if e["type"] == "review" else {}
        if v.get("kind") == "tx_guard" and v.get("tool_use_id"):
            guard[v["tool_use_id"]] = (e, h, v)
    for tid, (c, ch) in calls.items():
        if c["data"]["name"] != TOOL:
            continue
        res = results.get(tid)
        signed = bool(res and res[0]["data"].get("ok"))
        g = guard.get(tid)
        if g is None and signed:
            ctx.add("TK-X006", "critical", "transaction signed without a guard verdict",
                    "An OnchainTx was executed and no tx-guard verdict was recorded before it.", [(c, ch), res], tool_use_id=tid)
        elif g is not None and not g[2]["allow"] and signed:
            ctx.add("TK-X007", "critical", "transaction executed although the guard denied it",
                    "; ".join(g[2].get("reasons") or [])[:300], [(c, ch), (g[0], g[1]), res], tool_use_id=tid)
        elif g is not None and not g[2]["allow"]:
            ctx.add("TK-X008", "medium", "transaction blocked by the guard",
                    "; ".join(g[2].get("reasons") or [])[:300], [(c, ch), (g[0], g[1])], tool_use_id=tid)
    return ctx.out
