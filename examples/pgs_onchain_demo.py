#!/usr/bin/env python3
"""A wallet agent on a local chain, guarded by Proof-Gated Signing, with every guard verdict signed into Tracekit.

Needs the PGS repository and a local Hardhat chain (no real funds; chain id 31337):

    git clone <pgs repo> ../pgs && cd ../pgs && npm i && pip install z3-solver web3 && node compile.js && ./node.sh 8545
    python3 examples/pgs_onchain_demo.py --pgs ../pgs

Four transactions the agent proposes: two honest (pay Alice, swap USDC for WETH), two malicious (approve a drainer and
claim, a direct transfer to the attacker), and one swap whose pool is upgraded by the attacker between the guard's check
and execution (state drift). The script checks on-chain that the blocked transactions were never signed: the agent
account's nonce does not move and the attacker gains nothing. Then it exports the run and verifies it."""
import argparse
import os
import random
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pgs", default=os.path.join(HERE, "..", "..", "pgs"), help="path to the PGS repository")
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "pgs-run.tkb"))
    a = ap.parse_args(argv)
    sys.path.insert(0, os.path.abspath(a.pgs))
    from pgs import scenarios
    from pgs.defenses import make_policy
    from pgs.guard import Guard
    from pgs.world import E18, World, w3_connect

    from tracekit import bundle
    from tracekit.adapters.onchain import guarded_tx
    from tracekit.agent_sdk import Tracer

    w3 = w3_connect(a.rpc)
    w = World(w3).build()
    guard = Guard(w, make_policy(w), mode="sim+assert")
    rnd = random.Random(7)
    attacker_value = lambda: sum(w.balance(k, w.attacker) for k in ("USDC", "WETH", "DAI"))  # noqa: E731
    a0 = attacker_value()

    def send(calls, post, before=None):
        if before:
            before()  # the attacker moves between the guard's check and inclusion
        return w.exec_checked(calls, *post) if post else w.exec_raw(calls)

    outcomes = []
    with Tracer(agent="wallet-agent", cwd=os.getcwd()) as t:
        for fam in ("B4_pay_alice", "B1_swap_usdc_weth", "H3_approve_claim_drainer", "H1_direct_transfer", "H7_proxy_upgrade_toctou"):
            sc = scenarios.build(w, fam, rnd)
            t.prompt(sc["task"])
            for i, calls in enumerate(sc["txs"]):
                nonce = w3.eth.get_transaction_count(w.agent)
                hook = sc["hooks"]["before"].get(i)
                try:
                    r = guarded_tx(t, guard, calls, chain_id=w3.eth.chain_id,
                                   send=lambda c, post: send(c, post, hook))
                    outcome = f"signed and executed (tx {r.transactionHash.hex()[:18]}…, gas {r.gasUsed})"
                except PermissionError as e:
                    signed = w3.eth.get_transaction_count(w.agent) != nonce
                    outcome = "BLOCKED by the guard, never signed" + (" (NONCE MOVED!)" if signed else "") + f": {str(e)[:90]}"
                    if signed:
                        raise SystemExit("a blocked transaction was signed")
                except Exception as e:  # status 0, or the node rejecting a reverted tx (Hardhat automine)
                    if "revert" not in str(e).lower():
                        raise
                    reason = "guard:" + str(e).split("guard:", 1)[1].split("'", 1)[0] if "guard:" in str(e) else str(e)[:70]
                    outcome = f"signed, REVERTED on-chain by the post-conditions ({reason}): the drift could not take funds"
                outcomes.append((fam, i, outcome))
                print(f"{fam:<28} tx{i}: {outcome}")
                break  # one transaction per scenario keeps the demo short
        t.done("wallet session finished")
    gain = (attacker_value() - a0) / E18
    print(f"\nattacker gain over the session: {gain:.2f} tokens")
    run = t.session_id
    home = _signer_home()
    import subprocess
    subprocess.run([sys.executable, "-m", "tracekit", "analyze", "--home", home, "--run", run], check=True)  # signs TK-X00x findings
    bundle.export(home, a.out, run=run)
    rep, code = bundle.verify(a.out)
    print(f"bundle {a.out}: tracekit verify exit {code}")
    return 0 if code == 0 and gain <= 0 else 1


def _signer_home():
    from tracekit import client
    return client.client_config().get("signer_home")


if __name__ == "__main__":
    sys.exit(main())
