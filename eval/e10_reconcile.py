"""E10: the v2 signer's reconciliation of tool calls across capture layers (tracekit/signer/reconcile.py).

Scripted runs against an in-process signer, for each layer combination (L2 only, L2+L3, L1+L2+L3): clean runs,
including the hard clean cases (coerced arguments that differ from the model's, a provider-executed tool, an L3 record
that arrives late inside the grace window), and runs with one seeded discrepancy of each kind. Without L3 the L3 steps
are left out and no run may be flagged. Exit 0 only when every seeded discrepancy is flagged with its kind, no clean run
gets a reconcile record, and run.final names the layers that reported.

    python3 eval/e10_reconcile.py           # writes eval/results/e10_reconcile.json"""
import itertools
import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit.format.canon import event_hash  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.signer.service import SignerService  # noqa: E402

GRACE_S = 60
COMBINATIONS = (("L2",), ("L2", "L3"), ("L1", "L2", "L3"))
REQUEST_IDS = itertools.count()


def use(tcid, tool="read_file", args=None, **kw):
    return {"id": tcid, "name": tool, "executed_by": "client", "args_source": "parsed",
            "args_digest": event_hash({"tool": tool, "args": {"path": "a"} if args is None else args}), **kw}


class Run:
    def __init__(self, s, layers):
        self.s, self.layers, self.seq = s, layers, 0
        out = s.register_run({"request_id": self.rid(), "agent": {"name": "e10"}})
        self.run = {"run_id": out["run_id"], "run_token": out["run_token"]}

    @staticmethod
    def rid():
        return f"e10-{next(REQUEST_IDS)}"

    def ev(self, **kw):
        self.seq += 1
        return {"request_id": self.rid(), **self.run, "stream": "s", "client_seq": self.seq - 1, **kw}

    def model(self, uses=(), sent=()):
        """An L3 model response asking for `uses`, its request having sent back the results of `sent`."""
        if "L3" in self.layers:
            self.s.model_event(self.ev(provider="p", model="m", phase="response", tool_uses=list(uses),
                                       tool_results_sent=list(sent)))

    def call(self, tcid, tool="read_file", args=None, source="parsed"):
        """An L2 decide and complete, and with L1 the state write the call made."""
        args = {"path": "a"} if args is None else args
        d = self.s.decide(self.ev(tool_call_id=tcid, tool=tool, args_source=source, args=args))
        self.s.complete(self.ev(tool_call_id=tcid, decision_id=d["decision_id"], status="ok", result={"ok": 1},
                                args_digest=event_hash({"tool": tool, "args": args})))
        if "L1" in self.layers:
            self.s.state_write(self.ev(key="session", value_digest=event_hash({"after": tcid})))

    def close(self):
        self.s.close_run({"request_id": self.rid(), **self.run})


def late(r):
    r.call("tc-1")
    r.close()
    r.s.sweep(time.monotonic() + GRACE_S / 2)
    r.model([use("tc-1")])


# name -> (the reconcile kinds expected with L3, the run's steps); a run is closed after its steps unless it closed
SCENARIOS = {
    "clean": ([], lambda r: (r.model([use("tc-1"), use("tc-2", "list_dir")]), r.call("tc-1"), r.call("tc-2", "list_dir"))),
    "clean: coerced args": ([], lambda r: (r.model([use("tc-1", args={"n": "1"})]),
                                           r.call("tc-1", args={"n": 1}, source="coerced"))),
    "clean: provider-executed tool": ([], lambda r: (r.model([{"id": "ws-1", "name": "web_search",
                                                               "executed_by": "provider"}, use("tc-1")]),
                                                     r.call("tc-1"))),
    "clean: late L3 inside grace": ([], late),
    "hook_missing": (["hook_missing"], lambda r: (r.model([use("tc-1"), use("tc-2")]), r.call("tc-1"))),
    "fabricated": (["fabricated"], lambda r: (r.model([use("tc-1")]), r.call("tc-1"), r.call("tc-2"))),
    "args_mismatch: tool": (["args_mismatch"], lambda r: (r.model([use("tc-1")]), r.call("tc-1", "write_file"))),
    "args_mismatch: args": (["args_mismatch"], lambda r: (r.model([use("tc-1")]), r.call("tc-1", args={"path": "b"}))),
    "args_unparseable": (["args_unparseable"], lambda r: (
        r.model([{"id": "tc-1", "name": "read_file", "executed_by": "client", "args_source": "raw",
                  "args_unparseable": True}]), r.call("tc-1"))),
    "result_without_call": (["result_without_call"], lambda r: (r.model([use("tc-1")]), r.call("tc-1"),
                                                                r.model(sent=["tc-1", "tc-9"]))),
}


def run():
    d = tempfile.mkdtemp()
    s = SignerService(d, policy=Engine({}), grace_s=GRACE_S, idle_s=3600)
    rows = []
    try:
        started = []
        for layers in COMBINATIONS:
            for name, (kinds, steps) in SCENARIOS.items():
                r = Run(s, layers)
                steps(r)
                if not s.log.runs[(s.tenant, r.run["run_id"])]["closed"]:
                    r.close()
                started.append((layers, name, kinds if "L3" in layers else [], r))
        s.sweep(time.monotonic() + GRACE_S + 1)
        for layers, name, kinds, r in started:
            events = s.read({**r.run, "limit": 1000})["events"]
            got = sorted(e["type"][len("reconcile."):] for e in events if e["type"].startswith("reconcile."))
            reported = events[-1]["data"]["coverage"]["layers"] if events[-1]["type"] == "run.final" else None
            rows.append({"layers": "+".join(layers), "scenario": name, "expected": sorted(kinds), "flagged": got,
                         "layers_reported": reported,
                         "ok": got == sorted(kinds) and reported == list(layers)})
    finally:
        s.close()
        shutil.rmtree(d, True)
    seeded = [x for x in rows if x["expected"]]
    return {"runs": len(rows), "seeded": len(seeded), "seeded_flagged": sum(x["ok"] for x in seeded),
            "false_positives": sum(bool(x["flagged"]) for x in rows if not x["expected"]),
            "ok": all(x["ok"] for x in rows), "rows": rows}


if __name__ == "__main__":
    out = run()
    for x in out["rows"]:
        print(f"{'ok ' if x['ok'] else 'BAD'} {x['layers']:<9} {x['scenario']:<32} expected {x['expected']} "
              f"flagged {x['flagged']}")
    print(f"E10: {out['seeded_flagged']}/{out['seeded']} seeded discrepancies flagged, "
          f"{out['false_positives']} false positive(s) over {out['runs']} runs")
    os.makedirs(os.path.join(ROOT, "eval", "results"), exist_ok=True)
    with open(os.path.join(ROOT, "eval", "results", "e10_reconcile.json"), "w") as f:
        json.dump(out, f, indent=2)
    sys.exit(0 if out["ok"] else 1)
