#!/usr/bin/env python3
"""E17 part 1: does signer-side detection (tracekit/signer/detect.py) see what it should, and only that?  Offline: an
in-process signer per scenario, nothing executed. Scenarios: a sequence split across two runs (caught at session scope
only when the second names the first as parent_run); a tool alias the policy does not map (unknown: matches every
step); parallel runs; a GET with a query string as egress (the shipped pack); a denied step that doesn't count; a
restart mid-sequence (from the snapshot, and replayed from the log); a snapshot then a crash; storage recovery
(`_recover`); a deployment that adds a sequence keeps the pack's; and the detector's state staying the same size however
many calls a run makes. Writes eval/results/e17_detection.json; exit 0 only when every scenario holds."""
import json
import os
import shutil
import sys
import tempfile
import threading
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit.identity.base import CallerIdentity  # noqa: E402
from tracekit.policy2 import compile as pc  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.quotas import Limits  # noqa: E402
from tracekit.storage.file import FileStorage  # noqa: E402

ME = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)
PACKS = os.path.join(ROOT, "tracekit", "policy2", "packs")
POLICY = {
    "unknown_tools": "flag",
    "tools": {"read_file": "fs", "http_get": "http", "shell": "shell"},
    "deny": [{"id": "T-DENY", "class": "fs", "field": "path", "pattern": "forbidden"}],
    "flag": [{"id": "T-SECRET", "class": "fs", "field": "path", "pattern": "\\.env", "label": "secret"},
             {"id": "T-EGRESS", "field": "target", "pattern": "://", "label": "egress"},
             {"id": "T-DEL", "class": "shell", "pattern": "^rm ", "label": "destructive"}],
    "sequences": [{"id": "Q", "steps": ["secret", "egress"], "scope": "session", "window": 600}],
    "limits": [{"id": "L", "match": "destructive", "count": True, "max": 3, "window": 60}],
    "respond": [{"trigger": "denied_calls", "mode": "shadow", "action": "notify", "max": 2, "window": 60}],
}
SECRET = ("read_file", {"path": "/srv/app/.env"})
EGRESS = ("http_get", {"url": "https://example.org/x"})


def engine(pol=None, path=None):
    """An Engine of the policy dict `pol` (compiled from a JSON file, as a signer would) or the file `path`."""
    if path is None:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(pol or POLICY, f)
    out, errors = pc.build(path)
    if errors:
        raise ValueError(errors)
    return Engine(out)


class Signer:
    """An in-process signer over its own data dir, reopened at will."""

    def __init__(self, eng=None):
        self.dir, self.eng, self.n, self.seqs = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None), \
            eng or engine(), 0, {}
        self.open()

    def open(self):
        self.s = svc.SignerService(self.dir, policy=self.eng, grace_s=60, idle_s=60,
                                   limits=Limits(events_per_s=1e6, burst=10 ** 6))

    def call(self, method, req):
        self.n += 1
        return self.s.call(ME, method, {"request_id": f"req-{self.n}", **req})

    def register(self, parent=None):
        out = self.call("register_run", {"agent": {"name": "a"}, **({"parent": parent} if parent else {})})
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def decide(self, run, call, tcid=None, hint=None):
        seq = self.seqs[run["run_id"]] = self.seqs.get(run["run_id"], -1) + 1
        tool, args = call
        req = {**run, "stream": "s", "client_seq": seq, "tool_call_id": tcid or f"tc-{seq}", "tool": tool,
               "args_source": "parsed", "args": args, **({"tool_class_hint": hint} if hint else {})}
        return self.call("decide", req)

    def events(self, run=None):
        with open(os.path.join(self.dir, "store", "records.jsonl"), "rb") as f:
            es = [json.loads(line)["event"] for line in f.read().splitlines()]
        return [e for e in es if run is None or e["run_id"] == run["run_id"]]

    def incidents(self, run=None, typ="incident.opened"):
        return [e["data"] for e in self.events(run) if e["type"] == typ]

    def crash(self):
        """Close without the snapshot a clean close writes."""
        with mock.patch.object(FileStorage, "snapshot_put"):
            self.s.close()

    def close(self):
        self.s.close()
        shutil.rmtree(self.dir, True)


def session_scope():
    s = Signer()
    a, b = s.register(), s.register()   # same owner, no parent_run: two sessions
    s.decide(a, SECRET)
    s.decide(b, EGRESS)
    apart = s.incidents()
    c = s.register()
    child = s.register(parent=c)
    s.decide(c, SECRET)
    s.decide(child, EGRESS)
    joined = s.incidents(child)
    s.close()
    ok = apart == [] and [(i["trigger"], i["rule_ids"], i["scope"]["kind"], i["scope"]["id"]) for i in joined] == [
        ("sequence", ["Q"], "session", c["run_id"])]
    return ok, {"without_parent_run": len(apart), "with_parent_run": len(joined)}


def alias_unknown():
    s = Signer()
    run = s.register()
    s.decide(run, ("read_secret_v2", {"p": "anything"}))   # an alias the policy does not map: unknown, every step
    s.decide(run, EGRESS)
    got = s.incidents(run)
    s.close()
    return [i["rule_ids"] for i in got] == [["Q"]], {"incidents": len(got)}


def parallel():
    s = Signer()
    runs = [s.register() for _ in range(8)]

    def work(run):
        s.decide(run, SECRET)
        s.decide(run, EGRESS)
    threads = [threading.Thread(target=work, args=(r,)) for r in runs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    per_run = [len(s.incidents(r)) for r in runs]
    s.close()
    return per_run == [1] * len(runs), {"incidents_per_run": per_run}


def get_query_egress():
    s = Signer(engine(path=os.path.join(PACKS, "server.yaml")))
    run = s.register()
    s.decide(run, ("Read", {"file_path": "/srv/app/.env"}))
    s.decide(run, ("WebFetch", {"url": "https://example.org/collect?k=v", "prompt": "summarise"}))
    got = s.incidents(run)
    s.close()
    return [i["rule_ids"] for i in got] == [["TK-Q001"]], {"incidents": [i["rule_ids"] for i in got]}


def denied_step():
    s = Signer()
    run = s.register()
    d = s.decide(run, ("read_file", {"path": "/srv/forbidden/.env"}))   # T-DENY and T-SECRET: denied, no step
    s.decide(run, EGRESS)
    no_sequence = s.incidents(run) == [] and d["decision"] == "deny"
    for i in range(3):   # max 2: the third distinct denied call opens denied_calls
        s.decide(run, ("read_file", {"path": f"/forbidden/{i}"}))
    got = s.incidents(run)
    s.close()
    return no_sequence and [i["trigger"] for i in got] == ["denied_calls"], {"incidents": [i["trigger"] for i in got]}


def restart_mid_sequence():
    out = {}
    for replay in (False, True):   # from the snapshot close() writes, or (none) replayed from the log
        s = Signer()
        run = s.register()
        s.decide(run, SECRET)
        s.s.close()
        if replay:
            shutil.rmtree(os.path.join(s.dir, "store", "snapshots"))
        s.open()
        d = s.decide(run, EGRESS)
        out["replay" if replay else "snapshot"] = (len(s.incidents(run)), s.events(run)[-2]["data"]["detect"]["state"]
                                                   if d else None)
        s.close()
    return all(v == (1, "complete") for v in out.values()), out


def snapshot_then_restart():
    s = Signer()
    run = s.register()
    s.s.snapshot()
    s.decide(run, SECRET)   # after the snapshot: replayed on open
    s.crash()
    s.open()
    s.decide(run, EGRESS)
    got = s.incidents(run)
    s.close()
    return len(got) == 1, {"incidents": len(got)}


def recover():
    s = Signer()
    run = s.register()
    s.decide(run, SECRET)
    log = s.s.log
    log.write(lambda tx: setattr(log, "down", ("2026-01-01T00:00:00.000000Z", "seeded outage")))
    log._last_try = 0.0
    s.decide(run, EGRESS)   # the writer recovers first: storage reopened, state replayed
    kinds = [e["data"].get("kind") for e in s.events(run) + s.events() if e["type"] == "capture.gap"]
    got = s.incidents(run)
    s.close()
    return "signer_unavailable" in kinds and len(got) == 1, {"incidents": len(got)}


def merge_keeps_pack():
    d = tempfile.mkdtemp()
    try:
        shutil.copytree(PACKS, os.path.join(d, "packs"))
        path = os.path.join(d, "packs", "deploy.yaml")
        with open(path, "w") as f:
            f.write("extends: server.yaml\nsequences:\n  - id: X-MINE\n    steps: [destructive, egress]\n"
                    "    window: 60\n")
        pol, errors = pc.build(path)
    finally:
        shutil.rmtree(d, True)
    ids = [x["id"] for x in pol.get("sequences", [])]
    return not errors and ids == ["TK-Q001", "X-MINE"] and len(pol["limits"]) == 2, {"sequences": ids,
                                                                                       "errors": errors}


def shape(v):
    """`v` with every number and string replaced by its type: what grows with labels, not with counts."""
    if isinstance(v, dict):
        return {k: shape(x) for k, x in v.items()}
    return [shape(x) for x in v] if isinstance(v, list) else type(v).__name__


def detector_cost():
    s = Signer()
    run = s.register()
    shapes = []
    for n in range(400):
        s.decide(run, ("shell", {"command": "rm a"}) if n % 2 else SECRET)
        if n in (49, 399):
            shapes.append(shape(s.s.log.det))
    s.close()
    return shapes[0] == shapes[1], {"state_keys_after_50_and_400_calls": [len(json.dumps(x)) for x in shapes]}


SCENARIOS = {f.__name__: f for f in (session_scope, alias_unknown, parallel, get_query_egress, denied_step,
                                     restart_mid_sequence, snapshot_then_restart, recover, merge_keeps_pack,
                                     detector_cost)}


def run():
    out = {}
    for name, f in SCENARIOS.items():
        ok, detail = f()
        out[name] = {"ok": ok, **detail}
    return out


def main():
    out = run()
    os.makedirs(os.path.join(ROOT, "eval", "results"), exist_ok=True)
    with open(os.path.join(ROOT, "eval", "results", "e17_detection.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    for name, r in out.items():
        print(f"{'ok  ' if r['ok'] else 'FAIL'} {name}")
    return 0 if all(r["ok"] for r in out.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
