"""tracekitd: the signer daemon (I1, I2, I3, C2, C4, C5, C8).

System mode runs as a dedicated OS user (`tracekit`); dev mode runs as the agent's user. The
agent sends events over the configured local transport. For each event the daemon:
  1. validates it against schema v1,
  2. checks the client's per-run, per-stream counter for gaps and the run lifecycle for ordering,
  3. checks the attached transcript mark against what it saw before (C2: trace.tamper),
  4. assigns its own monotonic seq and prev_hash, signs, fsyncs,
  5. every N records and at run.end, signs a checkpoint and publishes it to the witnesses.
In the background it cross-checks proxy-recorded model tool requests against hook-recorded
tool calls (C4), flags runs that go quiet without run.end (C5) and retries late witnesses.

It cannot tell a real event from a well-formed fake (docs/signing.md); what it guarantees is
that nothing it accepted can later be changed, dropped or reordered without detection.

    python -m tracekit.daemon --home /var/lib/tracekit [--socket PATH]
"""
import argparse
import getpass
import hmac
import json
import math
import os
import signal
import socket
import socketserver
import struct
import sys
import threading
import time
from urllib.parse import urlsplit

try:
    import pwd
except ImportError:
    pwd = None

from . import schema as schema_mod
from .core import GENESIS, SCHEMA_VERSION, new_id, now_ts
from .ledger import Keys, Ledger
from .policy import policy_hash
from .witness import from_spec, make_checkpoint

DEFAULT_HOME = "/var/lib/tracekit"
MAX_LINE = 8 * 1024 * 1024
MAX_SIGNER_CONNECTIONS = 64
MAX_CACHED_RUNS = 10000
MAX_CACHED_TRANSCRIPTS = 10000
MAX_CACHED_APPROVALS = 10000
STATE_RETENTION_S = 24 * 3600
CLIENT_SOURCES = {"hook", "proxy", "transcript", "sdk", "migrated"}
TRUSTED_ONLY_SOURCES = {"proxy"}   # accepted only from the signer's own uid: the proxy runs as the tracekit user
HARNESS_WRAPPERS = {"sh", "bash", "dash", "zsh", "env", "python", "python3", "timeout", "uv", "uvx", "nice"}


def load_config(home):
    path = os.path.join(home, "config.json")
    cfg = {"checkpoint_every": 50, "witnesses": [], "socket": os.path.join(home, "tracekitd.sock"), "socket_mode": "0666",
           "stale_after_s": 4 * 3600, "crosscheck_grace_s": 90, "approval_max_s": 3600, "approvers": None,
           "allow_same_user_approval": False, "mode": "system"}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


def _user_name(uid):
    if uid is None:
        return getpass.getuser()
    if pwd is not None:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            pass
    return str(uid)


# ---------- /proc helpers (C8 self-approval checks) ----------
def _proc_stat(pid):
    """(comm, ppid, tty_nr) from /proc/<pid>/stat, or None."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
        comm = s[s.index("(") + 1:s.rindex(")")]
        rest = s[s.rindex(")") + 2:].split()
        return comm, int(rest[1]), int(rest[4])
    except (OSError, ValueError, IndexError):
        return None


def _ancestors(pid, limit=64):
    out = []
    while pid and pid > 1 and len(out) < limit:
        st = _proc_stat(pid)
        if not st:
            break
        out.append((pid, st[0], st[2]))
        pid = st[1]
    return out


def harness_of(hook_pid):
    """The first ancestor of the hook process that isn't a shell/python wrapper: the harness."""
    for pid, comm, tty in _ancestors(hook_pid)[1:]:
        if comm not in HARNESS_WRAPPERS:
            return pid, tty
    return None, 0


class Signer:
    def __init__(self, home, cfg):
        self.home, self.cfg = home, cfg
        self.my_uid = os.getuid() if hasattr(os, "getuid") else None
        self.keys = Keys.load_or_create(os.path.join(home, "keys"))
        self.ledger = Ledger(os.path.join(home, "ledger", "ledger.jsonl"), self.keys)
        with open(os.path.join(home, "ledger", "signer.pub"), "wb") as f:
            f.write(self.keys.public)
        self.blobs = os.path.join(home, "blobs")
        os.makedirs(self.blobs, exist_ok=True)
        self.witnesses = [from_spec(s) for s in cfg.get("witnesses", [])]
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.runs = {}            # run_id -> state (see _run)
        self.transcripts = {}     # path -> {"length", "hash", "history": {length: hash}}
        self.tool_uses = {}       # tool_use_id -> {"model": (run, name, t) | None, "hook": (run, t) | None, "done": bool}
        self.approvals = {}       # approval id -> pending approval
        self.since_cp = 0
        self.last_cp_seq = -1
        self.retry = []           # [(checkpoint, witness, attempts, next_time)]
        self.write_errors = 0
        self._load_runs()
        self._prune_runtime_state(time.time())
        if self.ledger.torn:
            self._internal("capture.gap", {"reason": "torn final record found at startup (crash during a write)", "kind": "torn_write"})
        if self.ledger.seq >= 0:
            self._internal("capture.gap", {"reason": "tracekitd started; events sent while it was down were not signed",
                                           "kind": "signer_restart"})

    # ---------- state ----------
    @staticmethod
    def _new_run():
        return {"cseq": {}, "started": False, "ended": False, "proxy": False, "last": time.time(), "stale_flagged": False,
                "agent_uid": None}

    def _run(self, run_id):
        st = self.runs.get(run_id)
        if st is None:
            st = self.runs[run_id] = self._new_run()
        return st

    def _load_runs(self):
        from .ledger import read_records
        for _, rec, _ in read_records(self.ledger.path):
            if not rec or rec.get("elided"):
                continue
            ev = rec["event"]
            st = self._run(ev["run_id"])
            st["last"] = time.time()
            if ev["type"] == "run.start":
                st.update(started=True, ended=False, proxy="proxy" in ev["data"].get("capture_sources", []))
            elif ev["type"] == "run.end":
                st["ended"] = True
            elif ev["type"] == "checkpoint":
                self.last_cp_seq = ev["data"]["head_seq"]
            tr = ev.get("transcript")
            if tr and not tr.get("missing"):
                self._note_transcript(tr["path"], tr["length"], tr["hash"])
        state = os.path.join(self.home, "runs.json")
        if os.path.exists(state):
            try:
                with open(state) as f:
                    for rid, c in json.load(f).items():
                        if rid in self.runs:
                            self.runs[rid]["cseq"] = c if isinstance(c, dict) else {"hook": c}
            except ValueError:
                pass

    def _save_runs(self):
        tmp = os.path.join(self.home, "runs.json.tmp")
        with open(tmp, "w") as f:
            json.dump({k: v["cseq"] for k, v in self.runs.items()}, f)
        os.replace(tmp, os.path.join(self.home, "runs.json"))

    def _append(self, ev):
        rec = self.ledger.append(ev)
        self.since_cp += 1
        return rec

    def _internal(self, typ, data, run_id="_signer"):
        ev = {"schema_version": SCHEMA_VERSION, "id": new_id(), "seq": 0, "prev_hash": GENESIS, "ts": now_ts(),
              "ts_signed": now_ts(), "run_id": run_id, "agent_id": "tracekitd", "parent_id": None,
              "source": "signer", "type": typ, "data": data}
        errs = schema_mod.validate(ev)
        assert not errs, errs
        return self._append(ev)

    # ---------- checkpoints ----------
    def checkpoint(self):
        with self.lock:
            if self.ledger.seq < 0 or self.ledger.seq == self.last_cp_seq:
                return None
            cp = make_checkpoint(self.ledger.seq, self.ledger.head, self.keys)
            with open(os.path.join(self.home, "checkpoints.jsonl"), "a") as f:
                f.write(json.dumps(cp, sort_keys=True) + "\n")
                f.flush(); os.fsync(f.fileno())
            ok = []
            for w in self.witnesses:
                try:
                    ok.append(w.publish(cp))
                except Exception as e:
                    self.retry.append([cp, w, 1, time.time() + 1])
                    self._internal("capture.gap", {"reason": f"checkpoint seq {cp['head_seq']} not yet on {w.name}: {str(e)[:200]}",
                                                   "kind": "witness_late"})
            self._internal("checkpoint", {"head_seq": cp["head_seq"], "head_hash": cp["head_hash"], "kid": cp["kid"], "witnesses": ok})
            self.last_cp_seq = cp["head_seq"]
            self.since_cp = 0
            return cp

    def retry_witnesses(self):
        with self.lock:
            keep = []
            for cp, w, n, t in self.retry:
                if time.time() < t:
                    keep.append([cp, w, n, t]); continue
                try:
                    w.publish(cp)
                    self._internal("capture.gap", {"reason": f"checkpoint seq {cp['head_seq']} reached {w.name} late after {n} retries",
                                                   "kind": "witness_late"})
                except Exception:
                    if n < 8:
                        keep.append([cp, w, n + 1, time.time() + min(60, 2 ** n)])
                    else:
                        self._internal("capture.gap", {"reason": f"gave up publishing checkpoint seq {cp['head_seq']} to {w.name}",
                                                       "kind": "witness_failed"})
            self.retry = keep

    # ---------- policy snapshots ----------
    def _blob(self, h):
        return os.path.join(self.blobs, h.split(":")[1] + ".json")

    def _store_policy(self, text, claimed):
        try:
            if policy_hash(json.loads(text)) != claimed:
                return "attached policy does not match the policy hash in the event"
        except ValueError:
            return "attached policy is not JSON"
        blob = self._blob(claimed)
        if not os.path.exists(blob):
            with open(blob, "w", encoding="utf-8") as f:
                f.write(text)
        return None

    # ---------- C2: transcript marks ----------
    def _note_transcript(self, path, length, h):
        t = self.transcripts.setdefault(path, {"length": -1, "hash": None, "history": {}})
        t["updated_at"] = time.time()
        if length >= t["length"]:
            t["length"], t["hash"] = length, h
        t["history"][length] = h
        if len(t["history"]) > 64:
            for k in sorted(t["history"])[:-32]:
                if k != t["length"]:
                    del t["history"][k]

    def _check_transcript(self, mark, run_id):
        """Compare a transcript mark with the last one; emit trace.tamper on deletion, truncation or edits."""
        path = mark["path"]
        prev = self.transcripts.get(path)
        if prev is None or prev["length"] < 0:
            if not mark.get("missing"):
                self._note_transcript(path, mark["length"], mark["hash"])
            return
        before = {"hash": prev["hash"], "length": prev["length"]}
        kind = None
        if mark.get("missing"):
            kind = "deleted"
        elif mark["length"] < prev["length"]:
            kind = "truncated"
        else:
            pl, ph = mark.get("prefix_length"), mark.get("prefix_hash")
            if pl is None or pl not in prev["history"]:
                kind = "prefix_unverifiable"
            elif prev["history"][pl] != ph:
                kind = "edited"
        if kind:
            self._internal("trace.tamper", {"path": path, "kind": kind, "before": before,
                                            "after": {"hash": None if mark.get("missing") else mark["hash"],
                                                      "length": None if mark.get("missing") else mark["length"]}}, run_id)
            # start over from what is there now, so one rewrite produces one event
            self.transcripts[path] = {"length": -1, "hash": None, "history": {}}
        if not mark.get("missing"):
            self._note_transcript(path, mark["length"], mark["hash"])

    # ---------- C4 / C5: background checks ----------
    def _tool_use(self, tid):
        tu = self.tool_uses.get(tid)
        if tu is None:
            tu = self.tool_uses[tid] = {"model": None, "hook": None, "done": False, "t": time.time()}
        return tu

    def sweep(self, now=None, run_end=None):
        """Cross-check proxy vs hook (C4) and flag stale runs (C5). run_end: check that run now."""
        now = now or time.time()
        grace = float(self.cfg.get("crosscheck_grace_s", 90))
        with self.lock:
            for tid, tu in list(self.tool_uses.items()):
                if tu["done"]:
                    if now - tu["t"] > 3600:
                        del self.tool_uses[tid]
                    continue
                m, h = tu["model"], tu["hook"]
                if m and h:
                    tu["done"] = True
                    continue
                due = now - tu["t"] > grace or (run_end is not None and (m or h) and (m or h)[0] == run_end)
                if not due:
                    continue
                if m and not h:
                    run = m[0]
                    self._internal("capture.gap", {"reason": f"model requested tool call {tid} ({m[1]}) but no hook recorded it "
                                                             "(hooks disabled, removed or bypassed?)", "kind": "hook_missing",
                                                   "tool_use_id": tid}, run)
                    tu["done"] = True
                elif h and not m:
                    run = h[0]
                    if self.runs.get(run, {}).get("proxy"):
                        self._internal("capture.gap", {"reason": f"hook recorded tool call {tid} with no matching model exchange "
                                                                 "(proxy bypassed, e.g. ANTHROPIC_BASE_URL unset?)", "kind": "proxy_missing",
                                                       "tool_use_id": tid}, run)
                    tu["done"] = True
            stale = float(self.cfg.get("stale_after_s", 4 * 3600))
            for rid, st in self.runs.items():
                if rid.startswith("_") or not st["started"] or st["ended"] or st["stale_flagged"]:
                    continue
                if now - st["last"] > stale:
                    self._internal("capture.gap", {"reason": f"run has no events for {int(now - st['last'])}s and never recorded "
                                                             "run.end (hooks disabled or session killed?)", "kind": "stale_run"}, rid)
                    st["stale_flagged"] = True
            self._prune_runtime_state(now)

    def _prune_runtime_state(self, now):
        try:
            retention = max(1.0, float(self.cfg.get("state_retention_s", STATE_RETENTION_S)))
        except (TypeError, ValueError):
            retention = STATE_RETENTION_S
        changed_runs = False
        for run_id, state in list(self.runs.items()):
            if (state["ended"] or state["stale_flagged"]) and now - state["last"] > retention:
                del self.runs[run_id]
                changed_runs = True
        while len(self.runs) > MAX_CACHED_RUNS:
            run_id = min(self.runs, key=lambda rid: self.runs[rid]["last"])
            del self.runs[run_id]
            self._internal("capture.gap", {"reason": "signer evicted old run state to stay within its memory limit",
                                           "kind": "run_state_evicted"}, run_id)
            changed_runs = True
        for path, state in list(self.transcripts.items()):
            if now - state.get("updated_at", now) > retention:
                del self.transcripts[path]
                self._internal("capture.gap", {"reason": "signer expired transcript history; later transcript edits may be unverifiable",
                                               "kind": "transcript_state_expired"})
        while len(self.transcripts) > MAX_CACHED_TRANSCRIPTS:
            path = min(self.transcripts, key=lambda item: self.transcripts[item].get("updated_at", 0))
            del self.transcripts[path]
            self._internal("capture.gap", {"reason": "signer evicted transcript history to stay within its memory limit",
                                           "kind": "transcript_state_evicted"})
        for approval_id, approval in list(self.approvals.items()):
            if approval["decision"] is None and now >= approval["deadline"]:
                with self.cond:
                    self._record_approval(approval, "timeout", "tracekitd", "timeout")
            elif approval["decision"] is not None and now - approval.get("decided_at", now) > retention:
                del self.approvals[approval_id]
        if len(self.approvals) > MAX_CACHED_APPROVALS:
            decided = sorted((item for item in self.approvals.items() if item[1]["decision"] is not None),
                             key=lambda item: item[1].get("decided_at", 0))
            for approval_id, _ in decided[:len(self.approvals) - MAX_CACHED_APPROVALS]:
                del self.approvals[approval_id]
        if changed_runs:
            self._save_runs()

    # ---------- C8: approvals ----------
    def _approval_request(self, req, peer):
        run_id, tid = req.get("run_id"), req.get("tool_use_id")
        if not run_id or not tid:
            return {"ok": False, "error": "run_id and tool_use_id required"}
        if sum(a["decision"] is None for a in self.approvals.values()) >= MAX_CACHED_APPROVALS:
            return {"ok": False, "error": "too many pending approvals; retry after one is resolved"}
        try:
            requested_timeout = float(req.get("timeout_s") or 120)
            max_timeout = float(self.cfg.get("approval_max_s", 3600))
        except (TypeError, ValueError):
            return {"ok": False, "error": "approval timeout must be a finite positive number"}
        if not math.isfinite(requested_timeout) or requested_timeout <= 0:
            return {"ok": False, "error": "approval timeout must be a finite positive number"}
        if not math.isfinite(max_timeout) or max_timeout <= 0:
            max_timeout = 3600
        timeout = min(requested_timeout, max_timeout)
        aid = new_id()
        while aid in self.approvals:
            aid = new_id()
        hpid, htty = harness_of(peer[0]) if peer and peer[0] else (None, 0)
        agent_uid = peer[1] if peer else None
        if agent_uid is None and self.cfg.get("mode") == "dev":
            agent_uid = self.my_uid
        self.approvals[aid] = {"id": aid, "run_id": run_id, "tool_use_id": tid, "agent_id": req.get("agent_id") or "main",
                               "summary": str(req.get("summary") or "")[:500], "rule_ids": req.get("rule_ids") or [],
                               "agent_uid": agent_uid, "hook_pid": peer[0] if peer else None,
                               "harness_pid": hpid, "harness_tty": htty, "created": time.time(), "deadline": time.time() + timeout,
                               "decision": None, "approver": None, "channel": None}
        return {"ok": True, "approval_id": aid, "timeout_s": timeout}

    def _record_approval(self, a, decision, approver, channel, approver_uid=None, same_user=None):
        a["decision"], a["approver"], a["channel"] = decision, approver, channel
        a["decided_at"] = time.time()
        self._internal("approval", {"tool_use_id": a["tool_use_id"], "decision": decision, "approver": approver, "channel": channel,
                                    "approver_uid": approver_uid, "same_user": same_user,
                                    "wait_ms": int((time.time() - a["created"]) * 1000)}, a["run_id"])
        self.cond.notify_all()

    def _self_approval_reason(self, a, peer, interactive=None):
        """Why this approval must be refused, or None.

        The only boundary that holds is the OS user: an approval must come from a different user
        than the agent's (or from a configured approver). A same-user approval can always be
        forged by the agent itself (for example by detaching a new session with its own terminal,
        which defeats any process-tree or tty check), so it is refused unless the signer runs in
        dev mode with allow_same_user_approval, and then it is labelled untrustworthy."""
        if interactive is False:
            return "approvals need an interactive terminal"
        pid, uid = peer if peer else (None, None)
        if uid is None:
            if self.cfg.get("mode") == "dev" and self.cfg.get("allow_same_user_approval") and not self.cfg.get("approvers"):
                if not interactive:
                    return "approvals need an interactive terminal"
                return None
            return "cannot identify the approving OS user (no peer credentials on this platform)"
        approvers = self.cfg.get("approvers")
        if approvers:
            names = {_user_name(uid), str(uid)}
            if not names & {str(x) for x in approvers}:
                return f"uid {uid} is not in the configured approvers {approvers}"
            if a["agent_uid"] is not None and uid == a["agent_uid"]:
                return "the configured approver is the agent's own OS user, which the agent can impersonate"
            return None
        if a["agent_uid"] is None:
            return "the agent's OS user is unknown, so a different-user approval cannot be established"
        if uid != a["agent_uid"]:
            return None  # a different OS user than the agent: the case that holds
        if not self.cfg.get("allow_same_user_approval", False):
            return ("approvals must come from a different OS user than the agent, or a configured approver "
                    "(same-user approvals are only allowed in dev mode)")
        # dev mode only: best-effort checks that stop accidents, not a determined agent
        if pid is None:
            return "cannot identify the approving process"
        chain = _ancestors(pid)
        if a["harness_pid"] and any(p == a["harness_pid"] for p, _, _ in chain):
            return "the approving process runs inside the agent's own session"
        if a["hook_pid"] and any(p == a["hook_pid"] for p, _, _ in chain):
            return "the approving process runs inside the hook"
        my_tty = chain[0][2] if chain else 0
        if my_tty == 0:
            return "approvals need an interactive terminal (no controlling tty)"
        if a["harness_tty"] and my_tty == a["harness_tty"]:
            return "the approving terminal is the agent's own terminal"
        return None

    def _approve(self, req, peer):
        aid, decision = req.get("approval_id"), req.get("decision")
        if decision not in ("approve", "reject"):
            return {"ok": False, "error": "decision must be approve or reject"}
        a = self.approvals.get(aid)
        if not a:
            return {"ok": False, "error": f"no pending approval {aid!r}"}
        if a["decision"]:
            return {"ok": False, "error": f"approval {aid} already decided: {a['decision']}"}
        uid = peer[1] if peer else None
        who = _user_name(uid) if uid is not None else "unattested dev user"
        interactive = req.get("interactive") if "interactive" in req else None
        why = self._self_approval_reason(a, peer, interactive)
        tty = ""
        if peer and peer[0]:
            try:
                tty = os.readlink(f"/proc/{peer[0]}/fd/0")
            except OSError:
                tty = ""
        same = uid == a["agent_uid"] if uid is not None and a["agent_uid"] is not None else None
        channel = f"cli uid={uid} tty={tty or '?'}"
        if same:
            channel += " (same OS user as the agent: not trustworthy, dev mode)"
        elif same is None:
            channel += " (peer identity unavailable; untrusted dev mode)"
        if why:
            self._internal("approval", {"tool_use_id": a["tool_use_id"], "decision": "self_approval_refused", "approver": who,
                                        "channel": f"{channel}: {why}", "approver_uid": uid, "same_user": same,
                                        "wait_ms": int((time.time() - a["created"]) * 1000)}, a["run_id"])
            return {"ok": False, "error": f"refused: {why}"}
        self._record_approval(a, decision, who, channel, uid, same)
        return {"ok": True, "approval_id": aid, "decision": decision, "same_user": same}

    def _approval_wait(self, req):
        a = self.approvals.get(req.get("approval_id"))
        if not a:
            return {"ok": False, "error": "unknown approval"}
        end = min(time.time() + float(req.get("wait_s") or 20), a["deadline"])
        while a["decision"] is None and time.time() < end:
            self.cond.wait(timeout=max(0.05, end - time.time()))
        if a["decision"] is None and time.time() >= a["deadline"]:
            self._record_approval(a, "timeout", "tracekitd", "timeout")
        return {"ok": True, "decision": a["decision"], "approver": a["approver"], "channel": a["channel"]}

    def _approval_list(self):
        now = time.time()
        return {"ok": True, "pending": [{k: a[k] for k in ("id", "run_id", "tool_use_id", "agent_id", "summary", "rule_ids")}
                                        | {"expires_in_s": int(a["deadline"] - now)}
                                        for a in self.approvals.values() if a["decision"] is None and a["deadline"] > now]}

    # ---------- requests ----------
    def handle(self, req, peer_uid=None, peer_pid=None):
        peer = (peer_pid, peer_uid) if peer_uid is not None else None
        op = req.get("op")
        with self.lock:
            if op == "status":
                return {"ok": True, "seq": self.ledger.seq, "head": self.ledger.head, "kid": self.keys.kid,
                        "witnesses": [w.name for w in self.witnesses], "last_checkpoint_seq": self.last_cp_seq,
                        "pending_witness_retries": len(self.retry), "pending_approvals": len(self._approval_list()["pending"]),
                        "write_errors": self.write_errors}
            if op == "checkpoint":  # harmless: only ever adds a signed checkpoint (used by export)
                cp = self.checkpoint()
                return {"ok": True, "head_seq": self.last_cp_seq, "new": bool(cp)}
            if op == "approval_request":
                return self._approval_request(req, peer)
            if op == "approval_wait":
                return self._approval_wait(req)
            if op == "approve":
                return self._approve(req, peer)
            if op == "approval_list":
                return self._approval_list()
            if op != "append":
                return {"ok": False, "error": f"unsupported op {op!r} (no delete, rewrite or key export exists)"}
            try:
                return self._handle_append(req, peer_uid)
            except OSError as e:
                self.write_errors += 1
                return {"ok": False, "error": f"ledger write failed: {e}", "retryable": True}

    def _handle_append(self, req, peer_uid):
        ev = dict(req.get("event") or {})
        run_id, cseq = ev.get("run_id"), req.get("cseq")
        stream = str(req.get("stream") or ev.get("source") or "hook")[:32]
        if ev.get("source") not in CLIENT_SOURCES:
            return {"ok": False, "error": f"source must be one of {sorted(CLIENT_SOURCES)}"}
        uncredentialed_dev = self.cfg.get("mode") == "dev" and peer_uid is None
        peer_is_signer = peer_uid is not None and self.my_uid is not None and peer_uid == self.my_uid
        if ev.get("source") in TRUSTED_ONLY_SOURCES and not peer_is_signer and not uncredentialed_dev:
            self._internal("error", {"message": f"refused source={ev['source']} event from uid {peer_uid}: only the signer's own "
                                                "user (the proxy) may send it", "client_run_id": str(run_id)[:200]})
            return {"ok": False, "error": f"source {ev['source']} is only accepted from the signer's user"}
        ev.setdefault("schema_version", SCHEMA_VERSION)
        ev.setdefault("id", new_id())
        ev.setdefault("ts", now_ts())
        ev["ts_signed"] = now_ts()
        ev["seq"], ev["prev_hash"] = 0, GENESIS  # placeholders; the ledger assigns the real values
        if ev.get("type") == "run.start" and isinstance(ev.get("data"), dict):
            if peer_uid is not None:
                ev["data"]["os_user"] = _user_name(peer_uid)
                ev["data"]["os_user_attested"] = True
            else:
                ev["data"]["os_user_attested"] = False
        errs = schema_mod.validate(ev)
        if errs:
            self._internal("error", {"message": "rejected invalid event: " + "; ".join(errs[:5])[:900],
                                     "client_run_id": str(run_id)[:200]})
            return {"ok": False, "error": "schema: " + "; ".join(errs[:5])}
        attach = req.get("attach") or {}
        st = self._run(run_id)
        st["last"] = time.time()
        st["stale_flagged"] = False
        if isinstance(cseq, int):
            last = st["cseq"].get(stream, -1)
            if cseq != last + 1:
                why = (f"client counter for run ({stream}) jumped {last} -> {cseq}" if cseq > last + 1
                       else f"client counter for run ({stream}) went backwards {last} -> {cseq} (replay or reset)")
                self._internal("capture.gap", {"reason": why, "missed_events": max(0, cseq - last - 1), "kind": "counter"}, run_id)
            st["cseq"][stream] = max(last, cseq)
        else:
            self._internal("capture.gap", {"reason": "event without client counter", "kind": "counter"}, run_id)
        claimed = (ev["data"].get("policy") or {}).get("hash") if ev["type"] == "run.start" else \
            (ev["data"].get("policy_hash") if ev["type"] == "policy.decision" else None)
        if attach.get("policy") is not None and claimed:
            err = self._store_policy(attach["policy"], claimed)
            if err:
                return {"ok": False, "error": err}
        if ev["type"] == "policy.decision" and claimed and not os.path.exists(self._blob(claimed)):
            self._internal("capture.gap", {"reason": f"decision made under policy {claimed[:19]} whose snapshot was never recorded",
                                           "kind": "policy_unrecorded", "tool_use_id": ev["data"].get("tool_use_id")}, run_id)
        if ev["type"] == "run.start":
            if st["started"] and not st["ended"]:
                self._internal("capture.gap", {"reason": "run.start for a run that never recorded run.end", "kind": "no_run_end"}, run_id)
            st.update(started=True, ended=False, proxy="proxy" in ev["data"].get("capture_sources", []), agent_uid=peer_uid)
        elif ev["source"] == "proxy":
            pass  # proxy exchanges may arrive before the hook's run.start
        elif not st["started"]:
            self._internal("capture.gap", {"reason": "events before run.start (hooks installed mid-run or run.start lost)",
                                           "kind": "no_run_start"}, run_id)
            st["started"] = True
        elif st["ended"]:
            self._internal("capture.gap", {"reason": "event after run.end", "kind": "after_run_end"}, run_id)
        if ev.get("transcript"):
            self._check_transcript(ev["transcript"], run_id)
        rec = self._append(ev)
        d = ev["data"]
        if ev["type"] == "tool.call" and ev["source"] == "hook":
            tu = self._tool_use(d["tool_use_id"])
            tu["hook"] = (run_id, time.time())
        elif ev["type"] == "model.exchange" and d.get("phase", "response") == "response":
            for t in d.get("tool_uses") or []:
                tu = self._tool_use(t["id"])
                tu["model"] = (run_id, t["name"], time.time())
        if ev["type"] == "run.end":
            st["ended"] = True
            self.sweep(run_end=run_id)
        self._save_runs()
        if ev["type"] == "run.end" or self.since_cp >= int(self.cfg.get("checkpoint_every", 50)):
            self.checkpoint()
        resp = {"ok": True, "seq": rec["event"]["seq"], "hash": rec["hash"], "kid": rec["kid"]}
        if ev.get("transcript"):
            t = self.transcripts.get(ev["transcript"]["path"])
            resp["transcript_ack"] = t["length"] if t else None
        return resp


def _peer(conn):
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED"), struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", creds)
        return pid, uid
    except (AttributeError, OSError):
        return None, None


def _has_peer_credentials():
    return hasattr(socket, "SO_PEERCRED")


class _Handler(socketserver.StreamRequestHandler):
    def setup(self):
        self.request.settimeout(30)
        super().setup()

    def handle(self):
        pid, uid = _peer(self.connection)
        while True:
            try:
                line = self.rfile.readline(MAX_LINE + 1)
            except OSError:
                return
            if not line:
                return
            if len(line) > MAX_LINE:
                self.wfile.write(b'{"ok": false, "error": "request too large"}\n')
                self.close_connection = True
                return
            try:
                req = json.loads(line)
                token = getattr(self.server, "socket_token", None)
                if token is not None:
                    supplied = req.pop("_tracekit_token", "")
                    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, token):
                        resp = {"ok": False, "error": "unauthorized local signer request"}
                    else:
                        resp = self.server.signer.handle(req, uid, pid)
                else:
                    resp = self.server.signer.handle(req, uid, pid)
            except Exception as e:  # never crash the daemon on one bad request
                resp = {"ok": False, "error": f"internal: {e}"}
            self.wfile.write((json.dumps(resp) + "\n").encode("utf-8"))
            self.wfile.flush()


class _BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_SIGNER_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(b'{"ok": false, "error": "signer busy", "retryable": true}\n')
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class ThreadingTCPServer(_BoundedThreadingMixIn, socketserver.TCPServer):
    pass


def _unix_server_class():
    unix_server = getattr(socketserver, "UnixStreamServer", None)
    if unix_server is None:
        if not hasattr(socket, "AF_UNIX"):
            return None

        class AFUnixServer(socketserver.TCPServer):
            address_family = socket.AF_UNIX

        unix_server = AFUnixServer

    class ThreadingUnixServer(_BoundedThreadingMixIn, unix_server):
        pass

    return ThreadingUnixServer


UnixServer = _unix_server_class()


def serve(home, socket_path=None):
    cfg = load_config(home)
    sock = socket_path or cfg["socket"]
    if sock.startswith("tcp://"):
        endpoint = urlsplit(sock)
        if (endpoint.hostname != "127.0.0.1" or endpoint.port is None or not 1 <= endpoint.port <= 65535
                or endpoint.username or endpoint.password
                or endpoint.path or endpoint.query or endpoint.fragment):
            raise ValueError("TCP signer endpoint must use 127.0.0.1 and an explicit port")
        if not isinstance(cfg.get("socket_token"), str) or not cfg["socket_token"]:
            raise ValueError("TCP signer endpoint requires an authentication token")
    else:
        if not _has_peer_credentials():
            raise RuntimeError("Unix signer sockets require kernel peer credentials; rerun `tracekit init --dev` to configure authenticated TCP")
        if UnixServer is None:
            raise RuntimeError("Unix sockets are unavailable; initialize Tracekit in dev mode to use TCP")
        os.makedirs(os.path.dirname(sock) or ".", exist_ok=True)
        if os.path.exists(sock):
            os.unlink(sock)
    signer = Signer(home, cfg)
    try:
        if sock.startswith("tcp://"):
            srv = ThreadingTCPServer((endpoint.hostname, endpoint.port), _Handler)
            srv.socket_token = cfg["socket_token"]
        else:
            srv = UnixServer(sock, _Handler)
            os.chmod(sock, int(str(cfg.get("socket_mode", "0666")), 8))
            srv.socket_token = None
    except BaseException:
        signer.ledger.close()
        if not sock.startswith("tcp://"):
            try:
                os.unlink(sock)
            except OSError:
                pass
        raise
    srv.signer = signer

    def bg():
        n = 0
        while True:
            time.sleep(1)
            n += 1
            try:
                signer.retry_witnesses()
                if n % 5 == 0:
                    signer.sweep()
            except Exception as e:  # keep the background thread alive
                print(f"tracekitd: background error: {e}", file=sys.stderr, flush=True)
    threading.Thread(target=bg, daemon=True).start()

    def stop(*_):
        with signer.lock:
            signer.checkpoint()
        srv.shutdown()
    signal.signal(signal.SIGTERM, lambda *a: threading.Thread(target=stop).start())
    print(f"tracekitd: kid={signer.keys.kid} seq={signer.ledger.seq} socket={sock} witnesses={[w.name for w in signer.witnesses]}",
          flush=True)
    if not hasattr(socket, "SO_PEERCRED"):
          print("tracekitd: WARNING: no SO_PEERCRED on this platform: caller identity is not attested; "
              "dev-mode proxy events and approvals are untrusted. System mode is Linux-only in v0.2.",
              file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    finally:
        try:
            srv.server_close()
        finally:
            try:
                signer.ledger.close()
            finally:
                if not sock.startswith("tcp://"):
                    try:
                        os.unlink(sock)
                    except OSError:
                        pass


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekitd")
    ap.add_argument("--home", default=os.environ.get("TRACEKIT_SIGNER_HOME", DEFAULT_HOME))
    ap.add_argument("--socket")
    a = ap.parse_args(argv)
    os.umask(0o022)
    serve(a.home, a.socket)


if __name__ == "__main__":
    sys.exit(main())
