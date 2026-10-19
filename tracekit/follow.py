"""`tracekit follow`: another sandbox's audit log, followed into the v2 signer while it is written. Each decision the
sandbox logs becomes a policy.external record (decision_import) of an imported run: the sandbox's word for what it
decided, signed by the signer when it arrives, and trusted as nothing more. docs/integrations/nono.md, agentsh.md.

    tracekit follow nono [--root DIR] [--quiet S]   # every nono session: DIR/<session>/audit-events.ndjson (default
                                                     # $XDG_STATE_HOME/nono/audit, else ~/.local/state/nono/audit)
    tracekit follow agentsh --log PATH              # agentsh's JSONL audit log (`audit.output`), from its end on

The follower calls the signer as its own identity ($TRACEKIT_SIGNER_*, tracekit.sdk.client), which signer.yaml lists in
`importers` and lets call register_run, decision_import, tailer_heartbeat, tailer_lost and close_run (`authorize`).
Each log is one run (agent `nono` or `agentsh`), registered at its first record; a nono session's run is closed at its
session_ended. A run the signer closed meanwhile (its idle_s) goes on in a new run at the next record. A decision's
record is the line as the sandbox wrote it, which the signer keeps only as a commitment; its tool_call_id is
`<session>:<sequence>` for nono, the event's `id` for agentsh (else `line-<n>`, the follower's count).

Gaps, each a capture.gap tailer_lost that the signer writes: a sequence other than the one after the last (records
skipped or repeated: nono's `sequence`, agentsh's `integrity.sequence` when its audit.integrity is on); agentsh starting
a new integrity chain for any reason but `initial` (its `integrity_chain_rotated` record); a line that is not a record
of the log's format, or a decision this module doesn't map; a log truncated, replaced or removed under the follower
(agentsh's log renamed away is followed into the new one at its path); no new record for `quiet` seconds and no
session_ended (nono stopped before it finished the session, or the session is idle); the follower stopped (SIGTERM,
Ctrl-C) first. The last three end the following of that log. A follower that is killed sends no more heartbeats, and
the signer writes the gap itself. While the signer can't be reached the follower waits and goes on from the line it
was at: the log on disk is the queue, and a line's request ids derive from its run and position, so a line sent again
is recorded once.

At start it follows the nono sessions still running (no session.json, which nono writes when a session finishes, and a
log written to in the last `quiet` seconds) from their first record, then each new session as it appears.
"""
import argparse
import functools
import hashlib
import json
import os
import re
import signal
import sys
import time

from tracekit.sdk.client import Client, RunHandle, SignerUnavailable
from tracekit.signer.rpc_schema import MAX_EXTERNAL_RECORD, RPCError
from tracekit.signer.service import HEARTBEAT_S, IDLE_S

POLL_S = 1.0
# lean: half the signer's default idle_s, so the quiet gap lands in a run still open; ask the signer for its idle_s if
# deployments change it
QUIET_S = IDLE_S / 2
ENDED = ("run_closed", "unknown_run")
SESSION = re.compile(r"[A-Za-z0-9_-]{1,64}")   # a nono session id (nono-cli rollback_runtime.rs, session dirs)
# nono's NetworkAuditDecision (crates/nono/src/undo/types.rs) and command-policy `decision` vocabulary
# (crates/nono-cli/src/tool-sandbox/command_policy_decision.rs), as allow, deny or ask
NETWORK = {"allow": "allow", "approve_granted": "allow", "approve_requested": "ask", "deny": "deny",
           "approve_denied": "deny", "approve_timeout": "deny", "approve_error": "deny"}
# agentsh's Decision values (pkg/types/decision.go) as allow, deny or ask: `audit` allows with more logging, `redirect`
# and `soft_delete` carry out something other than what was asked (another command or path, the trash)
AGENTSH = {"allow": "allow", "audit": "allow", "approve": "ask", "deny": "deny", "redirect": "deny",
           "soft_delete": "deny"}
ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")   # rpc_schema's ID
COMMAND = {**dict.fromkeys(("allowed", "approve_granted", "capture", "capture_credential", "capture_credential_cached",
                            "exec", "invocation_allowed", "invocation_approve_granted", "respond"), "allow"),
           **dict.fromkeys(("denied", "approve_denied", "invocation_denied", "invocation_approve_denied"), "deny")}


def nono(session, rec):
    """What one line of nono's audit-events.ndjson says: an AuditEventRecord {sequence, prev_chain, leaf_hash,
    chain_hash, event_json, event} whose `event` is tagged by `type` (crates/nono/src/audit.rs)."""
    seq, ev = rec["sequence"], rec["event"]
    if type(seq) is not int:
        raise TypeError(f"sequence {seq!r} is not an integer")
    kind, out = ev["type"], {"seq": seq}
    if kind in ("session_started", "sandbox_runtime"):
        return out
    if kind == "session_ended":
        return dict(out, end=True)
    if kind == "capability_decision":   # decision: "Granted", "Timeout" or {"Denied": {"reason": ...}}
        e, d = ev["entry"], ev["entry"]["decision"]
        decision, why = (("allow", None) if d == "Granted" else ("deny", "the approval timed out") if d == "Timeout"
                         else ("deny", d["Denied"]["reason"]) if isinstance(d, dict) else (None, None))
        tool, why = "capability_decision/" + e["request"]["capability_type"], f"{e['backend']}: {why or 'granted'}"
    elif kind == "url_open":
        d = ev["success"]
        decision, tool, why = "allow" if d is True else "deny" if d is False else None, "url_open", ev["error"]
    elif kind == "network":
        d = ev["event"]["decision"]
        decision, tool, why = NETWORK.get(d), "network", ev["event"].get("reason")
    elif kind == "command_policy":
        d = ev["event"]["decision"]
        decision, tool, why = COMMAND.get(d), "command_policy/" + ev["event"]["command"], ev["event"]["reason"]
    else:
        return dict(out, unknown=f"nono event type {kind!r} is not one Tracekit maps")
    if decision is None:
        return dict(out, unknown=f"nono {kind} decision {d!r} is not one Tracekit maps")
    return dict(out, decision={"decision": decision, "tool": tool[:256], "tool_call_id": f"{session}:{seq}",
                               **({"reason": why[:1024]} if why else {})})


def agentsh(rec):
    """What one line of agentsh's JSONL audit log (its `audit.output`) says: a types.Event (pkg/types/events.go), with
    `integrity` {format_version, sequence, prev_hash, entry_hash} when audit.integrity is on
    (internal/audit/integrity.go Wrap). An `integrity_chain_rotated` record starts a new chain at sequence 0
    (internal/store/integrity_wrapper.go appendRotationBoundary); its `reason_code` other than `initial` is a gap."""
    integrity, kind = rec.get("integrity"), rec["type"]
    seq = None if integrity is None else integrity["sequence"]
    if seq is not None and type(seq) is not int:
        raise TypeError(f"integrity.sequence {seq!r} is not an integer")
    out = {"seq": seq}
    if kind == "integrity_chain_rotated":
        f = rec["fields"]
        last = (f.get("prior_chain_summary") or {}).get("last_sequence_seen_in_log")
        return dict(out, restart=None if f["reason_code"] == "initial" else (
            f"agentsh started a new integrity chain ({f['reason_code']}: {f.get('reason')})"
            + ("" if last is None else f"; agentsh says the last sequence of the chain before was {last}")))
    policy = rec.get("policy") or {}
    said, applied = policy.get("decision"), policy.get("effective_decision") or policy.get("decision")
    if not applied:
        return out
    if applied not in AGENTSH:
        return dict(out, unknown=f"agentsh {kind} decision {applied!r} is not one Tracekit maps")
    why = applied + (f", policy said {said}" if said and said != applied else "") + (
        f": {policy['message']}" if policy.get("message") else "")
    eid = rec.get("id")
    return dict(out, decision={"decision": AGENTSH[applied], "tool": kind[:256], "reason": why[:1024],
                               "rule_ids": [policy["rule"][:64]] if policy.get("rule") else [],
                               **({"tool_call_id": eid} if isinstance(eid, str) and ID.fullmatch(eid) else {})})


class Log:
    """One followed log: its file, the bytes read of it, the run its records go to, and the sequence the next record
    should carry (None: not known yet)."""

    def __init__(self, client, path, system, read, want=None, quiet=None, offset=0, rotates=False):
        """`offset`: where to start reading; `rotates`: the writer renames the log away and starts a new one at `path`
        (followed from its start), else a log replaced or removed is a gap that ends the following."""
        self.client, self.path, self.system, self.read, self.want, self.quiet = client, path, system, read, want, quiet
        self.rotates, self.f = rotates, open(path, "rb")
        self.ino = os.fstat(self.f.fileno()).st_ino
        # off: the bytes of complete lines read; n: the lines recorded so far, across rotations
        self.off, self.n, self.run, self.done, self.ending = offset, 0, None, False, None
        self.grew = self.beat = time.monotonic()

    def call(self, method, k, **fields):
        """`method` for the log's run, registered first when it has none and again once the signer closed it; the
        request id is the k-th call for the log's next line in that run, so a retried line is recorded once."""
        for again in (False, True):
            if self.run is None:
                self.run = RunHandle(self.client, self.client.call("register_run", {"agent": {"name": self.system}}))
                print(f"tracekit follow: {self.path}: run {self.run.run_id}", file=sys.stderr)
            rid = "fl-" + hashlib.sha256(f"{self.run.run_id}/{self.n}/{k}".encode()).hexdigest()[:32]
            try:
                return self.run.call(method, request_id=rid, **fields)
            except RPCError as e:
                if e.code not in ENDED or again:
                    raise
                self.run = None

    def gap(self, reason, at, k=0):
        self.call("tailer_lost", k, reason=reason[:1024], offset=at)

    def stop(self, reason=None):
        """A gap that ends the following of this log, and its run closed; tried again at each step until both are
        recorded, reading nothing more meanwhile."""
        self.ending = self.ending or (reason, self.off)
        reason, at = self.ending
        self.gap(f"{reason}; Tracekit no longer follows {self.path}", at, 5)
        self.call("close_run", 6)
        self.run, self.done = None, True
        self.f.close()

    def line(self, raw, at):
        """Record one line; the follower's state moves on only once every call for it is answered."""
        try:
            text = raw.decode("utf-8")
            got = self.read(json.loads(text))
        except (ValueError, KeyError, TypeError, AttributeError) as e:   # not a record of this log's format
            got = {"seq": None, "unknown": f"the line is not a {self.system} audit record ({type(e).__name__}: "
                                           f"{str(e)[:200]})"}
        seq = got["seq"]
        if got.get("restart"):
            self.gap(got["restart"] + ("" if self.want is None else f"; the last Tracekit read was {self.want - 1}"),
                     at)
        elif "restart" not in got and None not in (seq, self.want) and seq != self.want:
            self.gap(f"{self.system} sequence {seq} follows {self.want - 1}: " + (
                f"{seq - self.want} record(s) missing" if seq > self.want else "records repeated or out of order")
                + f"; read {self.path} for what they say", at)
        if "unknown" in got:
            self.gap(f"{got['unknown']} (byte {at} of {self.path}): read it there", at, 1)
        if "decision" in got and len(text) > MAX_EXTERNAL_RECORD:
            self.gap(f"the record at byte {at} of {self.path} has {len(text)} characters, more than the signer "
                     f"takes ({MAX_EXTERNAL_RECORD}): its decision is in that log only", at, 1)
        elif "decision" in got:
            self.call("decision_import", 2, system=self.system, record=text,
                      **{"tool_call_id": f"line-{self.n}", **got["decision"]})
        if got.get("end"):
            self.call("close_run", 3)
            self.run, self.done = None, True
            self.f.close()
        self.want = self.want if seq is None else seq + 1
        self.n, self.grew = self.n + 1, time.monotonic()

    def lines(self):
        """Record each complete line past `off`. An incomplete last line is read again next time: its writer may still
        finish it, or take it back (agentsh truncates a write that failed)."""
        self.f.seek(self.off)
        self.buf = self.f.read()
        while not self.done and b"\n" in self.buf:
            raw = self.buf[:self.buf.index(b"\n")]
            self.line(raw, self.off)
            self.buf, self.off = self.buf[len(raw) + 1:], self.off + len(raw) + 1

    def step(self):
        """Record what the log has new. SignerUnavailable (or a retryable refusal) leaves the rest for the next step."""
        if self.ending:
            return self.stop()
        self.lines()
        if self.done:
            return
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            st = None
        moved = st is None or st.st_ino != self.ino
        if moved and self.rotates:
            if st is None:
                return   # renamed away, the new log not made yet
            self.lines()   # what was written to it before it was renamed away
            if self.buf:
                self.gap(f"{self.path} was rotated with an incomplete last line ({len(self.buf)} bytes)", self.off, 4)
            self.f.close()
            self.f = open(self.path, "rb")
            self.ino, self.off = os.fstat(self.f.fileno()).st_ino, 0
            self.lines()
        elif moved or st.st_size < self.off:
            self.stop(f"{self.path} was " + ("removed" if st is None else "replaced" if moved else
                                             f"truncated to {st.st_size} bytes") + f" after Tracekit read {self.off} "
                      "bytes of it: what it held past those, and anything written to it later, is not recorded")
        elif self.quiet and time.monotonic() - self.grew > self.quiet:
            self.stop(f"no new record for {self.quiet:.0f}s and no session_ended: nono stopped before it finished "
                      "the session, or the session is idle")

    def heartbeat(self):
        if self.run is not None and time.monotonic() - self.beat >= HEARTBEAT_S:
            try:
                self.run.call("tailer_heartbeat")
            except RPCError as e:
                if e.code not in ENDED:
                    raise
                self.run = None   # the signer closed it (idle_s): the next record starts a new one
            self.beat = time.monotonic()


def follow(discover, stopping):
    """Step each log `discover()` finds until `stopping()`; then end each one still followed with a gap."""
    logs = []

    def each(fn):
        for log in logs:
            try:
                fn(log)
            except SignerUnavailable:
                pass
            except RPCError as e:
                if e.code != "unavailable" and e.retry_after_ms is None:
                    raise
        logs[:] = [log for log in logs if not log.done]

    while not stopping():
        logs += discover()
        each(lambda log: (log.step(), log.heartbeat()))
        time.sleep(POLL_S)
    each(lambda log: log.stop("the follower was stopped before the log ended"))
    return [log.path for log in logs]


def nono_sessions(client, root, quiet):
    """discover() for follow: the logs of nono sessions under `root` not followed yet."""
    seen, started = set(), []

    def discover():
        try:
            names = sorted(os.listdir(root))
        except FileNotFoundError:
            names = []
        new = []
        for name in names:
            path = os.path.join(root, name, "audit-events.ndjson")
            if name in seen or not SESSION.fullmatch(name) or not os.path.isfile(path):
                continue   # a session directory made before its log is looked at again at the next wake
            seen.add(name)
            if not started and (os.path.exists(os.path.join(root, name, "session.json"))
                                or time.time() - os.path.getmtime(path) > quiet):
                continue   # finished, or quiet, before the follower started
            new.append(Log(client, path, "nono", functools.partial(nono, name), want=0, quiet=quiet))
        started.append(True)
        return new
    return discover


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit follow", description="follow another sandbox's audit log into the "
                                 "v2 signer as it is written (docs/integrations/nono.md)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("nono", help="every nono session's audit-events.ndjson")
    state = os.environ.get("XDG_STATE_HOME")
    p.add_argument("--root", default=os.path.join(state if state and os.path.isabs(state) else
                                                  os.path.expanduser("~/.local/state"), "nono", "audit"),
                   help="nono's audit directory (default: $XDG_STATE_HOME/nono/audit, else ~/.local/state/nono/audit)")
    p.add_argument("--quiet", type=float, default=QUIET_S,
                   help="seconds without a new record after which a session is no longer followed "
                        f"(default {QUIET_S:.0f})")
    p = sub.add_parser("agentsh", help="agentsh's JSONL audit log, from its end on")
    p.add_argument("--log", required=True, help="the log agentsh writes: `audit.output` in its config")
    a = ap.parse_args(argv)
    stop = []
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.append(True))
    client = Client()
    if a.cmd == "agentsh":
        try:
            log = Log(client, a.log, "agentsh", agentsh, offset=os.path.getsize(a.log), rotates=True)
        except OSError as e:
            print(f"tracekit follow: {e}: name the log agentsh writes (`audit.output`)", file=sys.stderr)
            return 2
        new = [log]
        discover, end = (lambda: [new.pop()] if new else []), (lambda: stop or log.done)
    else:
        discover, end = nono_sessions(client, a.root, a.quiet), lambda: stop
    try:
        left = follow(discover, end)
    except RPCError as e:
        print(f"tracekit follow: the signer refused a call ({e})" + (
            "; grant this identity register_run, decision_import, tailer_heartbeat, tailer_lost and close_run in "
            "signer.yaml's authorize" if e.code == "forbidden" else ""), file=sys.stderr)
        return 1
    finally:
        client.close()
    for path in left:
        print(f"tracekit follow: could not report that {path} was left unfinished: the signer writes the gap once "
              "the heartbeats stop", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
