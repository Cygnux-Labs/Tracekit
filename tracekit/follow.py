"""`tracekit follow agentsh --log PATH`: agentsh's JSONL audit log (`audit.output`), followed into the v2 signer from
its end on, while it is written. Each decision agentsh logs becomes a policy.external record (decision_import) of an
imported run: agentsh's word for what it decided, signed by the signer when it arrives, and trusted as nothing more.
docs/integrations/agentsh.md.

The follower calls the signer as its own identity ($TRACEKIT_SIGNER_*, tracekit.sdk.client), which signer.yaml lists in
`importers` and lets call register_run, decision_import, tailer_heartbeat, tailer_lost and close_run (`authorize`).
The log is one run (agent `agentsh`), registered at its first record. A run the signer closed meanwhile (its idle_s)
goes on in a new run at the next record. A decision's record is the line as agentsh wrote it, which the signer keeps
only as a commitment; its tool_call_id is the event's `id` (else `line-<n>`, the follower's count).

Gaps, each a capture.gap tailer_lost that the signer writes: an `integrity.sequence` (when agentsh's audit.integrity is
on) other than the one after the last (records skipped or repeated); agentsh starting a new integrity chain for any
reason but `initial` (its `integrity_chain_rotated` record); a line that is not a record of agentsh's format, a
decision this module doesn't map, or one the signer would refuse (checked against its RPC schema first); the log
truncated under the follower; the follower stopped (SIGTERM, Ctrl-C) first.
The last two end the following. A log renamed away (agentsh's rotation) is followed into the new one at its path. A
follower that is killed sends no more heartbeats, and the signer writes the gap itself. While the signer can't be
reached the follower waits and goes on from the line it was at: the log on disk is the queue, and a line's request ids
derive from its run and position, so a line sent again is recorded once.
"""
import argparse
import hashlib
import json
import os
import re
import signal
import sys
import time

from tracekit.sdk.client import Client, RunHandle, SignerUnavailable
from tracekit.signer.rpc_schema import MAX_EXTERNAL_RECORD, REQUESTS, RPCError, validate
from tracekit.signer.service import HEARTBEAT_S
from tracekit.wiki import wiki_url

POLL_S = 1.0
DECISION = REQUESTS["decision_import"]["properties"]
ENDED = ("run_closed", "unknown_run")
# agentsh's Decision values (pkg/types/decision.go) as allow, deny or ask: `audit` allows with more logging, `redirect`
# and `soft_delete` carry out something other than what was asked (another command or path, the trash)
AGENTSH = {"allow": "allow", "audit": "allow", "approve": "ask", "deny": "deny", "redirect": "deny",
           "soft_delete": "deny"}
ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")   # rpc_schema's ID


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
    """agentsh's log, followed from its end: its file, the bytes read of it, the run its records go to, and the sequence
    the next record should carry (None: not known yet). agentsh rotates it by renaming it away and starting a new one at
    `path`, which is followed from its start."""

    def __init__(self, client, path):
        self.client, self.path, self.f = client, path, open(path, "rb")
        st = os.fstat(self.f.fileno())
        # off: the bytes of complete lines read; n: the lines recorded so far, across rotations
        self.ino, self.off, self.n, self.want = st.st_ino, st.st_size, 0, None
        self.run, self.done, self.ending, self.beat = None, False, None, time.monotonic()

    def call(self, method, k, **fields):
        """`method` for the log's run, registered first when it has none and again once the signer closed it; the
        request id is the k-th call for the log's next line in that run, so a retried line is recorded once."""
        for again in (False, True):
            if self.run is None:
                self.run = RunHandle(self.client, self.client.call("register_run", {"agent": {"name": "agentsh"}}))
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
            got = agentsh(json.loads(text))
        except (ValueError, KeyError, TypeError, AttributeError) as e:   # not a record of agentsh's format
            got = {"seq": None, "unknown": f"the line is not an agentsh audit record ({type(e).__name__}: "
                                           f"{str(e)[:200]})"}
        seq = got["seq"]
        if got.get("restart"):
            self.gap(got["restart"] + ("" if self.want is None else f"; the last Tracekit read was {self.want - 1}"),
                     at)
        elif "restart" not in got and None not in (seq, self.want) and seq != self.want:
            self.gap(f"agentsh sequence {seq} follows {self.want - 1}: " + (
                f"{seq - self.want} record(s) missing" if seq > self.want else "records repeated or out of order")
                + f"; read {self.path} for what they say", at)
        if "unknown" in got:
            self.gap(f"{got['unknown']} (byte {at} of {self.path}): read it there", at, 1)
        fields = "decision" in got and {"system": "agentsh", "record": text, "tool_call_id": f"line-{self.n}",
                                        **got["decision"]}
        refused = fields and [e.replace("$", k, 1) for k, v in fields.items() for e in validate(DECISION[k], v)]
        if fields and len(text) > MAX_EXTERNAL_RECORD:
            self.gap(f"the record at byte {at} of {self.path} has {len(text)} characters, more than the signer "
                     f"takes ({MAX_EXTERNAL_RECORD}): its decision is in that log only", at, 1)
        elif refused:   # one the signer would refuse would stop the following
            self.gap(f"the record at byte {at} of {self.path} holds a decision the signer would refuse "
                     f"({'; '.join(refused)[:200]}): it is in that log only", at, 1)
        elif fields:
            self.call("decision_import", 2, **fields)
        self.want = self.want if seq is None else seq + 1
        self.n += 1

    def lines(self):
        """Record each complete line past `off`. An incomplete last line is read again next time: agentsh may still
        finish it, or take it back (it truncates a write that failed)."""
        self.f.seek(self.off)
        self.buf = self.f.read()
        while b"\n" in self.buf:
            raw = self.buf[:self.buf.index(b"\n")]
            self.line(raw, self.off)
            self.buf, self.off = self.buf[len(raw) + 1:], self.off + len(raw) + 1

    def step(self):
        """Record what the log has new. SignerUnavailable (or a retryable refusal) leaves the rest for the next step."""
        if self.ending:
            return self.stop()
        self.lines()
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return   # renamed away, the new log not made yet
        if st.st_ino != self.ino:   # renamed away and a new log made at its path
            self.lines()   # what was written to it before it was renamed away
            if self.buf:
                self.gap(f"{self.path} was rotated with an incomplete last line ({len(self.buf)} bytes)", self.off, 4)
            self.f.close()
            self.f = open(self.path, "rb")
            self.ino, self.off = os.fstat(self.f.fileno()).st_ino, 0
            self.lines()
        elif st.st_size < self.off:
            self.stop(f"{self.path} was truncated to {st.st_size} bytes after Tracekit read {self.off} bytes of it: "
                      "what it held past those, and anything written to it later, is not recorded")

    def heartbeat(self):
        if self.run is not None and time.monotonic() - self.beat >= HEARTBEAT_S:
            try:
                self.run.call("tailer_heartbeat")
            except RPCError as e:
                if e.code not in ENDED:
                    raise
                self.run = None   # the signer closed it (idle_s): the next record starts a new one
            self.beat = time.monotonic()


def follow(log, stopping):
    """Step `log` until it ends or `stopping()`; then end it with a gap. `log.done` is False after if that gap could not
    be recorded."""
    def attempt(fn):
        try:
            fn()
        except SignerUnavailable:
            pass
        except RPCError as e:
            if e.code != "unavailable" and e.retry_after_ms is None:
                raise

    while not log.done and not stopping():
        attempt(lambda: (log.step(), log.heartbeat()))
        time.sleep(POLL_S)
    if not log.done:
        attempt(lambda: log.stop("the follower was stopped before the log ended"))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit follow", description="follow agentsh's audit log into the v2 signer "
                                 f"as it is written ({wiki_url('docs/integrations/agentsh.md')})")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("agentsh", help="agentsh's JSONL audit log, from its end on")
    p.add_argument("--log", required=True, help="the log agentsh writes: `audit.output` in its config")
    a = ap.parse_args(argv)
    stop = []
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.append(True))
    client = Client()
    try:
        log = Log(client, a.log)
    except OSError as e:
        print(f"tracekit follow: {e}: name the log agentsh writes (`audit.output`)", file=sys.stderr)
        return 2
    try:
        follow(log, lambda: stop)
    except RPCError as e:
        print(f"tracekit follow: the signer refused a call ({e})" + (
            "; grant this identity register_run, decision_import, tailer_heartbeat, tailer_lost and close_run in "
            "signer.yaml's authorize" if e.code == "forbidden" else ""), file=sys.stderr)
        return 1
    finally:
        client.close()
    if not log.done:
        print(f"tracekit follow: could not report that {log.path} was left unfinished: the signer writes the gap once "
              "the heartbeats stop", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
