"""Kernel sensor import (experimental): the process, connect and file events a kernel sensor exports as JSON lines,
recorded by the v2 signer in the run each is attributed to, as effect.observed under the import's own signer identity
(observe_effect with `sensor`). Tetragon and Falco: docs/integrations/tetragon.md, docs/integrations/falco.md.

    tracekit sensor import --config sensor.yaml [FILE]   # FILE: an export file, followed (with --follow) through
                                                        # rotation; none: stdin (`tetra getevents -o json | ...`,
                                                        # Falco's program_output)

sensor.yaml:
    sensor: tetragon                       # or falco
    signer: https://signer.internal:8443   # the import's own identity: $TRACEKIT_SIGNER_* (tracekit.sdk.client),
                                           # granted observe_effect in signer.yaml authorize
    runs:                                  # which processes are an agent's, and whose runs their events go to
      - match: {namespace: agents, pod: "coder-*"}   # globs over namespace, pod, container (id) and uid; all must match
        caller: k8s_sa:system:serviceaccount:agents:coder   # that identity's latest open run takes the event

The first `runs` entry that matches an event attributes it; an event none matches is not an agent's and is skipped
(counted on stderr at exit). Losses go to the signer as `lost`, an observer_lost gap in each run the import covers: the
ones the sensor reports in its stream, lines the import can't read, an agent's events it can't record (no binary, a
field the signer would refuse), and events past MAX_PENDING while the signer can't take them. Every call is the import's
heartbeat; one goes at least every HEARTBEAT_S. Each call names this process (`instance`), so the signer sees a
restart.
"""
import argparse
import collections
import fnmatch
import hashlib
import json
import os
import re
import signal
import sys
import threading
import time
import uuid

from tracekit import yamlmini
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.signer.rpc_schema import ID, REQUESTS, RPCError, validate
from tracekit.signer.service import HEARTBEAT_S

KEYS = {"sensor", "signer", "runs"}
MATCH = {"namespace", "pod", "container", "uid"}
MAX_EFFECTS = 256   # per observe_effect call
MAX_BYTES = 1 << 19   # of a call's effects, well inside the signer's frame (quotas.MAX_LINE) with one more
MAX_PENDING = 100_000   # effects waiting for the signer; past it new ones are dropped and sent as `lost`
FLUSH_S = 1.0
FINAL_TRIES = 30   # at the end of the input, one a second while the signer can't take what is left
ITEM = REQUESTS["observe_effect"]["properties"]["effects"]["items"]
CALL_ID = re.compile(ID["pattern"])
TIME = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z")
# Codex exports each shell call's id into the process (codex-rs/protocol/src/shell_environment.rs); the sensor reads it
# only from the processes it is configured to keep that variable of
CODEX_ENV = "CODEX_TOOL_CALL_ID"


def _ts(v):
    """A sensor's RFC 3339 UTC time (nanoseconds at most) in the signer's form, microseconds."""
    m = TIME.fullmatch(v)
    if not m:
        raise ValueError(f"not a UTC time: {v!r}")
    return f"{m[1]}.{(m[2] or '').ljust(6, '0')[:6]}Z"


def _digest(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def tetragon(e):
    """(attributes, effect) of one Tetragon export line (GetEventsResponse as protojson with proto names: cilium/tetragon
    api/v1/tetragon/events.proto, tetragon.proto), a loss it reports, or None for one the import doesn't record. The
    attributes are read first: an effect that can't be built raises only for a process some `runs` entry matches."""
    if "rate_limit_info" in e:   # its export rate limit dropped events (pkg/ratelimit/ratelimit.go)
        n = e["rate_limit_info"].get("number_of_dropped_process_events", "?")
        return f"Tetragon's export rate limit dropped {n} event(s) (raise --export-rate-limit)"
    if "process_throttle" in e:   # its cgroup rate limit (--cgroup-rate) stopped sending exec and exit events
        t = e["process_throttle"]
        return (f"Tetragon throttled the exec and exit events of cgroup {t.get('cgroup', '?')} (--cgroup-rate)"
                if t.get("type") == "THROTTLE_START" else None)
    typ = next((k for k in ("process_exec", "process_exit", "process_kprobe") if k in e), None)
    if typ is None:
        return None
    ev = e[typ]
    p = ev.get("process") or {}
    pod = p.get("pod") or {}
    attrs = {"namespace": pod.get("namespace"), "pod": pod.get("name"),
             "container": (pod.get("container") or {}).get("id") or p.get("docker"), "uid": p.get("uid")}

    def effect():
        if typ == "process_exec":
            if "procFS" in p.get("flags", "").split():   # running when Tetragon started: read from /proc, no exec
                return None
            out = {"kind": "exec", **({"args_digest": _digest(p["arguments"])} if p.get("arguments") else {})}
        elif typ == "process_exit":   # protojson leaves out a zero status and an empty signal
            out = {"kind": "exit", "status": ev.get("status", 0), **({"signal": ev["signal"]} if ev.get("signal") else {})}
        else:
            out = _kprobe(ev.get("args", ()))
            if out is None:
                return None
        env = {v.get("Key"): v.get("Value") for v in p.get("environment_variables", ())}
        return {**out, "ts": _ts(e["time"]), "pid": p["pid"], "binary": p["binary"], "exec_id": p["exec_id"],
                **_claim(env.get(CODEX_ENV))}
    return attrs, effect


def _kprobe(args):
    """The effect of a process_kprobe's arguments: a sockaddr (security_socket_connect) or sock (tcp_connect) is a
    connect, a file or path argument a file event; None for any other hook."""
    for a in args:
        if "sockaddr_arg" in a:
            return {"kind": "connect", "host": a["sockaddr_arg"]["addr"].lower(), "port": a["sockaddr_arg"].get("port", 0)}
        if "sock_arg" in a:
            return {"kind": "connect", "host": a["sock_arg"]["daddr"].lower(), "port": a["sock_arg"].get("dport", 0)}
        if "file_arg" in a or "path_arg" in a:
            return {"kind": "file", "path": (a.get("file_arg") or a["path_arg"])["path"]}
    return None


def falco(e):
    """(attributes, effect) of one Falco alert as its json_output writes it (falcosecurity/falco userspace/engine/
    formats.cpp; internal ones userspace/falco/falco_outputs.cpp), a loss it reports, or None. Only rules tagged
    `tracekit` are recorded, from the fields their output names (docs/integrations/falco.md)."""
    if e.get("rule") == FALCO_DROP:   # userspace/falco/event_drops.cpp: one second's counts, as strings
        f = e.get("output_fields") or {}
        return (f"Falco reported dropping {f.get('n_drops', '?')} of {f.get('n_evts', '?')} syscall event(s) in one "
                "second (raise syscall_event_drops.rate for every second's report)")
    if e.get("source") != "syscall" or "tracekit" not in e.get("tags", ()):
        return None
    f = e["output_fields"]
    attrs = {"namespace": f.get("k8s.ns.name"), "pod": f.get("k8s.pod.name"), "container": f.get("container.id"),
             "uid": f.get("user.uid")}

    def effect():
        kind = FALCO_KINDS.get(f.get("evt.type"))
        if kind == "exec":
            out = {"kind": kind, **({"args_digest": _digest(f["proc.cmdline"])} if f.get("proc.cmdline") else {})}
        elif kind == "connect":
            out = {"kind": kind, "host": f["fd.sip"].lower(), "port": f["fd.sport"]}
        elif kind == "file":
            out = {"kind": kind, "path": f["fd.name"]}
        else:
            return None
        return {**out, "ts": _ts(e["time"]), "pid": f["proc.pid"], "binary": f["proc.exepath"],
                **_claim(f.get(f"proc.env[{CODEX_ENV}]"))}
    return attrs, effect


FALCO_DROP = "Falco internal: syscall event drop"
FALCO_KINDS = {"execve": "exec", "execveat": "exec", "connect": "connect", "open": "file", "openat": "file",
               "openat2": "file"}


def _claim(call_id):
    """The tool call id a process's environment carried, when it is one the signer takes."""
    return {"tool_call_id": call_id} if isinstance(call_id, str) and CALL_ID.match(call_id) and len(call_id) <= 128 \
        else {}


PARSERS = {"tetragon": tetragon, "falco": falco}


class Import:
    """The events of one sensor's stream, attributed and sent to the signer in order."""

    def __init__(self, client, sensor, runs):
        self.client, self.parse, self.sensor, self.runs = client, PARSERS[sensor], sensor, runs
        self.instance = uuid.uuid4().hex
        self.lock = threading.Lock()
        # lean: effects wait in memory (MAX_PENDING) while the signer can't take them, and a killed import loses them
        # (its restart is a signed gap); spool them to disk if outages outlast the memory
        self.pending = collections.deque()   # effects not yet sent, oldest first
        self.lost = collections.Counter()   # loss -> times, not yet sent
        self.sending = None   # the call in flight: sent again, same request_id, until the signer takes it
        self.beat = 0.0   # monotonic time of the last call the signer took
        self.skipped = 0

    def add(self, line):
        """One line of the sensor's stream."""
        try:
            got = self.parse(json.loads(line))
            if isinstance(got, tuple):
                attrs, effect = got
                rule = next((r for r in self.runs if _matches(r["match"], attrs)), None)
                got = rule and effect()
                if got is not None:
                    got = {"caller": rule["caller"], **got}
                    if validate(ITEM, got):   # one the signer would refuse would hold up every event after it
                        raise ValueError(got)
        except (ValueError, KeyError, TypeError, AttributeError):
            got = f"{self.sensor} lines the import could not read or record"
        with self.lock:
            if got is None:
                self.skipped += 1
            elif isinstance(got, str):
                self.lost[got] += 1
            elif len(self.pending) >= MAX_PENDING:
                self.lost[f"events past the import's {MAX_PENDING} waiting for the signer"] += 1
            else:
                self.pending.append(got)

    def flush(self, now=None):
        """Send what is pending, or a heartbeat when one is due. True when nothing is left unsent; False when the signer
        can't take it now (it is sent again, as the same request, next time). A refusal raises RPCError: the import
        stops, and the runs it covers get observer_lost once its heartbeats stop."""
        now = time.monotonic() if now is None else now
        while True:
            with self.lock:
                if self.sending is None:
                    effects, size = [], 0
                    while self.pending and len(effects) < MAX_EFFECTS and size < MAX_BYTES:
                        effects.append(self.pending.popleft())
                        size += len(json.dumps(effects[-1]))
                    lost = "; ".join(f"{n} x {why}" for why, n in self.lost.items())[:1024]
                    self.lost.clear()
                    if not effects and not lost and now - self.beat < HEARTBEAT_S:
                        return True
                    self.sending = {"request_id": "sn-" + uuid.uuid4().hex, "instance": self.instance,
                                    "sensor": self.sensor, "effects": effects, **({"lost": lost} if lost else {})}
                req = self.sending
            try:
                self.client.observe_effect(req)
            except SignerUnavailable:
                return False
            except RPCError as e:
                if e.code == "unavailable" or e.retry_after_ms is not None:
                    return False
                raise
            with self.lock:
                self.sending, self.beat = None, now
                if not self.pending and not self.lost:
                    return True


def _matches(match, attrs):
    return all(attrs.get(k) is not None and fnmatch.fnmatchcase(str(attrs[k]), str(v)) for k, v in match.items())


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not KEYS <= set(cfg) or cfg["sensor"] not in PARSERS:
        raise ValueError(f"{path}: needs sensor (one of {sorted(PARSERS)}), signer and runs")
    for r in cfg["runs"] if isinstance(cfg["runs"], list) else [None]:
        if not (isinstance(r, dict) and set(r) == {"match", "caller"} and isinstance(r["match"], dict) and r["match"]
                and set(r["match"]) <= MATCH and isinstance(r["caller"], str) and ":" in r["caller"]):
            raise ValueError(f"{path}: each runs entry is a match (of {sorted(MATCH)}) and a caller (scheme:subject)")
    return cfg


def _follow(f, path):
    """The lines of `path`, open as `f`, from its end on as the sensor appends them, across its rotation (a new file at
    `path`)."""
    f.seek(0, os.SEEK_END)
    part = b""
    while True:
        line = f.readline()
        part += line
        if part.endswith(b"\n"):
            yield part
            part = b""
            continue
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        if st and st.st_ino != os.fstat(f.fileno()).st_ino:   # rotated: what the old file still had was read above
            f.close()
            f = open(path, "rb")
            if part:
                yield part   # its last line was cut off: unreadable, a loss
                part = b""
        elif st and st.st_size < f.tell():   # truncated in place
            f.seek(0)
        else:
            time.sleep(0.2)


def run(imp, lines):
    """Feed `lines` to `imp` on a thread while this one sends; returns once they end and everything is sent (0), or
    the signer could not take it for FINAL_TRIES seconds, or the input could not be read (1)."""
    done, failed = threading.Event(), []

    def read():
        try:
            for line in lines:
                imp.add(line)
        except OSError as e:
            failed.append(e)
        finally:
            done.set()
    threading.Thread(target=read, name="tracekit-sensor-read", daemon=True).start()
    up = True
    try:
        while not done.wait(FLUSH_S):
            if up != imp.flush():
                up = not up
                print("tracekit sensor: " + ("the signer takes events again" if up else
                      "the signer is unreachable; events wait in memory, and the runs this import covers record "
                      "observer_lost if it stays so"), file=sys.stderr)
    except KeyboardInterrupt:
        pass
    for _ in range(FINAL_TRIES):
        if imp.flush():
            print(f"tracekit sensor: {'stopped: ' + str(failed[0]) if failed else 'done'}; {imp.skipped} event(s) of "
                  "no agent skipped", file=sys.stderr)
            return 1 if failed else 0
        time.sleep(1)
    print(f"tracekit sensor: the signer could not take {len(imp.pending)} event(s); they are not recorded",
          file=sys.stderr)
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit sensor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("import", help="record a kernel sensor's JSON events (a file or stdin) with the signer")
    p.add_argument("--config", required=True)
    p.add_argument("--follow", action="store_true", help="follow FILE from its end, through rotation")
    p.add_argument("file", nargs="?", help="the sensor's JSON export; default stdin")
    a = ap.parse_args(argv)
    try:
        cfg = load_config(a.config)
        f = open(a.file, "rb") if a.file else sys.stdin.buffer
        lines = _follow(f, a.file) if a.follow and a.file else f
    except (OSError, ValueError) as e:
        print(f"tracekit sensor: {e}", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, signal.default_int_handler)   # systemd, docker, k8s: stop as on Ctrl-C, sending
    try:
        return run(Import(Client(cfg["signer"]), cfg["sensor"], cfg["runs"]), lines)
    except RPCError as e:
        print(f"tracekit sensor: the signer refused the import's events ({e.code}: {e.message})"
              + ("; grant this identity observe_effect in signer.yaml authorize" if e.code == "forbidden" else ""),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
