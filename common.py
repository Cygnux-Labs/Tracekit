"""Shared helpers: paths, redaction, canonical hashing, ledger append/read."""
import hashlib
import json
import os
import re
import time

from tracekit.locking import lock_file, unlock_file

HOME = os.environ.get("TRACEKIT_HOME", os.path.expanduser("~/.tracekit"))
LEDGER = os.path.join(HOME, "ledger.jsonl")
STATE = os.path.join(HOME, "state.json")
ANCHORS = os.path.join(HOME, "anchors.log")
POLICY = os.environ.get("TRACEKIT_POLICY", os.path.join(HOME, "policy.json"))
GENESIS = "0" * 64
MAX_STR = int(os.environ.get("TRACEKIT_MAX_STR", "20000"))

# Secrets are masked BEFORE anything is written, so the ledger never holds them.
SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)(\s*[=:]\s*)([^\s'\"]{6,})"),
]


def _redact_str(s):
    for p in SECRET_PATTERNS:
        if p.groups >= 3:
            s = p.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", s)
        else:
            s = p.sub("[REDACTED]", s)
    if len(s) > MAX_STR:
        full = hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
        s = s[:MAX_STR] + f"\n…[truncated {len(s) - MAX_STR} chars; sha256 of full={full}]"
    return s


def redact(obj):
    if isinstance(obj, str):
        return _redact_str(obj)
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    return obj


def canon(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(canon(body).encode("utf-8")).hexdigest()


def _last_record(f):
    """Return the last *valid* record, reading backwards so records of any size work.
    A torn final line (crash mid-write) is skipped, not treated as an empty ledger,
    so the chain never silently restarts from genesis."""
    f.seek(0, os.SEEK_END)
    end = f.tell()
    if end == 0:
        return None
    fb = f
    block, buf, pos = 1 << 16, b"", end
    while pos > 0:
        step = min(block, pos)
        pos -= step
        fb.seek(pos)
        buf = fb.read(step) + buf
        lines = buf.split(b"\n")
        # lines[0] may be partial unless we reached the start of the file
        complete = lines if pos == 0 else lines[1:]
        for raw in reversed(complete):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw.decode("utf-8"))
                if isinstance(rec, dict) and "hash" in rec and "seq" in rec:
                    return rec
            except Exception:
                continue  # torn or corrupt line: keep looking further back
        if pos > 0:
            buf = lines[0]  # carry the partial head into the next read
    return None


def load_policy(path=None):
    """(policy, error). A missing file means no rules; an unreadable one is reported,
    never silently treated as 'no rules'."""
    path = path or POLICY
    if not os.path.exists(path):
        return {}, None
    try:
        with open(path, encoding="utf-8") as f:
            pol = json.load(f)
        for section in ("deny", "flag"):
            for rule in pol.get(section, []):
                re.compile(rule["pattern"])
                re.compile(rule.get("tool", ".*"))
        return pol, None
    except Exception as e:  # invalid JSON or regex
        return {}, f"policy file unusable: {e}"


class locked:
    """Exclusive inter-process lock on ~/.tracekit/<name>.lock."""
    def __init__(self, name):
        self.path = os.path.join(HOME, name + ".lock")

    def __enter__(self):
        os.makedirs(HOME, exist_ok=True)
        self.f = open(self.path, "a")
        try:
            lock_file(self.f)
        except BaseException:
            self.f.close()
            raise
        return self

    def __exit__(self, *a):
        try:
            unlock_file(self.f)
        finally:
            self.f.close()


def append(events, path=None):
    """Append events to the hash-chained ledger under an exclusive lock (binary I/O)."""
    path = path or LEDGER
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "ab+") as f:
        lock_file(f)
        try:
            last = _last_record(f)
            prev = last["hash"] if last else GENESIS
            seq = last["seq"] + 1 if last else 0
            f.seek(0, os.SEEK_END)
            out = []
            if f.tell() > 0:
                f.seek(-1, os.SEEK_END)
                if f.read(1) != b"\n":
                    out.append(b"\n")  # isolate a torn line so it cannot merge with ours
            for ev in events:
                rec = {"seq": seq, "ts": time.time(), **redact(ev), "prev": prev}
                rec["hash"] = record_hash(rec)
                out.append((json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8"))
                prev, seq = rec["hash"], seq + 1
            f.seek(0, os.SEEK_END)
            f.write(b"".join(out))
            f.flush()
            os.fsync(f.fileno())
        finally:
            unlock_file(f)


def read_ledger(path=LEDGER):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue  # torn/corrupt line: verify.py reports it
    return out


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)
