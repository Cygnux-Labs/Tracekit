"""Shared helpers: paths, redaction, canonical hashing, ledger append/read."""
import hashlib
import json
import os
import re
import time

try:
    import fcntl  # Unix only
except ImportError:  # pragma: no cover
    fcntl = None

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
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size == 0:
        return None
    chunk = min(size, 1 << 20)
    f.seek(size - chunk)
    lines = f.read().splitlines()
    for line in reversed(lines):
        line = line.strip()
        if line:
            try:
                return json.loads(line)
            except Exception:
                return None
    return None


def append(events):
    """Append events to the hash-chained ledger under an exclusive lock."""
    os.makedirs(HOME, exist_ok=True)
    with open(LEDGER, "a+", encoding="utf-8") as f:
        if fcntl:
            fcntl.flock(f, fcntl.LOCK_EX)
        try:
            last = _last_record(f)
            prev = last["hash"] if last else GENESIS
            seq = last["seq"] + 1 if last else 0
            f.seek(0, os.SEEK_END)
            for ev in events:
                rec = {"seq": seq, "ts": time.time(), **redact(ev), "prev": prev}
                rec["hash"] = record_hash(rec)
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                prev, seq = rec["hash"], seq + 1
            f.flush()
            os.fsync(f.fileno())
        finally:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_UN)


def read_ledger(path=LEDGER):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
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
