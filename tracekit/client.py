"""Client side: send events to tracekitd over its local transport. Runs as the agent's user and
never writes the ledger. Its own small state (per-run counters, pending gaps) is agent-writable
by design: tampering with it only produces capture.gap events on the signer side."""
import json
import os
import socket
from urllib.parse import urlsplit

from .core import now_ts
from .locking import lock_file, unlock_file

DEFAULT_SOCKET = "/var/lib/tracekit/tracekitd.sock"


class SignerUnavailable(Exception):
    pass


def client_dir():
    d = os.environ.get("TRACEKIT_CLIENT_HOME") or os.path.join(os.path.expanduser("~"), ".tracekit-client")
    os.makedirs(os.path.join(d, "runs"), exist_ok=True)
    return d


def client_config():
    p = os.path.join(client_dir(), "config.json")
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            return {}
    return {}


def socket_path():
    return os.environ.get("TRACEKIT_SOCKET") or client_config().get("socket") or DEFAULT_SOCKET


def _rpc(req, timeout=5.0, config=None):
    cfg = config if config is not None else client_config()
    endpoint = cfg.get("socket", DEFAULT_SOCKET) if config is not None else socket_path()
    request = req
    if endpoint.startswith("tcp://"):
        try:
            parsed = urlsplit(endpoint)
            if (parsed.hostname != "127.0.0.1" or parsed.port is None or not 1 <= parsed.port <= 65535
                    or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
                raise ValueError("TCP signer endpoint must use 127.0.0.1 and an explicit port")
        except ValueError as e:
            raise SignerUnavailable(f"invalid signer endpoint: {e}") from e
        token = cfg.get("socket_token") or os.environ.get("TRACEKIT_SOCKET_TOKEN")
        if not isinstance(token, str) or not token:
            raise SignerUnavailable("TCP signer endpoint has no authentication token")
        address = (parsed.hostname, parsed.port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        request = dict(req, _tracekit_token=token)
    else:
        if not hasattr(socket, "AF_UNIX"):
            raise SignerUnavailable("this Python build has no Unix sockets; initialize Tracekit in dev mode to use TCP")
        address = endpoint
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(address)
        s.sendall((json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf or b"{}")
    except (OSError, ValueError) as e:
        raise SignerUnavailable(str(e)) from e
    finally:
        s.close()


def status():
    return _rpc({"op": "status"})


def rpc(req, timeout=5.0):
    return _rpc(req, timeout)


class _RunLock:
    def __init__(self, run_id, stream="hook"):
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in run_id)[:120]
        suffix = "" if stream == "hook" else "." + stream
        self.path = os.path.join(client_dir(), "runs", safe + suffix + ".json")

    def __enter__(self):
        self.fh = open(self.path + ".lock", "a")
        try:
            lock_file(self.fh)
        except BaseException:
            self.fh.close()
            raise
        try:
            with open(self.path, encoding="utf-8") as f:
                self.state = json.load(f)
        except (OSError, ValueError):
            self.state = {"cseq": -1, "gap": None}
        return self

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.state, f)
        os.replace(tmp, self.path)

    def __exit__(self, *a):
        try:
            unlock_file(self.fh)
        finally:
            self.fh.close()


def send(event, attach=None, stream="hook"):
    """Send one event; returns the signer's response. Raises SignerUnavailable.
    A failed send is remembered so the next successful one is preceded by a capture.gap.
    Each stream (hook, proxy) keeps its own counter per run."""
    run_id = event["run_id"]
    with _RunLock(run_id, stream) as rl:
        gap = rl.state.get("gap")
        try:
            if gap:
                g = {k: event[k] for k in ("run_id", "agent_id", "parent_id")}
                rl.state["cseq"] += 1
                _rpc({"op": "append", "stream": stream, "cseq": rl.state["cseq"], "event": {
                    **g, "source": event.get("source", "hook"), "type": "capture.gap", "ts": now_ts(),
                    "data": {"reason": "signer unavailable (client-reported, fail-open)", "from_ts": gap["from_ts"],
                             "to_ts": gap["to_ts"], "missed_events": gap["missed"], "kind": "signer_down"}}})
                rl.state["gap"] = None
            rl.state["cseq"] += 1
            resp = _rpc({"op": "append", "stream": stream, "cseq": rl.state["cseq"], "event": event, "attach": attach or {}})
            if not resp.get("ok") and resp.get("retryable"):
                raise SignerUnavailable(resp.get("error", "signer could not write"))
            rl.save()
            return resp
        except SignerUnavailable:
            rl.state["cseq"] -= 1  # the signer never saw this counter value
            g = rl.state.get("gap") or {"from_ts": event.get("ts") or now_ts(), "missed": 0}
            g["missed"] += 1
            g["to_ts"] = event.get("ts") or now_ts()
            rl.state["gap"] = g
            rl.save()
            raise
