"""Client side: send events to tracekitd over its local transport. Runs as the agent's user and
never writes the ledger. Its own small state (per-run counters, pending gaps) is agent-writable
by design: tampering with it only produces capture.gap events on the signer side."""
import hashlib
import json
import os
import socket
import time
from urllib.parse import urlsplit

from .core import now_ts, scrub
from .locking import lock_file, unlock_file

DEFAULT_SOCKET = "/var/lib/tracekit/tracekitd.sock"


class SignerUnavailable(Exception):
    pass


def client_dir():
    d = os.environ.get("TRACEKIT_CLIENT_HOME") or os.path.join(os.path.expanduser("~"), ".tracekit-client")
    os.makedirs(os.path.join(d, "runs"), exist_ok=True)
    return d


SYSTEM_CONFIG = "/etc/tracekit/client.json"


class SystemConfigError(RuntimeError):
    """/etc/tracekit/client.json exists but cannot be trusted or read: the client must fail closed."""


def system_config():
    """The root-owned client config written by `sudo tracekit init` (0.2.1), or None when there is none.

    When it exists it is the only source of the signer address, policy path and fail mode: the agent's own
    ~/.tracekit-client/config.json and TRACEKIT_SOCKET are ignored, so the agent cannot point its hooks at a
    signer it runs itself. A file that exists but is unreadable, malformed, not owned by root, or writable by
    others raises SystemConfigError instead of falling back to the agent's own settings.
    Windows has no root-owned config (no os.getuid): system mode is unsupported there and the file is ignored."""
    if not hasattr(os, "getuid"):
        return None
    try:
        st = os.stat(SYSTEM_CONFIG)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise SystemConfigError(f"{SYSTEM_CONFIG} cannot be read: {e}") from e
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise SystemConfigError(f"{SYSTEM_CONFIG} must be owned by root and not group- or world-writable")
    try:
        with open(SYSTEM_CONFIG, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        raise SystemConfigError(f"{SYSTEM_CONFIG} cannot be parsed: {e}") from e
    if not isinstance(cfg, dict):
        raise SystemConfigError(f"{SYSTEM_CONFIG} must hold a JSON object")
    return cfg


def system_fail_closed():
    """True in system mode unless the root-owned config explicitly allows fail-open; True when it is untrusted."""
    try:
        sc = system_config()
    except SystemConfigError:
        return True
    return sc is not None and sc.get("fail_mode", "closed") != "open"


def state_name(run_id):
    """Collision-free file name for a run's client state: distinct run ids never share a file."""
    return hashlib.sha256(run_id.encode("utf-8", "surrogatepass")).hexdigest()


def _legacy_state_name(run_id):
    """The file name used before state_name(); read only to carry an existing run's state over."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in run_id)[:120]


def state_file(run_id, suffix):
    """Path of a run's client state file; a file under the legacy name is renamed to it once."""
    runs = os.path.join(client_dir(), "runs")
    path = os.path.join(runs, state_name(run_id) + suffix)
    old = os.path.join(runs, _legacy_state_name(run_id) + suffix)
    if not os.path.exists(path) and os.path.exists(old):
        try:
            os.replace(old, path)
        except OSError:
            pass  # another process moved it first
    return path


def client_config():
    sc = system_config()
    if sc is not None:
        return sc
    p = os.path.join(client_dir(), "config.json")
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            return {}
    return {}


def socket_path():
    sc = system_config()
    if sc is not None:
        return sc.get("socket") or DEFAULT_SOCKET
    return os.environ.get("TRACEKIT_SOCKET") or client_config().get("socket") or DEFAULT_SOCKET


def remote_url_error(url):
    """Why `url` may not receive credentials, or None: https to any host, plain http only to
    localhost, 127.0.0.1 or ::1, and never a URL with userinfo (user@host)."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        parsed.port  # raises ValueError on a malformed port
    except ValueError as e:
        return f"invalid URL: {e}"
    if "@" in parsed.netloc:
        return "URL must not contain user@ credentials"
    if not host:
        return "URL has no host"
    if parsed.scheme == "https" or (parsed.scheme == "http" and host in ("localhost", "127.0.0.1", "::1")):
        return None
    return "URL must use https (plain http only for localhost, 127.0.0.1 or ::1)"


def no_redirect_opener():
    """A urllib opener that bypasses proxies and returns any 3xx as an HTTPError instead of following it,
    so credential headers are never re-sent to a redirect target."""
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _http_rpc(endpoint, cfg, req, timeout):
    """Remote transport: POST the request to an ingest gateway (docs/remote-ingest.md)."""
    import urllib.error
    import urllib.request
    err = remote_url_error(endpoint)
    if err:
        raise SignerUnavailable(f"remote signer endpoint: {err}")
    token = cfg.get("socket_token") or os.environ.get("TRACEKIT_REMOTE_TOKEN")
    if not isinstance(token, str) or not token:
        raise SignerUnavailable("remote endpoint has no token (set it with `tracekit init --remote`)")
    url = endpoint.rstrip("/") + ("" if endpoint.rstrip("/").endswith("/v1/rpc") else "/v1/rpc")
    r = urllib.request.Request(url, data=json.dumps(req, ensure_ascii=False).encode("utf-8"), method="POST",
                               headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    try:
        with no_redirect_opener().open(r, timeout=timeout) as resp:
            return _reply(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except ValueError:
            body = {}
        if e.code in (429, 503):
            body.setdefault("retryable", True)
        return {"ok": False, "error": body.get("error") or f"HTTP {e.code}", **({"retryable": True} if body.get("retryable") else {})}
    except (OSError, ValueError) as e:
        raise SignerUnavailable(str(e)) from e


def _reply(raw):
    """Decode a signer reply; an empty or non-object reply means the signer is unavailable."""
    if not raw.strip():
        raise SignerUnavailable("empty reply from signer")
    out = json.loads(raw)
    if not isinstance(out, dict):
        raise SignerUnavailable("unexpected reply from signer")
    return out


def is_remote(config=None):
    cfg = config if config is not None else client_config()
    return str(cfg.get("socket", "")).startswith(("https://", "http://"))


def _rpc(req, timeout=5.0, config=None):
    req = scrub(req)  # lone surrogates cannot be encoded as UTF-8 for the wire
    cfg = config if config is not None else client_config()
    endpoint = cfg.get("socket", DEFAULT_SOCKET) if config is not None else socket_path()
    if endpoint == "tcp://127.0.0.1:0" and cfg.get("signer_home"):
        # dev TCP signer bound an ephemeral port and recorded it in its own config
        try:
            with open(os.path.join(cfg["signer_home"], "config.json"), encoding="utf-8") as f:
                endpoint = json.load(f).get("socket") or endpoint
        except (OSError, ValueError):
            pass
    request = req
    if endpoint.startswith(("https://", "http://")):
        return _http_rpc(endpoint, cfg, req, max(timeout, 10.0))
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
        for attempt in range(40):  # a full accept queue shows up as EAGAIN (Unix sockets): wait briefly and retry
            try:
                s.connect(address)
                break
            except BlockingIOError:
                if attempt == 39:
                    raise
                time.sleep(0.02 + 0.01 * attempt)
        s.sendall((json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return _reply(buf)
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
        suffix = "" if stream == "hook" else "." + stream
        self.path = state_file(run_id, suffix + ".json")

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
