"""Run inside a box (`tracekit up --isolated`) by tests/test_box.py: tries to reach the signer outside it the ways an
agent would, and prints one line per try. Exit 1 if any try got through.

    python box_probe.py DATA_DIR [SOCKET ...]

DATA_DIR is the box signer's data dir on the host, SOCKET the host's Docker sockets. The box runs it as its first
process, so signalling every process it can reach (stop the signer) signals none of the host's.
"""
import http.client
import json
import os
import signal
import socket
import ssl
import sys


def attempt(name, fn):
    try:
        got = fn()
    except Exception as e:   # every refusal is the point: print what refused it
        print(f"probe {name}: refused ({type(e).__name__}: {str(e)[:120]})")
        return True
    print(f"probe {name}: GOT THROUGH ({str(got)[:200]})")
    return False


def read_key(data_dir):
    with open(os.path.join(data_dir, "keys", "log.key"), "rb") as f:
        return f.read()


def find_key():
    found = [os.path.join(d, n) for d, dirs, names in os.walk("/") for n in names
             if n in ("log.key", "record.key", "server.key", "tokens.json") and not d.startswith(("/proc", "/sys"))]
    if not found:
        raise FileNotFoundError("no signer key or token store anywhere in the box")
    return found


def stop_signer():
    """Signal a signer process the box can see, then every process it can reach."""
    for pid in filter(str.isdigit, os.listdir("/proc")):
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            if b"signer\0serve" in f.read():
                os.kill(int(pid), signal.SIGTERM)
                return f"sent SIGTERM to signer pid {pid}"
    os.kill(-1, signal.SIGTERM)   # ProcessLookupError: nothing but this process to signal
    return "signalled every process it could"


def docker_socket(paths):
    for p in paths:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(p)
            return f"connected to {p}"
        except OSError:
            continue
    for port in (2375, 2376):
        try:
            socket.create_connection(("host.docker.internal", port), timeout=2).close()
            return f"connected to host.docker.internal:{port}"
        except OSError:
            continue
    raise FileNotFoundError(f"no Docker socket at {', '.join(paths)} and no Docker API on host.docker.internal")


def reach(targets):
    """Connect to any of `targets` ((host, port)): the host's services, the VM's sshd, the internet."""
    for host, port in targets:
        try:
            socket.create_connection((host, port), timeout=3).close()
            return f"connected to {host}:{port}"
        except OSError:
            continue
    raise ConnectionRefusedError(f"none of {', '.join(f'{h}:{p}' for h, p in targets)} answered")


def rewrite_store(data_dir):
    with open(os.path.join(data_dir, "store", "records.jsonl"), "ab") as f:
        f.write(b"{}\n")
    return "appended to records.jsonl"


def rpc(method, req):
    """The signer's answer to one raw request, sent with the box's token: past the client's own checks."""
    url = os.environ["TRACEKIT_SIGNER"].split("//", 1)[1]
    host, _, port = url.rpartition(":")
    ctx = ssl.create_default_context(cafile=os.environ["TRACEKIT_SIGNER_CA"])
    with open(os.environ["TRACEKIT_SIGNER_TOKEN_FILE"], encoding="utf-8") as f:
        token = f.read().strip()
    c = http.client.HTTPSConnection(host, int(port), context=ctx, timeout=10)
    c.request("POST", "/v2/rpc", json.dumps({"method": method, **req}),
              {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    out = json.loads(c.getresponse().read())
    if "error" in out:
        raise PermissionError(f"{out['error']['code']}: {out['error'].get('message', '')}")
    return out


def main(data_dir, *sockets):
    ok = all([
        attempt("read the signer's key", lambda: read_key(data_dir)),
        attempt("find a key or token store in the box", find_key),
        attempt("stop the signer", stop_signer),
        attempt("reach the Docker socket", lambda: docker_socket(["/var/run/docker.sock", "/run/docker.sock", *sockets])),
        attempt("rewrite the store", lambda: rewrite_store(data_dir)),
        attempt("reach the host's services", lambda: reach([("host.docker.internal", 22), ("192.168.5.2", 22),
                                                             ("172.17.0.1", 22), ("host.docker.internal", 80)])),
        attempt("reach the internet", lambda: reach([("1.1.1.1", 443), ("example.com", 443)])),
        attempt("claim an isolation", lambda: rpc("register_run", {"request_id": "probe-1", "agent": {"name": "probe"},
                                                                   "signer_isolation": "separate-user"})),
        attempt("answer an approval", lambda: rpc("approval_decide", {"request_id": "probe-2", "approval_id": "a1",
                                                                      "decision": "approve"})),
        attempt("become root", lambda: os.setuid(0)),
    ])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
