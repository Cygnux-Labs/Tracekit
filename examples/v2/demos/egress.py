"""Network coverage: an egress observer outside the agent. The agent's shell call runs an install script, and the script
downloads from a host no call of the run names. Its connections go through `tracekit egress serve` (the run's
proxy_env), which reports hosts, ports and bytes to the signer, never content. The signer records a signed
effect.observed and, since nothing in the run explains that host, a reconcile.unexplained_effect. Offline: the
"outside" host is a web server on this machine, which egress.yaml allows as localhost. The agent is you, on the
signer's Unix socket: the proxy names a run by its token and, on Linux, by the uid of the connection too, and the two
must agree.

    python examples/v2/demos/egress.py
"""
import http.server
import json
import os
import subprocess
import sys
import threading
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import AGENT, Signer, export_and_verify, show   # noqa: E402

from tracekit.sdk.client import Client   # noqa: E402

POLICY = "extends: packs/server.yaml\n"
INSTALL = "import sys, urllib.request; print(urllib.request.urlopen(sys.argv[1]).read().decode().strip())"


class Mirror(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"installed 1 package\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


mirror = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mirror)
threading.Thread(target=mirror.serve_forever, daemon=True).start()
url = f"http://localhost:{mirror.server_address[1]}/pkg"
with Signer(POLICY, {"egress": ["observe_effect"]}, observe_grace_s=1, authorize={
        f"uid:{os.getuid()}": [*AGENT, "checkpoint_nudge"], "token:egress": ["observe_effect"]}) as signer:
    config = os.path.join(signer.dir, "egress.yaml")
    with open(config, "w") as f:   # JSON is YAML
        json.dump({"listen": "127.0.0.1:0", "signer": signer.url, "allow": ["localhost"]}, f)
    proxy = subprocess.Popen([sys.executable, "-m", "tracekit", "egress", "serve", "--config", config],
                             stdout=subprocess.PIPE, text=True,
                             env={**os.environ, "TRACEKIT_SIGNER_TOKEN_FILE": signer.token("egress")})
    os.environ["TRACEKIT_EGRESS_PROXY"] = "http://" + proxy.stdout.readline().split()[-1]   # its address
    time.sleep(1)   # lean: a second for its first heartbeat, which covers the runs after it; poll if hosts miss it
    with Client(os.environ["TRACEKIT_SIGNER"]).run(agent="coding-agent") as run:   # the Unix socket
        args = {"command": "./install.sh"}
        d = run.decide("call-1", "Bash", args)
        print(f"Bash {args['command']!r}: {d['decision']} {' '.join(d['rule_ids'])}".rstrip())
        env = {k: v for k, v in os.environ.items() if k.lower() != "no_proxy"}   # localhost goes through it too
        out = subprocess.run([sys.executable, "-c", INSTALL, url], env={**env, **run.proxy_env}, capture_output=True,
                             text=True)
        print(f"  the script fetched {url}: {out.stdout.strip() or out.stderr.strip()}")
        run.complete("call-1")
        proxy.terminate()   # on SIGTERM the observer reports every total it holds
        proxy.wait()
    code = export_and_verify(run.run_id, signer.config)
print("\nwhat the observer saw and the signer made of it:")
show(f"{run.run_id}.tkb", "policy.decision", "effect.observed", "reconcile.unexplained_effect", "incident.opened")
sys.exit(code)
