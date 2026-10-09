"""Live scene for the observer video: a dev signer, `tracekit observe`, and four scripted coding agents
(Claude Code, Codex, Cursor, Gemini) fixing a bug side by side. Each is offered a planted instruction to upload
.env; the policy blocks it. Content and reasoning are recorded in clear so the video is readable.

    python docs/demo/observer_scene.py [--port 8799] [--pace 1.2]

Prints the observer URL, runs the agents, then keeps the observer up until Ctrl-C. `record_observer.mjs` records it.
Scripted hook payloads, not models."""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from tracekit import demo, install  # noqa: E402

POLICY = "extends: default\nversion: observer-demo\ncontent_capture: full\nreasoning_capture: true\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--pace", type=float, default=2.5, help="seconds between an agent's actions")
    a = ap.parse_args()
    d = tempfile.mkdtemp(prefix="tk-scene-", dir="/tmp")  # short: the signer's Unix socket lives under it
    home = os.path.join(d, "signer")
    with open(os.path.join(d, "policy.yaml"), "w") as f:
        f.write(POLICY)
    env = dict(os.environ, TRACEKIT_CLIENT_HOME=os.path.join(d, "client"), TRACEKIT_POLICY=os.path.join(d, "policy.yaml"),
               TRACEKIT_DEMO_PACE=str(a.pace), PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    os.environ.update({k: env[k] for k in ("TRACEKIT_CLIENT_HOME", "TRACEKIT_POLICY", "TRACEKIT_DEMO_PACE")})
    install.init_dev(home, [], checkpoint_every=5)
    obs = subprocess.Popen([sys.executable, "-m", "tracekit", "observe", "--home", home, "--port", str(a.port)], env=env)
    try:
        time.sleep(1.5)
        print(f"observer: http://127.0.0.1:{a.port}/", flush=True)
        time.sleep(3)  # let the recorder open the page before the first event
        threads = []
        for i, agent in enumerate(demo.AGENTS):
            os.makedirs(os.path.join(d, agent), exist_ok=True)
            proj = demo._project(os.path.join(d, agent))
            t = threading.Thread(target=demo.scripted, args=(env, proj, agent), daemon=True)
            t.start()
            threads.append(t)
            time.sleep(a.pace * 0.6)  # staggered starts: lanes begin at different times
        for t in threads:
            t.join()
        print("agents done; observer still running (Ctrl-C to stop)", flush=True)
        obs.wait()
    except KeyboardInterrupt:
        pass
    finally:
        obs.terminate()
        install.stop_dev_daemon(home)
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
