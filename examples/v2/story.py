"""What the v2 examples share: the shell commands their mock models ask for, approving an `ask`, and exporting and
verifying the finished run.

With `--scripted` each approval is given from a second process (`tracekit approvals approve`), as a person would;
without it the example waits for you to approve from another terminal.
"""
import contextlib
import os
import subprocess
import sys
import threading
import time

SCRIPTED = "--scripted" in sys.argv
SAFE, RISKY, HELD = "ls", "sudo rm -rf /", 'echo "unterminated'   # allow; deny (TK-D001); ask (TK-SHELL-PARSE)


def tracekit(*argv, check=True):
    p = subprocess.run([sys.executable, "-m", "tracekit", *argv], capture_output=True, text=True)
    if check and p.returncode:
        sys.exit(f"tracekit {' '.join(argv)} failed:\n{p.stdout}{p.stderr}")
    return p


@contextlib.contextmanager
def approver(client, run_id):
    """While inside: each approval the run requests is approved (--scripted) or shown for a person to answer."""
    stop, seen = threading.Event(), set()

    def watch():
        while not stop.wait(0.1):
            for a in client.approval_list({"run_id": run_id})["approvals"]:
                if a["state"] != "requested" or a["approval_id"] in seen:
                    continue
                seen.add(a["approval_id"])
                if SCRIPTED:
                    print(tracekit("approvals", "approve", a["approval_id"]).stdout.strip(), flush=True)
                else:
                    print(f"{a['tool']} waits for a person. In another terminal:\n"
                          f"  tracekit approvals show {a['approval_id']}\n"
                          f"  tracekit approvals approve {a['approval_id']}    # or reject", flush=True)
    t = threading.Thread(target=watch, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join()


def wait(run, approval_id):
    """The approval's final state: approved, rejected or expired."""
    state = "requested"
    while state == "requested":
        state = run.call("approval_wait", approval_id=approval_id, timeout_ms=60000)["state"]
    return state


def export_and_verify(run_id):
    """Export the closed run once the signer has finalised it (a few seconds after it closes), verify it against this
    signer's pinned key and print the report. Returns the verifier's exit code."""
    out = f"{run_id}.tkb"
    tracekit("signer", "trust", "-o", "trust.json")
    deadline = time.monotonic() + 30
    while True:
        if os.path.exists(out):
            os.remove(out)
        tracekit("export", "--v2", "--run", run_id, "-o", out)
        p = tracekit("verify", out, "--trust", "trust.json", check=False)
        if "Integrity: VERIFIED." in p.stdout or time.monotonic() > deadline:
            break
        time.sleep(0.5)
    print(f"\n$ tracekit verify {out} --trust trust.json\n{p.stdout}{p.stderr}", end="")
    return p.returncode
