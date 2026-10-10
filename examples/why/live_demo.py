"""Watch agents live: the demo system, slowed down, recorded into a folder while `tracekit why serve` shows it.

    tracekit why serve runs-live                       # terminal 1, then open the URL it prints
    python examples/why/live_demo.py runs-live block   # terminal 2  (or "alert" to let it through)

Each run appears as it is recorded. The guard checks every sensitive tool call before it executes:
in "block" mode the email to the vendor address (a value only the poisoned vendor note supplied)
is refused, the agent gets an error back, and the app shows a high alert as it happens. The email
to the customer goes through: that address also came from the trusted order lookup.
No API key needed: the models are the demo's seeded mock policies, the tools are fakes.
"""
import sys
import time

from tracekit.why import Guard
from tracekit.why.demo import SYSTEM
from tracekit.why.replay import System


def slow(fn, seconds):
    def wrapped(*a, **kw):
        time.sleep(seconds)
        return fn(*a, **kw)
    return wrapped


def main(out: str = "runs-live", mode: str = "block", runs: int = 6) -> None:
    live = System(program=SYSTEM.program, task=SYSTEM.task, name=SYSTEM.name,
                  sensitive_tools=SYSTEM.sensitive_tools,
                  models={k: slow(f, 1.2) for k, f in SYSTEM.models.items()},
                  tools={k: slow(f, 0.4) for k, f in SYSTEM.tools.items()})

    def on_alert(a):
        verb = "BLOCKED" if a["blocked"] else a["severity"].upper()
        print(f"   [{verb}] {a['agent']}.{a['tool']} {a['args']}: {a['title']}")

    for seed in range(runs):
        run_id = f"live-{time.strftime('%H%M%S')}-s{seed}"
        print(f"{run_id}: running")
        run = live.run(seed=seed, out_dir=out, run_id=run_id, guard=Guard(mode, on_alert=on_alert))
        print(f"{run_id}: done, tools: {', '.join(e['tool'] + ('(blocked)' if e['status'] == 'blocked' else '') for e in run.of_type('action'))}")
        time.sleep(1.5)


if __name__ == "__main__":
    main(*sys.argv[1:3])
