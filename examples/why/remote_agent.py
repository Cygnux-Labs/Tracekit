"""Ship events from an agent process to a `tracekit view --why` collector.

    TRACEKIT_VIEW_TOKEN=dev-token tracekit view --why runs-server --port 7788 \
        --allow-program tracekit.why.demo:SYSTEM                                            # terminal 1
    python examples/why/remote_agent.py                                                     # terminal 2
    open "http://127.0.0.1:7788/?token=dev-token"

The collector checks the token, every event hash, the link to the previously stored event and
every blob hash before it writes anything.
"""
from tracekit.why.core import HttpSink
from tracekit.why.demo import SYSTEM

for seed in range(3):
    run = SYSTEM.run(seed=seed, run_id=f"remote-{seed}", sink=HttpSink("http://127.0.0.1:7788", "dev-token"),
                     signer=False)
    print("sent", run.run_id, len(run.events), "events")
