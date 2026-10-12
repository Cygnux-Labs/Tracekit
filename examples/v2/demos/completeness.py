"""Completeness and tamper evidence: an agent's call is allowed but its result never comes back (the tool hung, the
process died, a post-call hook didn't fire). The signer, which saw the decision, writes a signed
`capture.gap{decided_not_completed}` when the run ends: the missing outcome is in the record, not silently absent.
Then a copy of the bundle with one byte changed (the gap's call id, call-2 to call-1) fails verification. Offline,
on the dev signer.

    python examples/v2/demos/completeness.py
"""
import os
import sys
import zipfile

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import export_and_verify, show, tracekit   # noqa: E402

from tracekit.sdk.client import Client   # noqa: E402


def one_byte_changed(src, dst):
    """A copy of bundle `src` whose gap record's tool_use_id names call-1 where it said call-2."""
    with zipfile.ZipFile(src) as z:
        files = {n: z.read(n) for n in z.namelist()}
    name = next(n for n in files if n.startswith("runs/"))
    lines = files[name].split(b"\n")
    i = next(i for i, line in enumerate(lines) if b'"type":"capture.gap"' in line)
    lines[i] = lines[i].replace(b'"tool_use_id":"call-2"', b'"tool_use_id":"call-1"')
    files[name] = b"\n".join(lines)
    with zipfile.ZipFile(dst, "w") as z:
        for n, data in files.items():
            z.writestr(n, data)


with Client().run(agent="completeness-demo") as run:
    for call_id, command in (("call-1", "ls"), ("call-2", "npm test")):
        d = run.decide(call_id, "Bash", {"command": command})
        print(f"Bash {command!r}: {d['decision']}")
    run.complete("call-1")   # call-2's result never comes back
    print("call-1 completed; call-2 never did, and the run ends")
code = export_and_verify(run.run_id)
bundle = f"{run.run_id}.tkb"
print("\nthe signed records of both calls:")
show(bundle, "policy.decision", "tool.result", "capture.gap")
one_byte_changed(bundle, "tampered.tkb")
p = tracekit("verify", "tampered.tkb", "--trust", "trust.json", check=False)
print("\none byte changed in a copy (the gap's tool_use_id call-2 now reads call-1):\n"
      f"$ tracekit verify tampered.tkb --trust trust.json\n{p.stdout}{p.stderr}", end="")
sys.exit(code or (p.returncode != 1))
