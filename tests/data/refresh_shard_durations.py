"""Rewrite tests/data/shard_durations.json from the logs of one green CI run on main.

    python tests/data/refresh_shard_durations.py RUN_ID

Each test's time is the gap since the previous report of its xdist worker (the shard jobs run pytest -v). A file's
weight is its parallel seconds divided by the workers, plus its serial seconds (the serial step runs alone), averaged
over the Pythons and rounded: the wall time the file adds to its shard's job.
"""
import collections
import datetime
import json
import os
import re
import subprocess
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shard_durations.json")
PARALLEL = re.compile(r"^(\S+)Z \[(gw\d+)\] \[ *\d+%\] \w+(?:\(.*?\))? (tests/\S+?\.py)::")
SERIAL = re.compile(r"^(\S+)Z (tests/\S+?\.py)::\S+ \w+ +\[ *\d+%\]")
COLLECTED = re.compile(r"^(\S+)Z collecting \.\.\. collected \d+ items")


def when(stamp):
    return datetime.datetime.fromisoformat(stamp[:26]).timestamp()


def weights(log):
    """file -> seconds this shard job spent on it, from one job's log."""
    parallel, serial = collections.Counter(), collections.Counter()
    last, workers = {}, set()
    for line in log.splitlines():
        line = line.lstrip("﻿")
        if m := COLLECTED.match(line):
            last["serial"] = when(m[1])
        elif m := PARALLEL.match(line):
            workers.add(m[2])
            if m[2] in last:
                parallel[m[3]] += when(m[1]) - last[m[2]]
            last[m[2]] = when(m[1])
        elif (m := SERIAL.match(line)) and "serial" in last:
            serial[m[2]] += when(m[1]) - last["serial"]
            last["serial"] = when(m[1])
    return {f: parallel[f] / max(len(workers), 1) + serial[f] for f in parallel.keys() | serial.keys()}


def gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def main(run):
    jobs = json.loads(gh("run", "view", run, "--json", "jobs"))["jobs"]
    per_python = collections.defaultdict(collections.Counter)
    for job in jobs:
        if m := re.match(r"py(3\.\d+) on ubuntu-latest \(shard", job["name"]):
            if job["conclusion"] != "success":
                sys.exit(f"{job['name']} did not succeed: use a green run")
            per_python[m[1]].update(weights(gh("api", f"repos/{{owner}}/{{repo}}/actions/jobs/{job['databaseId']}/logs")))
    if not per_python:
        sys.exit("no shard jobs in that run")
    files = set().union(*per_python.values())
    data = {f: max(1, round(sum(p[f] for p in per_python.values()) / len(per_python))) for f in sorted(files)}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=0, sort_keys=True)
        f.write("\n")
    print(f"{len(data)} files, {sum(data.values())} s in {OUT}")


if __name__ == "__main__":
    main(sys.argv[1])
