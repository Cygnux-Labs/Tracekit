#!/bin/sh
# Smoke test of a running public witness: register a throwaway log, get its checkpoint cosigned (the cosignature is
# verified against VKEY), then read /stats. Needs python3 with tracekit installed. Each run adds one origin, which
# /stats counts.
#   deploy/public-witness/smoke.sh https://witness.example.org "witness.example.org/w1+1234abcd+BA..."
set -eu
url=${1:?usage: smoke.sh URL VKEY}
vkey=${2:?usage: smoke.sh URL VKEY}
python3 - "$url" "$vkey" <<'PY'
import os
import sys

from tracekit import crypto, merkle
from tracekit.format import checkpoint
from tracekit.tlog_witness import TlogWitness

url, vkey = sys.argv[1:3]
secret, public = crypto.generate()
origin = "smoke.tracekit.invalid/" + os.urandom(8).hex()
log_vkey = checkpoint.vkey(origin, checkpoint.ED25519, public)
leaves = [merkle.leaf_hash(b"smoke %d" % i) for i in range(3)]
text = checkpoint.body(origin, len(leaves), merkle.root(leaves))
lines = TlogWitness(url, vkey).add_checkpoint(text + "\n" + checkpoint.sign(text, origin, secret), log_vkey, 0,
                                              lambda m: merkle.consistency_proof(m, leaves))
print(f"smoke: {origin} registered and cosigned:\n{lines}", end="")
PY
curl -fsS "$url/stats"
echo
