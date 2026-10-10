"""`tracekit deploy compose [--dir DIR]`: write the compose stack of deploy/compose/ (docs/deploy-compose.md).

Copies the templates, then writes signer.yaml (Postgres storage, the stack's witness pinned with --witness-class),
policy.yaml (the server pack, yours to edit), viewer.yaml, the witness's key (secrets/witness.key for omniwitness, secrets/witness.ssh for litewitness: one key),
the Postgres passwords and the signer's and viewer's DSNs (secrets/, 0600) and postgres/20-schema.sql (the tables of
tracekit.storage.postgres and each role's grants). Run as root, each secret is owned by the uid of the one container
that reads it (compose bind-mounts secret files as they are on the host).

Idempotent: keys, passwords and policy.yaml already there are kept, every other file must equal what this run would write, and a
file that differs stops the run before anything is written. Needs a source checkout: the stack builds its images
from it.
"""
import argparse
import base64
import os
import secrets
import sys

from tracekit.deploy import files
from tracekit.format import checkpoint

SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEMPLATES = os.path.join(SRC, "deploy", "compose")
COPIED = ("docker-compose.yaml", ".env.example", "witness/Dockerfile", "witness/entrypoint.sh", "postgres/10-roles.sh")
SIGNER_UID, WITNESS_UID, POSTGRES_UID = 10001, 10002, 999   # the signer image, witness/Dockerfile, postgres image
OWNERS = {"signer.dsn": SIGNER_UID, "viewer.dsn": SIGNER_UID, "witness.key": WITNESS_UID, "witness.ssh": WITNESS_UID,
          "pg-admin.password": POSTGRES_UID, "pg-signer.password": POSTGRES_UID, "pg-viewer.password": POSTGRES_UID}
CLASSES = ("public", "customer", "tracekit", "operator")


def _signer_yaml(witness_vkey, witness_class):
    return f"""# Written by `tracekit deploy compose`. Every key: the docstring of tracekit/signer/service.py.
data_dir: /var/lib/tracekit-signer
socket: /run/tracekit-signer/signer.sock     # in the volume only the agent service shares
socket_mode: "0666"                          # the agent's uid connects; its identity is its peer uid
durability: ack-on-fsync
storage: {{postgres: {{dsn_file: /run/secrets/signer.dsn}}}}
tenants: {{"uid:1000": default}}               # the agent service's uid
metrics: {{listen: 0.0.0.0:9464, allow_remote: true}}   # /metrics and the /logs/v0 list the witness polls
policy: /etc/tracekit/policy.yaml            # ./policy.yaml
witnesses:                                   # class {witness_class}: docs/deploy-compose.md says which to use
  - {{url: "http://witness:8080", vkey: "{witness_vkey}", class: {witness_class}}}
"""


POLICY_YAML = """# Written once by `tracekit deploy compose`, then yours: a rerun keeps it (docs/policy-v2.md).
# The signer's policy: the image's server pack (packs/ is tracekit/policy2/packs). Map your tools under `tools` and
# redefine a rule by id to change it.
extends: packs/server.yaml
"""

VIEWER_YAML = """# Written by `tracekit deploy compose`: the viewer reads the store as the SELECT-only role.
data_dir: /tmp/tracekit-view
storage: {postgres: {dsn_file: /run/secrets/viewer.dsn}}
"""


def _schema_sql():
    from tracekit.storage import pg_schema as postgres
    return ("-- Written by `tracekit deploy compose` from tracekit.storage.postgres: the tables, then each role's grants.\n"
            "CREATE SCHEMA tracekit;\nSET search_path TO tracekit;\n" + postgres.SCHEMA
            + f"INSERT INTO tracekit_schema VALUES ({postgres.VERSION});\n"
            + postgres.GRANTS.format(schema="tracekit", role="tracekit_signer")
            + postgres.READ_GRANTS.format(schema="tracekit", role="tracekit_viewer"))


def _dsn(role, password):
    return f"host=postgres dbname=tracekit user={role} password='{password}' options='-csearch_path=tracekit'\n"


def _note_key(name, seed):
    """omniwitness's key file: a note signing key, PRIVATE+KEY+<name>+<key id>+<base64(0x01 || seed)>."""
    from tracekit import crypto
    kid = checkpoint.key_id(name, checkpoint.ED25519, crypto.public_from_secret(seed)).hex()
    return f"PRIVATE+KEY+{name}+{kid}+{base64.b64encode(bytes([checkpoint.ED25519]) + seed).decode()}\n"


def _ssh_key(seed):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def plan(out, witness_name, witness_class):
    """{relative path: (content, mode)} of the stack in `out`, keeping the keys and passwords already there."""
    from tracekit import crypto
    secret = lambda name: _read(os.path.join(out, "secrets", name))   # noqa: E731
    want = {}
    for rel in COPIED:
        src = os.path.join(TEMPLATES, rel)
        want[rel] = (_read(src), 0o755 if os.access(src, os.X_OK) else 0o644)
    key = secret("witness.key")
    if key:
        _, _, witness_name, _, raw = key.strip().split("+", 4)   # the key's name wins over --witness-name
        seed = base64.b64decode(raw)[1:]
    else:
        seed = os.urandom(32)
    vkey = checkpoint.vkey(witness_name, checkpoint.COSIGNATURE, crypto.public_from_secret(seed))
    pw = {r: secret(f"pg-{r}.password") or secrets.token_urlsafe(24) + "\n" for r in ("admin", "signer", "viewer")}
    want.update({
        "signer.yaml": (_signer_yaml(vkey, witness_class), 0o644),
        "policy.yaml": (_read(os.path.join(out, "policy.yaml")) or POLICY_YAML, 0o644),
        "viewer.yaml": (VIEWER_YAML, 0o644),
        "witness.vkey": (vkey + "\n", 0o644),
        "postgres/20-schema.sql": (_schema_sql(), 0o644),
        "secrets/witness.key": (key or _note_key(witness_name, seed), 0o600),
        "secrets/witness.ssh": (secret("witness.ssh") or _ssh_key(seed), 0o600),
        "secrets/signer.dsn": (_dsn("tracekit_signer", pw["signer"].strip()), 0o600),
        "secrets/viewer.dsn": (_dsn("tracekit_viewer", pw["viewer"].strip()), 0o600),
        **{f"secrets/pg-{r}.password": (p, 0o600) for r, p in pw.items()},
    })
    yaml = want["docker-compose.yaml"][0]
    want["docker-compose.yaml"] = (yaml.replace("context: ../..", f"context: {SRC}"), 0o644)
    return want


def write(out, want):
    """Write the files of `want` missing from `out`; returns (written, kept). Raises ValueError, writing nothing,
    when a file there differs."""
    changed = [rel for rel, (data, _) in want.items() if _read(os.path.join(out, rel)) not in (None, data)]
    if changed:
        raise ValueError(f"{out}: changed since it was written, not overwritten: {', '.join(sorted(changed))}")
    written = [rel for rel in want if _read(os.path.join(out, rel)) is None]
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    os.makedirs(out, exist_ok=True)
    for rel in written:
        data, mode = want[rel]
        sub, name = os.path.split(rel)
        top = files.open_dir(out)
        d = files.subdir(top, sub, 0o700 if sub == "secrets" else 0o755) if sub else top
        try:
            uid = OWNERS.get(name) if root else None
            files.write(d, name, data.encode("utf-8"), mode, uid, uid)
        finally:
            files.close(d)
            if d != top:
                files.close(top)
    return written, len(want) - len(written)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit deploy")
    ap.add_argument("target", choices=("compose",),
                    help="compose: write the compose stack (signer, witness, viewer, Postgres, an example agent)")
    ap.add_argument("--dir", default="tracekit-compose", help="where to write it (default ./tracekit-compose)")
    ap.add_argument("--witness-name", default="tracekit.local/compose-witness",
                    help="the witness's key name, in its cosignatures (kept from an existing key)")
    ap.add_argument("--witness-class", choices=CLASSES, default="operator",
                    help="the witness's class in signer.yaml and the trust config: operator (default) when you run "
                         "it yourself; customer, public or tracekit only when someone else runs it")
    a = ap.parse_args(argv)
    out = os.path.abspath(a.dir)
    if not os.path.isfile(os.path.join(TEMPLATES, "docker-compose.yaml")):
        print(f"tracekit deploy compose: no templates at {TEMPLATES}: run it from a source checkout", file=sys.stderr)
        return 2
    try:
        written, kept = write(out, plan(out, a.witness_name, a.witness_class))
    except (OSError, ValueError, checkpoint.NoteError) as e:
        print(f"tracekit deploy compose: {e}", file=sys.stderr)
        return 1
    print(f"wrote {len(written)} file(s) to {out}, {kept} already there")
    if hasattr(os, "geteuid") and os.geteuid() != 0 and any(r.startswith("secrets/") for r in written):
        print("note: not root, so secrets/ is owned by you; on Linux the containers (uids 10001, 10002, 999) can't "
              "read it: run this as root, or chown each file as docs/deploy-compose.md shows", file=sys.stderr)
    print(f"""next:
  cd {out}
  cp .env.example .env                    # ports
  docker compose up -d --build --wait     # docker compose build --build-arg WITNESS=litewitness witness: litewitness
  docker compose run --rm agent           # a run from the example agent service; prints its run id
  docker compose logs viewer              # the viewer's URL and token
docs/deploy-compose.md: what `witnessed` needs (the witness here is class {a.witness_class}).""")
    return 0
