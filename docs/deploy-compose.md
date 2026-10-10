# The compose stack

`deploy/compose/` runs the v2 signer with a Postgres store, a C2SP witness, the viewer and an example agent on one
Docker host. `tracekit deploy compose` writes a ready-to-run copy with its own keys and passwords.

```sh
sudo tracekit deploy compose --dir /srv/tracekit     # from a source checkout: the stack builds its images from it
cd /srv/tracekit
cp .env.example .env                                  # ports only
docker compose up -d --build --wait
docker compose run --rm agent                         # registers a run from the agent service; prints its run id
docker compose logs viewer                            # the viewer's URL with its token (http://127.0.0.1:7778/?token=...)
```

| Service | What | Reaches |
|---|---|---|
| `signer` | the signer image (deploy/docker/Dockerfile), read-only, uid 10001; keys in the `signer-data` volume | Postgres (`db`), the witness (`witness`) |
| `postgres` | `postgres:17-bookworm`, pinned by digest; the store, on its own network | nothing |
| `witness` | omniwitness built from a pinned commit (`deploy/compose/witness/Dockerfile`), uid 10002 | the signer's `/logs/v0` |
| `viewer` | `tracekit view` as a SELECT-only role, published on 127.0.0.1 only | Postgres |
| `agent` | an example agent, uid 1000, profile `agent` | only the signer's socket (`signer-run` volume, read-only) |

Every network but the viewer's is `internal` (no route out). The agent's network has nothing else on it: the agent
reaches the signer only through the Unix socket in the `signer-run` volume, which no other service mounts, and its
identity is its peer uid (`tenants: {"uid:1000": default}` in signer.yaml). Replace the `agent` service with yours: same
volume mounted read-only (`:ro`: it can connect to the socket but not unlink or replace it), same kind of network, a
uid that is not 10001 or root, no secrets.

## What `deploy compose` writes

| File | |
|---|---|
| `docker-compose.yaml`, `.env.example`, `witness/`, `postgres/10-roles.sh` | the templates, copied (the compose file's build context set to the source checkout) |
| `signer.yaml` | Postgres storage, metrics and `/logs/v0` on the internal network, the stack's witness pinned with its class, `policy: /etc/tracekit/policy.yaml` |
| `policy.yaml` | the signer's policy, mounted at `/etc/tracekit/policy.yaml`: `extends: packs/server.yaml`, the server pack the image ships in `/etc/tracekit/packs` ([policy-v2.md](policy-v2.md#packs-shipped)). Yours to edit (map your tools, redefine rules by id) or replace; a rerun keeps it |
| `viewer.yaml` | the viewer's store: the SELECT-only role's DSN |
| `postgres/20-schema.sql` | the store's tables (`tracekit.storage.postgres`) and each role's grants: the signer's role inserts and selects on the logs, never updates or deletes them; the viewer's role selects only |
| `witness.vkey` | the witness's cosignature verifier key |
| `secrets/` (0700; files 0600) | `witness.key` (omniwitness's note key) and `witness.ssh` (the same key for litewitness), the Postgres passwords, the signer's and the viewer's DSNs |

Keys and DSNs reach the containers as compose secrets (files), never environment variables. Compose bind-mounts a
secret file with its host owner and mode, so run `deploy compose` as root: each secret is then owned by the uid of the
container that reads it (signer and viewer 10001, witness 10002, Postgres 999). Not as root, chown them yourself:

```sh
sudo chown 10001 secrets/signer.dsn secrets/viewer.dsn
sudo chown 10002 secrets/witness.key secrets/witness.ssh
sudo chown 999 secrets/pg-*.password
```

Running it again is safe: keys and passwords are kept, files equal to what it would write are left alone, and if any
file was changed it stops and writes nothing. Postgres reads `postgres/` once, when its volume is created.

## The witness

The witness registers the signer's logs from the `logs/v0` list the signer serves on its metrics port (polled every
10 s), so a new tenant's registry log is cosigned too; until it has polled, the signer retries. The signer's first
start writes a signed `degraded_unanchored` gap: the witness does not know its log yet.

litewitness (filippo.io/torchwood v0.10.0) is the alternative build, with the same key:

```sh
docker compose build --build-arg WITNESS=litewitness witness && docker compose up -d witness
```

## What "witnessed" needs

`tracekit verify` reports `Assurance: witnessed` only when a pinned witness whose class is not `operator` cosigned the
bundle's checkpoint (docs/witnesses.md). A witness you run in the same stack is class `operator`, the default of
`deploy compose`: it shows the log was not rewritten behind the witness's back, but whoever runs the stack runs the
witness too, so bundles verify as `local`. For `witnessed`, have someone else run the witness container (your security
team: `customer`; a third party: `public`) on infrastructure you can't change, point `url` in signer.yaml at it, and
write the stack with that class:

```sh
sudo tracekit deploy compose --dir /srv/tracekit --witness-class customer
```

Then export and verify with the trust config of the signer:

```sh
docker compose exec -T signer sh -c 'tracekit signer trust --config /etc/tracekit/signer.yaml -o /tmp/out && cat /tmp/out' > trust.json
docker compose exec -T signer sh -c 'tracekit export --v2 --run RUN_ID --config /etc/tracekit/signer.yaml -o /tmp/out && cat /tmp/out' > run.tkb
tracekit verify run.tkb --trust trust.json
```

A verifier should pin the witness's key from the witness's operator (its `witness.vkey`), not take the signer's word.

## End-to-end test

`deploy/compose/e2e.sh` writes a stack with the witness classed `customer`, brings it up, registers a run from the agent
service, waits for a cosigned checkpoint, exports the run, verifies it at `witnessed` and takes the stack down
(`WITNESS=litewitness` for litewitness). It needs docker and root or passwordless sudo; `tests/test_compose.py` runs it
when both are there.
