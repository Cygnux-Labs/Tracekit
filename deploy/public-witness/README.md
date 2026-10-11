# Deploying the public witness

`tracekit public-witness serve` (tracekit/public_witness_server.py) behind Caddy, which terminates TLS for one domain.
Signers opt in with `witnesses: [public]` once the two constants in `tracekit/public_witness.py` name this deployment
(docs/witnesses.md, "The public witness"). It stores, per log origin, the log's key, the latest cosigned size and root
and when it last cosigned; no request is logged and no client address is stored.

Needs a host with Docker Compose, ports 80 and 443 open, and a DNS name (`DOMAIN` below) pointing at it.

## Steps

From the repo root:

1. Build and create the key (once; the name is the witness's key name, by convention `<domain>/<id>`):

   ```bash
   cd deploy/public-witness
   export DOMAIN=witness.example.org
   docker compose build
   docker compose run --rm witness init --home /data --name "$DOMAIN/w1"
   ```

   It prints the cosignature vkey, `witness.example.org/w1+<id>+<key>`. Running `init` again prints the same vkey.

2. Start it:

   ```bash
   docker compose up -d
   ```

3. Read the vkey again at any time: `docker compose run --rm witness init --home /data --name "$DOMAIN/w1"`.

4. Set the two constants in `tracekit/public_witness.py` and release:

   ```python
   URL = "https://witness.example.org"
   VKEY = "witness.example.org/w1+<id>+<key>"
   ```

5. Check it:

   ```bash
   curl -fsS "https://$DOMAIN/stats"          # {"origins_7d": 0, "weeks": {}}
   ./smoke.sh "https://$DOMAIN" "<vkey>"      # registers a throwaway log and verifies its cosignature
   ```

   Each smoke run adds one origin, which `/stats` counts.

## Backup

The `witness-data` volume holds everything: `witness.key` (the signing key: losing it means a new vkey and a new
release; leaking it lets anyone cosign as this witness), `witness.vkey` and `state.db` (SQLite: each origin's key and
latest cosigned size and root). Back up the key once, offline:

```bash
docker run --rm -v tracekit-public-witness_witness-data:/data -v "$PWD":/out alpine tar czf /out/witness-key.tgz -C /data witness.key witness.vkey
```

Back up the state daily with SQLite's online backup, so a copy taken while it runs is consistent:

```bash
docker compose exec witness python -c "import sqlite3; sqlite3.connect('/data/state.db').backup(sqlite3.connect('/data/state.bak.db'))"
docker compose cp witness:/data/state.bak.db "state-$(date +%F).db"
```

Restoring an older `state.db` rolls origins back to older sizes: the witness then answers those logs with 409 and the
size it holds, and they catch up with a consistency proof, so nothing forks; a log registered after the backup
registers again on its next checkpoint.

## Limits

Set in `tracekit/public_witness_server.py`: bodies of 10 KiB, 100 registrations per client network (IPv4 address or
IPv6 /64) a day, 30 checkpoints per origin a minute (429), 100,000 origins (then registration is refused). docs/limits.md lists them with
what a signer sees.
