# Deploying the public witness

`tracekit public-witness serve` (tracekit/public_witness_server.py) behind Caddy, which terminates TLS for one domain
and reads each request body whole (at most 10 KiB) before passing it on (Caddyfile here). Only the compose file passes
`--proxied`, which makes the witness trust X-Forwarded-For: never pass it without a proxy that sets that header.
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

The state must never roll back. A witness restored from an older `state.db` holds older sizes and would cosign a
tree that forks from one it cosigned after the backup, which is exactly what a witness exists to prevent. So a backup
of `state.db` is not a way to restore this witness: if the state is lost, or anything older replaces it, retire the key
and start a new witness (`init` in a fresh volume: a new vkey), and release tracekit with the new vkey in
`tracekit/public_witness.py`. Protect the volume itself (a replicated or snapshotted disk) instead.

## Limits

Set in `tracekit/public_witness_server.py`: bodies of 10 KiB, 100 registrations per client network (IPv4 /24 or
IPv6 /48) a day and 60 in all a minute, 30 checkpoints per origin and client network a minute (429), 8 requests at a
time per client, 100,000 origins (then registration is refused). Origins never cosigned within 24 hours of registering,
or not cosigned for 90 days, are deleted. docs/limits.md lists them with
what a signer sees.
