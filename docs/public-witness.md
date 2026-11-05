# Deploy the public witness

This page is for the witness's operator. What the witness receives and keeps, for everyone who sends it checkpoints:
[what the public witness sees](public-witness-privacy.md).

The public witness is not deployed yet. `URL` and `VKEY` in `tracekit/public_witness.py` are empty, so Tracekit anchors
nothing by default: `tracekit init --v2` and `tracekit up --wait` say `not anchored`, and verify says `NOT ANCHORED`
when no other independent witness or anchor cosigned a bundle.

The server is `tracekit public-witness serve` (`tracekit/public_witness_server.py`) behind Caddy, which terminates TLS
for one domain and reads each request body whole (at most 10 KiB) before passing it on. The files are in
`deploy/public-witness/`. Only the compose file passes `--proxied`, which makes the witness trust `X-Forwarded-For`:
never pass it without a proxy that sets that header.

You need a Linux VM with Docker Engine and its Compose plugin, a DNS name (`DOMAIN` below) pointing at the VM, and
inbound TCP ports 80 and 443 open in both the cloud firewall and the VM's.

## Steps

1. Get the code and choose the name:

   ```bash
   git clone https://github.com/Cygnux-Labs/Tracekit.git
   cd Tracekit/deploy/public-witness
   export DOMAIN=witness.example.org
   ```

2. Build the image and create the witness key in the `witness-data` volume (once; the key's name is by convention
   `<domain>/w1`):

   ```bash
   docker compose build
   docker compose run --rm witness init --home /data --name "$DOMAIN/w1"
   ```

   It prints the cosignature vkey, `witness.example.org/w1+<id>+<key>`. Running `init` again prints the same vkey.

3. Start it:

   ```bash
   docker compose up -d
   docker compose ps
   ```

   Caddy gets and renews the certificate. The witness listens only on the compose network; only Caddy publishes ports
   80 and 443.

4. Check it:

   ```bash
   curl -fsS "https://$DOMAIN/stats"          # {"origins_7d": 0, "weeks": {}}
   ./smoke.sh "https://$DOMAIN" "<vkey>"      # registers a throwaway log and verifies its cosignature
   ```

   Each smoke run adds one origin, which `/stats` counts.

5. Set the two constants in `tracekit/public_witness.py` and release Tracekit:

   ```python
   URL = "https://witness.example.org"
   VKEY = "witness.example.org/w1+<id>+<key>"
   ```

   Signers use the witness only from that release on.

## Backup

The `witness-data` volume holds everything: `witness.key` (the signing key: losing it means a new vkey and a new
release; leaking it lets anyone cosign as this witness), `witness.vkey` and `state.db` (SQLite: each origin's key and
latest cosigned size and root). Back up the key once, offline:

```bash
docker run --rm -v tracekit-public-witness_witness-data:/data -v "$PWD":/out alpine tar czf /out/witness-key.tgz -C /data witness.key witness.vkey
```

The state must never roll back. A witness restored from an older `state.db` holds older sizes and would cosign a tree
that forks from one it cosigned after the backup, which is exactly what a witness exists to prevent. So a backup of
`state.db` is not a way to restore this witness: if the state is lost, or anything older replaces it, retire the key,
start a new witness (`init` in a fresh volume: a new vkey), and release Tracekit with the new vkey. Protect the volume
itself (a replicated or snapshotted disk) instead.

## Logs

The witness writes no request log and keeps client addresses only in memory. Caddy has no access log configured, but
its error log, which Docker keeps, can name a client's address when a request fails at the proxy. Keep Docker's log
small (`max-size` in `/etc/docker/daemon.json`) and don't ship it anywhere.

## Limits

Set in `tracekit/public_witness_server.py`: bodies of 10 KiB, 100 registrations per client network (IPv4 /24 or IPv6
/48) a day and 60 in all a minute, 30 checkpoints per origin and client network a minute (429), 8 requests at a time
per client, 100,000 origins (then registration is refused). Origins never cosigned within 24 hours of registering, or
not cosigned for 90 days, are deleted. [Limits](limits.md#witnesses-and-monitor) lists them with what a signer sees.
