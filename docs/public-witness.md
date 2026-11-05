# Deploy the public witness

Tracekit's public C2SP witness is not currently deployed. `URL` and `VKEY` in
`tracekit/public_witness.py` are empty, so Tracekit does not anchor evidence by
default. Until an operator deploys a witness and sets both constants in a
release, `tracekit init --v2` reports this and the verifier reports `NOT
ANCHORED` when no independent anchor covers a bundle.

This procedure deploys the server in `deploy/public-witness/` on a generic
Linux VM with Docker Compose v2. It assumes you have a DNS name pointing to the
VM and can allow inbound TCP ports 80 and 443 in both the cloud firewall and
the VM firewall.

1. Install Docker Engine and its Compose plugin using Docker's instructions
   for your Linux distribution. Confirm `docker compose version` works, then
   log in as a user allowed to run Docker.
2. Clone Tracekit on the VM and enter the deployment directory:

   ```bash
   git clone https://github.com/Cygnux-Labs/Tracekit.git
   cd Tracekit/deploy/public-witness
   export DOMAIN=witness.example.org
   ```

   Replace `witness.example.org` with the DNS name that resolves to this VM.
3. Build the image and create the witness key in the persistent Docker volume:

   ```bash
   docker compose build
   docker compose run --rm witness init --home /data --name "$DOMAIN/w1"
   ```

   Save the printed `vkey` and fingerprint in your deployment records. Keep
   `witness.key` private. The key name is conventionally `$DOMAIN/w1`.
4. Start the witness and Caddy TLS proxy:

   ```bash
   docker compose up -d
   docker compose ps
   curl -fsS "https://$DOMAIN/stats"
   ```

   Caddy obtains and renews the certificate. The witness listens only on the
   private Docker network; only Caddy publishes ports 80 and 443.
5. Release a Tracekit build with the deployment URL and exact vkey in
   `tracekit/public_witness.py`:

   ```python
   URL = "https://witness.example.org"
   VKEY = "witness.example.org/w1+<id>+<key>"
   ```

   Until that release is installed, no Tracekit signer uses this deployment
   automatically. Validate a deployment with `./smoke.sh` from this directory;
   each run registers a throwaway origin.

## State and recovery

The `witness-data` volume contains `witness.key`, `witness.vkey`, and
`state.db`. Back up the private key offline. The database must never be rolled
back: if it is lost or restored to an older state, retire this key and deploy a
fresh witness with a new vkey. Restoring old witness state could make a fork
appear valid. Protect and monitor the VM and volume accordingly.

The server limits request bodies to 10 KiB, registrations to 100 per client
network per day and 60 total per minute, checkpoint growth to 30 per origin
and client network per minute, concurrent requests to 8 per client, and total
origins to 100,000. Registrations without a cosigned checkpoint expire after
24 hours; inactive origins expire after 90 days. See [limits](limits.md).
