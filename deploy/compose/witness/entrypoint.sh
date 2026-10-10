#!/bin/sh
# Run the witness on :8080, registering the signer's logs from the logs/v0 list it serves on its metrics port.
set -eu
logs=http://signer:9464/logs/v0
if command -v omniwitness >/dev/null; then
    exec omniwitness --listen=:8080 --metrics_listen= --db_file=/data/witness.db \
        --private_key_path=/run/secrets/witness.key --rate_limit=10 \
        --public_witness_config_url="$logs" --public_witness_config_poll_interval=10s
fi
# litewitness: its key in a dedicated ssh-agent, the list pulled with witnessctl (it adds logs, never changes them)
ssh-agent -a /tmp/agent.sock >/dev/null
SSH_AUTH_SOCK=/tmp/agent.sock ssh-add -q /run/secrets/witness.ssh
(while sleep 10; do witnessctl pull-logs -db /data/witness.db -source "$logs" || true; done) &
exec litewitness -ssh-agent /tmp/agent.sock -key "$(ssh-keygen -lf /run/secrets/witness.ssh | cut -d' ' -f2)" \
    -name "$(cut -d+ -f3 /run/secrets/witness.key)" -db /data/witness.db -listen :8080
