#!/bin/sh
# Runs once, when the Postgres volume is created: the signer's and the viewer's login roles, with the passwords
# `tracekit deploy compose` wrote. 20-schema.sql then creates the tables and grants each role its set.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v signer="$(cat /run/secrets/pg-signer.password)" -v viewer="$(cat /run/secrets/pg-viewer.password)" <<'SQL'
CREATE ROLE tracekit_signer LOGIN PASSWORD :'signer';
CREATE ROLE tracekit_viewer LOGIN PASSWORD :'viewer';
SQL
