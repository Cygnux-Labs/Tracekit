"""The Postgres store's tables and each role's grants (tracekit.storage.postgres), without psycopg: `tracekit deploy
compose` writes them into the stack's init script."""
VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS tracekit_schema (version int NOT NULL);
CREATE TABLE IF NOT EXISTS tracekit_records (seq bigint PRIMARY KEY, tenant text NOT NULL, run_id text NOT NULL,
    run_seq bigint NOT NULL, hash text NOT NULL, record json NOT NULL, UNIQUE (tenant, run_id, run_seq));
CREATE TABLE IF NOT EXISTS tracekit_registry (tenant text, idx bigint, leaf bytea NOT NULL, PRIMARY KEY (tenant, idx));
CREATE TABLE IF NOT EXISTS tracekit_notes (id bigserial PRIMARY KEY, tree text NOT NULL, size bigint NOT NULL,
    note text NOT NULL);
CREATE INDEX IF NOT EXISTS tracekit_notes_tree ON tracekit_notes (tree, id);
CREATE TABLE IF NOT EXISTS tracekit_anchors (id bigserial PRIMARY KEY, size bigint NOT NULL, anchor text NOT NULL);
CREATE TABLE IF NOT EXISTS tracekit_witness_queue (id int PRIMARY KEY CHECK (id = 1), state text NOT NULL);
CREATE TABLE IF NOT EXISTS tracekit_tiles (tree text, level int, idx bigint, width int, data bytea NOT NULL,
    PRIMARY KEY (tree, level, idx, width));
CREATE TABLE IF NOT EXISTS tracekit_snapshots (size bigint PRIMARY KEY, mac text NOT NULL, body text NOT NULL);
CREATE TABLE IF NOT EXISTS tracekit_meta (key text PRIMARY KEY, value text NOT NULL);
"""
GRANTS = """
GRANT USAGE ON SCHEMA {schema} TO {role};
GRANT SELECT ON tracekit_schema TO {role};
GRANT SELECT, INSERT ON tracekit_records, tracekit_registry, tracekit_notes, tracekit_anchors TO {role};
GRANT USAGE ON SEQUENCE tracekit_notes_id_seq, tracekit_anchors_id_seq TO {role};
GRANT SELECT, INSERT, UPDATE ON tracekit_witness_queue, tracekit_tiles, tracekit_meta TO {role};
GRANT SELECT, INSERT, UPDATE, DELETE ON tracekit_snapshots TO {role};
"""
READ_GRANTS = """
GRANT USAGE ON SCHEMA {schema} TO {role};
GRANT SELECT ON tracekit_schema, tracekit_records, tracekit_registry, tracekit_notes, tracekit_anchors, tracekit_tiles,
    tracekit_meta TO {role};
"""
