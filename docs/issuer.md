# Record-key issuer

A v2 signer signs records with a record key. By default that key is a file, `keys/record.key`, pinned for the life of
the log. With an issuer, the signer instead signs with short-lived record keys. A separate service certifies each
key and holds the CA key; the signer never does. Every certificate is published to a witness before the signer gets
it back, so a certificate the issuer handed out in secret can't verify.

```
signer ──(new key + proof of possession)──▶ issuer ──(certificate leaf)──▶ issuance log ──▶ witness cosigns
signer ◀──(certificate, inclusion proof, cosigned checkpoint)── issuer
signer: signer.epoch{keys: [{kid, alg, spki, cert}]} then key.retire{previous kid, last_seq}
```

## Certificates

A certificate is a small signed JSON document, not X.509 (`tracekit/format/cert.py`):

```json
{"cert": {"kid": "sha256:…", "spki": "<base64 DER>", "log_id": "…", "tenants": ["acme"],
          "not_before": 1791547200, "not_after": 1791633600, "serial": "<hex>"},
 "sig": "<base64 Ed25519 by the CA key over {…cert, \"t\": \"tracekit.cert.v2\"}>"}
```

Times are unix seconds. `not_before` is set `BACKDATE_S` (300 s) in the past, so a signer whose clock runs a little
behind the issuer's still signs inside the validity window. A revocation is `{"revocation": {"serial", "last_seq"?},
"sig"}`, signed by the CA key under the `tracekit.retire.v2` tag. Without `last_seq` it covers every record of the key.
With `last_seq`, it covers only the records after that seq.

Each certificate and each revocation is a leaf of the issuer's **issuance log**. The leaf data is SHA-256 of the
document's canonical JSON. The log is a C2SP checkpointed RFC 6962 tree like the signer's, signed by its own log key
(not the CA key). The issuer answers a request with the issuance entry
`{certificate, index, inclusion, checkpoint}`, and only once at least one configured witness has cosigned a
checkpoint that includes the leaf. If no witness cosigns, the request fails with `unavailable` and nothing is
returned. The leaf stays in the log, and the next checkpoint covers it.

## Running the issuer

```
tracekit issuer serve  --config issuer.yaml
tracekit issuer vkey   --config issuer.yaml          # {"vkey", "issuance_log_vkey"}: the trust config's issuers entry
tracekit issuer revoke SERIAL [--last-seq N] --config issuer.yaml
```

```yaml
data_dir: /var/lib/tracekit-issuer         # keys/ca.key, keys/log.key, issuance.jsonl
http: {listen: 0.0.0.0:8444, cert: tls/issuer.pem, key: tls/issuer.key,
       client_ca: {acme.org: tls/acme-ca.pem}, authenticators: [mtls, k8s_sa]}
name: issuer.example.org                    # the CA key's vkey name
origin: issuer.example.org/issuance         # the issuance log's origin
ca_key: {aws_kms: {key_id: alias/tracekit-ca, region: eu-west-1}}    # default keys/ca.key
log_key: {aws_kms: {key_id: alias/tracekit-issuance, region: eu-west-1}}   # default keys/log.key
witnesses:
  - {url: https://witness.example.org, vkey: "witness.example.org/w1+1234abcd+BA..."}
identities:                                 # identity or prefix:* -> scope
  "mtls:spiffe://acme.org/signer": {log_ids: ["3f2a…"], tenants: [acme], max_ttl_s: 86400}
```

The `http` section is the signer's (mTLS, `k8s_sa` or bearer-token identities; see `tracekit/transport/http.py`).
Every request is checked against the caller's scope: the `log_id` must be listed (or the list must be `["*"]`), every
requested tenant must be listed, and `ttl_s` must be in `1..max_ttl_s`. A caller with no entry gets nothing. A request
must also carry a proof of possession: the requested key's signature over `cert.pop_message(spki, log_id, tenants,
ttl_s)`. Any failed check is answered `forbidden` (`invalid_request` for a malformed request).

A new signer's `log_id` is random and stays unknown until the log's first record is written. Start such a signer under
`log_ids: ["*"]`, read its `log_id` from its first record or its default origin `tracekit.local/<log_id>`, then
narrow the scope.

Keep the CA key where the signer's credentials can't reach it. In AWS, grant `kms:Sign` on the CA key to the issuer's
role only, never to the signer's.

## The signer

```yaml
record_key:
  issuer:
    url: https://issuer.internal:8444
    vkey: "issuer.example.org+…"                # from `tracekit issuer vkey`
    issuance_log_vkey: "issuer.example.org/issuance+…"
    tenants: [acme]                             # every tenant this signer writes records for
    ttl_s: 86400
    cert: tls/signer.pem                        # mTLS client certificate (or token_file: a bearer token)
    key: tls/signer.key
    ca: tls/issuer-ca.pem
```

At every start, and once two thirds of the current certificate's validity have passed, the signer:

1. generates a fresh record key in memory (it is never written to disk);
2. gets the key certified, and checks the answer against the pinned `vkey` and `issuance_log_vkey`;
3. writes a `signer.epoch` that carries the issuance entry, signed by the new key, followed by `key.retire` of the
   previous key with `last_seq` set to the record before the epoch.

If the issuer can't be reached at start, the signer does not start. If renewal fails, the signer retries every 60 s
and keeps signing with the current key. Records written after that key's `not_after` fail verification.
`tracekit signer fsck` checks each record against the certified keys the log declared. Without `record_key`, the
pinned file key path is unchanged.

## Verifying

Pin the issuer in the trust config:

```json
{"logs": ["…"], "witnesses": [{"vkey": "witness.example.org/w1+…", "class": "customer"}], "algs": ["ed25519"],
 "issuers": [{"vkey": "issuer.example.org+…", "issuance_log_vkey": "issuer.example.org/issuance+…"}]}
```

A key whose `signer.epoch` entry has a `cert` is declared only when all of these hold: the certificate is signed by a
pinned issuer; it names that key and the log's `log_id`; it is included in that issuer's issuance log at a checkpoint
signed by the issuance log key and cosigned by `max(1, witnesses_required)` pinned witnesses. If any of these fails,
`keys` fails, and the key's records fail `signatures` with `unknown kid`. Each record under a certified key must also
have its `ts` inside the certificate's validity window, and its tenant among the certificate's tenants. The signer's
own records are exempt from the tenant check. The `key assurance` line then reads `certified: n of m record key(s)`.

Revocations come from the verifier's side, never from the bundle:

```
tracekit verify run.tkb --trust trust.json --revocations issuance.jsonl
```

A `--revocations` file is JSON lines. The issuer's `issuance.jsonl` works as is; lines that are not revocations are
ignored, and a revocation no pinned issuer signed is a warning. Records of a revoked key after the revocation's
`last_seq` make the verdict `UNVERIFIABLE (key revoked)` (exit 2), not `FAILED`, unless another check fails.

## Limits

All limits: [limits.md](limits.md).

- `tracekit monitor` still flags each `signer.epoch` after seq 0 as a key announcement it was not told about. A
  rotating signer's kids can't be listed in advance with `--allow KID`, so expect those conflicts until the monitor
  can pin issuers.
- The issuer handles one issuance at a time and re-reads `issuance.jsonl` for each one. That is fine for record-key
  volumes; past ~100k certificates it needs an index and tiles.
- The verifier does not fetch revocations itself; pass the issuer's log, or a copy of it, with `--revocations`.
