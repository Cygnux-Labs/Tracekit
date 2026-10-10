"""Record-key issuer (04-design §3): certifies short-lived record keys of v2 signers. docs/issuer.md.

    tracekit issuer serve  --config issuer.yaml
    tracekit issuer revoke SERIAL [--last-seq N] --config issuer.yaml
    tracekit issuer vkey   --config issuer.yaml     # the trust config's `issuers` entry, as JSON

issuer.yaml:
    data_dir: /var/lib/tracekit-issuer         # keys/ (ca.key, log.key) and issuance.jsonl
    http: {listen: 0.0.0.0:8444, ...}           # the signer's `http` section (tracekit/transport/http.py)
    name: issuer.example.org                    # the CA key's name in its vkey
    origin: issuer.example.org/issuance         # the issuance log's checkpoint origin, its log key's name
    ca_key: {aws_kms: {key_id, region}}         # default keys/ca.key (tracekit.signer.logkey backends)
    log_key: {aws_kms: {key_id, region}}        # default keys/log.key
    witnesses: [{url, vkey}]                    # C2SP tlog-witnesses; one must cosign each issuance
    identities:                                 # identity or prefix:* -> scope; no entry: no certificate
      "mtls:spiffe://acme/signer": {log_ids: ["<log_id>"], tenants: [acme], max_ttl_s: 86400}

`log_ids: ["*"]` takes any log_id: a new signer's log_id is random until its first record is written.

A request (POST /v2/rpc) is {"method": "issue", spki, log_id, tenants, ttl_s, pop}: `pop` is the requested key's
signature over format.cert.pop_message. The issuer checks the caller's scope and the proof, signs the certificate with
the CA key (valid from BACKDATE_S before now for ttl_s), appends its leaf to the issuance log (fsync'd), signs a note of
the log with the log key and returns the issuance entry only once a witness cosigned that note. A revocation is
appended and witnessed the same way. Nothing else is served."""
import argparse
import base64
import json
import os
import secrets
import ssl
import sys
import time
import urllib.request

from tracekit import crypto, merkle, yamlmini
from tracekit.client import remote_url_error
from tracekit.format import cert, checkpoint
from tracekit.format.canon import canonical, loads_strict
from tracekit.format.records import RecordSigner, verify_record
from tracekit.locking import lock_file
from tracekit.signer import logkey
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import PREFIX_ENDS, _secret, lookup
from tracekit.storage.file import _mkdir
from tracekit.tlog_witness import TlogWitness

BACKDATE_S = 300   # not_before this far back, for signers whose clock is behind the issuer's
TIMEOUT_S = 30.0
KEYS = {"data_dir", "http", "name", "origin", "ca_key", "log_key", "witnesses", "identities"}
REQUEST = {"method", "spki", "log_id", "tenants", "ttl_s", "pop"}
SIGNER_KEYS = {"url", "vkey", "issuance_log_vkey", "tenants", "ttl_s", "cert", "key", "ca", "token_file"}


def _b64(data):
    return base64.b64encode(data).decode("ascii")


class Issuer:
    def __init__(self, data_dir, name, origin, identities, witnesses, ca_key=None, log_key=None, clock=time.time):
        """`identities` maps identities or prefixes to {log_ids, tenants, max_ttl_s}; `witnesses` are
        tlog_witness.TlogWitness (or objects with its `name` and `add_checkpoint`); `ca_key`, `log_key`: signer.logkey
        keys (default: file keys in data_dir/keys)."""
        keys = os.path.join(data_dir, "keys")
        _mkdir(keys)
        os.chmod(keys, 0o700)
        self.ca = ca_key or logkey.FileKey(_secret(os.path.join(keys, "ca.key"), lambda: crypto.generate()[0]))
        self.log_key = log_key or logkey.FileKey(_secret(os.path.join(keys, "log.key"), lambda: crypto.generate()[0]))
        self.origin, self.identities, self.witnesses, self.clock = origin, identities, list(witnesses), clock
        self.vkey = checkpoint.vkey(name, checkpoint.ED25519, self.ca.public)
        self.log_vkey = checkpoint.vkey(origin, checkpoint.ED25519, self.log_key.public)
        self.path = os.path.join(data_dir, "issuance.jsonl")
        self._sizes = {}   # witness name -> the size it last cosigned

    def handle_frame(self, identity, frame):
        if frame.get("method") != "issue":
            raise RPCError("invalid_request", "the issuer answers `issue` only")
        return self.issue(identity, frame)

    def issue(self, identity, req):
        """The issuance entry of a certificate for the requested key, in the caller's scope; RPCError otherwise."""
        scope = lookup(self.identities, f"{identity.scheme}:{identity.subject}")
        if scope is None:
            raise RPCError("forbidden", f"{identity.scheme}:{identity.subject[:256]} may not get certificates")
        if not (set(req) == REQUEST and all(isinstance(req[k], str) for k in ("spki", "log_id", "pop"))
                and isinstance(req["tenants"], list) and req["tenants"]
                and all(isinstance(t, str) for t in req["tenants"]) and type(req["ttl_s"]) is int):
            raise RPCError("invalid_request", f"issue takes {sorted(REQUEST - {'method'})}")
        try:
            der, pop = base64.b64decode(req["spki"], validate=True), base64.b64decode(req["pop"], validate=True)
        except ValueError:
            raise RPCError("invalid_request", "spki and pop are base64") from None
        if crypto.key_alg(der) != "ed25519":
            raise RPCError("invalid_request", "spki is not an Ed25519 key")
        if not crypto.verify_v2("ed25519", der, cert.pop_message(req["spki"], req["log_id"], req["tenants"],
                                                                  req["ttl_s"]), pop):
            raise RPCError("forbidden", "the proof of possession does not verify under the requested key")
        if "*" not in scope["log_ids"] and req["log_id"] not in scope["log_ids"]:
            raise RPCError("forbidden", f"log_id {req['log_id'][:64]} is out of scope")
        if set(req["tenants"]) - set(scope["tenants"]):
            raise RPCError("forbidden", f"tenants {sorted(set(req['tenants']) - set(scope['tenants']))[:8]} out of scope")
        if not 0 < req["ttl_s"] <= scope["max_ttl_s"]:
            raise RPCError("forbidden", f"ttl_s is 1..{scope['max_ttl_s']}")
        now = int(self.clock())
        body = {"kid": crypto.spki_kid(der), "spki": _b64(der), "log_id": req["log_id"],
                "tenants": sorted(set(req["tenants"])), "not_before": now - BACKDATE_S, "not_after": now + req["ttl_s"],
                "serial": secrets.token_hex(16)}
        return self._publish(self._signed("cert", body))

    def revoke(self, serial, last_seq=None):
        """Append the CA-signed revocation of the certificate `serial` (of its records after `last_seq`, default
        all) and have it witnessed; returns the revocation document. ValueError for an unknown serial."""
        if not any(d.get("cert", {}).get("serial") == serial for d in self.documents()):
            raise ValueError(f"no certificate with serial {serial[:64]} in {self.path}")
        doc = self._signed("revocation", {"serial": serial, **({} if last_seq is None else {"last_seq": last_seq})})
        self._publish(doc)
        return doc

    def documents(self):
        try:
            with open(self.path, "rb") as f:
                return [loads_strict(line) for line in f.read().split(b"\n") if line]
        except FileNotFoundError:
            return []

    def _signed(self, kind, body):
        try:
            return cert.sign(kind, body, self.ca.sign)
        except logkey.KeyUnavailable as e:
            raise RPCError("unavailable", f"CA key: {e}") from None

    def _publish(self, doc):
        """Append `doc` to the issuance log and return its issuance entry once a witness cosigned the log's note."""
        # lean: one issuance at a time, across processes, re-reading the whole log; an index and tiles past ~100k
        # certificates
        with open(self.path, "a+b") as f:
            lock_file(f)
            f.seek(0)
            data = f.read()
            if data and not data.endswith(b"\n"):   # a torn line from a crash, never answered: set aside
                f.truncate(data.rfind(b"\n") + 1)
                data = data[:data.rfind(b"\n") + 1]
            leaves = [merkle.leaf_hash(cert.leaf(loads_strict(line))) for line in data.split(b"\n") if line]
            f.write(canonical(doc) + b"\n")
            f.flush()
            os.fsync(f.fileno())
            leaves.append(merkle.leaf_hash(cert.leaf(doc)))
            text = checkpoint.body(self.origin, len(leaves), merkle.root(leaves))
            try:
                note = text + "\n" + checkpoint.log_line(self.origin, self.log_key.public,
                                                         self.log_key.sign(text.encode("utf-8")))
            except logkey.KeyUnavailable as e:
                raise RPCError("unavailable", f"issuance log key: {e}") from None
            cosigs, errors = "", []
            for w in self.witnesses:
                try:
                    cosigs += w.add_checkpoint(note, self.log_vkey, self._sizes.get(w.name, 0),
                                               lambda n: merkle.consistency_proof(n, leaves))
                    self._sizes[w.name] = len(leaves)
                except Exception as e:   # WitnessError, or anything else: this witness did not cosign
                    errors.append(f"{w.name}: {e}")
        if not cosigs:
            raise RPCError("unavailable", "no witness cosigned the issuance log: " + "; ".join(errors)[:900])
        i = len(leaves) - 1
        return {"certificate": doc, "index": i, "inclusion": [_b64(h) for h in merkle.inclusion_proof(i, leaves)],
                "checkpoint": note + cosigs}


# --- the signer's side ---

def certify(cfg, log_id):
    """(a RecordSigner of a fresh record key, its issuance entry) from the issuer of signer.yaml's
    `record_key.issuer` section `cfg`; the entry is checked against the pinned issuer first."""
    secret = crypto.generate()[0]
    logkey.mlock(secret)
    sign = RecordSigner(secret)
    spki = _b64(sign.spki)
    req = {"method": "issue", "spki": spki, "log_id": log_id, "tenants": cfg["tenants"], "ttl_s": cfg["ttl_s"],
           "pop": _b64(crypto.sign(secret, cert.pop_message(spki, log_id, cfg["tenants"], cfg["ttl_s"])))}
    ctx = None
    if cfg["url"].startswith("https:"):
        ctx = ssl.create_default_context(cafile=cfg.get("ca"))
        if cfg.get("cert"):
            ctx.load_cert_chain(cfg["cert"], cfg.get("key"))
    headers = {"Content-Type": "application/json"}
    if cfg.get("token_file"):
        with open(cfg["token_file"], encoding="utf-8") as f:
            headers["Authorization"] = "Bearer " + f.read().strip()
    with urllib.request.urlopen(urllib.request.Request(cfg["url"].rstrip("/") + "/v2/rpc", json.dumps(req).encode(),
                                                       headers), timeout=TIMEOUT_S, context=ctx) as r:
        out = loads_strict(r.read(1 << 20))
    if "error" in out:
        raise RPCError("unavailable", f"issuer: {out['error'].get('code')}: {str(out['error'].get('message'))[:512]}")
    c, _ = cert.check(out, [cfg])
    if (c["kid"], c["log_id"]) != (sign.kid, log_id):
        raise ValueError("the issuer certified another key or log")
    return sign, out


def record_verifier(cfg):
    """verify(record) for fsck of a signer with `record_key.issuer` section `cfg`: keys are those of signer.epoch
    records whose certificates the pinned issuer signed, from the record that declares them on (records in order)."""
    keys = []

    def verify(r):
        if r["event"].get("type") == "signer.epoch":
            for k in r["event"]["data"].get("keys", []):
                if "cert" in k and cert.check(k["cert"], [cfg])[0]["kid"] == k["kid"]:
                    keys.append(base64.b64decode(k["spki"]))
        verify_record(r, keys, {RecordSigner.alg})
    return verify


def check_signer_section(section, where):
    """Validate signer.yaml's `record_key` section in place, its paths made absolute from `where`'s directory."""
    s = section.get("issuer") if isinstance(section, dict) and set(section) == {"issuer"} else None
    if not (isinstance(s, dict) and {"url", "vkey", "issuance_log_vkey", "tenants", "ttl_s"} <= set(s) <= SIGNER_KEYS
            and isinstance(s["url"], str) and not remote_url_error(s["url"])
            and isinstance(s["tenants"], list) and s["tenants"] and all(isinstance(t, str) for t in s["tenants"])
            and type(s["ttl_s"]) is int and s["ttl_s"] > 0):
        raise ValueError(f"{where}: record_key is {{issuer: {{url, vkey, issuance_log_vkey, tenants, ttl_s, cert?, key?, "
                         "ca?, token_file?}}}}, url https (or http to loopback)")
    for k in ("vkey", "issuance_log_vkey"):
        checkpoint.parse_vkey(s[k])
    base = os.path.dirname(os.path.abspath(where))
    for k in ("cert", "key", "ca", "token_file"):
        if s.get(k):
            s[k] = os.path.join(base, s[k])


# --- tracekit issuer ---

def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not {"data_dir", "name", "origin", "witnesses",
                                                             "identities"} <= set(cfg):
        raise ValueError(f"{path}: needs data_dir, name, origin, witnesses and identities; takes {sorted(KEYS)}")
    base = os.path.dirname(os.path.abspath(path))
    cfg["data_dir"] = os.path.join(base, cfg["data_dir"])
    if "http" in cfg:
        from tracekit.transport import http
        http.resolve(cfg["http"], base)
        http.configure(cfg["http"])
    for k in {"ca_key", "log_key"} & set(cfg):
        kms = cfg[k].get("aws_kms") if isinstance(cfg[k], dict) and set(cfg[k]) == {"aws_kms"} else None
        if not (isinstance(kms, dict) and set(kms) == {"key_id", "region"}
                and all(isinstance(v, str) and v for v in kms.values())):
            raise ValueError(f"{path}: {k} is {{aws_kms: {{key_id, region}}}} (default: keys/{k.split('_')[0]}.key)")
    if not (isinstance(cfg["witnesses"], list) and cfg["witnesses"]
            and all(isinstance(w, dict) and set(w) == {"url", "vkey"} for w in cfg["witnesses"])):
        raise ValueError(f"{path}: witnesses is a non-empty list of {{url, vkey}}")
    ids = cfg["identities"]
    if not (isinstance(ids, dict) and all(
            isinstance(v, dict) and set(v) == {"log_ids", "tenants", "max_ttl_s"}
            and all(isinstance(v[k], list) and all(isinstance(x, str) for x in v[k]) for k in ("log_ids", "tenants"))
            and type(v["max_ttl_s"]) is int and v["max_ttl_s"] > 0 for v in ids.values())):
        raise ValueError(f"{path}: identities maps identities to {{log_ids, tenants, max_ttl_s}}")
    for k in ids:
        if "*" in k and not (k.endswith(PREFIX_ENDS) and k.count("*") == 1):
            raise ValueError(f"{path}: {k!r}: a prefix key must end in :* or /*")
    checkpoint.body(cfg["origin"], 0, merkle.root([]))   # a valid origin
    checkpoint.vkey(cfg["name"], checkpoint.ED25519, bytes(32))   # a valid key name
    return cfg


def open_issuer(cfg):
    return Issuer(cfg["data_dir"], cfg["name"], cfg["origin"], cfg["identities"],
                  [TlogWitness(w["url"], w["vkey"]) for w in cfg["witnesses"]],
                  ca_key=cfg.get("ca_key") and logkey.from_config(cfg["ca_key"]),
                  log_key=cfg.get("log_key") and logkey.from_config(cfg["log_key"]))


def serve(cfg, issuer):
    """The issuer's HTTPS server for a loaded config, not yet serving; stop it with shutdown() and server_close()."""
    from tracekit.transport import http
    return http.HttpServer(*http.configure(cfg["http"]), issuer.handle_frame)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit issuer", description="the record-key issuer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the issuer in the foreground").add_argument("--config", required=True)
    p = sub.add_parser("revoke", help="revoke a certificate: append a CA-signed revocation to the issuance log")
    p.add_argument("serial")
    p.add_argument("--last-seq", type=int, help="revoke only the key's records after this seq (default: all)")
    p.add_argument("--config", required=True)
    sub.add_parser("vkey", help="print the trust config's issuers entry").add_argument("--config", required=True)
    a = ap.parse_args(argv)
    try:
        cfg = load_config(a.config)
        if a.cmd == "serve":
            logkey.harden()   # before any key is read
            if "http" not in cfg:
                raise ValueError(f"{a.config}: serve needs an http section")
        issuer = open_issuer(cfg)
        if a.cmd == "vkey":
            print(json.dumps({"vkey": issuer.vkey, "issuance_log_vkey": issuer.log_vkey}))
            return 0
        if a.cmd == "revoke":
            print(json.dumps(issuer.revoke(a.serial, a.last_seq)))
            return 0
        srv = serve(cfg, issuer)
    except RPCError as e:   # a revocation appended, but not witnessed yet
        print(f"tracekit issuer: {e}; the revocation is in issuance.jsonl and the next issuance witnesses it",
              file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"tracekit issuer: {e}", file=sys.stderr)
        return 2
    print(f"tracekit issuer: {issuer.vkey.split('+')[0]} serving {srv.server_address[0]}:{srv.server_address[1]}",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
