"""Proof-carrying messages (experimental, #436): a message from one agent to another that the signer signed as the
sending run's own agent, with a typed intent, claims and a chain of grants. This module is the format and the offline
verifier: a receiver needs only its trust.json (the signer's pinned log key) and the schema documents it agreed on.

A schema document is content-addressed (`schema_ref`): flat typed fields, the claim types its intent needs and
whether a grant is required. A grant is signed by the log key too: a root grant comes from a person's approval in the
issuer's run, a child from its parent's subject, only narrower (`narrows`) and only below a `delegable` grant."""
import base64
import collections
import datetime
import json
import re
import time

from tracekit import crypto
from tracekit.format import checkpoint, sigmsg
from tracekit.format.canon import MAX_SAFE_INT, event_hash
from tracekit.schema import _check
from tracekit.signer.rpc_schema import CLAIM_TYPES, DIGEST, HOST, ID, PCM_MESSAGE, TS, _END, _obj, _str

MEDIA_TYPE = "application/vnd.pcm+json"

_SAFE = {"type": "integer", "minimum": -MAX_SAFE_INT, "maximum": MAX_SAFE_INT}
_OPT = {"optional": {"type": "boolean"}}
_FIELD = {"oneOf": [
    _obj(["type", "max"], type={"const": "string"}, max={"type": "integer", "minimum": 1, "maximum": 65536}, **_OPT),
    _obj(["type", "min", "max"], type={"const": "int"}, min=_SAFE, max=_SAFE, **_OPT),
    _obj(["type", "currency", "max"], type={"const": "money"}, currency=_str(3, pattern=r"^[A-Z]{3}" + _END),
         max=dict(_SAFE, minimum=0), **_OPT),
    _obj(["type", "pattern"], type={"const": "id"}, pattern=_str(256, minLength=1), **_OPT),
    _obj(["type", "values"], type={"const": "enum"}, values={"type": "array", "minItems": 1, "maxItems": 256,
                                                             "items": {"type": "string"}}, **_OPT),
    _obj(["type"], type={"const": "bool"}, **_OPT),
    _obj(["type"], type={"const": "time"}, **_OPT)]}
SCHEMA_DOC = _obj(["pcm_schema", "name", "fields"], pcm_schema={"type": "integer", "const": 0},
                  name=_str(64, pattern=r"^[a-z][a-z0-9_.-]*" + _END),
                  fields={"type": "object", "additionalProperties": _FIELD,
                          "propertyNames": {"type": "string", "pattern": r"^[a-z][a-z0-9_]{0,63}" + _END}},
                  claims={"type": "array", "maxItems": len(CLAIM_TYPES), "items": {"enum": CLAIM_TYPES}},
                  grant={"type": "boolean"},
                  tool=_str(256, minLength=1))   # the tool the intent stands for: approved_by's `covers` reads it


def _errors(schema, value):
    """Errors of `value`, with every pattern matched whole and ASCII-only (a TS compares lexically)."""
    errs = []
    _check(value, schema, schema, "$", errs, strict=True)
    return errs


# value rules: no coercion, so True, 120.0 and "120" are not ints
_FITS = {"string": lambda s, v: type(v) is str and len(v) <= s["max"],
         "int": lambda s, v: type(v) is int and s["min"] <= v <= s["max"],
         "money": lambda s, v: type(v) is int and 0 <= v <= s["max"],   # minor units (cents) of `currency`
         "id": lambda s, v: type(v) is str and len(v) <= 128 and re.fullmatch(s["pattern"], v) is not None,
         "enum": lambda s, v: type(v) is str and v in s["values"],
         "bool": lambda s, v: type(v) is bool,
         "time": lambda s, v: not _errors(TS, v)}
_OPS = {"int": "== <= >= < >", "money": "== <= >= < >", "time": "== <= >=", "string": "== in", "id": "== in",
        "enum": "== in", "bool": "=="}
# claim args, in the schema language
CLAIM_ARGS = {"tests_passed": {"suite": {"type": "string", "max": 4096}},
              "approved_by": {"person": {"type": "string", "max": 256},
                              "call": {"type": "id", "pattern": ID["pattern"]},
                              "covers": {"type": "bool", "optional": True}},
              "reached_host": {"host": {"type": "id", "pattern": HOST["pattern"]}},
              "file_written": {"path": {"type": "string", "max": 4096},
                               "digest": {"type": "id", "pattern": DIGEST["pattern"]}}}


def check_schema(doc):
    """Errors of a schema document (empty when it is well-formed)."""
    errs = _errors(SCHEMA_DOC, doc)
    if errs:
        return errs
    for name, f in doc["fields"].items():
        if f["type"] == "int" and f["min"] > f["max"]:
            errs.append(f"$.fields.{name}: min above max")
        if f["type"] == "enum" and len(set(f["values"])) != len(f["values"]):
            errs.append(f"$.fields.{name}: values repeat")
        if f["type"] == "id":
            try:
                re.compile(f["pattern"])
            except re.error as e:
                errs.append(f"$.fields.{name}: bad pattern ({e})")
    if len(set(doc.get("claims", []))) != len(doc.get("claims", [])):
        errs.append("$.claims: types repeat")
    return errs


def schema_ref(doc):
    return f"{doc['name']}@{event_hash(doc)}"


def check_args(doc, args):
    """Errors of an intent's args against its (checked) schema document."""
    if not isinstance(args, dict):
        return ["args: not an object"]
    errs = [f"args.{k}: not in the schema" for k in args if k not in doc["fields"]]
    for k, f in doc["fields"].items():
        if k not in args:
            if not f.get("optional"):
                errs.append(f"args.{k}: missing")
        elif not _FITS[f["type"]](f, args[k]):
            errs.append(f"args.{k}: {json.dumps(args[k])[:64]} is not a valid {f['type']}")
    return errs


def _show(c):
    return f"{c['field']} {c['op']} {json.dumps(c['value'])[:64]}"


def check_caveats(doc, caveats):
    """Problems of grant caveats against the intent's schema: the field exists, the op suits its type, and every value
    passes the field's value rule (`in`: 1..64 distinct values)."""
    out = []
    for c in caveats:
        f = doc["fields"].get(c["field"])
        if f is None:
            out.append(f"{_show(c)}: no field {c['field']} in {doc['name']}")
        elif c["op"] not in _OPS[f["type"]].split():
            out.append(f"{_show(c)}: {c['op']} does not apply to a {f['type']} field")
        else:
            vals = c["value"] if c["op"] == "in" else [c["value"]]
            if not (isinstance(vals, list) and 1 <= len(vals) <= 64 and all(_FITS[f["type"]](f, x) for x in vals)
                    and len(set(vals)) == len(vals)):
                out.append(f"{_show(c)}: not a valid {f['type']} value")
    return out


def _norm(c):
    """A caveat as one of ("==", v), ("in", strings), ("<=", b), (">=", b), with `< b` as `<= b-1` and `> b` as
    `>= b+1`; None for a caveat with no meaning (a value no field type has, a bound that is no int or time, an `in`
    that is no set of strings)."""
    op, v = c["op"], c["value"]
    if op in ("<", ">"):
        return None if type(v) is not int else ("<=", v - 1) if op == "<" else (">=", v + 1)
    if op in ("<=", ">="):
        return (op, v) if type(v) in (int, str) else None
    if op == "in":
        ok = isinstance(v, list) and v and all(type(x) is str for x in v) and len(set(v)) == len(v)
        return ("in", set(v)) if ok else None
    return (op, v) if type(v) in (int, str, bool) else None


def _implies(c, p):
    """Whether every value that passes normalised caveat `c` passes `p`."""
    (cop, cv), (pop, pv) = c, p
    if pop == "==":
        return cop == "==" and type(cv) is type(pv) and cv == pv or cop == "in" and cv == {pv}
    if pop == "in":
        return cop == "==" and type(cv) is str and cv in pv or cop == "in" and cv <= pv
    if pop == "<=":
        return cop in ("==", "<=") and type(cv) is type(pv) and cv <= pv
    return cop in ("==", ">=") and type(cv) is type(pv) and cv >= pv


def narrows(parent, child):
    """Problems with caveat list `child` as a narrowing of `parent`: [] when each parent caveat is implied by one child
    caveat on its field. A missing caveat counts as widening; the child may add caveats on any field."""
    kids = [(c["field"], _norm(c)) for c in child]
    out = [f"{_show(c)}: not a valid caveat" for c, (_, n) in zip(child, kids) if n is None]
    for p in parent:
        n = _norm(p)
        if n is None:
            out.append(f"{_show(p)}: not a valid caveat")
        elif not any(f == p["field"] and k is not None and _implies(k, n) for f, k in kids):
            out.append(f"{_show(p)}: dropped or widened")
    return out


def satisfies(args, c):
    """Whether intent args pass caveat `c` (a missing field, or args that are not an object, do not)."""
    n = _norm(c)
    return isinstance(args, dict) and c["field"] in args and n is not None and _implies(("==", args[c["field"]]), n)


def sign(key, vkey, purpose, body):
    """`body` signed for `purpose` ("pcm" or "pcm-grant") by the log key `key`, whose pinned vkey is `vkey`."""
    # lean: the log key signs PCM too, so a PCM signing bug means rotating it; pin a dedicated PCM key in trust.json
    # before PCM leaves experimental
    name, kid, _, _ = checkpoint.parse_vkey(vkey)
    sig = key.sign(sigmsg.message(purpose, body))
    return {**body, "sig": {"key": f"{name}+{kid.hex()}", "sig": base64.b64encode(sig).decode("ascii")}}


def check_sig(obj, purpose, trust):
    """None when `obj` holds a valid `purpose` signature by an Ed25519 log key trust.json pins, else the problem."""
    # lean: Ed25519 only, even where trust pins a hybrid SLH-DSA key; add the hybrid line when agents need it
    body = {k: v for k, v in obj.items() if k != "sig"}
    for vk in trust.get("logs", []):
        name, kid, type_, public = checkpoint.parse_vkey(vk)
        if type_ != checkpoint.ED25519 or f"{name}+{kid.hex()}" != obj["sig"]["key"]:
            continue
        try:   # canonical base64 only (PCM 0.1), so a signature has one text form
            ok = crypto.verify_v2("ed25519", crypto.spki(public), sigmsg.message(purpose, body),
                                  checkpoint._unb64(obj["sig"]["sig"]))
        except ValueError:
            ok = False
        return None if ok else "bad signature"
    return f"signed by {obj['sig']['key']}, a key trust.json does not pin"


def verify_grants(msg, doc, trust):
    """The grant chain of a message whose envelope and signature passed, against its intent's schema document."""
    grants, args, out = msg.get("grants", []), msg["intent"]["args"], []
    if not grants:
        need = bool(doc.get("grant"))
        return {"result": "failed" if need else "none", "steps": 0, "root": None,
                "problems": ["the intent needs a grant"] if need else []}
    for i, g in enumerate(grants):
        at = f"grant {i}"
        if g["sig"]["key"] != msg["sig"]["key"]:   # another pinned log's grant holds nothing here
            out.append(f"{at}: signed by {g['sig']['key']}, not the log that signed the message ({msg['sig']['key']})")
        elif e := check_sig(g, "pcm-grant", trust):
            out.append(f"{at}: {e}")
        if g["intent"] != msg["intent"]["type"]:
            out.append(f"{at}: for {g['intent']}, not this intent")
        out += [f"{at}: {e}" for e in check_caveats(doc, g["caveats"])]
        if msg["ts"] > g["expires_at"]:
            out.append(f"{at}: expired at {g['expires_at']}")
        if g["issuer"]["tenant"] != msg["from"]["tenant"]:
            out.append(f"{at}: issued in tenant {g['issuer']['tenant']}, not the sender's {msg['from']['tenant']}")
        for c in g["caveats"]:   # every caveat of every grant: the check does not rest on narrowing alone
            if not satisfies(args, c):
                got = json.dumps(args[c["field"]])[:64] if isinstance(args, dict) and c["field"] in args else "missing"
                out.append(f"{at}: {c['field']} {got} breaks {_show(c)}")
        if i == 0:
            if g["parent"] is not None:
                out.append(f"{at}: the root grant has a parent")
            if g["issuer"]["kind"] != "person":
                out.append(f"{at}: the root grant must come from a person's approval")
            elif not g["issuer"].get("person"):   # authority comes from a person the signer's config names
                out.append(f"{at}: the root grant's issuer names no person")
            if g["issuer"]["id"] == g["subject"]:
                out.append(f"{at}: the root grant's issuer is its own subject")
            continue
        p = grants[i - 1]
        if g["parent"] != event_hash(p):
            out.append(f"{at}: its parent is not grant {i - 1}")
        if not p["delegable"]:   # so no child, delegable or not, below it
            out.append(f"{at}: grant {i - 1} can't be passed on")
        if (g["issuer"]["kind"], g["issuer"]["id"]) != ("agent", p["subject"]):
            out.append(f"{at}: issued by {g['issuer']['id']}, not grant {i - 1}'s subject {p['subject']}")
        if g["expires_at"] > p["expires_at"]:
            out.append(f"{at}: outlives its parent")
        out += [f"{at}: {e}" for e in narrows(p["caveats"], g["caveats"])]
    if grants[-1]["subject"] != msg["from"]["agent"]:
        out.append(f"the last grant is for {grants[-1]['subject']}, not the sender {msg['from']['agent']}")
    root = grants[0]["issuer"]
    return {"result": "failed" if out else "ok", "steps": len(grants),
            "root": {k: root[k] for k in ("kind", "id", "person") if k in root}, "problems": out}


def _epoch(ts):
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc).timestamp()


class Replay:
    """One receiver's replay state, in memory. A message passes once: within `window_s` of this receiver's clock, not
    sent before it started (so a restart needs no saved state), newer than the sender's floor and with a new nonce.
    A sender is the log key that signed and the agent (PCM 0.1): one agent name under two logs is two senders.
    Past `per_sender` nonces the oldest is forgotten and raises the floor. `window_s=None` (an auditor over a saved
    conversation) skips the clocks and checks nonces only."""
    # lean: per process, so replicas behind one address don't share it; share it through the signer's store when the
    # A2A gateway scales out

    def __init__(self, window_s=300.0, per_sender=4096, now=None):
        self.window_s, self.per_sender = window_s, per_sender
        # in whole microseconds, as a ts is rounded: else a message signed in the receiver's first microsecond (on
        # Windows before Python 3.13, its first 15.6 ms clock tick) can read as sent before it started
        self.started = int((time.time() if now is None else now) * 1e6) / 1e6
        self.seen, self.floor = {}, {}

    def check(self, msg, now=None, record=True):
        """(ok, detail) for a message whose signature passed; a passing one is remembered when `record`."""
        now = time.time() if now is None else now
        try:
            t, sender = _epoch(msg["ts"]), (msg["sig"]["key"], msg["from"]["agent"])
        except ValueError:   # the TS pattern passes a month 13 or a year 0
            return False, f"sent at {msg['ts']}, which is no real time"
        if self.window_s is not None:
            if abs(now - t) > self.window_s:
                return False, f"sent at {msg['ts']}, more than {self.window_s:g} s from this receiver's clock"
            if t < self.started:
                return False, "sent before this receiver started: ask for it again"
        if t <= self.floor.get(sender, float("-inf")):
            return False, "older than the messages this receiver remembers from the sender"
        if msg["nonce"] in self.seen.get(sender, ()):
            return False, "replayed: this nonce was seen before"
        if not record:
            return True, "fresh"
        seen = self.seen.setdefault(sender, collections.OrderedDict())
        seen[msg["nonce"]] = t
        while seen and self.window_s is not None and next(iter(seen.values())) < now - self.window_s:
            seen.popitem(last=False)   # the window refuses it now
        while len(seen) > self.per_sender:
            self.floor[sender] = max(self.floor.get(sender, float("-inf")), seen.popitem(last=False)[1])
        return True, "fresh"


def _verdict(out, doc, strict, sent):
    """The verdict and its reasons from the parts of `out`, for a message whose claims are `sent`."""
    claims = out["claims"] or []
    bad = [f"replay: {out['replay']['detail']}"] if out["replay"]["ok"] is False else []
    bad += [f"schema: {e}" for e in out["schema"]["errors"]]
    bad += [f"grant: {p}" for p in (out["grants"] or {}).get("problems", [])]
    bad += [f"{c['type']}: failed ({c['detail']})" for c in claims if c["result"] == "failed"]
    proven = {c["type"] for c in claims if c["result"] == "proven"}
    # an approved_by meets the schema's need only when it says it covers this request (PCM 0.1 6.6)
    met = {c["type"] for c, s in zip(claims, sent) if c["result"] == "proven"
           and (c["type"] != "approved_by" or s["args"].get("covers") is True)}
    missing = [f"{t}: required, not proven" + " to cover this request: claim it with covers true" * (t in proven)
               for t in (doc or {}).get("claims", []) if t not in met]
    if bad or strict and missing:
        return "reject", bad + (missing if strict else [])
    soft = [f"{c['type']}: unproven ({c['detail']})" for c in claims if c["result"] == "unproven"] + missing
    return ("accept-unproven", soft) if soft else ("accept", [])


def verify(msg, trust, schemas, replay=None, me=None, strict=False, now=None):
    """Check a message: envelope and signature, replay and recipient (`me`), its intent's schema among the documents
    `schemas`, its grants and its claims. `verdict` is accept, accept-unproven or reject, with one reason per cause;
    `skipped` names the checks not asked for (replay without `replay`, recipient without `me`). `strict`: a claim type
    the schema requires must be proven."""
    logs = [checkpoint.parse_vkey(vk) for vk in trust.get("logs", [])]
    for w in trust.get("witnesses", []):
        checkpoint.parse_vkey(w["vkey"])   # a bad pin is the receiver's own error (NoteError), wherever it sits
    for name, n in collections.Counter(x for x, _, type_, _ in logs if type_ == checkpoint.ED25519).items():
        if n > 1:
            raise ValueError(f"trust.json pins {n} Ed25519 keys for log {name}; PCM verifies with one: pass a trust "
                             "file with only the current key (`tracekit signer trust --config <signer.yaml> -o "
                             "pcm-trust.json` writes one)")
    out = {"signature": None, "replay": None, "schema": None, "grants": None, "claims": None, "verdict": "reject",
           "reasons": [], "skipped": ["replay"] * (replay is None) + ["recipient"] * (me is None)}
    errs = _errors(PCM_MESSAGE, msg)
    if errs:
        out["reasons"] = [f"envelope: {e}" for e in errs[:8]]
        return out
    e = check_sig(msg, "pcm", trust)
    out["signature"] = {"ok": e is None, "key": msg["sig"]["key"]}
    if e:
        out["reasons"] = [f"signature: {e}"]
        return out
    docs = {}
    for i, d in enumerate(schemas):
        if errs := check_schema(d):
            raise ValueError(f"schema document {i}: {'; '.join(errs)}")
        docs[schema_ref(d)] = d
    ref = msg["intent"]["type"]
    doc = docs.get(ref)
    errs = [f"unknown schema {ref}"] if doc is None else check_args(doc, msg["intent"]["args"])
    if me is not None and msg["to"]["agent"] != me:   # for another receiver, or failing its schema: no nonce spent
        ok, detail = False, f"addressed to {msg['to']['agent']}, not {me}"
    else:
        ok, detail = replay.check(msg, now, record=not errs) if replay is not None else (None, "not checked")
    out["replay"] = {"ok": ok, "detail": detail}
    out["schema"] = {"ok": not errs, "ref": ref, "errors": errs}
    if doc is not None:
        out["grants"] = verify_grants(msg, doc, trust)
    from tracekit.pcm.claims import check_claim   # claims.py imports this module
    out["claims"] = [check_claim(c, msg, trust, doc) for c in msg.get("claims", [])]
    out["verdict"], out["reasons"] = _verdict(out, doc, strict, msg.get("claims", []))
    return out
