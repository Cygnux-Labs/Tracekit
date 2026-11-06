"""Intent grants (docs/intent-grants.md): a person approves a kind of costly call once, within limits, for one run.

A grant is a PCM grant (tracekit.pcm) of an intent's schema document, in PCM's format as it is. The signer's
`intent.grant` record carries it with its limits (totals over every call that uses it) and the person's own words. The
signer reads each held call of an opted-in rule into the intent's fields, and releases it when the fields pass every
caveat and the totals stay within every limit; anything it can't read stays held. The signer, the CLI and the Python
verifier share this module. Payments (`payment.send`) are the one intent so far."""
import datetime
import json
import re

from tracekit import pcm
from tracekit.format.canon import MAX_SAFE_INT, event_hash
from tracekit.policy2.classes import PAYEE_KEYS

MAX_S = 86400   # a grant's longest life, as PCM's (SPEC 7.4)
# the minor units of each currency a person may type an amount in (ISO 4217's, and 6 for the USD stablecoins)
# lean: a fixed table; add a currency here when a payment tool uses it
DECIMALS = {"USD": 2, "EUR": 2, "GBP": 2, "INR": 2, "CAD": 2, "AUD": 2, "CHF": 2, "SGD": 2, "JPY": 0, "USDC": 6,
            "USDT": 6}
_CURRENCY, _PAYEE = r"[A-Z][A-Z0-9]{2,9}", r"[A-Za-z0-9._:@/+=-]{1,128}"
PAYMENT = {"pcm_schema": 0, "name": "payment.send", "grant": True,
           "fields": {"amount": {"type": "int", "min": 1, "max": MAX_SAFE_INT},   # in the currency's minor units
                      "currency": {"type": "id", "pattern": _CURRENCY},
                      "payee": {"type": "id", "pattern": _PAYEE}}}
INTENTS = {"payment.send": PAYMENT}
REFS = {pcm.schema_ref(doc): name for name, doc in INTENTS.items()}   # schema ref -> intent name
# what a payment call may carry besides amount, currency and payees: words that describe the payment and move no money
# lean: a closed list, so any other argument (a fee, a split, a second recipient) holds the call; add a key here when a
# payment tool's plain descriptive argument holds calls that should run
EXTRA = frozenset({"memo", "description", "note", "reference", "idempotency_key", "invoice_id", "order_id",
                   "statement_descriptor"})
LIMIT_OPS = ("sum", "count")


def ref(intent):
    """The schema ref (`name@sha256:…`) of intent `intent`, as a grant's `intent` names it."""
    return pcm.schema_ref(INTENTS[intent])


def grant_id(grant):
    """A grant's short id, `g-` and the first 16 hex digits of its hash: what people type and reasons name."""
    return "g-" + event_hash(grant)[len("sha256:"):][:16]


def parse_amount(text):
    """(minor units, currency) of an amount as a person writes it (`500 USDC`, `12.50 usd`); ValueError when it isn't
    one, names a currency DECIMALS doesn't know, or has more decimals than the currency's minor unit."""
    m = re.fullmatch(r"\s*([0-9]{1,15})(?:\.([0-9]{1,18}))?\s*([A-Za-z][A-Za-z0-9]{2,9})\s*", text or "")
    if not m:
        raise ValueError(f"{text!r} is not an amount: write it as a number and a currency, such as 500 USDC")
    whole, frac, cur = m.group(1), m.group(2) or "", m.group(3).upper()
    if cur not in DECIMALS:
        raise ValueError(f"tracekit knows the minor units of {', '.join(sorted(DECIMALS))}; {cur} isn't one of them")
    d = DECIMALS[cur]
    if len(frac.rstrip("0")) > d:
        raise ValueError(f"{text.strip()}: {cur} has {d} decimal place(s)")
    minor = int(whole) * 10 ** d + int((frac + "0" * d)[:d] or 0)
    if not 0 < minor <= MAX_SAFE_INT:
        raise ValueError(f"{text.strip()}: an amount is above zero and below 2^53 minor units")
    return minor, cur


def number(minor, currency):
    """Minor units as the number a person reads, without the currency: `200`, `0.5`; the minor units when the currency
    is unknown."""
    d = DECIMALS.get(currency)
    if d is None or type(minor) is not int:
        return json.dumps(minor)[:32]
    whole, frac = divmod(minor, 10 ** d)
    return f"{whole}{('.' + str(frac).zfill(d).rstrip('0')) if frac else ''}"


def show(minor, currency):
    """Minor units as a person reads them: `200 USDC`, `0.5 USDC`; minor units by name when the currency is unknown."""
    unit = currency if currency in DECIMALS and type(minor) is int else f"{currency} (minor units)"
    return f"{number(minor, currency)} {unit}"


def parse_for(text):
    """Seconds of a duration a person writes as `30m`, `4h` or `24h`; ValueError past MAX_S or in another form."""
    m = re.fullmatch(r"\s*([0-9]{1,5})\s*([mh])\s*", text or "")
    if not m:
        raise ValueError(f"{text!r} is not a duration: write minutes or hours, such as 30m or 4h")
    s = int(m.group(1)) * (60 if m.group(2) == "m" else 3600)
    if not 0 < s <= MAX_S:
        raise ValueError(f"{text.strip()}: a grant lasts at most 24h")
    return s


def payee(v):
    """A payee as grants compare it: an EVM address in lower case (its case is only a checksum), anything else as is."""
    return v.lower() if isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", v) else v


def read(intent, args):
    """(fields, None) of call arguments `args` as intent `intent` reads them, else (None, why they can't be read).
    payment.send: exactly one of amount and amount_cents, a whole number above zero (minor units); a currency (its
    letters in upper case); every payee key (classes.PAYEE_KEYS) present naming one payee; and nothing else but EXTRA's
    plain values. Anything else is a call the grant can't read, so it stays held."""
    if intent != "payment.send":
        return None, f"no grant reads {intent!r} calls"
    if not isinstance(args, dict):
        return None, "the arguments are not an object"
    keys = [k for k in ("amount", "amount_cents") if k in args]
    if len(keys) != 1:
        return None, "no amount in the call" if not keys else "the call has both amount and amount_cents"
    amount = args[keys[0]]
    if type(amount) is not int or not 0 < amount <= MAX_SAFE_INT:
        return None, (f"amount {json.dumps(amount)[:32]} is not a whole number of the currency's smallest unit "
                      "(cents, or a token's base unit)")
    cur = args.get("currency")
    if not isinstance(cur, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{2,9}", cur):
        return None, "no currency in the call" if cur is None else f"currency {json.dumps(cur)[:32]} is not a code"
    payees = {k: args[k] for k in PAYEE_KEYS if k in args}
    if not payees:
        return None, "no payee in the call"
    if not all(isinstance(v, str) for v in payees.values()):
        return None, "a payee is not a plain string"
    names = {payee(v) for v in payees.values()}
    if len(names) != 1:
        return None, f"the call names {len(names)} payees ({', '.join(sorted(payees))})"
    who = names.pop()
    if not re.fullmatch(_PAYEE, who):
        return None, f"payee {json.dumps(who)[:64]} has characters a grant doesn't compare"
    other = sorted(set(args) - {keys[0], "currency", *payees} - EXTRA)
    if other:
        return None, f"argument {json.dumps(other[0])[:64]} is not one a payment grant reads"
    bad = sorted(k for k in set(args) & EXTRA if not isinstance(args[k], (str, int)) or isinstance(args[k], bool))
    if bad:
        return None, f"argument {bad[0]} is not a plain string or number"
    return {"amount": amount, "currency": cur.upper(), "payee": who}, None


def problems(intent, caveats, limits, expires_at, now, ceilings=None):
    """What is wrong with a grant a person asks for, at ISO time `now`: an unknown intent; caveats that are not valid
    for its schema document (pcm.check_caveats); for payments, a currency not pinned with ==, payees not named with ==
    or in, or no `sum` limit of amount; limits that are not distinct sum/count entries with a whole max above zero; an
    expiry not after now or more than MAX_S later; and a total over the operator's ceiling for the currency
    (`ceilings`: {intent: {currency: minor units}}, from signer.yaml's grants section). Empty when it may be issued."""
    doc = INTENTS.get(intent)
    if doc is None:
        return [f"no intent {intent!r}: grants cover {', '.join(INTENTS)}"]
    out = pcm.check_caveats(doc, caveats)
    pinned = {c["field"]: c for c in caveats if c["op"] in ("==", "in")}
    if (pinned.get("currency") or {}).get("op") != "==":
        out.append("a payment grant names its one currency (currency == USDC)")
    if "payee" not in pinned:
        out.append("a payment grant names its payees (payee in [...])")
    seen = set()
    for x in limits:
        k = (x.get("op"), x.get("field"))
        if x.get("op") not in LIMIT_OPS or (x["op"] == "sum") != ("field" in x) or set(x) - {"op", "field", "max"} \
                or (doc["fields"].get(x.get("field", "amount")) or {}).get("type") != "int" \
                or type(x.get("max")) is not int or not 0 < x["max"] <= MAX_SAFE_INT:
            out.append(f"limit {json.dumps(x)[:96]}: a limit is {{op: sum, field, max}} of a whole-number field "
                       "(amount) or {op: count, max}, max a whole number above zero")
        elif k in seen:
            out.append(f"limit {x['op']} {x.get('field', '')}: given twice".replace("  ", " "))
        seen.add(k)
    total = next((x["max"] for x in limits if (x.get("op"), x.get("field")) == ("sum", "amount")
                  and type(x.get("max")) is int), None)
    if total is None:
        out.append("a payment grant has a total (a sum limit of amount)")
    if not now < expires_at <= _plus(now, MAX_S):
        out.append(f"expires_at {expires_at} is not in the next {MAX_S // 3600} h")
    cur = (pinned.get("currency") or {}).get("value")
    caps = (ceilings or {}).get(intent)
    if caps is not None and total is not None and isinstance(cur, str):
        if cur not in caps:
            out.append(f"signer.yaml's grants.{intent}.ceiling sets no ceiling for {cur}: grants in "
                       f"{', '.join(sorted(caps)) or 'no currency'} only")
        elif total > caps[cur]:
            out.append(f"the total {show(total, cur)} is over this signer's ceiling of {show(caps[cur], cur)} a grant "
                       f"(signer.yaml grants.{intent}.ceiling)")
    return out


def _plus(ts, s):
    """ISO time `ts` plus `s` seconds."""
    t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ") + datetime.timedelta(seconds=s)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ceilings(section):
    """{intent: {currency: minor units}} from signer.yaml's `grants` section ({intent: {ceiling: ["1000 USDC", ...]}});
    ValueError when it is malformed."""
    out = {}
    for intent, v in (section or {}).items():
        if intent not in INTENTS or not isinstance(v, dict) or set(v) - {"ceiling"} \
                or not isinstance(v.get("ceiling"), list):
            raise ValueError(f"grants.{intent}: write grants: {{payment.send: {{ceiling: [1000 USDC, ...]}}}}")
        caps = {}
        for text in v["ceiling"]:
            minor, cur = parse_amount(str(text))
            if cur in caps:
                raise ValueError(f"grants.{intent}.ceiling names {cur} twice")
            caps[cur] = minor
        out[intent] = caps
    return out


def zero(limits):
    """The totals of no calls, one per limit."""
    return [0] * len(limits)


def add(limits, used, fields):
    """The totals `used` (one per limit) after one more call with `fields`."""
    return [u + (fields[x["field"]] if x["op"] == "sum" else 1) for x, u in zip(limits, used)]


def _why(c, fields):
    """Why `fields` break caveat `c`, in words: `amount 700 USDC is over 200 USDC each`."""
    f, v, cur = c["field"], fields.get(c["field"]), fields.get("currency")
    if f == "amount" and c["op"] in ("<=", "<"):
        return f"amount {show(v, cur)} is over {show(c['value'] - (c['op'] == '<'), cur)} each"
    if f == "amount" and c["op"] in (">=", ">"):
        return f"amount {show(v, cur)} is under {show(c['value'] + (c['op'] == '>'), cur)} each"
    allowed = c["value"] if c["op"] == "in" else [c["value"]]
    return f"{f} {json.dumps(v)[:64]} is not {'one of ' if len(allowed) > 1 else ''}" + ", ".join(
        json.dumps(x)[:64] for x in allowed[:8]) + (f" and {len(allowed) - 8} more" if len(allowed) > 8 else "")


def _over(x, u, before, cur):
    """Why a call that would bring limit `x`'s total to `u` (from `before`) is over it, in words."""
    if x["op"] == "count":
        return f"{before} of {x['max']} payments made"
    return f"{number(before, cur)} of {show(x['max'], cur)} used; this call needs {show(u - before, cur)}"


def left(entry):
    """What a grant entry has left, in words: `380 of 500 USDC left, 8 of 10 payments`."""
    cur = next((c["value"] for c in entry["grant"]["caveats"] if c["field"] == "currency" and c["op"] == "=="), "")
    return ", ".join(f"{number(x['max'] - u, cur)} of {show(x['max'], cur)} left" if x["op"] == "sum"
                     else f"{x['max'] - u} of {x['max']} payments left" for x, u in zip(entry["limits"], entry["used"]))


def words(grant, limits, used=None):
    """A payment grant's bounds in words: `to 0xa1…, 0xb2…, up to 200 USDC each, 380 of 500 USDC left`."""
    by = {c["field"]: c for c in grant["caveats"]}
    cur = by["currency"]["value"]
    payees = by["payee"]["value"] if by["payee"]["op"] == "in" else [by["payee"]["value"]]
    each = by.get("amount")
    return ", ".join([f"to {', '.join(payees)}", *([f"up to {show(each['value'], cur)} each"] if each else []),
                      left({"grant": grant, "limits": limits, "used": used or zero(limits)})])


def state(entry, now):
    """live, revoked, expired or used_up: whether grant entry `entry` may still release a call at ISO time `now`."""
    if entry.get("revoked"):
        return "revoked"
    if now >= entry["grant"]["expires_at"]:
        return "expired"
    return "used_up" if any(u >= x["max"] for x, u in zip(entry["limits"], entry["used"])) else "live"


def check(entry, fields, now):
    """(totals after the call, None) when a call with `fields` is within grant entry `entry` ({grant, limits, used,
    revoked?}) at ISO time `now`, else (None, why not, in words)."""
    gid, g = grant_id(entry["grant"]), entry["grant"]
    if entry.get("revoked"):
        return None, f"grant {gid} was revoked"
    if now >= g["expires_at"]:
        return None, f"grant {gid} expired at {g['expires_at']}"
    for c in g["caveats"]:
        if not pcm.satisfies(fields, c):
            return None, f"grant {gid}: {_why(c, fields)}"
    used = add(entry["limits"], entry["used"], fields)
    for x, u, before in zip(entry["limits"], used, entry["used"]):
        if u > x["max"]:
            return None, f"grant {gid}: {_over(x, u, before, fields.get('currency'))}"
    return used, None


def decide(grants, intent, args, now):
    """Which of a run's grants (id -> entry) releases a call of intent `intent` with `args` at ISO time `now`:
    (grant id, fields, totals after it, None), or (None, fields, None, why every live grant of the intent holds it).
    The first grant in issue order that has room releases it."""
    fields, unread = read(intent, args)
    mine = [(gid, e) for gid, e in grants.items() if REFS.get(e["grant"]["intent"]) == intent]
    if fields is None:
        return None, None, None, f"grant {mine[0][0]}: {unread}, so a person decides" if mine else unread
    whys = []
    for gid, e in mine:
        used, why = check(e, fields, now)
        if why is None:
            return gid, fields, used, None
        whys.append(why)
    return None, fields, None, "; ".join(whys[:3]) or f"no grant of this run covers {intent}"
