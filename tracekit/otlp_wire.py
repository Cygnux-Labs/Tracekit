"""Decode OTLP trace export requests (protobuf or JSON) into plain dicts, with no dependencies.

Both encodings normalise to the same shape, one dict per span:

    {"trace_id": hex32, "span_id": hex16, "parent_span_id": hex16 | None, "name": str, "kind": int,
     "start_ns": int, "end_ns": int, "attrs": {key: value}, "events": [{"name", "time_ns", "attrs"}],
     "status_code": 0|1|2, "status_message": str, "resource": {key: value}, "scope": str}

Attribute values become plain Python values (str, bool, int, float, bytes-as-hex, list, dict).
Every decoder is bounded: body size, span count, nesting depth and string length are capped so a
hostile or buggy exporter cannot exhaust memory. Protobuf is read through memoryviews (no copies), and a repeated field
past its cap (MAX_SPANS spans and scopes, MAX_ATTRS attributes or array values) is refused as it is read, never
collected first. Malformed input raises WireError, never anything else (a RecursionError included).

Field numbers follow opentelemetry/proto/collector/trace/v1/trace_service.proto and
opentelemetry/proto/trace/v1/trace.proto (stable since OTLP 1.0)."""
import gzip
import json
import struct
import zlib

MAX_BODY = 4 * 1024 * 1024          # compressed or not, as received
MAX_DECODED = 16 * 1024 * 1024      # after gzip/deflate
MAX_SPANS = 10_000                  # per request
MAX_DEPTH = 16                      # AnyValue nesting
MAX_STR = 256 * 1024                # one attribute string
MAX_ATTRS = 512                     # per span / resource / event
MAX_EVENTS = 256                    # per span


class WireError(ValueError):
    pass


# ---------------------------------------------------------------- content encoding

def decompress(body, encoding):
    enc = (encoding or "identity").strip().lower()
    if enc in ("", "identity"):
        return body
    if enc not in ("gzip", "deflate"):
        raise WireError(f"unsupported Content-Encoding {encoding!r} (use gzip, deflate or none)")
    wbits = 16 + zlib.MAX_WBITS if enc == "gzip" else zlib.MAX_WBITS
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(body, MAX_DECODED + 1)
        if len(out) > MAX_DECODED or d.unconsumed_tail:
            raise WireError(f"decompressed body exceeds {MAX_DECODED} bytes")
        if enc == "deflate" and not d.eof:  # some clients send raw deflate without the zlib header
            raise zlib.error("truncated")
        return out
    except zlib.error:
        if enc == "deflate":
            try:
                d = zlib.decompressobj(-zlib.MAX_WBITS)
                out = d.decompress(body, MAX_DECODED + 1)
                if len(out) <= MAX_DECODED and not d.unconsumed_tail:
                    return out
            except zlib.error:
                pass
        raise WireError(f"body is not valid {enc}")


def gzip_bytes(b):
    return gzip.compress(b)


# ---------------------------------------------------------------- protobuf wire format

def _varint(buf, i):
    shift = result = 0
    while True:
        if i >= len(buf):
            raise WireError("truncated varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise WireError("varint too long")


def _fields(buf):
    """Yield (field_number, wire_type, value) for one message. value: int for varint/fixed, bytes for len."""
    i, n = 0, len(buf)
    while i < n:
        key, i = _varint(buf, i)
        fn, wt = key >> 3, key & 7
        if fn == 0:
            raise WireError("field number 0")
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 1:
            if i + 8 > n:
                raise WireError("truncated fixed64")
            v = struct.unpack_from("<Q", buf, i)[0]
            i += 8
        elif wt == 2:
            ln, i = _varint(buf, i)
            if i + ln > n:
                raise WireError("truncated length-delimited field")
            v = buf[i:i + ln]
            i += ln
        elif wt == 5:
            if i + 4 > n:
                raise WireError("truncated fixed32")
            v = struct.unpack_from("<I", buf, i)[0]
            i += 4
        else:
            raise WireError(f"unsupported wire type {wt}")
        yield fn, wt, v


def _repeated(buf, fn, cap, what):
    """The length-delimited values of field `fn` in `buf`; WireError once there are more than `cap`."""
    out = []
    for f, wt, v in _fields(buf):
        if f == fn and wt == 2:
            if len(out) == cap:
                raise WireError(f"more than {cap} {what} in one request")
            out.append(v)
    return out


def _s(b):
    return bytes(b[:MAX_STR]).decode("utf-8", "replace")


def _i64(v):
    return v - (1 << 64) if v >= 1 << 63 else v


def _any_pb(buf, depth):
    if depth > MAX_DEPTH:
        return "[truncated: nesting too deep]"
    out = None
    for fn, wt, v in _fields(buf):
        if fn == 1 and wt == 2:
            out = _s(v)
        elif fn == 2 and wt == 0:
            out = bool(v)
        elif fn == 3 and wt == 0:
            out = _i64(v)
        elif fn == 4 and wt == 1:
            out = struct.unpack("<d", struct.pack("<Q", v))[0]
        elif fn == 5 and wt == 2:
            out = [_any_pb(x, depth + 1) for x in _repeated(v, 1, MAX_ATTRS, "array values")]
        elif fn == 6 and wt == 2:
            out = _kvs_pb(_repeated(v, 1, MAX_ATTRS, "kvlist values"), depth + 1)
        elif fn == 7 and wt == 2:
            out = bytes(v).hex()
    return out


def _kvs_pb(items, depth=0):
    out = {}
    for raw in items:
        k, val = None, None
        for fn, wt, v in _fields(raw):
            if fn == 1 and wt == 2:
                k = _s(v)
            elif fn == 2 and wt == 2:
                val = _any_pb(v, depth)
        if k is not None:
            out[k] = val
    return out


def _span_pb(buf, resource, scope):
    sp = {"trace_id": "", "span_id": "", "parent_span_id": None, "name": "", "kind": 0, "start_ns": 0, "end_ns": 0,
          "attrs": {}, "events": [], "status_code": 0, "status_message": "", "resource": resource, "scope": scope}
    attrs, events = [], []
    for fn, wt, v in _fields(buf):
        if fn == 1 and wt == 2:
            sp["trace_id"] = bytes(v).hex()
        elif fn == 2 and wt == 2:
            sp["span_id"] = bytes(v).hex()
        elif fn == 4 and wt == 2:
            sp["parent_span_id"] = bytes(v).hex() or None
        elif fn == 5 and wt == 2:
            sp["name"] = _s(v)
        elif fn == 6 and wt == 0:
            sp["kind"] = v
        elif fn == 7 and wt == 1:
            sp["start_ns"] = v
        elif fn == 8 and wt == 1:
            sp["end_ns"] = v
        elif fn == 9 and wt == 2:
            if len(attrs) == MAX_ATTRS:
                raise WireError(f"more than {MAX_ATTRS} span attributes in one request")
            attrs.append(v)
        elif fn == 11 and wt == 2 and len(events) < MAX_EVENTS:
            ev = {"name": "", "time_ns": 0, "attrs": _kvs_pb(_repeated(v, 3, MAX_ATTRS, "event attributes"))}
            for f2, w2, x in _fields(v):
                if f2 == 1 and w2 == 1:
                    ev["time_ns"] = x
                elif f2 == 2 and w2 == 2:
                    ev["name"] = _s(x)
            events.append(ev)
        elif fn == 15 and wt == 2:
            for f2, w2, x in _fields(v):
                if f2 == 2 and w2 == 2:
                    sp["status_message"] = _s(x)
                elif f2 == 3 and w2 == 0:
                    sp["status_code"] = x
    sp["attrs"] = _kvs_pb(attrs)
    sp["events"] = events
    return sp


def _guarded(decoder, body, what):
    """decoder(body) checked; any error but WireError (a RecursionError, a shape the decoder did not expect) is
    malformed input too."""
    try:
        return _checked(decoder(body))
    except WireError:
        raise
    except Exception as e:
        raise WireError(f"malformed {what}: {type(e).__name__}: {e}"[:500]) from None


def _protobuf(body):
    spans = []
    for fn, wt, rs in _fields(memoryview(body)):
        if fn != 1 or wt != 2:
            continue
        resource, scope_blobs = {}, _repeated(rs, 2, MAX_SPANS, "scope spans")
        for f2, w2, v in _fields(rs):
            if f2 == 1 and w2 == 2:
                resource = _kvs_pb(_repeated(v, 1, MAX_ATTRS, "resource attributes"))
        for ss in scope_blobs:
            scope = ""
            for f3, w3, v in _fields(ss):
                if f3 == 1 and w3 == 2:
                    scope = next((_s(x) for f4, w4, x in _fields(v) if f4 == 1 and w4 == 2), "")
            for sb in _repeated(ss, 2, MAX_SPANS - len(spans), "spans"):
                spans.append(_span_pb(sb, resource, scope))
    return spans


def decode_protobuf(body):
    return _guarded(_protobuf, body, "protobuf")


def encode_response_protobuf(rejected=0, message=""):
    """ExportTraceServiceResponse. Empty for full success, else partial_success {rejected_spans, error_message}."""
    if not rejected and not message:
        return b""

    def varint(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)
    msg = message.encode("utf-8")[:4096]
    inner = (b"\x08" + varint(rejected) if rejected else b"") + (b"\x12" + varint(len(msg)) + msg if msg else b"")
    return b"\x0a" + varint(len(inner)) + inner


# ---------------------------------------------------------------- OTLP/JSON

def _g(d, *names):
    """OTLP/JSON uses lowerCamelCase; accept snake_case too (some SDKs and hand-written payloads use it)."""
    for n in names:
        if n in d:
            return d[n]
    return None


def _num(v, default=0):
    if v is None:
        return default
    if isinstance(v, bool):
        raise WireError("expected a number")
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    raise WireError(f"expected an integer, got {v!r}")


def _hexid(v, n):
    if v in (None, ""):
        return ""
    if not isinstance(v, str):
        raise WireError("ids must be strings")
    s = v.strip().lower()
    if len(s) == n and all(c in "0123456789abcdef" for c in s):
        return s
    import base64  # tolerate base64 ids (protobuf JSON mapping default) as some exporters emit them
    try:
        raw = base64.b64decode(v, validate=True)
    except ValueError:
        raise WireError(f"invalid id {v!r}")
    if len(raw) * 2 != n:
        raise WireError(f"invalid id {v!r}")
    return raw.hex()


def _any_json(v, depth):
    if depth > MAX_DEPTH:
        return "[truncated: nesting too deep]"
    if not isinstance(v, dict):
        return None
    if "stringValue" in v or "string_value" in v:
        s = _g(v, "stringValue", "string_value")
        return s[:MAX_STR] if isinstance(s, str) else str(s)
    if "boolValue" in v or "bool_value" in v:
        return bool(_g(v, "boolValue", "bool_value"))
    if "intValue" in v or "int_value" in v:
        return _num(_g(v, "intValue", "int_value"))
    if "doubleValue" in v or "double_value" in v:
        x = _g(v, "doubleValue", "double_value")
        return float(x) if isinstance(x, (int, float, str)) and not isinstance(x, bool) else None
    if "arrayValue" in v or "array_value" in v:
        vals = (_g(v, "arrayValue", "array_value") or {}).get("values") or []
        return [_any_json(x, depth + 1) for x in vals[:MAX_ATTRS]]
    if "kvlistValue" in v or "kvlist_value" in v:
        return _kvs_json((_g(v, "kvlistValue", "kvlist_value") or {}).get("values") or [], depth + 1)
    if "bytesValue" in v or "bytes_value" in v:
        import base64
        try:
            return base64.b64decode(_g(v, "bytesValue", "bytes_value") or "").hex()
        except ValueError:
            return None
    return None


def _kvs_json(items, depth=0):
    out = {}
    if not isinstance(items, list):
        raise WireError("attributes must be a list")
    for kv in items[:MAX_ATTRS]:
        if isinstance(kv, dict) and isinstance(kv.get("key"), str):
            out[kv["key"]] = _any_json(kv.get("value"), depth)
    return out


def decode_json(body):
    return _guarded(_json, body, "JSON")


def _json(body):
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise WireError(f"invalid JSON: {type(e).__name__}: {e}"[:500]) from None
    if not isinstance(doc, dict):
        raise WireError("body must be a JSON object")
    spans = []
    for rs in _g(doc, "resourceSpans", "resource_spans") or []:
        if not isinstance(rs, dict):
            raise WireError("resourceSpans entries must be objects")
        resource = _kvs_json(((rs.get("resource") or {}).get("attributes")) or [])
        for ss in _g(rs, "scopeSpans", "scope_spans", "instrumentationLibrarySpans") or []:
            if not isinstance(ss, dict):
                raise WireError("scopeSpans entries must be objects")
            scope = ((_g(ss, "scope", "instrumentationLibrary") or {}).get("name")) or ""
            for s in ss.get("spans") or []:
                if not isinstance(s, dict):
                    raise WireError("spans must be objects")
                if len(spans) >= MAX_SPANS:
                    raise WireError(f"more than {MAX_SPANS} spans in one request")
                st = s.get("status") or {}
                code = st.get("code", 0)
                if isinstance(code, str):  # enum by name is allowed in proto3 JSON
                    code = {"STATUS_CODE_UNSET": 0, "STATUS_CODE_OK": 1, "STATUS_CODE_ERROR": 2}.get(code, 0)
                kind = s.get("kind", 0)
                if isinstance(kind, str):
                    kind = {"SPAN_KIND_UNSPECIFIED": 0, "SPAN_KIND_INTERNAL": 1, "SPAN_KIND_SERVER": 2, "SPAN_KIND_CLIENT": 3,
                            "SPAN_KIND_PRODUCER": 4, "SPAN_KIND_CONSUMER": 5}.get(kind, 0)
                events = []
                for e in (s.get("events") or [])[:MAX_EVENTS]:
                    if isinstance(e, dict):
                        events.append({"name": str(e.get("name") or ""), "time_ns": _num(_g(e, "timeUnixNano", "time_unix_nano")),
                                       "attrs": _kvs_json(e.get("attributes") or [])})
                spans.append({
                    "trace_id": _hexid(_g(s, "traceId", "trace_id"), 32), "span_id": _hexid(_g(s, "spanId", "span_id"), 16),
                    "parent_span_id": _hexid(_g(s, "parentSpanId", "parent_span_id"), 16) or None,
                    "name": str(s.get("name") or "")[:1024], "kind": _num(kind),
                    "start_ns": _num(_g(s, "startTimeUnixNano", "start_time_unix_nano")),
                    "end_ns": _num(_g(s, "endTimeUnixNano", "end_time_unix_nano")),
                    "attrs": _kvs_json(s.get("attributes") or []), "events": events,
                    "status_code": _num(code), "status_message": str(st.get("message") or "")[:4096],
                    "resource": resource, "scope": str(scope)[:256]})
    return spans


def _checked(spans):
    for sp in spans:
        if len(sp["trace_id"]) != 32 or sp["trace_id"] == "0" * 32:
            raise WireError("span with a missing or invalid trace id")
        if len(sp["span_id"]) != 16 or sp["span_id"] == "0" * 16:
            raise WireError("span with a missing or invalid span id")
        if sp["parent_span_id"] in ("0" * 16,):
            sp["parent_span_id"] = None
        if sp["parent_span_id"] is not None and len(sp["parent_span_id"]) != 16:
            raise WireError("invalid parent span id")
    return spans


def decode(body, content_type, content_encoding=None):
    """-> (spans, fmt) where fmt is 'protobuf' or 'json'. Raises WireError."""
    if len(body) > MAX_BODY:
        raise WireError(f"body exceeds {MAX_BODY} bytes")
    ct = (content_type or "").split(";")[0].strip().lower()
    raw = decompress(body, content_encoding)
    if ct in ("application/x-protobuf", "application/protobuf"):
        return decode_protobuf(raw), "protobuf"
    if ct == "application/json":
        return decode_json(raw), "json"
    raise WireError(f"unsupported Content-Type {content_type!r} (use application/x-protobuf or application/json)")
