"""Signer metrics (04-design §2.10) in the Prometheus text exposition format 0.0.4, served on their own port.

    metrics: {listen: 127.0.0.1:9464}        # in signer.yaml; a non-loopback listen needs allow_remote: true

Label values come only from signer-defined sets (record types, gap kinds, refusal codes, verdicts, the witness names
of signer.yaml), never a run id, tenant or identity; past MAX_VALUES a label value is counted as "other", so the series count stays bounded.
docs/observability.md lists every metric.
"""
import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler

from tracekit.netserver import Server

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
DEFAULT_LISTEN = "127.0.0.1:9464"
MAX_VALUES = 64   # distinct values of one label
_SECONDS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5)


def _num(v):
    return "+Inf" if v == float("inf") else repr(v)


def _labels(**kw):
    return "{" + ",".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in kw.items()) + "}" if kw else ""


class Counter:
    def __init__(self, name, help, label=None):
        self.name, self.help, self.type, self.label = name, help, "counter", label
        self._values, self._lock = {} if label else {None: 0}, threading.Lock()

    def inc(self, value=None, n=1):
        with self._lock:
            if value not in self._values and len(self._values) >= MAX_VALUES:
                value = "other"
            self._values[value] = self._values.get(value, 0) + n

    def samples(self):
        with self._lock:
            items = sorted(self._values.items(), key=lambda kv: str(kv[0]))
        for value, n in items:
            yield self.name, _labels(**{self.label: value}) if self.label else "", n


class Gauge:
    """Read at scrape time from `fn()`: a number, or with a `label` a {label value: number} dict."""

    def __init__(self, name, help, fn, label=None):
        self.name, self.help, self.type, self.fn, self.label = name, help, "gauge", fn, label

    def samples(self):
        if not self.label:
            yield self.name, "", self.fn()
            return
        for value, n in sorted(self.fn().items()):
            yield self.name, _labels(**{self.label: value}), n


class Histogram:
    def __init__(self, name, help, buckets):
        self.name, self.help, self.type = name, help, "histogram"
        self.buckets = (*sorted(buckets), float("inf"))
        self._counts, self._sum, self._lock = [0] * len(self.buckets), 0.0, threading.Lock()

    def observe(self, v):
        with self._lock:
            self._counts[next(i for i, b in enumerate(self.buckets) if v <= b)] += 1
            self._sum += v

    def samples(self):
        with self._lock:
            counts, total = list(self._counts), self._sum
        n = 0
        for b, c in zip(self.buckets, counts):
            n += c
            yield self.name + "_bucket", _labels(le=_num(float(b))), n
        yield self.name + "_sum", "", total
        yield self.name + "_count", "", n


class SignerMetrics:
    """The signer's metrics; the service adds its gauges with add()."""

    def __init__(self):
        self.metrics = []
        self.batch_size = self.add(Histogram("tracekit_signer_batch_size", "Items the writer took in one batch.",
                                             (1, 2, 4, 8, 16, 32, 64, 128, 256, 512)))
        self.ack_seconds = self.add(Histogram("tracekit_signer_ack_seconds",
                                              "Seconds from a client write's submit to its answer.", _SECONDS))
        self.fsync_seconds = self.add(Histogram("tracekit_signer_fsync_seconds", "Seconds one log sync took.",
                                                _SECONDS))
        self.records = self.add(Counter("tracekit_signer_records_total", "Records written, by event type.", "type"))
        self.gaps = self.add(Counter("tracekit_signer_gaps_total", "capture.gap records written, by kind.", "kind"))
        self.refusals = self.add(Counter("tracekit_signer_refusals_total", "RPC calls refused, by error code.", "code"))
        self.auth_failures = self.add(Counter("tracekit_signer_auth_failures_total",
                                              "Failed authentications on the HTTP transport."))
        self.decisions = self.add(Counter("tracekit_signer_policy_decisions_total",
                                          "policy.decision records written, by verdict.", "verdict"))
        self.nondeterministic = self.add(Counter("tracekit_signer_policy_nondeterministic_total",
                                                 "Policy decisions that hit the regex timeout (denied)."))
        self.checkpoints = self.add(Counter("tracekit_signer_checkpoints_total",
                                            "Signed checkpoint notes of the record tree written."))
        self.witness_failures = self.add(Counter("tracekit_signer_witness_publish_failures_total",
                                                 "Checkpoint notes a witness did not cosign, by witness.", "witness"))
        self.log_key_failures = self.add(Counter("tracekit_signer_log_key_failures_total",
                                                 "Checkpoint notes the log key failed to sign (retried next round)."))
        self.loop_errors = self.add(Counter("tracekit_signer_loop_errors_total",
                                            "Unexpected errors of a background loop, which carried on, by loop.", "loop"))
        self.otel_dropped = self.add(Counter("tracekit_signer_otel_export_dropped_total",
                                             "Runs the OTLP exporter (otel_out) did not deliver, by reason.", "reason"))
        self.webhook_dropped = self.add(Counter("tracekit_signer_webhook_dropped_total",
                                                "Events a webhook did not deliver, by reason.", "reason"))

    def add(self, m):
        self.metrics.append(m)
        return m

    def written(self, records):
        """Count a batch of records once storage has taken it."""
        for r in records:
            e = r["event"]
            self.records.inc(e["type"])
            if e["type"] == "capture.gap":
                self.gaps.inc(e["data"]["kind"])
            elif e["type"] == "policy.decision":
                self.decisions.inc(e["data"]["decision"])
                if e["data"].get("nondeterministic"):
                    self.nondeterministic.inc()

    def render(self):
        out = []
        for m in self.metrics:
            out += [f"# HELP {m.name} {m.help}", f"# TYPE {m.name} {m.type}"]
            out += [f"{name}{labels} {_num(v)}" for name, labels, v in m.samples()]
        return "\n".join(out) + "\n"


def _loopback(host):
    try:
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def server(cfg, registry, logs=None, tlog=None):
    """A bound, not yet started, HTTP server answering only `GET /metrics` with `registry`, `GET /logs/v0` with
    `logs()` (the signer's logs list) when given, and any other GET with `tlog(path)` (bytes, or None for 404). `cfg` is the `metrics` section of signer.yaml. Start it with serve_forever(); stop it with shutdown() and server_close()."""
    if not isinstance(cfg, dict) or set(cfg) - {"listen", "allow_remote", "serve_records"}:
        raise ValueError("metrics: takes listen, allow_remote and serve_records")
    host, _, port = str(cfg.get("listen", DEFAULT_LISTEN)).rpartition(":")
    if not _loopback(host) and cfg.get("allow_remote") is not True:
        raise ValueError(f"metrics: listen {host!r} is not loopback; set metrics.allow_remote: true to serve it")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/metrics":
                body, typ = registry.render().encode("utf-8"), CONTENT_TYPE
            elif path == "/logs/v0" and logs:
                body, typ = logs().encode("utf-8"), "text/plain; charset=utf-8"
            elif tlog and (body := tlog(path)) is not None:
                typ = "application/octet-stream"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", typ)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    # lean: IPv4 and host names only; set address_family from the host once an IPv6 listen is needed
    return Server((host, int(port)), Handler)
