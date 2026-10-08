"""Observer and replay rendering: every value interpolated into HTML goes through esc(), the observer's CSP uses a
per-response script nonce, tampered bundles are refused, and the access token never stays in a URL.

    python3 -m pytest tests/test_observe_render.py -v
"""
import http.client
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit import observe, policy, replay  # noqa: E402
from test_hardening import make_bundle, rewrite  # noqa: E402
from test_v02 import run_start, signer  # noqa: E402

XSS = '"><img src=x onerror=alert(1)>\'</script>__RECORDS__/*__RAW_DATA__*/null'
HTML_TAG = re.compile(r"<[a-zA-Z/!]")


def _scan(src, i, close=None, out=None, skel=None):
    """A minimal JS lexer: walks code from `i` until `close` (a `}` ending an interpolation) and records every template
    literal as (literal text, [(expression, expression skeleton)]). The skeleton is the expression with string literals
    replaced by Q and template literals by T."""
    depth, prev = 0, ""
    while i < len(src):
        c = src[i]
        if c in "\"'":
            j = i + 1
            while src[j] != c:
                j += 2 if src[j] == "\\" else 1
            skel is not None and skel.append("Q")
            i, prev = j + 1, "Q"
            continue
        if c == "`":
            i = _template(src, i + 1, out)
            skel is not None and skel.append("T")
            prev = "T"
            continue
        if c == "/" and src[i + 1] == "/":
            i = src.index("\n", i)
            continue
        if c == "/" and src[i + 1] == "*":
            i = src.index("*/", i) + 2
            continue
        if c == "/" and (prev == "" or prev in "(,=:[!&|?{};+"):
            j, cls = i + 1, False
            while cls or src[j] != "/":
                if src[j] == "\\":
                    j += 1
                elif src[j] == "[":
                    cls = True
                elif src[j] == "]":
                    cls = False
                j += 1
            i, prev = j + 1, "R"
            skel is not None and skel.append("R")
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            if depth == 0 and close:
                return i + 1
            depth -= 1
        skel is not None and skel.append(c)
        if not c.isspace():
            prev = c
        i += 1
    assert close is None, "unterminated interpolation"
    return i


def _template(src, i, out):
    text, exprs = [], []
    while src[i] != "`":
        if src[i] == "\\":
            text.append(src[i:i + 2]); i += 2; continue
        if src.startswith("${", i):
            skel = []
            j = _scan(src, i + 2, close="}", out=out, skel=skel)
            exprs.append((src[i + 2:j - 1].strip(), "".join(skel).replace(" ", "").replace("\n", "")))
            i = j
            continue
        text.append(src[i]); i += 1
    out.append(("".join(text), exprs))
    return i + 1


def templates(js):
    out = []
    _scan(js, 0, out=out)
    return out


def _single_call(skel, name):
    if not skel.startswith(name + "(") or not skel.endswith(")"):
        return False
    depth = 0
    for k, ch in enumerate(skel[len(name):]):
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if depth == 0:
            return k == len(skel) - len(name) - 1
    return False


LITERAL_CHOICE = re.compile(r"^[^?]+\?[TQ]:(?:[^?:]+\?[TQ]:)*[TQ]$")


def unescaped(js):
    """Every interpolation into an HTML-building template that is neither esc(...) nor a choice between literals."""
    bad = []
    for text, exprs in templates(js):
        if not HTML_TAG.search(text):
            continue
        for expr, skel in exprs:
            if not (_single_call(skel, "esc") or LITERAL_CHOICE.match(skel)):
                bad.append(expr)
    return bad


def script_of(html):
    return html[html.index("<script"):html.rindex("</script>")]


class EscapingStaticCheck(unittest.TestCase):
    def test_checker_catches_raw_interpolation(self):
        self.assertEqual(unescaped("x.innerHTML=`<td>${r.seq}</td><b>${esc(r.a)}</b>${a ? `<i>${n}</i>` : ''}`;"),
                         ["n", "r.seq"])
        self.assertEqual(unescaped("x=`seq ${r.seq}`; y=/[`]/g; z=\"`\";"), [])

    def test_terminal_html_escapes_every_interpolation(self):
        with open(observe.UI, encoding="utf-8") as f:
            js = script_of(f.read())
        self.assertGreater(len(templates(js)), 20)
        self.assertEqual(unescaped(js), [])

    def test_replay_page_escapes_every_interpolation(self):
        js = script_of(replay.PAGE)
        self.assertGreater(len(templates(js)), 10)
        self.assertEqual(unescaped(js), [])


def _hostile(v):
    if isinstance(v, str):
        return XSS
    if isinstance(v, dict):
        return {k: _hostile(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_hostile(x) for x in v]
    return v


class HostileBundleRendersInert(unittest.TestCase):
    def test_replay_embeds_hostile_strings_only_as_script_data(self):
        ev = {"seq": 0, "prev_hash": "0" * 64, "run_id": "r", "agent_id": "main", "source": "hook", "type": "tool.result",
              "ts": "2026-01-01T00:00:00.000Z", "data": {"ok": True, "duration_ms": "1.5<img src=x onerror=alert(2)>",
                                                       "output": {"value": "x"}, "tool_use_id": "t"}}
        manifest = _hostile({"selection": {"runs": ["r"]}, "seq_range": [0, 1], "kid": "k", "tracekit_version": "v",
                             "public_key_b64": "AAAA"})
        records = [{"seq": 1, "elided": True, "hash": "h", "prev_hash": "p"}, {"hash": "h", "sig": "s", "event": _hostile(ev)}]
        records[1]["event"]["data"]["duration_ms"] = 1.5
        cov = _hostile({"summary": "s", "sandbox": ["s"], "observed": ["o"], "inferred": ["i"], "warnings": ["w"],
                        "unsupported_used": ["u"], "unsupported": ["n"]})
        page = replay.render(manifest, records, [], cov, {"policies/abc.json": json.dumps({"id": XSS})})
        body = page[page.index("<script>") + len("<script>"):page.rindex("</script>")]
        self.assertNotIn("<img", page)
        self.assertNotIn("</script", body)
        self.assertNotIn("<!--", body)
        data = body[body.index("const M=") + len("const M="):]
        dec = json.JSONDecoder()
        got, end = dec.raw_decode(data)
        self.assertEqual(got, manifest)  # a placeholder name inside the manifest was not substituted again
        got, _ = dec.raw_decode(data[end + len(", R="):])
        self.assertEqual(got, records)


class ObserverHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        home = os.path.join(cls.d, "s")
        s = signer(home, witnesses=[f"file:{cls.d}/w.jsonl"], every=100)
        s.handle({"op": "append", "cseq": 0, "event": run_start("r"), "attach": {"policy": policy.load()[1]}})
        cls.path = os.path.join(home, "ledger", "ledger.jsonl")

    def serve(self, token=None, hosts=None):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), observe.make_handler(observe.Feed(self.path), token, hosts))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def get(self, port, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        return r.status, r.getheaders(), r.read()

    def test_csp_uses_a_fresh_nonce_and_no_unsafe_inline_script(self):
        port = self.serve()
        nonces = []
        for _ in range(2):
            code, h, body = self.get(port, "/")
            self.assertEqual(code, 200)
            csp = dict(h)["Content-Security-Policy"]
            script_src = re.search(r"script-src ([^;]*)", csp).group(1)
            self.assertNotIn("unsafe-inline", script_src)
            nonce = re.fullmatch(r"'nonce-([A-Za-z0-9_-]{16,})'", script_src).group(1)
            self.assertIn(f'<script nonce="{nonce}">'.encode(), body)
            self.assertEqual(body.count(b"<script"), 1)
            self.assertNotRegex(body, rb"\son[a-z]+=")  # an inline handler would not run under the nonce
            nonces.append(nonce)
        self.assertNotEqual(nonces[0], nonces[1])

    def test_token_is_exchanged_for_a_cookie_and_leaves_the_url(self):
        port = self.serve("s3cret")
        self.assertEqual(self.get(port, "/")[0], 401)
        self.assertEqual(self.get(port, "/?token=nope")[0], 401)
        self.assertEqual(self.get(port, "/api/snapshot?token=s3cret")[0], 401)  # only the page exchanges it
        code, h, _ = self.get(port, "/?token=s3cret")
        self.assertEqual(code, 303)
        self.assertEqual(dict(h)["Location"], "/")
        cookie = dict(h)["Set-Cookie"]
        for attr in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(attr, cookie)
        self.assertNotIn("s3cret", cookie)
        jar = {"Cookie": cookie.split(";", 1)[0]}
        code, _, body = self.get(port, "/", jar)
        self.assertEqual(code, 200)
        self.assertNotIn(b"s3cret", body)
        self.assertNotIn(b"location.search", body)  # the page never reads or forwards a token from its URL
        self.assertEqual(self.get(port, "/api/snapshot", jar)[0], 200)
        self.assertEqual(self.get(port, "/api/snapshot", {"Cookie": "tracekit_observe=forged"})[0], 401)
        self.assertEqual(self.get(port, "/api/snapshot", {"Authorization": "Bearer s3cret"})[0], 200)

    def test_wildcard_bind_accepts_its_own_host_only_with_the_token(self):
        port = self.serve("s3cret", ["0.0.0.0"])
        remote = {"Host": f"10.1.2.3:{port}"}
        self.assertEqual(self.get(port, "/api/snapshot", remote)[0], 403)
        self.assertEqual(self.get(port, "/api/snapshot", {"Host": "0.0.0.0"})[0], 403)
        self.assertEqual(self.get(port, "/api/snapshot", {**remote, "Authorization": "Bearer s3cret"})[0], 200)
        code, h, _ = self.get(port, "/?token=s3cret", remote)
        self.assertEqual(code, 303)
        jar = {**remote, "Cookie": dict(h)["Set-Cookie"].split(";", 1)[0]}
        self.assertEqual(self.get(port, "/", jar)[0], 200)
        self.assertEqual(self.get(port, "/api/snapshot", jar)[0], 200)

    def test_loopback_without_token_still_refuses_foreign_hosts(self):
        port = self.serve()
        self.assertEqual(self.get(port, "/api/snapshot", {"Host": "evil.example"})[0], 403)


class ObserveBundle(unittest.TestCase):
    def test_tampered_bundle_is_refused(self):
        d = tempfile.mkdtemp()
        good, _ = make_bundle(d)
        bad = os.path.join(d, "bad.tkb")

        def edit(files, _manifest):
            recs = [json.loads(x) for x in files["records.jsonl"].splitlines()]
            recs[-1]["event"]["data"]["reason"] = "edited after signing"
            files["records.jsonl"] = "".join(json.dumps(r) + "\n" for r in recs).encode()
        rewrite(good, bad, edit)
        out = os.path.join(d, "o.html")
        self.assertEqual(observe.main(["--bundle", good, "--export", out]), 0)
        os.remove(out)
        self.assertNotEqual(observe.main(["--bundle", bad, "--export", out]), 0)
        self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
