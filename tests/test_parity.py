"""The browser verifiers (replay.html and the observer) recompute every record's hash in JavaScript. If their
canonical JSON differs from Python's by one byte, a valid run shows as TAMPERED. This runs the real JavaScript
from both pages under Node against the Python canonicaliser on awkward values: floats Python writes in exponent
form, integers beyond 2**53, astral and high-BMP key ordering, escapes and control characters.
Skipped when Node is not installed."""
import json
import os
import random
import shutil
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import core  # noqa: E402

NODE = shutil.which("node")


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def js_sources():
    """The canon functions exactly as shipped in each page."""
    replay = read("tracekit/replay.py")
    a = replay[replay.index("function cp(a,b)"):replay.index("const enc=")]
    term = read("tracekit/ui/terminal.html")
    b = term[term.index("function cpCompare"):term.index("async function sha256")]
    return {"replay.html": (a, "cp"), "observer": (b, "cpCompare")}


def corpus():
    rnd = random.Random(2026)
    keys = ["a", "b", "Z", "é", "日本", "￿", "", "\U00010000", "\U0001f600", "k ", 'q"uote', "back\\slash", ""]
    strings = ["", "plain", "tab\there", "nl\nline", "\x00\x01\x1f", "  ", "emoji \U0001f600", "\\u0041", "\"", "</script>"]
    floats = [1e-5, 1.5e-7, 1e-6, 9.9e-7, 1e16, 1.5e20, 1e21, 1e22, 5e-324, 1.7976931348623157e308, 0.0001, 0.5, -2.5e-9,
              123456789012345680000.0, 2.0, -0.0, 3.141592653589793]
    ints = [0, 1, -1, 2 ** 53 - 1, 2 ** 53, 2 ** 53 + 1, 10 ** 18 + 7, -(10 ** 19), 1234567890123456789]

    def value(depth):
        k = rnd.random()
        if depth > 3 or k < 0.45:
            return rnd.choice([rnd.choice(floats), rnd.choice(ints), rnd.choice(strings), None, True, False,
                               rnd.uniform(-1, 1) * 10 ** rnd.randint(-25, 25)])
        if k < 0.7:
            return [value(depth + 1) for _ in range(rnd.randint(0, 4))]
        return {rnd.choice(keys): value(depth + 1) for _ in range(rnd.randint(0, 6))}

    return [value(0) for _ in range(400)] + [{k: 1 for k in keys}, floats, ints, {}, []]


@unittest.skipUnless(NODE, "needs Node.js")
class BrowserParity(unittest.TestCase):
    def run_js(self, source, cmp_name):
        script = source + "\nconst rows=JSON.parse(require('fs').readFileSync(0,'utf8'));" \
                          "process.stdout.write(JSON.stringify(rows.map(r=>canon(JSON.parse(r)))));"
        values = [core.scrub(v) for v in corpus()]
        # what a record looks like on disk, in both encodings the code base writes
        for ensure_ascii in (False, True):
            stored = [json.dumps(v, ensure_ascii=ensure_ascii) for v in values]
            r = subprocess.run([NODE, "-e", script], input=json.dumps(stored), capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr[:500])
            got = json.loads(r.stdout)
            bad = [(i, core.canon(values[i]), got[i]) for i in range(len(values)) if core.canon(values[i]) != got[i]]
            self.assertEqual(bad[:3], [], f"{len(bad)} of {len(values)} values canonicalise differently (ensure_ascii={ensure_ascii})")

    def test_replay_page_matches_python(self):
        src, cmp_name = js_sources()["replay.html"]
        self.run_js(src, cmp_name)

    def test_observer_matches_python(self):
        src, cmp_name = js_sources()["observer"]
        self.run_js(src, cmp_name)

    def test_javascript_number_formatting_for_random_floats(self):
        rnd = random.Random(9)
        vals = [rnd.uniform(-1, 1) * 10 ** rnd.randint(-30, 30) for _ in range(3000)]
        r = subprocess.run([NODE, "-e", "const v=JSON.parse(require('fs').readFileSync(0,'utf8'));"
                            "process.stdout.write(JSON.stringify(v.map(x=>JSON.stringify(x))))"],
                           input=json.dumps(vals), capture_output=True, text=True, timeout=60)
        self.assertEqual([core.js_number(v) for v in vals if v != int(v)], [j for v, j in zip(vals, json.loads(r.stdout)) if v != int(v)])


class PythonSide(unittest.TestCase):
    def test_big_integers_are_recorded_as_strings(self):
        self.assertEqual(core.scrub({"id": 10 ** 18 + 7, "n": 5, "ok": True}), {"id": str(10 ** 18 + 7), "n": 5, "ok": True})

    def test_canon_uses_javascript_number_text(self):
        self.assertEqual(core.canon({"x": 1e-5, "y": 1.5e20, "z": 2.5}), '{"x":0.00001,"y":150000000000000000000,"z":2.5}')
        self.assertEqual(core.canon({"a": [1, "é", None]}), '{"a":[1,"é",null]}')  # the fast path is unchanged

    def test_exponent_pattern_is_only_a_trigger(self):
        self.assertEqual(core.canon({"s": "1e5 and 2e-3"}), '{"s":"1e5 and 2e-3"}')


if __name__ == "__main__":
    unittest.main()
