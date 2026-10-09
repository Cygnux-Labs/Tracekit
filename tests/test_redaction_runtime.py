"""Redaction runs inside the hook on tool arguments, so every secret pattern must stay
fast on large adversarial input (a prefix of the pattern repeated, never completing)."""
import time
import unittest

from tracekit import privacy

SIZE = 256 * 1024
BOUND = 0.5  # seconds per input; generous for slow CI runners

ADVERSARIAL = {
    "private_key": ["-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n", "-----BEGIN "],  # agent-flow:allow-secret
    "anthropic_key": ["sk-ant-", "sk-ant- "],
    "openai_key": ["sk-", "sk- ", "sk-proj-"],
    "github_token": ["ghp_", "ghp_ ", "github_pat_"],
    "aws_access_key": ["AKIA", "AKIA "],
    "slack_token": ["xoxb-", "xoxb- "],
    "jwt": ["eyJ", "eyJ-", "eyJaaaaaaaa.", "eyJaaaaaaaa.-"],
    "connection_string": ["a://b:", "a://", "a-", "a.", "postgres://user:", "a://b:c", "a://b:@"],
    "google_api_key": ["AIza", "AIza-"],
    "stripe_key": ["sk_live_", "sk_live_ "],
    "npm_token": ["npm_", "npm_ "],
    "bearer_token": ["authorization: bearer ", "Authorization:", "authorization: bearer a"],
    "aws_secret_key": ["aws_secret_access_key=", "aws_secret_access_key= ", "aws_secret_access_key"],
}


def repeated(prefix):
    return (prefix * (SIZE // len(prefix) + 1))[:SIZE]


class RedactionRuntimeTests(unittest.TestCase):
    def test_every_pattern_has_adversarial_inputs(self):
        self.assertEqual({name for name, _ in privacy.SECRET_PATTERNS}, set(ADVERSARIAL))

    def test_adversarial_inputs_redact_quickly(self):
        for name, prefixes in ADVERSARIAL.items():
            for prefix in prefixes:
                with self.subTest(pattern=name, prefix=prefix):
                    s = repeated(prefix)
                    t = time.perf_counter()
                    privacy.redact_text(s)
                    self.assertLess(time.perf_counter() - t, BOUND)

    def test_realistic_connection_strings_still_redacted(self):
        for url in ("postgres://user:pass@host:5432/db", "mongodb+srv://u:p@h/x", "redis://:p@h:6379"):
            with self.subTest(url=url):
                out, hit = privacy.redact_text(f"connect {url} now")
                self.assertTrue(hit)
                self.assertEqual(out, "connect [REDACTED:connection_string] now")

    def test_long_scheme_run_before_url_is_fast_and_redacted(self):
        s = repeated("a-")[:-100] + "postgres://user:pass@host/db"
        t = time.perf_counter()
        out, hit = privacy.redact_text(s)
        self.assertLess(time.perf_counter() - t, BOUND)
        self.assertTrue(hit)
        self.assertNotIn("pass@host", out)

    def test_assignment_and_dotenv_redaction_fast(self):
        for s in (repeated("aws_secret_access_key"), repeated("password"), repeated("\n"), repeated(" \n"),
                  repeated("export ")):
            with self.subTest(prefix=s[:12]):
                t = time.perf_counter()
                privacy.redact_text(s)
                privacy.redact_dotenv(s)
                self.assertLess(time.perf_counter() - t, BOUND)

    def test_always_clear_fields_get_dotenv_redaction(self):
        rec = privacy.tool_input("Bash", {"command": "cat >> .env <<EOF\nDB_HOST=internal.example\nEOF"})
        self.assertNotIn("internal.example", rec["command"]["value"])
        self.assertIn("[REDACTED:dotenv]", rec["command"]["value"])
        plain = privacy.tool_input("Bash", {"command": "FOO=bar make test"})
        self.assertEqual(plain["command"]["value"], "FOO=bar make test")

    def test_realistic_secrets_still_redacted(self):
        # fake redaction fixtures  agent-flow:allow-secret
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        key = ("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"  # agent-flow:allow-secret
               "-----END RSA PRIVATE KEY-----")
        for name, text in (("jwt", f"jwt is {jwt}"), ("jwt", f"x-{jwt}"), ("private_key", f"key:\n{key}\n")):
            with self.subTest(name=name):
                out, hit = privacy.redact_text(text)
                self.assertTrue(hit)
                self.assertIn(f"[REDACTED:{name}]", out)


if __name__ == "__main__":
    unittest.main()
