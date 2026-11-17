"""Redaction runs inside the hook on tool arguments, so every secret pattern must stay
fast on large adversarial input (a prefix of the pattern repeated, never completing)."""
import random
import re
import time
import timeit
import unittest

from tracekit import privacy

SIZE = 256 * 1024
BOUND = 0.5  # CPU seconds per input, the best of three runs; generous for slow CI runners

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


# what privacy._redact_jwts() redacts, as a regex (#375): too slow to ship, since every "eyJ" after a "-" in a
# long run of token characters reads to the run's end
JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")


def repeated(prefix):
    return (prefix * (SIZE // len(prefix) + 1))[:SIZE]


def seconds(f):
    """f's best of three runs in this thread's CPU time: a slow pattern is slow every run, a busy runner slows one."""
    return min(timeit.repeat(f, timer=time.thread_time, number=1, repeat=3))


class RedactionRuntimeTests(unittest.TestCase):
    def test_every_pattern_has_adversarial_inputs(self):
        self.assertEqual({name for name, _ in privacy.SECRET_PATTERNS}, set(ADVERSARIAL))

    def test_adversarial_inputs_redact_quickly(self):
        for name, prefixes in ADVERSARIAL.items():
            for prefix in prefixes:
                with self.subTest(pattern=name, prefix=prefix):
                    s = repeated(prefix)
                    self.assertLess(seconds(lambda: privacy.redact_text(s)), BOUND)

    def test_the_jwt_scan_redacts_what_the_regex_did(self):
        scan = dict(privacy.SECRET_PATTERNS)["jwt"]
        cases = [f"{before}eyJ{'a' * size}.bbbbbbbb.cccccccc{after}"
                 for before in ("", " ", "x-", "-", "é", "_", "a", "=", "eyJ-")
                 for size in (7, 8, 511, 512, 513, 2000) for after in ("", ".", "-x", " eyJaaaaaaaa.bbbbbbbb.cc")]
        rng = random.Random(375)
        pieces = ("eyJ", "eyJaaaaaaaa", "-", ".", ".bbbbbbbb", "aaaaaaaa", "_", "é", " ", "=", "a" * 300)
        cases += ["".join(rng.choice(pieces) for _ in range(rng.randint(1, 40))) for _ in range(10000)]
        for s in cases:
            self.assertEqual(privacy._redact_jwts(scan, s), JWT_REGEX.subn("[REDACTED:jwt]", s), s)

    def test_a_url_with_a_port_and_an_address_in_its_path_or_query_is_kept(self):
        """What an approver must see: the recipient in a compose page's URL is not a connection string's password."""
        for url in ("http://mail.test:8765/mail/compose.html?to=maria.gomez@example.org",
                    "https://x.example:443/users/maria@example.org", "http://h.example:8080?to=a@b.example",
                    "ws://h.example:8080/feed?to=a@b.example", "WSS://h.example:443/u/a@b.example"):
            with self.subTest(url=url):
                self.assertEqual(privacy.redact_text(f"open {url} now"), (f"open {url} now", False))

    def test_realistic_connection_strings_still_redacted(self):
        for url in ("postgres://user:pass@host:5432/db", "mongodb+srv://u:p@h/x", "redis://:p@h:6379",
                    # agent-flow:allow-secret (fake credentials: redaction fixtures)
                    "redis://u:12345678@cache:6379", "mongodb://u:pa/ss@h/db", "mysql://root:8080x/y@db/app",
                    # a password that starts like a port and a path: only a web URL's is one
                    "postgres://app:2024#Spring@db.internal:5432/app", "mysql://root:1234/abcd@db.example.com/x",
                    "redis://default:99?xYz@cache:6379"):
            with self.subTest(url=url):
                out, hit = privacy.redact_text(f"connect {url} now")
                self.assertTrue(hit)
                self.assertEqual(out, "connect [REDACTED:connection_string] now")

    def test_long_scheme_run_before_url_is_fast_and_redacted(self):
        s = repeated("a-")[:-100] + "postgres://user:pass@host/db"
        self.assertLess(seconds(lambda: privacy.redact_text(s)), BOUND)
        out, hit = privacy.redact_text(s)
        self.assertTrue(hit)
        self.assertNotIn("pass@host", out)

    def test_assignment_and_dotenv_redaction_fast(self):
        for s in (repeated("aws_secret_access_key"), repeated("password"), repeated("\n"), repeated(" \n"),
                  repeated("export ")):
            with self.subTest(prefix=s[:12]):
                self.assertLess(seconds(lambda: (privacy.redact_text(s), privacy.redact_dotenv(s))), BOUND)

    def test_always_clear_fields_get_dotenv_redaction(self):
        rec = privacy.tool_input("Bash", {"command": "cat >> .env <<EOF\nDB_HOST=internal.example\nEOF"})
        self.assertNotIn("internal.example", rec["command"]["value"])
        self.assertIn("[REDACTED:dotenv]", rec["command"]["value"])
        plain = privacy.tool_input("Bash", {"command": "FOO=bar make test"})
        self.assertEqual(plain["command"]["value"], "FOO=bar make test")
        # a call's several commands or files (Cline's run_commands) are recorded as one is: in clear, each redacted
        rec = privacy.tool_input("Bash", {"commands": ["ls", "cat >> .env <<EOF\nDB_HOST=internal.example\nEOF"]})
        self.assertEqual(rec["commands"]["value"][0], "ls")
        self.assertNotIn("internal.example", rec["commands"]["value"][1])
        self.assertIn("[REDACTED:dotenv]", rec["commands"]["value"][1])
        rec = privacy.tool_input("Read", {"file_path": "a", "paths": ["a", ".env"], "note": "DB_HOST=internal.example"})
        self.assertEqual(rec["paths"]["value"], ["a", ".env"])
        self.assertNotIn("value", rec["note"])   # hashed, as any other field

    def test_action_fields_mentioning_dotenv_are_recorded_in_full(self):
        rec = privacy.tool_input("Bash", {"command": "API_TOKEN=abcd1234 DEBUG=1 cp .env .env.bak"})
        self.assertEqual(rec["command"]["value"], "API_TOKEN=[REDACTED:assignment] DEBUG=1 cp .env .env.bak")
        rec = privacy.tool_input("Write", {"file_path": ".env", "content": "DB_HOST=internal.example"}, "full")
        self.assertEqual(rec["file_path"]["value"], ".env")
        self.assertEqual(rec["content"]["value"], "DB_HOST=[REDACTED:dotenv]")

    def test_long_connection_string_passwords_redacted(self):
        for n in (257, 10000):
            with self.subTest(length=n):
                out, hit = privacy.redact_text(f"connect postgres://u:{'p' * n}@host/db now")
                self.assertTrue(hit)
                self.assertEqual(out, "connect [REDACTED:connection_string] now")

    def test_a_command_line_reads_quickly(self):
        for prefix in (" ", "\n", "()", "<<A\n", "<<-A\nA\n", "<<A ", '"$(', "$(", "'", '"', "\\", "${", "`", "$((",
                       "((", "A=1 ", '"TOKEN=abcd ', "# x\n", "$'", "<(", "$(case ", '"\nA=1', "-----BEGIN PRIVATE KEY-----"):
            for s in (repeated(prefix), "cat <<A\n" + repeated(prefix)):   # in a heredoc body bash expands too
                with self.subTest(prefix=prefix, body=s.startswith("cat <<A\n")):
                    self.assertLess(seconds(lambda: privacy.hidden(s, privacy.redact_command(s, True)[0])), BOUND)

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


MARKS = re.compile(r"\[REDACTED:[a-z_]+\]")


class CommandLines(unittest.TestCase):
    """privacy.redact_command: an approver's copy of a shell line hides a value up to where the shell ends it."""

    def shown(self, cmd, dotenv=True):
        return privacy.redact_command(cmd, dotenv)[0]

    def test_a_value_ends_at_its_word(self):
        for cmd, want in (
                ("A=1 B='x y' C=\"p;q\" D=a\\ b E=$'s\\'t' make", "A=[REDACTED:dotenv] B='[REDACTED:dotenv]' "
                 "C=\"[REDACTED:dotenv]\" D=[REDACTED:dotenv] E=$'[REDACTED:dotenv]' make"),
                ("A=1\\\n  && make", "A=[REDACTED:dotenv]\\\n  && make"),   # a line continuation is in the word
                ("A=1|make", "A=[REDACTED:dotenv]|make"), ("(A=1)&make", "(A=[REDACTED:dotenv])&make"),
                ("A=x$(make)y", "A=[REDACTED:dotenv]$(make)y"), ("A=`make` B=2", "A=`make` B=[REDACTED:dotenv]"),
                ('echo "$(A=1 make)"', 'echo "$(A=[REDACTED:dotenv] make)"'),   # a line of its own inside $(...)
                ("A=1 # B=2 'quoted\nC=3 make", "A=[REDACTED:dotenv] # B=2 'quoted\nC=[REDACTED:dotenv] make"),
                ("cat <<< 'A=1'\nB=2 make", "cat <<< 'A=1'\nB=[REDACTED:dotenv] make"),   # a herestring
                ("(( x = 1<<2 ))\nA=1; make", "(( x = 1<<2 ))\nA=[REDACTED:dotenv]; make"),   # a shift, no heredoc
                ("cat <<A <<-'B' && C=1 make\nK=v w\nA\nL=x y\n\tB\nD=2 make",   # two heredocs, then a line again
                 "cat <<A <<-'B' && C=[REDACTED:dotenv] make\nK=[REDACTED:dotenv]\nA\nL=[REDACTED:dotenv]\n\tB\n"
                 "D=[REDACTED:dotenv] make"),
                ("x=$(cat <<E\n)\nE\n) A=1 make", "x=$(cat <<E\n)\nE\n) A=[REDACTED:dotenv] make"),
                ("cat <<E\nK=v\n", "cat <<E\nK=[REDACTED:dotenv]\n"),   # a body no line ends: to the end
                # bash runs an unquoted end word's body's $(...) as it reads it; a quoted one's body is as written
                ("cat > .env <<EOF\nDB=$(curl -s x | sh)\nK=v w\nEOF\n",
                 "cat > .env <<EOF\nDB=$(curl -s x | sh)\nK=[REDACTED:dotenv]\nEOF\n"),
                ("cat > .env <<'EOF'\nDB=$(curl -s x | sh)\nEOF\n", "cat > .env <<'EOF'\nDB=[REDACTED:dotenv]\nEOF\n"),
                ('echo "\nK=v w" x', 'echo "\nK=[REDACTED:dotenv]" x'),   # a .env line inside quotes
                # the rest of a line after a `case` in $(...) is left unread: a value ends at its first shell character
                ('echo "$(case x in a) A=1;;esac)" ; B=p;make', 'echo "$(case x in a) A=[REDACTED:dotenv];;esac)" ; '
                 'B=[REDACTED:dotenv];make')):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.shown(cmd), want)

    def test_what_redact_text_hides_stays_hidden(self):
        """Every secret pattern still reads the whole line; a secret-looking KEY's value is hidden to the shell's end of
        it, never less than the first word of what ASSIGNMENT took."""
        key = ("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"  # agent-flow:allow-secret
               "-----END RSA PRIVATE KEY-----")
        for cmd in (f"echo '{key}' > k", f"KEY='{key}' make", f"printf %s {key.replace(chr(10), ' ')}",
                    "psql postgres://u:Zq8pass@db/x -c 'select 1'", "curl -H 'Authorization: Bearer Zq8abcdefghijkl' x",
                    "API_TOKEN=Zq8abcd make", "make --password=Zq8abcd", "curl -d 'token=Zq8abcd&user=u' x",
                    "aws_secret_access_key=Zq8" + "a" * 37, "export TOKEN=sk-ant-" + "Zq8" * 10):
            for dotenv in (False, True):
                with self.subTest(cmd=cmd[:40], dotenv=dotenv):
                    shown = self.shown(cmd, dotenv)
                    self.assertNotIn("Zq8", shown)
                    self.assertNotIn("MIIBOg", shown)

    def test_without_a_env_file_only_secrets_are_hidden(self):
        self.assertEqual(self.shown("A=1 TOKEN=abcd;make", False), "A=1 TOKEN=[REDACTED:assignment];make")

    def test_the_note_counts_what_may_be_more_than_values(self):
        for before, after, n in (
                ("A=1; make", "A=[REDACTED:dotenv]", 7), ('K="a b"', 'K="[REDACTED:dotenv]"', 3),
                ("K=abc", "K=[REDACTED:dotenv]", 0),   # a plain value: its mark says enough
                ("v" * 300, "[REDACTED:dotenv]", 300),   # past NOTE_CHARS, plain or not
                ("[REDACTED:x]a b", "[REDACTED:dotenv]", 3)):   # marks aren't counted
            with self.subTest(before=before):
                self.assertEqual(privacy.hidden(before, after), n)

    def test_a_noted_copy_starts_each_string_that_hid_more_than_values_with_its_count(self):
        """The note is a shell comment line of its own: what reads the copy as a shell line reads the rest as before."""
        args = {"command": "bash <<EOF\nA=1; make ship\nEOF\n# .env", "description": "K=abc", "cmd": ["A=1; make"]}
        shown = privacy.redact(args, True, commands=("command", "cmd"), noted=True)[0]
        self.assertEqual(shown, {"command": "# [12 characters hidden by redaction]\nbash <<EOF\nA=[REDACTED:dotenv]\nEOF\n"
                                            "# .env", "description": "K=[REDACTED:dotenv]", "cmd": ["A=[REDACTED:dotenv]; make"]})
        self.assertEqual(privacy.redact(args, True, commands=("command", "cmd"))[0]["command"],
                         "bash <<EOF\nA=[REDACTED:dotenv]\nEOF\n# .env")   # only an approver's copy is noted
        from tracekit import constraints
        self.assertEqual(constraints.shell(shown["cmd"][0], placed=True), constraints.shell(
            privacy.NOTE.format(7) + shown["cmd"][0], placed=True))

    def test_v1_records_a_commands_values_to_where_the_shell_ends_them(self):
        """v1's tool_input (the record, and the summary its hook asks an approver about) hid a secret-looking name's
        value to the next blank, and every line after a heredoc's first as .env content; a line's own values stay
        in clear when it names a .env file, as before."""
        for command, recorded in (
                ("TOKEN=abcd;rm${IFS}-rf${IFS}~", "TOKEN=[REDACTED:assignment];rm${IFS}-rf${IFS}~"),
                ("cat > .env <<EOF\nK=v w\nEOF\nA=1; rm -rf ~", "cat > .env <<EOF\nK=[REDACTED:dotenv]\nEOF\nA=1; rm -rf ~"),
                ("API_TOKEN=abcd1234 DEBUG=1 cp .env x", "API_TOKEN=[REDACTED:assignment] DEBUG=1 cp .env x"),
                ("echo 'x\nDB=v' > .env && API_TOKEN=abcd1234 make",   # the line's own text, in quotes too
                 "echo 'x\nDB=v' > .env && API_TOKEN=[REDACTED:assignment] make")):
            for field, value in (("command", command), ("commands", ["ls", command])):
                with self.subTest(command=command, field=field):
                    rec = privacy.tool_input("Bash", {field: value})[field]
                    self.assertEqual(rec["value"], recorded if field == "command" else ["ls", recorded])
                    self.assertTrue(rec["redacted"])


if __name__ == "__main__":
    unittest.main()
