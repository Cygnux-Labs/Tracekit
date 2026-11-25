"""The spellings of a secret that redaction and an approver's copy hide (tracekit/privacy.py): an option's value past
its quotes, a JSON key's, a structured argument's, a YAML block scalar's, a prefixed or triple-quoted string's. Each is
hidden in the approver's copy and in the record, and a value only a program's data stays clean in a held call's copy."""
import json
import re
import time
import timeit
import unittest

import pytest

from tracekit import privacy

S = "s3cr3tvalue123"   # a redaction fixture: agent-flow:allow-secret


def copy(command, tool="Bash"):
    """(the approver's copy of a held call's command, whether it is unclean: no person can approve it)."""
    shown, unclean = privacy.approver_copy({"command": command}, False, tool)
    return shown["command"], unclean


def record(args, tool="Bash"):
    """What v1 records of a call's `args`, as text."""
    return json.dumps(privacy.tool_input(tool, args, "full"))


class Hidden(unittest.TestCase):
    def check(self, args, tool="Bash", clean=None):
        """`args` hide S in the approver's copy and in the record; a held call's copy is `clean` (None: either)."""
        shown, unclean = privacy.approver_copy(args, False, tool)
        self.assertNotIn(S, json.dumps(shown), shown)
        self.assertNotIn(S, record(args, tool))
        if clean is not None:
            self.assertEqual(unclean, not clean, shown)
        return shown

    def commands(self, lines, clean):
        for line in lines:
            with self.subTest(line=line):
                self.check({"command": re.sub(r"(?<![A-Z_])S(?![A-Z_])", S, line)}, clean=clean)


class OptionValues(Hidden):
    def test_a_curl_user_passwords_part_is_hidden_and_its_user_kept(self):
        self.commands(["curl -u user:S https://x.example", 'curl -u "user:S" https://x.example',
                       "curl -u 'user:S' https://x.example", 'curl --user "user:S" https://x.example',
                       "curl -uuser:S https://x.example", "curl --proxy-user user:S https://x.example",
                       "sudo curl -u user:S https://x.example", 'bash -c "curl -u user:S https://x"'], True)
        self.assertEqual(copy(f'curl -u "user:{S}" https://x.example'),
                         ('curl -u "user:[REDACTED:assignment]" https://x.example', False))
        self.assertEqual(copy("curl -u user https://x.example")[0], "curl -u user https://x.example")

    def test_a_header_with_a_hyphenated_name_is_hidden(self):
        self.commands(['curl -H "X-Api-Key: S" https://x.example', "curl --header 'x-api-key: S' https://x.example"],
                      True)

    def test_a_password_option_of_a_program_that_only_sends_it_is_hidden_and_clean(self):
        self.commands(["wget --http-password 'S' https://x.example", 'wget --password="S" https://x.example',
                       'docker login -u x -p "S"', "docker login -u x -p S", 'docker login -u x --password "S"',
                       "docker login -u x --password S", "redis-cli -a S ping", 'redis-cli -a "S" ping',
                       "mysql -pS -h db", 'mysql -p"S" -h db', "mysql -p'S' -h db", 'mysql --password="S" -h db',
                       "sudo mysql -pS -h db", "env X=1 redis-cli -a S ping"], True)

    def test_sshpass_hides_its_password_and_keeps_the_command_it_runs(self):
        self.commands(["sshpass -p S ssh host", 'sshpass -p "S" ssh host', "sshpass -p'S' ssh host",
                       "sshpass -pS ssh host", "sh -c 'sshpass -p S ssh host'"], True)
        self.assertEqual(copy(f"sshpass -p {S} ssh host 'rm -rf /x'")[0],
                         "sshpass -p [REDACTED:assignment] ssh host 'rm -rf /x'")

    def test_a_secret_set_body_is_hidden_and_a_variable_is_not(self):
        self.commands(["gh secret set API_KEY --body S", 'gh secret set API_KEY --body "S"', "gh secret set API_KEY -b S",
                       'gh secret set API_KEY -b"S"', "gh secret set API_KEY -bS", "gh secret set API_KEY --body=S",
                       'gh secret set API_KEY -b "S" --repo a/b'], True)
        for line in (f"gh variable set X --body {S}", f"gh variable set X -b {S}"):
            self.assertEqual(copy(line), (line, False))

    def test_an_npm_config_secrets_value_is_hidden(self):
        self.commands(['npm config set //registry.npmjs.org/:_authToken "S"',
                       "npm config set //registry.npmjs.org/:_authToken S", "yarn config set npmAuthToken S",
                       "npm config set //registry.npmjs.org/:_authToken=S"], True)
        self.assertEqual(copy("npm config set registry https://r.example/")[0], "npm config set registry https://r.example/")

    def test_a_long_option_that_ends_in_a_secret_word_is_hidden(self):
        self.commands(["some-cli --client-secret S", "some-cli --token S --verbose", "some-cli --api-key=S",
                       "some-cli --password=S"], True)

    def test_a_quoted_value_given_to_a_program_not_known_to_only_read_it_stays_unclean(self):
        self.commands(['some-cli --token "S"', "some-cli --secret 'S'", 'some-cli --api-key="S"'], False)

    def test_what_names_a_secret_or_its_place_is_kept(self):
        for line in ("some-cli --secret-id prod/db --password-file /etc/pw --token-file /t --password-stdin",
                     "docker run -p 8080:80 img", "ls -a", "mysql -p db", "mysql -h db -p", "redis-cli -h host ping",
                     "some-cli --token", "some-cli --password --verbose"):
            with self.subTest(line=line):
                self.assertEqual(copy(line), (line, False))

    def test_a_variable_is_not_a_value(self):
        for line in ('curl -u "$USER:$PW" https://x.example', 'mysql -p"$PW" db', 'some-cli --token "$TOK"'):
            with self.subTest(line=line):
                self.assertEqual(copy(line), (line, False))

    def test_what_runs_after_a_hidden_value_stays_in_view(self):
        self.assertEqual(copy(f"curl -u u:{S} https://x; rm -rf /tmp/y")[0],
                         "curl -u u:[REDACTED:assignment] https://x; rm -rf /tmp/y")
        self.assertTrue(copy(f'curl -u u:"{S} $(id)" https://x')[1])
        self.assertTrue(copy(f"mysql -p'{S};id' db")[1])


class Variables(Hidden):
    def test_mysql_pwd_is_hidden_as_a_prefix_and_an_export(self):
        self.commands(["MYSQL_PWD=S mysql -h db", 'MYSQL_PWD="S" mysql -h db', "export MYSQL_PWD=S",
                       "DB_PWD=S ./run"], True)
        self.check({"file_path": "/tmp/x.env", "content": f"MYSQL_PWD={S}\n"}, "Write")


class JsonKeys(Hidden):
    def test_a_json_keys_value_is_hidden_in_content_a_command_and_a_body(self):
        text = json.dumps({"password": S})
        self.check({"file_path": "/tmp/x.json", "content": text}, "Write")
        self.check({"url": "https://x.example", "method": "POST", "body": text}, "http_request")
        self.check({"command": f"curl -d '{text}' https://x.example"}, clean=True)
        self.check({"content": '{"api_key":"%s", "token" : "%s"}' % (S, S)}, "Write")
        self.check({"content": "d = {'password': '%s'}" % S}, "Write")

    def test_a_key_escaped_in_a_string_is_hidden(self):
        self.check({"body": json.dumps(json.dumps({"password": S}))}, "http_request")

    def test_an_authorization_header_in_json_is_hidden(self):
        self.check({"body": '{"Authorization": "Bearer %s"}' % S}, "http_request")

    def test_the_value_ends_at_its_quote_and_a_name_is_kept(self):
        shown = privacy.approver_copy({"content": '{"password": "%s", "user": "ann"}' % S}, False, "Write")[0]
        self.assertEqual(shown["content"], '{"password": "[REDACTED:assignment]", "user": "ann"}')


class StructuredArguments(Hidden):
    def test_a_secret_looking_keys_string_is_hidden(self):
        self.check({"command": "./deploy.sh", "env": {"API_TOKEN": S}}, clean=True)
        self.check({"url": "u", "method": "POST", "body": {"password": S}}, "http_request", clean=True)
        self.check({"url": "u", "headers": {"Authorization": f"Bearer {S}", "X-Api-Key": S}}, "fetch", clean=True)
        self.check({"a": {"b": [{"client_secret": S}]}}, "x")

    def test_a_header_pair_hides_its_value(self):
        self.check({"url": "u", "headers": [{"name": "Authorization", "value": f"Bearer {S}"}]}, "http_request",
                   clean=True)
        self.check({"env": [{"name": "API_KEY", "value": S}]}, "k8s", clean=True)

    def test_a_name_that_is_not_a_secret_is_kept(self):
        args = {"env": {"SECRET_ID": "prod/db", "DB_PASSWORD_FILE": "/p", "REGION": "us"}, "max_tokens": "4096",
                "headers": [{"name": "Accept", "value": "json"}]}
        self.assertEqual(privacy.approver_copy(args, False, "x"), (args, False))

    def test_a_secret_with_code_in_it_is_unclean(self):
        self.assertTrue(privacy.approver_copy({"env": {"API_TOKEN": "a;b"}}, False, "Bash")[1])


class BlockScalars(Hidden):
    def test_the_lines_of_a_block_scalar_are_hidden_in_content_and_a_heredoc(self):
        for head in ("|", ">", "|-", ">+", "|2", "|+ # a note"):
            yaml = f"user: ann\npassword: {head}\n  {S}\n  more {S}\nname: x\n"
            with self.subTest(head=head):
                self.check({"file_path": "/tmp/x.yaml", "content": yaml}, "Write")
                shown = privacy.approver_copy({"content": yaml}, False, "Write", noted=False)[0]["content"]
                self.assertEqual(shown, f"user: ann\npassword: {head}\n  [REDACTED:assignment]\n"
                                        "  [REDACTED:assignment]\nname: x\n")
                self.check({"command": f"cat > c.yaml <<'EOF'\n{yaml}EOF"}, clean=True)

    def test_a_block_ends_at_the_next_line_not_more_indented_than_its_key(self):
        yaml = f"a:\n  - password: >\n      {S}\n    name: x\nz: 1\n"
        shown = privacy.approver_copy({"content": yaml}, False, "Write", noted=False)[0]["content"]
        self.assertEqual(shown, "a:\n  - password: >\n      [REDACTED:assignment]\n    name: x\nz: 1\n")

    def test_a_block_hiding_code_in_a_held_heredoc_is_unclean(self):
        self.assertTrue(copy(f"cat <<EOF\npassword: |\n  $(id) {S}\nEOF")[1])

    def test_a_key_with_no_block_hides_no_line(self):
        text = "password: |\nname: x\n"
        self.assertEqual(privacy.approver_copy({"content": text}, False, "Write")[0]["content"], text)


class PrefixedStrings(Hidden):
    def test_a_strings_prefix_and_triple_quotes_do_not_keep_its_value(self):
        for lead in ("r'", 'b"', 'f"', "u'", "rb'", 'R"', '"""', "'''", "Rb'"):
            close = lead[len(lead.rstrip("\"'")):]
            for name in ("password", "API_KEY", "token"):
                with self.subTest(string=lead, name=name):
                    self.check({"content": f"{name} = {lead}{S}{close}\nx = 1\n"}, "Write")
                    outer = "'" if '"' in lead else '"'
                    self.check({"command": f"python3 -c {outer}{name} = {lead}{S}{close}{outer}"})

    def test_a_triple_quoted_value_ends_at_its_close(self):
        shown = privacy.approver_copy({"content": f'password = """{S}"""\nuser = "ann"\n'}, False, "Write")[0]
        self.assertEqual(shown["content"], 'password = """[REDACTED:assignment]"""\nuser = "ann"\n')

    def test_a_word_that_only_starts_like_a_prefix_is_a_plain_value(self):
        shown = privacy.approver_copy({"content": "password = rabbitvalue1\n"}, False, "Write")[0]
        self.assertEqual(shown["content"], "password = [REDACTED:assignment]\n")


class Runtime(unittest.TestCase):
    """What the spellings read stays linear on large adversarial input (as tests/test_redaction_runtime.py)."""

    @pytest.mark.serial
    def test_the_spellings_read_in_linear_time(self):
        size = 256 * 1024
        for prefix in ("password: |\n", "password: |\n  x\n", "token\"", "password = \"\"\"", "password = rb", "api-key",
                       "_PWD", "--token ", "curl -u ", "mysql -p ", "gh secret set -b ", "npm config set _authToken ",
                       "PASSWORD", 'authorization": "bearer '):
            s = (prefix * (size // len(prefix) + 1))[:size]
            for name, read in (("text", lambda: privacy.redact_text(s)),
                               ("command", lambda: privacy.approver_copy({"command": s}, False, "Bash")),
                               ("record", lambda: privacy.tool_input("Bash", {"command": s}))):
                with self.subTest(prefix=prefix, read=name):
                    self.assertLess(min(timeit.repeat(read, timer=time.thread_time, number=1, repeat=3)), 0.5)


if __name__ == "__main__":
    unittest.main()
