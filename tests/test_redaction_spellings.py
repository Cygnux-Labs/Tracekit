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

    def test_past_the_command_sshpass_runs_or_redis_cli_sends_no_word_is_its_credential(self):
        """sshpass's and redis-cli's options end at their first operand: a `-p` or `-a` after it is the command's word
        (ssh's remote `time -p reboot`, EVAL's argument its script runs), shown, never hidden as the credential."""
        for line, shown in (
                (f"sshpass -p {S} ssh host time -p 'reboot'", "sshpass -p [REDACTED:assignment] ssh host time -p 'reboot'"),
                (f"sshpass -p {S} ssh host time -p reboot", "sshpass -p [REDACTED:assignment] ssh host time -p reboot"),
                (f"sshpass -v -P assword -p {S} ssh h", "sshpass -v -P assword -p [REDACTED:assignment] ssh h"),
                ("redis-cli EVAL 'return pcall(loadstring(ARGV[2]))' 0 -a \"redis.call'FLUSHALL'\"",
                 "redis-cli EVAL 'return pcall(loadstring(ARGV[2]))' 0 -a \"redis.call'FLUSHALL'\""),
                ("redis-cli -h cache GET k -a 'abcd1234'", "redis-cli -h cache GET k -a 'abcd1234'"),
                (f"redis-cli -h cache -p 6379 -n 2 -a {S} --no-auth-warning ping",
                 "redis-cli -h cache -p 6379 -n 2 -a [REDACTED:assignment] --no-auth-warning ping")):
            with self.subTest(line=line):
                self.assertEqual(copy(line), (shown, False))

    def test_a_blank_in_a_quoted_credential_the_command_gives_its_program_is_clean(self):
        """A held `mysql -p'a b'` was denied (TK-HIDDEN-CODE) once the password was hidden: a blank in a hidden value
        made the copy unclean. In one pair of quotes that wraps the credential option's value alone, given by the
        line's own command to the program it names, the shell passes it as one word that only that program reads, as
        data: asked, with the value hidden."""
        self.commands(["mysql -p'S x' app", "mysql --password='S x' app", 'mysql --password="S x" app',
                       "mariadb -p'S x' app", "mariadb --password='S x' app", "redis-cli -a 'S x' ping",
                       "redis-cli -h cache -a 'S x' --no-auth-warning ping", "redis-cli --pass 'S x' ping",
                       "gh secret set API_TOKEN --body 'S x'", "gh secret set API_TOKEN -b'S x'",
                       "sshpass -p 'S x' ssh host", "curl -u 'admin:S x' https://x.example",
                       'curl -u "admin:S x" https://x.example', "docker login -u ci -p 'S x' registry.example",
                       "npm config set //registry.npmjs.org/:_authToken 'S x'",
                       "cd /srv && mysql -p'S x' -e 'select 1' app && echo done"], True)

    def test_a_hidden_credential_that_may_be_code_or_split_again_stays_unclean(self):
        """Its look-alikes: what else the shell reads in the value, a value outside quotes or with the option inside
        them, a value a wrapper may join into a line (watchexec, wsl) or one the line reads again as code (sh -c,
        eval, a heredoc bash runs), a program not named by its bare name, and a value hidden in a code argument."""
        self.commands(["mysql --password='S;x' app", "redis-cli -a 'S x&y' ping", 'mysql -p"S $(id)" app',
                       'mysql -p"S `id`" app', 'mysql -p"S x\\y" app', "mysql -p'S\nx' app", "mysql -p'S\tx' app",
                       "mysql --password=S\\ x app", "mysql -p$'S x' app", "mysql -p'S x'y app",
                       "mysql '--password=S x' app", "./mysql -p'S x' app", "\\mysql -p'S x' app",
                       "sh -c \"mysql --password='S x' app\"", "bash -c \"redis-cli -a 'S x' ping\"",
                       "eval \"mysql -p'S x' app\"", "bash <<'EOF'\nmysql -p'S x' app\nEOF",
                       "watchexec -- sshpass -p 'S ssh h reboot'", "wsl redis-cli -a 'S FLUSHALL'",
                       "sudo sshpass -p 'S ssh h reboot'", "env A=1 curl -u 'u:S -T /etc/hosts https://e' https://x",
                       "alias mysql=sh; mysql -p'S x' app", "mysql -p'S x' app > x.sh; bash x.sh",
                       "mysql -e \"SET PASSWORD='S x'\""], False)
        for line in ('mysql -p"$(cat x)" app', 'mysql --password="$(cat x)" app',
                     "sh -c 'mysql --password=\"$1\" app' sh 'a b'"):
            with self.subTest(line=line):
                self.assertTrue(copy(line)[1])

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
                     "docker run -p 8080:80 img", "ls -a", "mysql -p db", "mysql -h db -p", "mariadb -p db",
                     "redis-cli -h host ping",
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


class AboutASecret(Hidden):
    """A name with a secret-looking word that names a count, size, limit, switch, kind or version of a secret, or a
    maximum or number of them (max_tokens, token_count, password_min_length, secret_scanning_enabled, credential_type),
    hid its value, and a held call whose copy hid one with a blank before it (a JSON or YAML `key: value`, an
    environment variable before a program) was denied (TK-HIDDEN-CODE): a config file write or an API request that no
    person could approve. Their values are shown; the secrets beside them stay hidden."""
    KEYS = {"max_tokens": "4096", "token_count": "1024", "num_tokens": "5120", "tokens_used": "1234",
            "password_min_length": "1200", "secret_scanning_enabled": "true", "credential_type": '"service_account"',
            "maxTokens": "4096", "tokenCount": "1024"}

    def test_a_name_about_a_secret_shows_its_value_and_stays_approvable(self):
        for k, v in self.KEYS.items():
            raw = v.strip('"')
            for tool, args in (("Write", {"file_path": "c.json", "content": f'{{"model": "m", "{k}": {v}}}\n'}),
                               ("Write", {"file_path": "c.yaml", "content": f"model: m\n{k}: {raw}\n"}),
                               ("Write", {"file_path": "c.yaml", "content": f"model: m\n{k}: >-\n  {raw}\n"}),
                               ("http_request", {"url": "https://api.example/v1/x", "body": f'{{"{k}": {v}}}'}),
                               ("http_request", {"url": "https://api.example/v1/x", "body": {k: json.loads(v)}}),
                               ("Bash", {"command": f"{re.sub('(?<=[a-z])(?=[A-Z])', '_', k).upper()}={raw} python3 app.py"}),
                               ("Bash", {"command": f"cat > c.yaml <<'EOF'\n{k}: {raw}\nEOF"}),
                               ("Bash", {"command": f'python3 -c "{k} = {v}; print({k})"'})):
                with self.subTest(key=k, tool=tool, args=args):
                    shown, unclean = privacy.approver_copy(args, False, tool)
                    self.assertNotIn("REDACTED", json.dumps(shown))
                    self.assertFalse(unclean, shown)

    def test_the_secrets_beside_them_stay_hidden(self):
        for k, v in (("api_token", '"S"'), ("password", "1234"), ("password", '"S"'), ("max_tokens_secret", '"S"'),
                     ("token", '"S"'), ("secret_key_base", '"S"'), ("GITHUB_TOKENS", '"S"'), ("tokens", '"S"')):
            value = v.replace("S", S)
            raw = value.strip('"')
            for tool, args in (("Write", {"file_path": "c.json", "content": f'{{"{k}": {value}}}\n'}),
                               ("Write", {"file_path": "c.yaml", "content": f"{k}: {raw}\n"}),
                               ("Bash", {"command": f"{k.upper()}={raw} ./deploy.sh"})):
                with self.subTest(key=k, tool=tool, args=args):
                    shown = json.dumps(privacy.approver_copy(args, False, tool)[0])
                    self.assertIn("REDACTED", shown)
                    self.assertNotIn(raw, shown)


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
