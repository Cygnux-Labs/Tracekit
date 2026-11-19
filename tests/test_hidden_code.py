"""A held call's approver's copy never hides code (tracekit/privacy.py, TK-HIDDEN-CODE): bash itself, run on a grammar
of lines that each run one payload program behind a secret-looking value, is the oracle for every copy asked about;
what each copy hides, against the shapes the approver's copy hid before shell lines were read as bash reads them; and
the lines that showed a copy hiding code or a value."""
import collections
import contextlib
import io
import os
import random
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from tracekit import privacy
from tracekit.policy2 import shell

PAYLOADS = ["zzpayload", "sk-ant-api03zzpayloadQQQQQQQQ", "ghp_" + "z" * 36, "AKIAZZPAYLOADZZZZZZZ"]
# harmless programs the lines may run; each payload is a program of its own on PATH that leaves a mark when it runs
SAFE = ["echo", "true", "printf", "cat", "env", "sh", "bash", "perl", "ruby", "nohup", "xargs", "sleep", "tee", "head",
        "grep", "sed", "awk", "find", "dirname", "basename", "date", "chmod", "test", "[", "zsh", "ksh", "python3", "make",
        "sqlite3", "osascript", "expect", "tclsh", "git", "wc", "tr", "cut"]


def slot(rng, p):
    """Words that, in a command's place, run payload `p`, mostly behind a value that looks secret."""
    if p == "zzpayload":
        return rng.choice([
            "A=TOKEN: zzpayload", "A=api_key: zzpayload", "A=password:\tzzpayload", "echo password = x; zzpayload",
            "X=secret:  zzpayload", "env A=TOKEN: zzpayload", "A=TOKEN: command zzpayload",
            "perl -e '$token=qx/zzpayload/'", "perl -e 'token:qx/zzpayload/'", "ruby -e 'token=%x/zzpayload/'",
            "ruby -e \"token=%x!zzpayload!\"", "perl -e \"\\$token=qx/zzpayload/\"",
            "TOKEN=zzpayload; $TOKEN", "TOKEN=zzpayload eval '$TOKEN'", "export TOKEN=zzpayload; trap $TOKEN EXIT",
            "shopt -s expand_aliases\nalias token=zzpayload\ntoken", "TOKEN=abcd;zzpayload", "TOKEN='ab;cd';zzpayload",
            "F=zzpayload; command \"$F\"", "x=TOKEN=abcd; $x zzpayload",
        ])
    return rng.choice([p, "A=1 " + p, "command " + p, "nohup " + p + " >/dev/null", "env " + p, "time " + p,
                       "bash " + p, ". " + p, "F=" + p + "; . \"$F\""])


def runner(rng, inner):
    """`inner` (no ' and no line end in it) given, quoted, to a program that runs it as shell code."""
    return rng.choice([
        f"sh -c '{inner}'", f"bash -c '{inner}'", f"zsh -c '{inner}'", f"eval '{inner}'", f"bash <<< '{inner}'",
        f"env -S '{inner}'" if inner.startswith("A=") else f"sh -c '{inner}'", f"sqlite3 :memory: '.shell {inner}'",
        f"osascript -e 'do shell script \"{inner}\"'" if '"' not in inner else f"sh -c '{inner}'",
        f"expect -c 'exec sh -c {{{inner}}}'" if "{" not in inner and "}" not in inner else f"sh -c '{inner}'",
        f"printf '%s\\n' '{inner}' > s.sh && sh s.sh", f"echo '{inner}' | sh", f"git -c alias.x='!{inner}' x",
        f"find . -maxdepth 0 -exec sh -c '{inner}' \\;",
    ])


def line(rng, depth, p):
    """A line with payload `p` somewhere in it (None: none), `depth` constructs deep at most."""
    if depth <= 0 or rng.random() < 0.3:
        if p:
            return slot(rng, p)
        return rng.choice(["echo hi", "true", "printf x", ":", "echo TOKEN=abcd", "A=TOKEN: x", "date >/dev/null"])
    a = lambda q=None: line(rng, depth - 1, q)  # noqa: E731
    one, two = (p, None) if rng.random() < 0.5 else (None, p)

    def quoted(fmt, bad):
        s = a(p)
        return fmt.format(s) if not any(c in s for c in bad) else s
    forms = [
        lambda: f"{{ {a(p)}; }}", lambda: f"( {a(p)} )", lambda: f"if {a(one)}; then {a(two)}; fi",
        lambda: f"! {a(p)}", lambda: f"{a(one)} && {a(two)}", lambda: f"{a(one)} || {a(two)}",
        lambda: f"{a(one)}; {a(two)}", lambda: f"echo x | {a(p)}", lambda: f"echo $({a(p)})",
        lambda: f"cat <({a(p)})", lambda: f"f() {{ {a(p)}; }}; f", lambda: f"case a in a) {a(p)};; esac",
        lambda: f"while {a(p)}; do break; done", lambda: f"for i in 1; do {a(p)}; done",
        lambda: f"bash <<'E'\n{a(p)}\nE", lambda: f"cat <<'E' >/dev/null\n{a(p)}\nE",
        lambda: quoted("bash <<< '{}'", "'"), lambda: quoted("sh -c '{}'", "'"), lambda: quoted('sh -c "{}"', '"$`\\'),
        lambda: quoted("eval '{}'", "'"), lambda: quoted("eval {}", "'\"$`\\;&|(){}<>\n"),
        lambda: f"env {a(p)}", lambda: f"nohup {a(p)} >/dev/null", lambda: f"time {a(p)}",
        lambda: f"xargs -I{{}} {a(p)} </dev/null", lambda: f"{a(one)}\n{a(two)}",
        lambda: f"until {a(p)}; do break; done", lambda: f"if false; then :; else {a(p)}; fi",
        # a script the line writes, then runs
        lambda: f"cat > x.sh <<'E'\n{a(p)}\nE\nbash x.sh", lambda: f"cat > x.sh <<E\n{a(p)}\nE\n. ./x.sh",
        lambda: quoted("printf '%s\\n' '{}' > x.sh; sh x.sh", "'"), lambda: quoted("echo '{}' > x.sh; bash x.sh", "'"),
        lambda: quoted('x="$(echo \'{}\')"; eval "$x"', "'"), lambda: f"{a(p)} # .env",
        # line continuations and comments
        lambda: f"echo x \\\n#don't\n{a(p)}\necho 'y'", lambda: f"{a(one)} \\\n&& {a(two)}",
        lambda: f"# it's\n{a(p)}", lambda: f"echo a#b'c\n{a(p)}\necho d'",
        # heredocs of every kind, with a quote in the body
        lambda: f"cat <<EOF >/dev/null\nx\\\nEOF\ndon't\nEOF\n{a(p)}\necho 'x'",
        lambda: f"cat <<-EOF >/dev/null\n\tit's\n\tEOF\n{a(p)}", lambda: f"cat <<'EOF' >/dev/null\n'\nEOF\n{a(p)}",
        lambda: f"cat <<E\"O\"F >/dev/null\n'\nEOF\n{a(p)}", lambda: f"cat <<\\EOF >/dev/null\n'\nEOF\n{a(p)}",
        lambda: f"cat <<EOF >/dev/null; {a(p)}\n'\nEOF", lambda: f"x=$(cat <<'E'\nit's\nE\n); {a(p)}",
        # quotes of every kind before the payload
        lambda: f"echo $'it\\'s'; {a(p)}", lambda: f"echo \"it's\"; {a(p)}", lambda: f"echo $\"a'b\"; {a(p)}",
        lambda: f"echo 'a\\'; {a(p)}",
        # runners of quoted text, and code in backquotes
        lambda: runner(rng, s) if "'" not in (s := a(p)) and "\n" not in s else s, lambda: f"echo `echo x`; {a(p)}",
    ]
    return rng.choice(forms)()


class Oracle(unittest.TestCase):
    """Bash runs each line whose copy is asked about and hides its payload's name, in a directory of its own with a
    PATH of harmless programs and the payloads: none may run its payload. Most lines start with a visible decoy of the
    payload's name (`echo zzpayload;`), which never runs it."""
    SEED, LINES = 20261118, 6000

    @unittest.skipUnless(shutil.which("bash") and os.name == "posix", "needs bash")
    def test_no_copy_asked_about_hides_a_program_bash_runs(self):
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)
        path, marker = os.path.join(work, "bin"), os.path.join(work, "marker")
        os.mkdir(path)
        for name in SAFE:
            if shutil.which(name):
                os.symlink(shutil.which(name), os.path.join(path, name))
        for p in PAYLOADS:
            with open(os.path.join(path, p), "w") as f:
                f.write(f"#!/bin/sh\necho ran >> '{marker}'\n")
            os.chmod(os.path.join(path, p), stat.S_IRWXU)
        rng, stats, ran = random.Random(self.SEED), collections.Counter(), []
        for _ in range(self.LINES):
            p, decoy = rng.choice(PAYLOADS), rng.random() < 0.6
            cmd = ("echo %s; " % p if decoy else "") + line(rng, rng.randint(1, 3), p)
            if sum(cmd.count(x) for x in PAYLOADS) != 1 + decoy:
                continue
            copy, unclean = privacy.approver_copy({"command": cmd}, privacy.mentions_dotenv(cmd), "Bash")
            shown = copy["command"].count(p) == cmd.count(p)
            stats["denied" if unclean else "shown" if shown else "hidden"] += 1
            if unclean or shown:
                continue
            if os.path.exists(marker):
                os.remove(marker)
            cwd = os.path.join(work, "cwd")
            shutil.rmtree(cwd, True)
            os.mkdir(cwd)
            try:
                subprocess.run(["bash", "-c", cmd], cwd=cwd, env={"PATH": path, "HOME": work, "LANG": "C"},
                               capture_output=True, timeout=5, executable=shutil.which("bash"), stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                continue
            if os.path.exists(marker):
                ran.append(cmd)
        self.assertEqual(ran, [], stats)
        self.assertGreater(stats["hidden"], 60, stats)   # the oracle ran bash on copies that hide the payload's name
        self.assertGreater(stats["shown"] + stats["hidden"], 200, stats)


# the shapes whose secrets (Zq8…) the approver's copy (v2) and v1's record hid before shell lines were read as bash
# reads them, and (kind, case) each left in view then: all the others must stay hidden
SHAPES = [
    "cat > .env <<'EOF'\nDB_HOST=x\nEOF\nexport DB_PASS=Zq8hunter2",
    "cat > .env <<'EOF'\nDB_PASSWORD=$Zq8uperSecret\nEOF",
    "cat > .env <<'EOF'\nDB_PASS=$Zq8uperSecret\nEOF",
    "export DB_PASSWORD='$Zq8uperSecret' && ./migrate",
    "PGPASSWORD='$Zq8uperSecret' psql -h db -U app",
    "mysql --password='$Zq8uperSecret' -h db",
    "TOKEN=\\$Zq8uperSecret ./run",
    "export API_TOKEN=$'$Zq8uperSecret'",
    "DB_PASS='$Zq8uperSecret' ./run  # .env",
    "echo 'API_KEY=$Zq8uperSecret' >> .env",
    "printf '%s\\n' 'SECRET_KEY=${Zq8uperSecret}' > config",
    "export SECRET_KEY='${Zq8uperSecret}'",
    "cat > .env <<EOF\nDB_PASS=Zq8abc\nEOF",
    "psql postgres://u:Zq8pass@h/db",
    "psql 'postgres://u:Zq8p;ss@h/db'",
    "psql postgres://u:Zq8p\\;ss@h/db",
    "export DB_PASS=\"Zq8 with spaces\"  # .env",
    "DB_PASS=Zq8ab#cd ./run # .env",
    "export SSH_KEY=\"Zq8line1\nZq8line2\"  # .env",
    "docker run -e POSTGRES_PASSWORD=Zq8abcd img",
    "curl -H 'Authorization: Bearer Zq8abcdefghijklmnop' https://api.example",
    "curl -H Authorization:Bearer\\ Zq8abcdefghijklmnop https://api.example",
    "git clone https://user:Zq8pass@github.example/x.git",
    "export AWS_SECRET_ACCESS_KEY=Zq8" + "A" * 37,
    "bash -c 'export TOKEN=Zq8abcd; ./run'",
    "bash <<'EOF'\nexport DB_PASSWORD=Zq8abcd\nEOF",
    "python3 - <<'EOF'\nDB_PASS = 'Zq8 abc'\nEOF\n# .env",
    "ssh host 'TOKEN=Zq8abcd ./run'",
    "TOKEN=Zq8ab`x`cd ./run",
    "TOKEN=Zq8ab$(x)cd ./run",
    "TOKEN=\"Zq8ab\"cd ./run",
    "echo -----BEGIN RSA PRIVATE KEY-----Zq8body-----END RSA PRIVATE KEY----- > k",
    "cat > .env <<-EOF\n\tDB_PASS=Zq8abc\n\tEOF",
    "cat > .env << EOF\nDB_PASS=Zq8abc\nEOF",
    "cat >.env <<\"EOF\"\nexport DB_PASS=Zq8abc\nEOF",
    "tee .env <<EOF >/dev/null\nDB_PASS=Zq8abc def\nEOF",
    "cat <<EOF > .env\nDB_PASS=Zq8abc\nEOF\nchmod 600 .env",
    "echo DB_PASS=Zq8abc > .env; cat > x <<EOF\nA=1\nEOF",
    "{ echo DB_PASS=Zq8abc; } > .env",
]
BASE_SHOWED = {
    ("v2", "curl -H Authorization:Bearer\\ Zq8abcdefghijklmnop https://api.example"),
    ("v2", "cat >.env <<\"EOF\"\nexport DB_PASS=Zq8abc\nEOF"),
    # v1 keeps a command's own .env values in clear but on the lines after its first heredoc line
    ("v1", "curl -H Authorization:Bearer\\ Zq8abcdefghijklmnop https://api.example"),
    ("v1", "cat >.env <<\"EOF\"\nexport DB_PASS=Zq8abc\nEOF"),
    ("v1", "DB_PASS='$Zq8uperSecret' ./run  # .env"), ("v1", "export DB_PASS=\"Zq8 with spaces\"  # .env"),
    ("v1", "DB_PASS=Zq8ab#cd ./run # .env"), ("v1", "export SSH_KEY=\"Zq8line1\nZq8line2\"  # .env"),
    ("v1", "echo DB_PASS=Zq8abc > .env; cat > x <<EOF\nA=1\nEOF"), ("v1", "{ echo DB_PASS=Zq8abc; } > .env"),
}


class Privacy(unittest.TestCase):
    def test_what_the_copy_hid_before_stays_hidden(self):
        """Each shape's secret stays out of the approver's copy, the record v1 keeps (as its hook reads it for a hold,
        and as any other caller records it) and the copy the signer keeps of a call it doesn't hold, as it was before
        shell lines were read as bash reads them; one of them it showed then (a $'...' value) it hides now."""
        for case in SHAPES:
            dotenv = privacy.mentions_dotenv(case)
            seen = {"v2": [privacy.approver_copy({"command": case}, dotenv, "Bash")[0]["command"],
                           privacy.approver_copy({"command": case}, dotenv, "Bash", noted=False)[0]["command"]],
                    "v1": [privacy.tool_input("Bash", {"command": case}, unclean=[])["command"]["value"],
                           privacy.tool_input("Bash", {"command": case})["command"]["value"]]}
            for kind, copies in seen.items():
                for copy in copies if (kind, case) not in BASE_SHOWED else ():
                    with self.subTest(case=case, kind=kind):
                        self.assertNotIn("Zq8", copy)

    def test_a_variables_name_stays_in_view_only_where_bash_expands_it(self):
        """`$NAME` is no value where bash expands it (code, "...", a body with an unquoted end word): what the remedy
        asks for stays asked about. Anywhere else it is text, which may be a secret: in '...', $'...', after a
        backslash, a body kept as written, a comment, an interpreter's program, an argv's word."""
        for command, shown in (
                ('curl -H "X-Token: $TK" x && TOKEN=$TK ./run', 'curl -H "X-Token: $TK" x && TOKEN=$TK ./run'),
                ("export TOKEN=${TK} && cat > x <<EOF\nTOKEN=$TK\nEOF", "export TOKEN=${TK} && cat > x <<EOF\nTOKEN=$TK\nEOF"),
                ("echo 'TOKEN=$Zq8a' x", "echo 'TOKEN=[REDACTED:assignment]' x"),
                ("echo TOKEN=$'$Zq8a' x", "echo TOKEN=$'[REDACTED:assignment]' x"),
                ("echo TOKEN=\\$Zq8a x", "echo TOKEN=[REDACTED:assignment] x"),
                ("cat > x <<'EOF'\nTOKEN=$Zq8a\nEOF", "cat > x <<'EOF'\nTOKEN=[REDACTED:assignment]\nEOF"),
                ("true # TOKEN=$Zq8a", "true # TOKEN=[REDACTED:assignment]"),
                # where the reader is unsure (past an end word it can't read), it may be a body kept as written
                ("cat > cfg <<$'EOF'\nDB_PASSWORD=$Zq8a\nEOF", "cat > cfg <<$'EOF'\nDB_PASSWORD=[REDACTED:assignment]\nEOF"),
                ("perl -e 'my $TOKEN=$Zq8a'", "perl -e 'my $TOKEN=[REDACTED:assignment]'"),
                (["curl", "--token=$Zq8a"], ["curl", "--token=[REDACTED:assignment]"])):
            with self.subTest(command=command):
                self.assertEqual(privacy.redact({"command": command}, commands=privacy.COMMAND_KEYS)[0]["command"], shown)
                if isinstance(command, str):
                    self.assertEqual(privacy.tool_input("Bash", {"command": command}, "full")["command"]["value"], shown)


def held(args, tool="Bash"):
    """(the approver's copy of a held call, whether it is denied: TK-HIDDEN-CODE)."""
    return privacy.approver_copy(args, privacy.mentions_dotenv(args.get("command")), tool)


class Lines(unittest.TestCase):
    """The lines whose held copy hid code: each copy shows what runs, or the call is denied."""

    def test_a_program_place_the_policys_parser_finds_is_never_hidden(self):
        for command in ("{ A=TOKEN: /tmp/xyzzy; }", "while AKIAZZPAYLOADZZZZZZZ; do :; done",
                        "if true; then ghp_" + "z" * 36 + "; fi", "! /tmp/sk-proj-" + "a" * 24,
                        "time AKIAZZPAYLOADZZZZZZZ", "bash ghp_" + "z" * 36, ". AKIAZZPAYLOADZZZZZZZ",
                        "F=/tmp/sk-proj-" + "a" * 24 + "; . \"$F\"", "X=ghp_" + "z" * 36 + "; $X",
                        "bash <<< 'sh -c 'command ghp_" + "z" * 36 + "''", "coproc AKIAZZPAYLOADZZZZZZZ",
                        "select x in 1; do AKIAZZPAYLOADZZZZZZZ; done", "python3 ghp_" + "z" * 36 + " --x",
                        "/tmp/AKIAZZPAYLOADZZZZZZZ.sh x"):
            with self.subTest(command=command):
                self.assertTrue(held({"command": command})[1])

    def test_a_line_the_policys_parser_cant_read_whole_hides_no_value(self):
        """A command whose program the parser can't read (from stdin, an expansion it can't follow), a line too long
        for it, an argv whose code is several words joined: no value on it is hidden from an approver."""
        from tracekit.policy2 import engine
        for args in ({"command": "echo TOKEN=abcd1234 | sh"}, {"command": "TOKEN=abcd1234 $(cat cmd)"},
                     {"command": "TOKEN=abcd ./run " + "x" * engine.MAX_SUBJECT},
                     {"command": ["ssh", "host", "TOKEN=abcd", "./run"]}):
            with self.subTest(args=str(args)[:80]):
                self.assertTrue(held(args)[1])
        self.assertEqual(held({"command": ["ssh", "host", "TOKEN=abcd ./run"]}),
                         ({"command": ["ssh", "host", "TOKEN=[REDACTED:assignment] ./run"]}, False))
        # an argv's word is data where a data reader gets it (sudo passes it on), else what its program may run
        self.assertEqual(held({"command": ["sudo", "curl", "-d", "token=abcd1234", "https://x"]}),
                         ({"command": ["sudo", "curl", "-d", "token=[REDACTED:assignment]", "https://x"]}, False))
        self.assertTrue(held({"command": ["sqlite3", "db", ".system TOKEN=abcd"]})[1])
        # a reading the parser's budget cut short (its loop values' readings) is no whole reading either
        real = shell.analyse

        def cut(line, **kw):
            out = real(line, **kw)
            return (*out[:5], {**out[5], "pieces_cut": True})
        with mock.patch.object(shell, "analyse", cut):
            self.assertTrue(held({"command": "TOKEN=abcd ./run"})[1])
        self.assertFalse(held({"command": "TOKEN=abcd ./run"})[1])

    def test_a_script_its_runner_reads_as_a_line_is_read_as_one(self):
        """eval, ssh, watch, trap, a heredoc a shell reads: the policy's parser reads each where the line holds it, so
        the copy reads it there too, its values hidden to where that shell ends them. Code the parser reads where the
        line doesn't hold it as written (an alias's value, GIT_SSH_COMMAND's, a git alias's, a script the line writes
        and then runs, a variable's value) can't be placed: any value hidden on the line, or in its span, denies."""
        run = "aws s3 cp db s3://x"
        for command, shown in (
                (f"eval TOKEN=abcd {run}", f"eval TOKEN=[REDACTED:assignment] {run}"),
                (f"watch 'TOKEN=abcd;{run}'", f"watch 'TOKEN=[REDACTED:assignment];{run}'"),
                (f"ssh host 'TOKEN=abcd;{run}'", f"ssh host 'TOKEN=[REDACTED:assignment];{run}'"),
                (f"bash <<'E'\nTOKEN=abcd;{run}\nE", f"bash <<'E'\nTOKEN=[REDACTED:assignment];{run}\nE"),
                (f"alias x='TOKEN=abcd;{run}'; x", None), (f"GIT_SSH_COMMAND='TOKEN=abcd;{run}' git fetch", None),
                (f"cat > r.sh <<'E'\nTOKEN=abcd;{run}\nE\nbash r.sh", None),
                (f"X='{run}'; TOKEN=abcd eval \"$X\"", None), ("TOKEN=reboot; bash <<EOF\n$TOKEN\nEOF", None),
                (f"TOKEN=abcd {run} `date`", f"TOKEN=[REDACTED:assignment] {run} `date`"),   # code read in place
                # a command's words as written in each reading the parser makes (an expansion empty), a function's
                # body where it is defined, a program an interpreter's code runs within its own span, a herestring
                # a data reader reads
                (f'echo "$(date)" && TOKEN=abcd {run}', f'echo "$(date)" && TOKEN=[REDACTED:assignment] {run}'),
                (f"f() {{ TOKEN=abcd {run}; }}; f", f"f() {{ TOKEN=[REDACTED:assignment] {run}; }}; f"),
                (f"TOKEN=abcd {run} && python3 -c 'import os; os.system(\"ls\")'",
                 f"TOKEN=[REDACTED:assignment] {run} && python3 -c 'import os; os.system(\"ls\")'"),
                ("cat <<< 'TOKEN=abcd1234'", "cat <<< 'TOKEN=[REDACTED:assignment]'"),
                (f"eval TOKEN=abcd\\;{run}", None), (f"eval 'TOKEN=abcd'\\;{run}", None),
                (f"git -c alias.x='!TOKEN=abcd;{run}' x", None), (f"env -S 'TOKEN=abcd;{run}'", None),
                # a quoted value a program the parser doesn't read may run: no blank or shell separator in it
                (f"printf '%s\\n' 'x\nPASSWORD=abcd {run}' # .env", None), (f'echo "TOKEN=ab$cd" {run}', None),
                (f"echo 'TOKEN=ab\\cd' {run}", f"# [5 characters hidden by redaction]\necho 'TOKEN=[REDACTED:assignment]' {run}")):
            with self.subTest(command=command):
                copy, denied = held({"command": command})
                self.assertEqual(None if denied else copy["command"], shown)

    def test_a_decoy_of_the_code_text_places_nothing(self):
        """The copy joins the policy parser's reading by where each program and each code text stands, never by its
        text: a visible decoy of the same text (`echo ./payload`) doesn't place the code a git alias runs, nor make a
        line the reader read otherwise (a backslash-newline, a heredoc's) read right."""
        for command in ("gh pr merge 912 --squash; echo ./payload; git -c alias.token=!./payload token",
                        "aws s3 cp ./a s3://team-bucket/; echo reboot; git -c alias.api_key=!reboot api_key",
                        "gh pr merge 912 --squash; echo ./payload; echo x \\\n#don't\nA=TOKEN: ./payload\necho 'y'\n",
                        "gh pr merge 912 --squash\necho ./payload\ncat <<EOF\nx\\\nEOF\ndon't\nEOF\nA=TOKEN: ./payload\n"
                        "echo 'x'\n", "echo AKIAZZPAYLOADZZZZZZZ; echo x \\\n#don't\nAKIAZZPAYLOADZZZZZZZ\necho 'y'"):
            with self.subTest(command=command):
                self.assertTrue(held({"command": command})[1])

    def test_a_backslash_newline_is_read_as_bash_deletes_it(self):
        """Outside quotes bash deletes a backslash-newline before it reads the line, so a # after one starts a comment;
        in an unquoted end word's heredoc it joins two lines before one can end the body: the copy reads both so."""
        run = "./run"
        for command, shown in (
                (f"echo x \\\n#don't\nTOKEN=abcd {run}\necho 'y'", f"echo x \\\n#don't\nTOKEN=[REDACTED:assignment] {run}\n"
                 "echo 'y'"),
                (f"cat <<EOF >/dev/null\nx\\\nEOF\ndon't\nEOF\nTOKEN=abcd {run}\necho 'x'",
                 f"cat <<EOF >/dev/null\nx\\\nEOF\ndon't\nEOF\nTOKEN=[REDACTED:assignment] {run}\necho 'x'"),
                (f"cat <<EOF >/dev/null\nE\\\nOF\nTOKEN=abcd {run}", f"cat <<EOF >/dev/null\nE\\\nOF\nTOKEN=[REDACTED:assignment] "
                 f"{run}")):
            with self.subTest(command=command):
                copy, denied = held({"command": command})
                self.assertEqual(None if denied else copy["command"], shown)

    def test_quoted_text_a_program_may_run_hides_no_value(self):
        """A quoted word goes to a program the policy's parser doesn't read: one of DATA_READERS reads it as data, any
        other may run it (sqlite3's .system, osascript, expect, vim -c, tar --to-command, make SHELL=, docker run,
        kubectl exec): a value hidden in it denies the hold, and so does one that starts a word of its own (`A=TOKEN:
        x`) anywhere but a data reader's word."""
        for command in ("sqlite3 :memory: '.system A=TOKEN: ./payload'", "sqlite3 :memory: '.system TOKEN=abcd'",
                        "osascript -e 'do shell script \"A=TOKEN: ./payload\"'",
                        "expect -c 'exec sh -c {A=TOKEN: ./payload}'", "vim -es -c '!A=TOKEN: ./payload' -c 'q!'",
                        "tar -xf a.tar --to-command='TOKEN=abcd'", "LD_PRELOAD='./sk-ant-api03zzpayloadQQQQQQQQ.so' ls",
                        "make SHELL='/bin/sh -c A=TOKEN:./payload' all", "docker run --entrypoint sh img -c 'TOKEN=abcd'",
                        "kubectl exec pod -- sh -c 'TOKEN=abcd'", "echo \"$(osascript -e 'x TOKEN=abcd')\"",
                        "sqlite3 db 'X-Token: abcd1234'", "sqlite3 db password: hunter22",
                        "bash <<'EOF'\napi_key: abcd1234\nEOF"):
            with self.subTest(command=command):
                self.assertTrue(held({"command": command})[1])
        for command, shown in (("curl -H 'X-Token=abcd1234' https://x", "curl -H 'X-Token=[REDACTED:assignment]' https://x"),
                               ("sudo curl -d 'token=abcd1234' https://x", "sudo curl -d 'token=[REDACTED:assignment]' https://x"),
                               ("K='TOKEN=abcd ef'", "K='TOKEN=[REDACTED:assignment] ef'"),
                               ("export K='token=abcd1234'", "export K='token=[REDACTED:assignment]'")):
            with self.subTest(command=command):
                self.assertEqual(held({"command": command}), ({"command": shown}, False))

    def test_data_a_program_reads_by_name_and_its_hostile_twin(self):
        """What a program only reads as data, though it may run other words it gets, as each allowlist names it: a
        data reader's word that starts a word of its own (`X-Token: x`), a value given a data name in the environment
        (_DATA_ENV), and the option values and connection URIs of _DATA_OPTIONS. Each one's twin, the same program with
        a word it may run, or a name the program may run, denies."""
        url, key = "postgres://app:hunter2@db/app", "/tmp/sk-proj-" + "a" * 24
        for command, twin in (
                # a data reader's word that starts a word of its own, and the same in a word a program may run
                ("curl -H 'X-Token: abcd1234' https://x", "sqlite3 db 'X-Token: abcd1234'"),
                ('echo "token: abcd1234efgh" > ~/.config/tool.yml', "vim -es -c 'token: abcd1234efgh'"),
                ("echo password: hunter22 && make", "sqlite3 db password: hunter22"),
                ("cat > c.yml <<'EOF'\napi_key: abcd1234\nEOF", "bash <<'EOF'\napi_key: abcd1234\nEOF"),
                # a value given a data name before a program, and given a name the program may run
                (f'DATABASE_URL="{url}" npm run migrate', f"NODE_OPTIONS='--require {key}' npm run migrate"),
                ("PGPASSWORD='S3cr3tpass' npm test", f"PYTHONSTARTUP='{key}' python3"),
                ("GH_TOKEN='ghp_" + "a" * 36 + "' gh pr merge 1", f"EDITOR='{key}' git commit"),
                ("AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' make deploy", f"BASH_ENV='{key}' make"),
                ("STRIPE_API_KEY='sk_live_" + "a" * 24 + "' npm start", f"MY_HOOK='{key}' npm start"),
                # an option's value, and the same program's word it may run
                ("terraform apply -var 'db_password=hunter2pass' -auto-approve", "terraform apply -target='token=abcd1234'"),
                ("terraform apply -var='db_password=hunter2pass'", f"terraform apply -var-file='{key}'"),
                ('helm upgrade app ./chart --set "secrets.apiToken=abc,def"', f"helm upgrade app ./chart --post-renderer '{key}'"),
                ("helm upgrade app ./chart --set-string 'token=abcd1234' --set-json 'x={\"password\": \"abcd1234\"}'",
                 "helm upgrade app ./chart -f 'token=abcd1234'"),
                ("kubectl create secret generic db --from-literal=password='S3cr3t!pass'",
                 "kubectl exec pod -- sh -c 'TOKEN=abcd'"),
                ("kubectl create secret generic db --from-literal 'password=S3cr3tpass'",
                 "kubectl run x --image=y -- 'token=abcd1234'"),
                # a database client's connection, and its code (psql -c and \!, -f, mysql -e, mongosh --eval, EVAL)
                (f"psql '{url}' -c 'select 1'", "psql -c 'select 1 -- token=abcd1234'"),
                (f"psql -U app -h db -d '{url}'", f"psql -h db -f '{key}'"),
                ("mysql -h db -u root --password='Zq8abcd' app", "mysql -e 'select 1 /* token=abcd1234 */'"),
                ("mysql 'mysql://u:hunter2@db/app'", "mysql app -e 'system token=abcd1234'"),
                ('mongosh "mongodb+srv://app:hunter2@cluster0.example.net/app"', "mongosh --eval 'token=\"abcd1234\"'"),
                ("redis-cli -u 'redis://default:hunter2@cache:6379' ping", "redis-cli EVAL 'token=abcd1234' 0")):
            with self.subTest(command=command):
                self.assertFalse(held({"command": command})[1])
            with self.subTest(twin=twin):
                self.assertTrue(held({"command": twin})[1])

    def test_tk_s012s_code_and_argv_arguments_are_read_as_code(self):
        """A code runner's, a notebook's or a process's arguments TK-S012 holds: code (any value hidden there denies)
        and an argv (run by the program beside it: sh -c's script read as a line), in the copy and in v1's record."""
        for tool, args, shown in (
                ("mcp__e2b__run_code", {"language": "ruby", "code": "token=%x/reboot/"}, None),
                ("mcp__nb__cell", {"cell_source": "token = 'abcd1234'"}, None),
                ("mcp__sandbox__exec", {"program": "sh", "args": ["-c", "A=TOKEN: reboot"]}, None),
                ("mcp__sandbox__exec", {"program": "sh", "args": ["-c", "TOKEN=abcd;reboot"]},
                 {"program": "sh", "args": ["-c", "TOKEN=[REDACTED:assignment];reboot"]}),
                ("mcp__shell__run", {"bash": "A=TOKEN: reboot"}, None)):   # (any string: a word of its own)
            with self.subTest(args=args):
                copy, hides = privacy.approver_copy(args, False, tool)
                self.assertEqual(None if hides else copy, shown)
                unclean = []
                privacy.tool_input(tool, args, "hashed", unclean)
                self.assertEqual(bool(unclean), shown is None)

    def test_a_call_of_many_strings_is_read_in_one_budget(self):
        """Each string's parse spends one budget for the whole call (privacy.Budget): thousands of strings with a
        value hidden in each are read in bounded time and, past it, denied; the same text read again costs nothing."""
        import time
        many = {"commands": [f"TOKEN=ab{i:06d};x{i}" for i in range(3000)]}
        t = time.perf_counter()
        _, hides = privacy.approver_copy(many, False, "Bash")
        self.assertTrue(hides)
        self.assertLess(time.perf_counter() - t, 30)
        same = {"commands": ["TOKEN=abcd;x"] * 3000}
        with mock.patch.object(shell, "analyse", wraps=shell.analyse) as parse:
            copy, hides = privacy.approver_copy(same, False, "Bash")
        self.assertEqual((parse.call_count, hides, copy["commands"][0]), (1, False, "TOKEN=[REDACTED:assignment];x"))

    def test_code_an_interpreter_reads_hides_no_value(self):
        """A value hidden in an interpreter's program may be its code: perl's qx//, ruby's %x(), a heredoc python3
        reads, an argv's program, an interpreter the parser doesn't read (deno)."""
        for args in ({"command": "perl -e '$token=qx/zzpayload/'"}, {"command": "ruby -e 'TOKEN=%x(zzpayload)'"},
                     {"command": "python3 - <<'EOF'\nk='sk-ant-api03zzpayloadQQQQQQQQ'\nEOF"},
                     {"command": "python3 -c 'k=\"sk-ant-api03zzpayloadQQQQQQQQ\"'"},
                     {"cmd": ["python3", "-c", "k='sk-ant-api03zzpayloadQQQQQQQQ'"]},
                     {"command": "deno eval 'const TOKEN=\"sk-ant-api03zzpayloadQQQQQQQQ\"'"},
                     {"command": "awk 'BEGIN{token=\"sk-ant-api03zzpayloadQQQQQQQQ\"}'"},
                     {"command": "python3 -c k=sk-ant-api03zzpayloadQQQQQQQQ"},   # (unquoted: interp all the same)
                     {"command": "deno eval k=sk-ant-api03zzpayloadQQQQQQQQ"},
                     {"command": "X='token=\"abcd1234\"'; python3 -c \"$X\""}):   # (a variable's value: the program)
            with self.subTest(args=args):
                self.assertTrue(held(args)[1])

    def test_every_line_the_signer_decides_as_shell_is_read_as_one(self):
        """typed_line and process_manage's data are decided as shell lines (signer.service.evaluate): the copy reads
        them so (privacy.typed_lines); and any other argument or key whose redaction takes a character that makes
        code (a SQL query, a program's code, a key under a command argument) is denied when held."""
        for tool, args, shown, denied in (
                ("Bash", {"command": "ls", "typed_line": "TOKEN=abcd;rm -rf ~"},
                 {"command": "ls", "typed_line": "TOKEN=[REDACTED:assignment];rm -rf ~"}, False),
                ("process_manage", {"action": "submit", "data": "TOKEN=abcd;rm -rf ~"},
                 {"action": "submit", "data": "TOKEN=[REDACTED:assignment];rm -rf ~"}, False),
                ("process_manage", {"action": "write", "data": "TOKEN='ab;cd' make"}, None, True),
                ("process_manage", {"action": "list", "data": "TOKEN=abcd;rm -rf ~"}, None, True),   # text: hid code
                ("sql", {"query": "select 1 where password=abcd;drop table x"}, None, True),
                ("python", {"code": "password=abcd;os.system(x)"}, None, True),
                ("x", {"command": {"TOKEN=abcd;rm -rf ~": 1}}, None, True),
                ("x", {"cmd": ["sh", "-c", "TOKEN=abcd;rm -rf ~"]}, {"cmd": ["sh", "-c", "TOKEN=[REDACTED:assignment];rm -rf ~"]},
                 False),
                ("http", {"url": "https://x/v1?api_key=abcd1234&limit=10"}, {"url": "https://x/v1?api_key=[REDACTED:assignment]"},
                 False)):   # a URL query's next parameter is no code
            with self.subTest(args=args):
                copy, hides = privacy.approver_copy(args, False, tool, noted=False)
                self.assertEqual(hides, denied)
                if shown:
                    self.assertEqual(copy, shown)
        self.assertEqual(privacy.typed_lines("process_manage", {"action": "write", "data": "x", "typed_line": "y"}),
                         ["typed_line", "data"])
        from tracekit.policy2 import engine
        self.assertIs(engine._COMMAND_KEYS, privacy.COMMAND_KEYS)

    def test_v1_shows_every_argument_and_prints_it_escaped(self):
        """v1's approval summary holds every argument as its record keeps it in clear (run_code's code, not only a
        command, a file or a URL), and `tracekit pending` and `tracekit approve` print it, and the rule ids, escaped:
        an agent's \\r or terminal escape can't redraw the approver's line."""
        args = {"language": "python", "code": "print(1)"}
        d = privacy.screened({"decision": "ask", "rule_ids": ["R"], "reasons": ["r"]}, "run_code", args,
                             privacy.tool_input("run_code", args), [])
        self.assertEqual((d["decision"], d["summary"]), ("ask", "run_code language=python code=print(1)"))
        from tracekit import hook
        seen, call = [], {"run_id": "r", "agent_id": "a", "data": {"name": "run_code", "tool_use_id": "t",
                                                                   "input": privacy.tool_input("run_code", args)}}
        with mock.patch.object(hook.client, "rpc", lambda req, timeout=None: seen.append(req) or (
                {"ok": True, "approval_id": "a1"} if req["op"] == "approval_request" else {"decision": "timeout"})), \
                mock.patch.object(hook, "APPROVAL_CAP_S", 1), contextlib.redirect_stderr(io.StringIO()):
            hook.wait_for_approval(call, d, {"approval_timeout_s": 1})
        self.assertEqual(next(r["summary"] for r in seen if r["op"] == "approval_request"), d["summary"])
        from tracekit import cli, client
        pend = [{"id": "a1", "run_id": "r", "summary": "Bash command=ls\r\x1b[2Kcommand=pwd", "rule_ids": ["R\x1b[2K"],
                 "expires_in_s": 5}]
        for argv, replies in ((["pending"], [{"pending": pend}]),
                              (["approve"], [{"pending": pend}, {"ok": True, "decision": "approve"}])):
            out = io.StringIO()
            with self.subTest(argv=argv), mock.patch.object(client, "socket_path", return_value="/x/s.sock"), \
                    mock.patch.object(client, "rpc", side_effect=replies), contextlib.redirect_stdout(out):
                cli.main(argv)
                self.assertNotIn("\r", out.getvalue())
                self.assertNotIn("\x1b", out.getvalue())
                self.assertIn('"Bash command=ls\\r\\u001b[2Kcommand=pwd"', out.getvalue())

    def test_v1_reads_the_same_lines(self):
        """v1's record (what its hook asks an approver about) reads every command argument (privacy.COMMAND_KEYS) and
        typed_line as the shell does, and a hold whose record would hide code is denied."""
        for ti, field, recorded, unclean in (
                ({"command": "ls", "typed_line": "TOKEN=abcd;rm -rf ~"}, "typed_line", "TOKEN=[REDACTED:assignment];rm -rf ~", False),
                ({"cmd": "TOKEN='ab;cd' make"}, "cmd", "TOKEN='[REDACTED:assignment]' make", True),
                ({"script": "export TOKEN=abcd && make"}, "script", "export TOKEN=[REDACTED:assignment] && make", False),
                ({"command": ["bash", "-lc", "TOKEN=abcd;make"]}, "command", ["bash", "-lc", "TOKEN=[REDACTED:assignment];make"],
                 False),
                # with a .env file named, a command argument's own values are hidden, as its text was; the command's
                # but after its first heredoc line, as before
                ({"cmd": "export K=abc && make", "file_path": ".env"}, "cmd", "export K=[REDACTED:dotenv] && make", False),
                ({"command": "export K=abc && make", "file_path": ".env"}, "command", "export K=abc && make", False)):
            with self.subTest(ti=ti):
                hides = []
                rec = privacy.tool_input("Bash", ti, "full", hides)
                self.assertEqual((rec[field]["value"], bool(hides)), (recorded, unclean))
        d = privacy.screened({"decision": "ask", "rule_ids": ["R"], "reasons": ["r"]}, "Bash",
                             {"command": "ls", "typed_line": "TOKEN='ab;cd' make"}, {}, [True])
        self.assertEqual((d["decision"], d["rule_ids"]), ("deny", ["R", privacy.HIDDEN_CODE]))

    def test_the_noise_a_held_honest_command_meets(self):
        """Honest commands with secrets in them, held: only those whose hidden value holds what a program may read as
        code (a blank in a file a shell may source, a ; or $ for a program that may run it, a sed program) are denied."""
        j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        denied = {
            "cat > .env <<'EOF'\nAPP_NAME=My App\nSECRET_KEY=abc def\nEOF",
            'mysql -h db -u root --password="p@ss;word" -e "select 1"',
            "sed -i 's/API_TOKEN=.*/API_TOKEN=abcd1234/' .env",
            "heroku config:set SECRET_KEY='abc$def' -a app",
            "terraform apply -var 'db_password=Pa$$w0rd!'",
            "TF_VAR_db_password='p@ss;w0rd' terraform apply",
            "PGPASSWORD='Tr0ub4dor&3' psql -h db -U app -c 'select 1' && aws s3 cp ./dump.sql s3://team-backups/",
        }
        for command in sorted(denied) + [
                'curl -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/me',
                f'curl -H "Authorization: Bearer {j}" https://api.example.com/v1/me',
                "docker login -u ci -p hunter2pass registry.example.com",
                "docker login --username ci --password=hunter2pass registry.example.com",
                "psql postgres://app:hunter2@db.internal:5432/app -c 'select 1'",
                'psql "postgres://app:hunter2@db.internal:5432/app?sslmode=require" -c "select 1"',
                "psql 'postgresql://app:hunter2@db.internal/app?sslmode=require&connect_timeout=10' -c 'select 1'",
                'mongosh "mongodb+srv://app:hunter2@cluster0.example.net/app?retryWrites=true&w=majority"',
                'DATABASE_URL="postgres://app:hunter2@db/app?sslmode=require" npm run migrate',
                'curl "https://api.example.com/v1/items?api_key=abcd1234&limit=10"',
                "curl 'https://api.example.com/v1/items?access_token=abcd1234&page=2'",
                "git clone https://oauth2:glpat-abcdefghijklmnop@gitlab.com/team/app.git",
                "cat > .env <<EOF\nDATABASE_URL=postgres://app:hunter2@db/app?sslmode=require\nEOF",
                "cat > .env <<'EOF'\nOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz\nDEBUG=true\nEOF",
                "cat > .env <<'EOF'\nNEXT_PUBLIC_URL=http://localhost:3000\nAUTH_SECRET=Zq8+/abc==\nEOF",
                "echo 'OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz' >> .env",
                "printf 'DB_PASSWORD=%s\\n' 'p@ss;word' > .env",
                "kubectl create secret generic db --from-literal=password='S3cr3t!pass'",
                "kubectl create secret generic db --from-literal=password='S3cr3t pass' && kubectl rollout restart "
                "deploy/web",
                "psql 'postgresql://app:hunter2@db.internal/app?sslmode=require&connect_timeout=10' -c 'select 1'",
                'psql "postgres://app:hunter2@db.internal:5432/app?sslmode=require" -c "select 1"',
                'mongosh "mongodb+srv://app:hunter2@cluster0.example.net/app?retryWrites=true&w=majority"',
                'helm upgrade app ./chart --set "secrets.apiToken=abc,def"',
                "DATABASE_URL='postgres://app:hunter2@db/app?sslmode=require' npm run migrate && kubectl rollout "
                "restart deploy/web",
                "terraform apply -var 'db_password=hunter2pass' -auto-approve",
                "GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789 gh pr merge 1 --squash",
                "npm config set //registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789",
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY aws s3 cp ./a s3://b/",
                "redis-cli -u redis://default:hunter2@cache:6379 ping",
                'curl -u "admin:hunter2" https://jenkins.example.com/api/json',
                'vercel env add API_TOKEN production <<< "abcd1234efgh"',
                'echo "token: abcd1234efgh" > ~/.config/tool.yml',
                'helm upgrade app ./chart --set db.password=hunter2pass --set image.tag=v2',
                'helm upgrade app ./chart --set "secrets.apiToken=abc,def"',
                "TF_VAR_db_password=hunter2pass terraform apply",
                "aws s3 cp ./build s3://team-site/ --recursive && curl -X POST "
                "'https://api.example.com/hooks?token=abcd1234&env=prod'",
                "DATABASE_URL='postgres://app:hunter2@db/app?sslmode=require' npm run migrate && kubectl rollout restart "
                "deploy/web"]:
            with self.subTest(command=command):
                copy, hides = privacy.approver_copy({"command": command}, privacy.mentions_dotenv(command), "Bash")
                self.assertEqual(hides, command in denied, copy)


if __name__ == "__main__":
    unittest.main()
