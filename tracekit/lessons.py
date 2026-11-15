"""Lessons: what coding agents keep relearning, found in signed records, approved by a person and given to the next
Claude Code session: the LESSONS part of `tracekit tips` and of tracekit view's TIPS page (docs/viewer.md#lessons).

Three kinds, each found the same way every time in the signed records of runs that verified, over the tips window, a
run joined to its Claude Code session and project by its calls' tool_use ids in the transcripts (tips.read_transcripts):

- lookup: a search (Grep, Glob, WebSearch, or a shell `rg`, `grep -r`, `git grep`, `find -name`) for an identifier of 4
  or more characters, then within PAIR_WITHIN calls of the same agent a Read of a file (or a WebFetch of a URL) it
  doesn't write in between; the same pair in MIN_SESSIONS sessions on MIN_DAYS days.
- fix: a shell call allowed or flagged whose signed result is not ok, its error (the transcript's tool result) read
  to one line (ERRORS, paths cut to their name, numbers masked), then within FIX_WITHIN calls of the same agent a shell
  call that worked and differs from it in at most FIX_TOKENS words, with no write and no deny or hold in between; the
  same failure and change FIX_TIMES times in FIX_SESSIONS sessions.
- told: a sentence the person typed (the hook's trusted observe of a prompt's typed part, never a paste or what the
  harness added) that states a standing instruction ("from now on", "always", "never", "remember to", ...), in one
  session: the person asked.

Never the agent's words: a lesson's text is a template over the calls' values, or the person's own sentence. An
occurrence is dropped when a value it uses came only from untrusted content: its decision's signed `provenance` names
the field, the run's provenance index isn't complete, or any decision of the window carried that value from untrusted
content (a page fetched in another session, a memory note written from one). A lesson that rests on a deny or a hold,
or whose words name holds, approvals, denies, Tracekit or its policy, is never given to the agent: NOT PROPOSED says
so to the person.

A person approves each one (`tracekit tips approve ID`): Folder writes it as a Claude Code auto-memory note with a
MEMORY.md index in <dev data dir>/lessons/projects/<project>/, a git repo whose history is the record of every change.
Proposals are worked out from the records on every read and never stored. The Claude Code hook gives the approved
lessons at a session's first prompt and again after a compaction or a resume (for_agent: BM25 against the prompt
within BUDGET bytes), after a signed observe (source SOURCE) that names the lesson ids it gave and the block's sha256,
never their text. Each lesson in use is measured on the detector that found it: before its approval against the
sessions that observe proves were given it (effect). No network, no model.
"""
import collections
import datetime
import difflib
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import time
import unicodedata

BUDGET = 8000   # bytes of lessons a session is given (Claude Code caps a hook's context at 10,000 characters)
INDEX_LINES, INDEX_BYTES = 200, 25_000   # MEMORY.md, as Claude Code loads its own
NOTE_BYTES = 4096   # one note's file
SHOWN = 8   # waiting lessons shown per project
MIN_SESSIONS, MIN_DAYS = 3, 2   # a lookup's
FIX_TIMES, FIX_SESSIONS = 3, 2   # a fix's
MIN_EXPOSED = 5   # sessions on each side before an effect is shown
PAIR_WITHIN, FIX_WITHIN, FIX_TOKENS = 3, 5, 4
AFTER_S = 14 * 86400   # an effect counts the sessions given a lesson this long after its approval
SAME = 0.6   # content-word Jaccard at which two typed sentences are one instruction
OFF = "TRACEKIT_LESSONS"   # 0: the hook gives no lessons
SOURCE = "tracekit:lessons"   # the observe that records which lessons a session was given
PERSON = "tracekit:lessons:person"   # the observe that records a person's answer: approve, retire, restore or add
PROMPT = ":UserPromptSubmit"   # the hook's trusted observe of a prompt's typed part (any harness's, for the viewer)
TYPED = "claude-code:UserPromptSubmit"   # the Claude Code hook's own: the only typed text a TOLD lesson is read from
TYPES = ("user", "feedback", "project", "reference")
# keys only Tracekit writes: `tracekit tips add` takes none of them from the person's words
HOST = ("status", "superseded_by", "retired_from", "supersedes", "origin", "id", "kind", "key", "evidence", "tier",
        "approved", "before", "signed")
LESSON_ID = re.compile(r"L-[0-9a-f]{8}")
SIGNED = re.compile(r"[\w.-]{1,128}:[0-9]{1,12}")   # run:run_seq of the signed record of a person's answer
MEASURE = "before and after on the same detector, not a controlled test"
NOTE_FILE = re.compile(r"(?!MEMORY\.md$)[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.md")
PROJECT_NAME = re.compile(r"[A-Za-z0-9-][A-Za-z0-9._-]{0,254}")   # never `.` or `..`: it starts with no dot
INTRO = ("Lessons from this project's signed runs, approved by the person (Tracekit). Each applies when what you are "
         "doing matches it.")
MORE = "More lessons: tracekit tips --for-agent --query WORDS"
NOT_YET = "No lessons approved for this project yet."

SEARCH = {"Grep": "pattern", "Glob": "pattern", "WebSearch": "query"}
OPEN = {"Read": "file_path", "WebFetch": "url"}
WRITES = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
RAN = ("allow", "flag")   # decisions under which a call ran as the agent sent it
SUBJECT = {"lookup": 1, "fix": 3}   # the leading words of a key that say what a lesson is about (its identifier;
# its program and failure): a new fact about the same thing supersedes the old
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
KEYWORDS = frozenset(("class", "function", "import", "from", "return", "const", "self", "this", "async", "await",
                      "export", "struct", "interface", "public", "private", "static", "void", "type", "true", "false",
                      "none", "null", "todo"))
# the failures a FIX lesson names, each in words of its own with only its variable part, a name, kept from the
# transcript's error text (which the agent's process writes)
ERRORS = (("no_module", re.compile(r"No module named '?([A-Za-z_][\w.]{0,63})'?(?![\w.])"), "no module named `{}`"),
          ("not_found", re.compile(r"command not found: ([\w.+-]{1,64})\b"), "`{}` is not installed"),
          ("not_found", re.compile(r"(?:^|[\s:])([\w.+-]{1,64}): (?:command )?not found\b"), "`{}` is not installed"),
          ("no_file", re.compile(r"No such file or directory"), "a file it names doesn't exist{}"),
          ("permission", re.compile(r"Permission denied"), "access to a file it uses is refused{}"))
# a value a lesson's template names: no space, quote, shell operator, comment or expansion, so never prose
TOKEN = re.compile(r"[\w./:@%+=,~-]{1,256}")
ENV_SET = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}=[\w./:@%+,~-]{0,128}")
CD_PREFIX = re.compile(r"\s*cd ([\w./:@%+,~-]{1,256}) && ")
NAME_WORDS, NAME_CHARS = 5, 64   # what one value a FIX lesson names may hold, split at SPLIT: a name, not a sentence
SPLIT = re.compile(r"[\s_.=/-]+")
ANSWERS = ("approve", "restore", "add")   # a person's answers that put a lesson in use
MARKERS = re.compile(r"\b(?:from now on|going forward|always|never|every time|remember (?:to|that)|don'?t forget)\b",
                     re.I)
HEDGES = re.compile(r"\b(?:maybe|perhaps|might|i think|i guess|not sure|probably|unless)\b", re.I)
# the never-evasion gate (memory 11-07): words about how a deny, a hold or a person's OK works, in prose; a hyphen
# breaks words (policy-check, deny-list), but the same letters inside a path or an identifier (tracekit/view.py,
# held_calls) say nothing about it
EVASION = re.compile(r"\bTK-[A-Z]|(?<![\w/.])(?:tracekit|hold\w*|held|approv\w*|den(?:y|ied|ies)|polic(?:y|ies)"
                     r"|permi(?:t|ssion)\w*|sign[- ]?offs?|confirm\w*|ask(?:ing)? first|(?-i:OK)"
                     r"|wait(?:s|ing)? for (?:a|the) (?:person|human|user|owner))(?![\w/]|\.\w)"
                     r"|bypass|get past|without asking|skip the hook|--no-verify", re.I)
# a lesson a person reads twice: a limit or an exemption from a check, trusting, buying from or paying a named source,
# or a host, email or account named in its text
RISKY = re.compile(r"\bno need to\b|\bskip\b|\btrust|\bpay\b|\bbuy\b|\baccount\b|https?://|[\w.+-]+@[\w-]+\.[\w.]+"
                   r"|\b[a-z0-9-]+\.(?:com|net|org|io|dev|ai|app|co|cloud)\b", re.I)
# a bank's numbers beside their words, which a lesson never keeps (a port of the money shapes of a learning guard)
MONEY = re.compile(r"\b(?:bank\s{1,3})?(?:account|acct|a/c)(?:\s{1,3}(?:number|no\.?|num))?\s{0,3}(?:#|:|\bis\b)?\s{0,3}"
                   r"(?!\d{4}-\d{2}-\d{2}\b)\d(?:[ -]?\d){5,}|\bIBAN\s{0,3}(?:#|:|\bis\b)?\s{0,3}[A-Z]{2}\d{2}"
                   r"(?:\s?[A-Z0-9]){10,30}|\b(?:routing|ABA)(?:\s{1,3}(?:number|no\.?|num))?\s{0,3}(?:#|:|\bis\b)?"
                   r"\s{0,3}\d{9}\b|\bsort\s{1,3}code\s{0,3}(?:#|:|\bis\b)?\s{0,3}\d{2}[- ]?\d{2}[- ]?\d{2}\b", re.I)
JOINER_SCRIPTS = ("ARABIC", "DEVANAGARI", "BENGALI", "GURMUKHI", "GUJARATI", "ORIYA", "TAMIL", "TELUGU", "KANNADA",
                  "MALAYALAM", "SINHALA", "KHMER", "MYANMAR")
STOP = frozenset((
    "a an and are as at be but by can do does for from has have how if in into is it its not of on or so than that the "
    "their them then there these they this to was we what when where which while who will with you your use used using "
    "note notes run runs lesson lessons").split())
PATH_WEIGHT = 3
WORDS = {  # why a candidate isn't proposed, in plain words
    "one_session": "Seen in {s} on {d}: a {kind} needs {need}.",
    "tainted": "A value in it came only from untrusted content ({where}): never a lesson.",
    "evasion": "It rests on a deny or a hold, or talks about holds, approvals or the policy: shown to you, never given "
               "to the agent.",
    "duplicate": "The same as a lesson in use.",
    "shown": f"Past the {SHOWN} shown for this project.",
    "too_large": f"Over {NOTE_BYTES:,} bytes: refused, never cut.",
    "invisible_unicode": "It holds a character a reader doesn't see: refused.",
    "secret_shape": "It holds text shaped like a secret or a bank number: refused, never cut.",
    "secret_value": "It quotes a value the signer redacted: refused.",
}


class Refused(Exception):
    """A change Folder refuses: `rule` (index_full, outside, status, ...), the reason in plain words."""

    def __init__(self, rule, text):
        super().__init__(text)
        self.rule = rule


# ----------------------------------------------------------------------------------------------- checks


def _emoji(c):
    return bool(c) and (0x1F000 <= ord(c) <= 0x1FAFF or 0x2600 <= ord(c) <= 0x27BF)


def _joins(c):
    """A letter of a script whose words need a joiner or non-joiner (a virama, then a consonant; Persian, Urdu)."""
    try:
        return bool(c) and unicodedata.category(c)[0] in "LM" and unicodedata.name(c).startswith(JOINER_SCRIPTS)
    except ValueError:
        return False


def hidden(text):
    """The index of the first character of `text` a reader doesn't see: a format, private-use, surrogate, line or
    paragraph separator, default-ignorable or braille-blank character, or a control but tab, newline and carriage
    return. A joiner between letters of a script that needs one or inside an emoji sequence, and U+FE0F after an
    emoji, are text. None when there is none."""
    from .provenance import _IGNORABLE
    for i, c in enumerate(text):
        o, cat = ord(c), unicodedata.category(c)
        if not (cat in ("Cf", "Co", "Cs", "Zl", "Zp") or o in _IGNORABLE or o == 0x2800
                or cat == "Cc" and c not in "\t\n\r"):
            continue
        before, after = text[i - 1:i] if i else "", text[i + 1:i + 2]
        if c == "️" and (_emoji(before) or before in tuple("0123456789#*") and after == "⃣"):
            continue
        if c in "‌‍" and _joins(before) and _joins(after):
            continue
        if c == "‍" and _emoji(after) and (_emoji(before) or before == "️" and _emoji(text[i - 2:i - 1])):
            continue
        return i
    return None


def problems(text):
    """What refuses a note's text (its whole file, or a lesson's name, description and body), never cut: [rule]."""
    from .privacy import redact_text
    out = []
    if len(text.encode("utf-8", "surrogatepass")) > NOTE_BYTES:
        out.append("too_large")
    if hidden(text) is not None:
        out.append("invisible_unicode")
    if redact_text(text)[1] or MONEY.search(text):
        out.append("secret_shape")
    if "[REDACTED" in text:   # the signer's redaction of what the record held
        out.append("secret_value")
    return out


def evasive(text):
    return bool(EVASION.search(text))


def risky(text):
    return bool(RISKY.search(text))


# ----------------------------------------------------------------------------------------------- notes


def project_of(cwd):
    """The Claude Code project folder name of working directory `cwd`: each character but a letter or digit as `-`.
    lean: Claude Code shortens and hashes a name past 200 characters, which this doesn't; a project that deep gets no
    lessons from the hook (`tracekit tips --for-agent --project` names it)"""
    return re.sub(r"[^A-Za-z0-9]", "-", cwd) if isinstance(cwd, str) and cwd else None


def lesson_id(kind, project, key, text):
    """`L-` and 8 hex digits of the lesson's kind, project, key and exact text (name, description, body): the text a
    person approves is the text its id names, and any other text is another lesson."""
    return "L-" + hashlib.sha256(json.dumps([kind, project, key, list(text)], ensure_ascii=False).encode()
                                 ).hexdigest()[:8]


def text_sha(note):
    """sha256 of what a session reads of a note (its name, description and body): the signed record of a person's
    answer names it, never the text."""
    return hashlib.sha256(json.dumps([note["name"], note["description"], note["body"].strip()], ensure_ascii=False)
                          .encode()).hexdigest()


def _one(text):
    return " ".join(str(text).split())


def _value(v):
    """A front matter value as Folder writes it: JSON (a YAML double-quoted scalar or flow list) unless bare words."""
    return v if isinstance(v, str) and re.fullmatch(r"[\w.:/+-]+", v) else json.dumps(v, ensure_ascii=False)


def render(note):
    """A note's file: its front matter (name, description, type, then each host key it has), then its body."""
    keys = ("name", "description", "type", *HOST)
    head = [f"{k}: {_value(note[k])}" for k in keys if note.get(k) not in (None, "", [])
            and not (k == "status" and note[k] == "active")]   # no status: in use
    return "---\n" + "\n".join(head) + "\n---\n" + note["body"].strip() + "\n"


def parse(file, text):
    """The note in `file` (its text), or the list of what is out of shape in it. A strict reader: front matter between
    two `---` lines, one `key: value` a line, each key once; JSON values (Folder writes them so) or bare words."""
    out = [] if NOTE_FILE.fullmatch(file) else [f"{file!r} is not a note's file name"]
    lf = text.replace("\r\n", "\n")
    head = re.match(r"---\n(.*?)\n---\n?", lf, re.S)
    if not head:
        return out + ["it does not start with closed front matter"]
    fields = {}
    for line in head.group(1).split("\n"):
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_-]*):(?: (.*))?", line)
        if not m:
            out.append(f"the front matter line {line[:40]!r} is not `key: value`")
            continue
        if m.group(1) in fields:
            out.append(f"{m.group(1)} appears twice")
        v = (m.group(2) or "").strip()
        try:
            fields[m.group(1)] = json.loads(v) if v[:1] in ('"', "[") else v
        except ValueError:
            out.append(f"{m.group(1)} is not a value")
    for k in ("name", "description"):
        if not isinstance(fields.get(k), str) or not fields.get(k):
            out.append(f"{k} is missing")
    if fields.get("type", "project") not in TYPES:
        out.append(f"type is not {', '.join(TYPES)}")
    if fields.get("status", "active") not in ("active", "retired", "superseded", "pending"):
        out.append("status is not retired, superseded or pending")
    if out:
        return out
    return {**fields, "file": file, "type": fields.get("type", "project"), "status": fields.get("status", "active"),
            "origin": fields.get("origin", "run"), "body": lf[head.end():]}


def index(notes):
    """MEMORY.md: one line per active note, by file name."""
    return "".join(f"- [{_one(n['name'])}]({n['file']}) — {_one(n['description'])}\n"
                   for n in sorted(notes, key=lambda n: n["file"]) if n["status"] == "active")


class Folder:
    """The lessons folder, <dev data dir>/lessons: one git repo, projects/<project>/ holding a project's notes and its
    MEMORY.md. `tracekit tips`' actions, run by a person, are its only writer; a folder that holds a link, or anything
    but folders and regular files, is refused whole, for reading too. `sign(action, id, sha256)`: records a person's
    answer as a signed observe (source PERSON) once every check has passed, before anything is written, and gives the
    record's `run:run_seq`, which the note keeps (`signed`); a note without one is never given to an agent."""

    def __init__(self, path, sign=None):
        self.path, self.sign = path, sign

    def _dir(self, project):
        """A project's folder; refused for a name that isn't one folder's (a transcript folder's name is the agent's
        to make)."""
        if not isinstance(project, str) or not PROJECT_NAME.fullmatch(project):
            raise Refused("outside", f"{project!r} is not a Claude Code project folder's name")
        return os.path.join(self.path, "projects", project)

    def _safe(self):
        """Refused if the folder, its .git, or anything under the folder outside .git is a link or neither a folder
        nor a regular file.
        lean: checked before each read and write, not held: a process of the person's own user could swap a file in
        between (policy denies the agent the data dir, TK-D007 and TK-D013); system mode keeps it out of reach"""
        if not os.path.lexists(self.path):
            return
        if os.path.islink(self.path) or not os.path.isdir(self.path) or os.path.islink(os.path.join(self.path, ".git")):
            raise Refused("outside", f"{self.path} or its .git is a link or not a folder: the lessons folder is refused")
        for d, dirs, names in os.walk(self.path, followlinks=False):
            if d == self.path:
                dirs[:] = [x for x in dirs if x != ".git"]
            for x in dirs + names:
                p = os.path.join(d, x)
                if os.path.islink(p) or x in names and not os.path.isfile(p):
                    raise Refused("file_mode", f"{p} is a link or not a regular file: the lessons folder is refused")

    def notes(self, project=None):
        """Every note of `project` (default: every project), each with its `project`; refused on a link or a note out
        of shape (its problems named)."""
        self._safe()
        root = os.path.join(self.path, "projects")
        out = []
        for p in ([project] if project else sorted(os.listdir(root)) if os.path.isdir(root) else []):
            d = self._dir(p)
            for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
                if f == "MEMORY.md" or not f.endswith(".md"):
                    continue
                fd = os.open(os.path.join(d, f), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as fh:
                    raw = fh.read(NOTE_BYTES + 1)   # never more: a note past the cap is refused, unread
                if len(raw) > NOTE_BYTES:
                    raise Refused("too_large", f"{os.path.join(d, f)}: " + WORDS["too_large"])
                try:
                    n = parse(f, raw.decode("utf-8"))
                except UnicodeDecodeError:
                    n = ["it is not UTF-8"]
                if isinstance(n, list):
                    raise Refused("note", f"{os.path.join(d, f)}: {'; '.join(n)}")
                out.append({**n, "project": p})
        return out

    def find(self, lid):
        return next((n for n in self.notes() if n.get("id") == lid), None)

    def head(self):
        """The folder's git commit, read from its files (no git process: the hook stays fast): 40 hex digits, else None
        (it goes into a signed record, so nothing else read from a file the user can write does).
        lean: a branch git has packed (git gc) is read from packed-refs; another ref layout, or a SHA-256 repository,
        gives None"""
        g = os.path.join(self.path, ".git")
        try:
            with open(os.path.join(g, "HEAD"), encoding="ascii") as f:
                ref = f.read(256).strip()
            if ref.startswith("ref: refs/heads/") and re.fullmatch(r"[\w.-]{1,128}", ref[16:]):
                ref = ref[5:]
                if os.path.isfile(os.path.join(g, ref)):
                    with open(os.path.join(g, ref), encoding="ascii") as f:
                        ref = f.read(256).strip()
                else:
                    with open(os.path.join(g, "packed-refs"), encoding="ascii") as f:
                        ref = next((x.split()[0] for x in f if x.rstrip().endswith(" " + ref)), "")
            return ref if re.fullmatch(r"[0-9a-f]{40}", ref) else None
        except (OSError, ValueError):
            return None

    def _write(self, project, changed, message, lid, action):
        """Write the notes `changed` of `project` (every one checked: refused, never cut), rebuild its MEMORY.md
        (refused past INDEX_LINES lines or INDEX_BYTES bytes), have the person's answer `action` to the first signed
        (sign), then commit. -> a note when no history was kept."""
        from .deploy import files
        self._dir(project)
        self._safe()
        notes = {n["file"]: n for n in self.notes(project)}
        notes.update({n["file"]: n for n in changed})
        idx = index(notes.values())
        if idx.count("\n") > INDEX_LINES or len(idx.encode()) > INDEX_BYTES:
            raise Refused("index_full", f"{project} would have {idx.count(chr(10))} lessons in use, "
                                        f"{len(idx.encode()):,} bytes of MEMORY.md: at most {INDEX_LINES} lines and "
                                        f"{INDEX_BYTES:,} bytes. Retire one first: refused, never cut")
        for signed in (False, True):   # every check, then the signed record, then every check of what it adds
            if signed and self.sign:
                changed[0]["signed"] = self.sign(action, lid, text_sha(changed[0]))
            texts = {n["file"]: render(n) for n in changed}
            for f, text in texts.items():
                bad = problems(text)
                if bad:
                    raise Refused(bad[0], f"{f}: " + WORDS[bad[0]])
        d = files.open_dir(os.path.dirname(self.path))
        try:
            top = files.subdir(d, os.path.basename(self.path))
            try:
                sub = files.subdir(top, "projects")
                try:
                    pd = files.subdir(sub, project)
                    try:
                        for f, text in texts.items():
                            files.write(pd, f, text.encode("utf-8"))
                        files.write(pd, "MEMORY.md", idx.encode("utf-8"))
                    finally:
                        files.close(pd)
                finally:
                    files.close(sub)
            finally:
                files.close(top)
        finally:
            files.close(d)
        return self._commit(f"lessons: {message}", lid)

    def _commit(self, message, lid):
        """One commit for the change, `Lesson-Id:` its trailer.
        lean: needs the git binary; without one the change is written with no history, and the person is told so"""
        git = shutil.which("git")
        if not git:
            return "no git binary on PATH: the change is written, with no history kept"
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env["GIT_TERMINAL_PROMPT"] = "0"

        def run(*a):   # no hook runs: one planted in the folder's .git would run on a person's approve
            return subprocess.run([git, "-C", self.path, "-c", "user.name=tracekit tips", "-c",
                                   "user.email=tips@tracekit.invalid", "-c", "commit.gpgsign=false", "-c",
                                   f"core.hooksPath={os.devnull}", *a],
                                  capture_output=True, text=True, env=env, timeout=60)
        if not os.path.isdir(os.path.join(self.path, ".git")) and run("init", "-q").returncode:
            return "git init failed: the change is written, with no history kept"
        run("add", "-A")
        r = run("commit", "-q", "-m", f"{message}\n\nLesson-Id: {lid}")
        return None if r.returncode == 0 else f"git commit failed ({_one(r.stderr or r.stdout)[:200]})"

    def approve(self, lesson, now=None):
        """Write waiting `lesson` (from proposals) as an active note, marking the notes it supersedes; refused unless
        its text is the text its id names (lesson_id), so what a person read is what is written."""
        if lesson_id(lesson["kind"], lesson["project"], lesson["key"],
                     (lesson["name"], lesson["description"], lesson["text"])) != lesson["id"]:
            raise Refused("changed", f"{lesson['id']}'s text is not the text its id names: refused")
        now = now or time.time()
        when = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        note = {k: lesson[k] for k in ("name", "description", "type", "origin", "id", "kind", "key", "tier")}
        note.update(file=lesson["file"], body=lesson["text"], approved=when, status="active",
                    evidence=[f"{e['run']}:{e['seq']}" for e in lesson["records"]][:8],
                    before=f"{lesson['seen']['hits']}/{lesson['seen']['exposed']}",
                    supersedes=[n["file"] for n in lesson.get("supersedes") or ()])
        old = [dict(n, status="superseded", superseded_by=note["file"]) for n in self.notes(lesson["project"])
               if n["file"] in note["supersedes"]]
        return self._write(lesson["project"], [note, *old], f"approve {lesson['id']}", lesson["id"], "approve")

    def retire(self, lid, proposal=None):
        """Retire the note `lid` (it leaves MEMORY.md and is never given again), or, with the waiting `proposal` of
        that id, keep it as retired so it is never proposed again."""
        n = self.find(lid)
        if n is None and proposal is None:
            raise Refused("missing", f"no lesson {lid} in use or waiting")
        if n is None:
            n = {k: proposal[k] for k in ("name", "description", "type", "origin", "id", "kind", "key", "tier",
                                           "file", "project")}
            n.update(body=proposal["text"], status="active")
            was = "pending"
        elif n["status"] == "retired":
            raise Refused("status", f"{lid} is retired already")
        else:
            was = "pending" if n["status"] == "pending" else "active"
        n = dict(n, status="retired", retired_from=was, superseded_by=None)
        return self._write(n["project"], [n], f"retire {lid}", lid, "retire")

    def restore(self, lid):
        """Give a retired note back the status it was retired from: in use, or proposed again (pending)."""
        n = self.find(lid)
        if n is None or n["status"] != "retired":
            raise Refused("status", f"no retired lesson {lid}")
        back = "active" if n.get("retired_from") == "active" else "pending"
        return self._write(n["project"], [dict(n, status=back, retired_from=None)], f"restore {lid}", lid, "restore")

    def add(self, project, body, name=None, description=None, kind_type="feedback", now=None):
        """The person's own lesson, in use at once (origin you): one-line name and description, or the body's first
        line; checked as every lesson is, its words through the never-evasion gate."""
        if any("\n" in v or "\r" in v for v in (name or "", description or "")):
            raise Refused("status", "a name or description is one line: a line break could set a key only Tracekit "
                                    "writes")
        body = (body or "").strip()
        name = _one(name or body.split("\n")[0])[:80]
        description = description or "Added by the person"
        if not body:
            raise Refused("note", "the lesson has no text")
        if kind_type not in TYPES:
            raise Refused("note", f"type is {', '.join(TYPES)}")
        if evasive(" ".join((name, description, body))):
            raise Refused("evasion", WORDS["evasion"])
        key = [body]
        lid = lesson_id("you", project, key, (name, description, body))
        if self.find(lid):
            raise Refused("duplicate", f"{lid} is there already")
        when = datetime.datetime.fromtimestamp(now or time.time(), datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        note = {"file": f"you-{lid[2:]}.md", "name": name, "description": description, "type": kind_type,
                "origin": "you", "id": lid, "kind": "you", "key": key, "tier": "you", "approved": when, "body": body,
                "status": "active"}
        return lid, self._write(project, [note], f"add {lid}", lid, "add")


# ----------------------------------------------------------------------------------------------- relevance


def words(text):
    """A text's words: lowercase letters and digits, two characters or more, no stop word and no bare number; a path's
    segments are words too."""
    return [w for w in re.findall(r"[a-z0-9]+", str(text).lower()) if len(w) > 1 and not w.isdigit() and w not in STOP]


def _paths(text):
    """The paths a text names: a diff's file lines, and lines that read as a path (a slash or a dot extension, no
    space)."""
    out = []
    for line in str(text).split("\n"):
        m = re.match(r"diff --git a/(\S+) b/(\S+)", line) or re.match(r"(?:\+\+\+|---) (?:[ab]/)?(\S+)", line)
        if m:
            out += [g for g in m.groups() if g != "/dev/null"]
            continue
        listed = re.sub(r"^[-*]\s+", "", line.strip())
        if re.fullmatch(r"[\w.-]+(?:/[\w.-]+)+|[\w-]+\.[a-z0-9]{1,8}", listed, re.I):
            out.append(listed)
    return out


def query(text):
    """{word: weight}: each word of `text` once (1), a path's words PATH_WEIGHT."""
    q = dict.fromkeys(words(text), 1)
    q.update(dict.fromkeys((w for p in _paths(text) for w in words(p)), PATH_WEIGHT))
    return q


def bm25(notes, q):
    """BM25 (k1 1.2, b 0.75) of each note (its name and description twice, then its body) against query `q`, the notes
    their own corpus; 0 for a note with none of its words."""
    if not q or not notes:
        return [0.0] * len(notes)
    bags = [words(f"{n['name']} {n['description']} {n['name']} {n['description']} {n['body']}") for n in notes]
    avg = sum(map(len, bags)) / len(bags) or 1
    counts = [collections.Counter(b) for b in bags]
    idf = {t: math.log(1 + (len(notes) - sum(t in c for c in counts) + 0.5) / (sum(t in c for c in counts) + 0.5))
           for t in q}
    return [sum(q[t] * idf[t] * c[t] * 2.2 / (c[t] + 1.2 * (0.25 + 0.75 * len(b) / avg)) for t in q if c[t])
            for b, c in zip(bags, counts)]


def _whole(n):
    return f"## {_one(n['name'])} ({n['file']})\n{_one(n['description'])}\n{n['body'].strip()}"


def _line(n):
    return f"- {_one(n['name'])} ({n['file']}): {_one(n['description'])}"


def block(whole, lines, more):
    parts = [INTRO, *map(_whole, whole)] + (["\n".join(map(_line, lines))] if lines else []) + ([MORE] if more else [])
    return "\n\n".join(parts) if whole or lines else ""


def select(notes, text, budget=BUDGET):
    """(whole, lines, left out) of `notes` (active, newest first) for a session whose prompt is `text`: every note
    whole while all fit `budget`; past it, the notes that share a word with the prompt, best first by bm25, each whole
    while it fits, then one line each for the rest in the same order within INDEX_LINES and INDEX_BYTES; a prompt
    that shares no word with any reads by recency. The block (block()) always fits the budget."""
    size = lambda n: len(_whole(n).encode()) + 2   # noqa: E731: with its blank line
    if len(INTRO.encode()) + sum(map(size, notes)) <= budget:
        return list(notes), [], []
    frame = len(INTRO.encode()) + len(MORE.encode()) + 4
    scores = bm25(notes, query(text or ""))
    ranked = sorted(range(len(notes)), key=lambda i: (-scores[i], i)) if any(scores) else list(range(len(notes)))
    bearing = sum(s > 0 for s in scores) if any(scores) else len(notes)
    room, whole, lines, used = budget - frame, [], [], 0
    for i in ranked[:bearing]:
        if size(notes[i]) <= room:
            room -= size(notes[i])
            whole.append(i)
    for i in ranked:
        b = len(_line(notes[i]).encode()) + 1
        if i in whole or len(lines) >= INDEX_LINES or b > room or used + b > INDEX_BYTES:
            continue
        room, used = room - b, used + b
        lines.append(i)
    w, ln = [notes[i] for i in whole], [notes[i] for i in lines]
    while len(block(w, ln, True).encode()) > budget and (ln or w):
        (ln or w).pop()
    return w, ln, [n for n in notes if n not in w and n not in ln]


def verified(client, notes, purpose="tracekit lessons"):
    """The ids of `notes` the signer backs: each note's named record (`signed`, run:run_seq) is read back (content_get,
    through `client`: one signed content.accessed record per run of answers) and the note kept when its kept value is
    the person's answer that put it in use (an approve, restore or add of this id and this text's sha256), or when the
    signer holds the run and its retention has since erased what it kept. A note naming a run the signer doesn't hold,
    or another answer, is left out, and so is every note when the signer can't be asked or keeps no content.
    lean: past the dev signer's retention (DEV_RETENTION_DAYS) only the run's existence is checked, the TIPS page
    reading the record itself; keep the answers' content longer if notes naming old runs are ever planted"""
    runs = collections.defaultdict(lambda: collections.defaultdict(list))
    for n in notes:
        run, seq = str(n.get("signed")).rsplit(":", 1)
        runs[run][int(seq)].append(n)
    out = set()
    for run, by_seq in runs.items():
        try:
            items = client.call("content_get", {"run_id": run, "seqs": sorted(by_seq), "purpose": purpose})["items"]
        except Exception:   # an unknown run, a refusal, no signer: none of its notes (fail closed)
            continue
        for it in items if isinstance(items, list) else ():
            v = it.get("content") if isinstance(it, dict) else None
            for n in by_seq.get(it.get("seq"), ()) if isinstance(it, dict) else ():
                if it.get("state") == "erased" or isinstance(v, dict) and v.get("action") in ANSWERS \
                        and v.get("id") == n["id"] and v.get("sha256") == text_sha(n):
                    out.add(n["id"])
    return out


def for_agent(cwd=None, prompt=None, q=None, folder=None, project=None, budget=BUDGET, check=None):
    """What a session in working directory `cwd` (or Claude Code project `project`) is given: the active lessons of
    its project that name the signed record of the person's answer that made them so (a note written any other way,
    or with an id that isn't one, is never given), chosen against `prompt` (select) or, with `q`, only those that
    share a word with it. Reads only the lessons folder (default: the dev data dir's).
    `check(notes)`: the ids of those to keep (verified, which the hook and --for-agent pass; the page passes what its
    signed records show). -> {project, commit, budget, bytes, block, lessons, given}: `given` is the signed observe's
    value, ids and the block's sha256, never text."""
    if folder is None:
        from .sdk.autospawn import data_dir
        folder = Folder(os.path.join(data_dir(), "lessons"))
    project = project or project_of(cwd)
    notes = folder.notes(project) if project and os.path.isdir(folder._dir(project)) else []
    notes = sorted((n for n in notes if n["status"] == "active" and LESSON_ID.fullmatch(str(n.get("id")))
                    and SIGNED.fullmatch(str(n.get("signed")))),
                   key=lambda n: n.get("approved") or "", reverse=True)
    if check is not None and notes:
        kept = check(notes)
        notes = [n for n in notes if n["id"] in kept]
    text = q if q is not None else prompt or ""
    scores = dict(zip((n["id"] for n in notes), bm25(notes, query(text)))) if notes else {}   # none: the prompt unread
    if q is not None:   # a lookup mid-task: only what shares a word with it, best first
        notes = sorted((n for n in notes if scores[n["id"]] > 0), key=lambda n: -scores[n["id"]])
    whole, lines, left = select(notes, text, budget)
    out, commit = block(whole, lines, bool(lines or left)), folder.head()
    return {"project": project, "commit": commit, "budget": budget, "bytes": len(out.encode()), "block": out,
            "lessons": [{**{k: n.get(k) for k in ("id", "file", "name", "description", "type", "kind", "origin")},
                         "score": round(scores[n["id"]], 2), "given": "whole" if n in whole else "line",
                         "text": n["body"].strip(), "evidence": n.get("evidence") or []} for n in whole + lines],
            "left_out": [n["id"] for n in left],
            "given": {"commit": commit, "whole": [n["id"] for n in whole], "lines": [n["id"] for n in lines],
                      "left_out": [n["id"] for n in left], "sha256": hashlib.sha256(out.encode()).hexdigest()}}


# ----------------------------------------------------------------------------------------------- detection


def _day(t):
    return time.strftime("%Y-%m-%d", time.gmtime(t))


def _rel(path, cwd):
    """A path as a lesson names it: relative to the session's working directory when under it."""
    if isinstance(path, str) and cwd and path.startswith(cwd.rstrip("/") + "/"):
        return path[len(cwd.rstrip("/")) + 1:]
    return path


def _argv(cmd):
    try:
        return shlex.split(cmd)
    except ValueError:
        return str(cmd).split()


def _searched(call):
    """The identifier a search call looks for: the longest of 4 or more characters in its pattern, else None."""
    a, tool = call["args"], call["tool"]
    pat = a.get(SEARCH[tool]) if tool in SEARCH else None
    if tool == "Bash" and isinstance(a.get("command"), str):
        argv = _argv(a["command"])
        prog = os.path.basename(argv[0]) if argv else ""
        rest = argv[2:] if prog == "git" and argv[1:2] == ["grep"] else argv[1:]
        if prog == "find":
            pat = next((rest[i + 1] for i, w in enumerate(rest[:-1]) if w in ("-name", "-iname")), None)
        elif prog == "rg" or prog == "git" and argv[1:2] == ["grep"] or prog in ("grep", "egrep") and any(
                w == "--recursive" or re.fullmatch(r"-[A-Za-z]*[rR][A-Za-z]*", w) for w in rest):
            pat = next((rest[i + 1] for i, w in enumerate(rest[:-1]) if w == "-e"), None) or next(
                (w for w in rest if not w.startswith("-")), None)
    if not isinstance(pat, str):
        return None
    found = [w for w in IDENT.findall(pat) if w.lower() not in KEYWORDS]
    return max(found, key=len) if found else None


def _failure(text):
    """(class, name, words) of a failure's error text (the transcript's, which the agent's process writes): the first of
    its lines one of ERRORS names, keeping only that error's variable part, a name its pattern reads; None for any other
    error, so no error line is ever a lesson's text."""
    if not isinstance(text, str):
        return None
    for line in text.split("\n")[:50]:
        for cls, pat, said in ERRORS:
            m = pat.search(line)
            if m:
                var = m.group(1) if pat.groups else ""
                return cls, var, said.format(var)
    return None


def _simple(cmd):
    """(cd, settings, argv) of a shell command that is one plain call, maybe after `cd DIR &&` and NAME=value
    settings, each word a TOKEN; None for anything else (quotes, pipes, redirects, expansions, comments, more lines).
    lean: a fix inside a compound command isn't found; FIX lessons name only such words, never a command's text"""
    if not isinstance(cmd, str) or "\n" in cmd:
        return None
    m = CD_PREFIX.match(cmd)
    cd, words = (m.group(1), cmd[m.end():].split()) if m else (None, cmd.split())
    if not words or not all(TOKEN.fullmatch(w) for w in words):
        return None
    n = next((i for i, w in enumerate(words) if not ENV_SET.fullmatch(w)), len(words))
    return (cd, words[:n], words[n:]) if words[n:] else None


def _named(value):
    """Whether `value`, one a FIX lesson names (a program, an error's name, a flag, a setting, a folder), is a name and
    not words: split at SPLIT, at most NAME_WORDS words and NAME_CHARS characters, no standing-instruction marker and
    nothing the never-evasion gate reads (`--note=never_wait_for_the_person` is words riding inside one value)."""
    spaced = " ".join(w for w in SPLIT.split(value) if w)
    return len(value) <= NAME_CHARS and len(spaced.split()) <= NAME_WORDS and not MARKERS.search(spaced) \
        and not evasive(spaced)


def _fix_shape(failed, worked):
    """(shape, value) of the change from command `failed` to command `worked` when it is one of FIXED's: another
    program, a flag added or removed (at most FIX_TOKENS words), a setting added, or `cd DIR` first; else None."""
    a, b = _simple(failed), _simple(worked)
    if not (a and b):
        return None
    (cd1, env1, x1), (cd2, env2, x2) = a, b
    if cd1 == cd2 and env1 == env2 and x1[0] == x2[0]:
        ops = [o for o in difflib.SequenceMatcher(None, x1[1:], x2[1:], autojunk=False).get_opcodes() if o[0] != "equal"]
        if len(ops) == 1 and ops[0][0] in ("insert", "delete"):
            tag, i1, i2, j1, j2 = ops[0]
            flag = x2[1:][j1:j2] if tag == "insert" else x1[1:][i1:i2]
            if flag[0].startswith("-") and len(flag) <= FIX_TOKENS:
                return ("flag added" if tag == "insert" else "flag removed"), " ".join(flag)
        return None
    if cd1 == cd2 and env1 == env2 and x1[1:] == x2[1:]:
        return "program", x2[0]
    if cd1 == cd2 and x1 == x2 and len(env2) > len(env1) and env2[:len(env1)] == env1:
        return "setting", " ".join(env2[len(env1):])
    if cd1 is None and cd2 and env1 == env2 and x1 == x2:
        return "cd", cd2
    return None


def _sentences(text):
    """The sentences the person typed in `text` that state a standing instruction: no code block, quoted or indented
    line, quote, question or hedge."""
    from .constraints import SENTENCE
    text = "".join(str(text).split("```")[::2])
    for line in text.split("\n"):
        if line.lstrip().startswith(">") or line.startswith(("    ", "\t")):
            continue
        for s in SENTENCE.split(line):
            s = s.strip()
            if (12 <= len(s) <= 300 and MARKERS.search(s) and not HEDGES.search(s) and not s.endswith("?")
                    and not re.search(r"[\"`“”]", s)):
                yield s


def _jaccard(a, b):
    a, b = set(words(a)), set(words(b))
    return len(a & b) / len(a | b) if a | b else 0


def calls(rows, tr):
    """The decided calls of the verified runs in `rows` (the viewer's rows: view.Translator's, with the arguments the
    dev signer's vault opened), each joined to its Claude Code session, agent and project by its tool_use id in the
    transcripts' calls `tr` (tips.read_transcripts), in each run's order; a run's calls the transcripts don't hold take
    its other calls' session. -> (calls, {run: (session, project, cwd)})."""
    results, out, runs = {}, [], {}
    for r in rows:
        if r.get("event") == "PostToolUse" and r.get("tool_use_id"):
            results[r.get("session_id"), r["tool_use_id"]] = r
    for r in rows:
        v = r.get("v2") or {}
        if r.get("event") != "PreToolUse" or v.get("type") != "policy.decision" or r.get("signer"):
            continue
        t, res = tr.get(r.get("tool_use_id")) or {}, results.get((r.get("session_id"), r.get("tool_use_id")))
        if t.get("project"):
            runs.setdefault(r["session_id"], (t["agent"].split("/")[0], t["project"], t.get("cwd")))
        out.append({"run": r["session_id"], "seq": v.get("run_seq"), "hash": r.get("hash"), "tid": r.get("tool_use_id"),
                    "tool": r.get("tool_name"), "args": r.get("tool_input") if isinstance(r.get("tool_input"), dict)
                    else {}, "decision": v.get("decision"), "prov": v.get("provenance") or [],
                    "state": v.get("provenance_state"), "held": bool(v.get("approval_id") or v.get("held")),
                    "ts": r.get("ts") or 0, "ok": None if res is None else not res.get("failed"),
                    "ms": (res or {}).get("duration_ms") or 0, "agent": t.get("agent"), "error": t.get("error")})
    for c in out:
        c["session"], c["project"], c["cwd"] = runs.get(c["run"], (None, None, None))
        c["agent"] = c["agent"] or c["run"]
    return [c for c in out if c["project"]], runs


def _untrusted(cs):
    """The values (provenance.values) of every argument a decision of `cs` names in its signed `provenance`: a value
    untrusted content brought into some run, in any session of the window."""
    from .provenance import values
    out = set()
    for c in cs:
        for p in c["prov"]:
            v = c["args"].get(p.get("field")) if isinstance(p, dict) else None
            if v is not None:
                out.update(values(v)[0])
    return out


def _taint(cs, fields, bad):
    """Why the calls `cs` of an occurrence can't be a lesson's, by the values of `fields` they use, or None: a run
    whose provenance index isn't complete, a decision whose provenance names one of those fields, or a value in `bad`
    (_untrusted)."""
    from .provenance import values
    for c in cs:
        if c["state"] not in (None, "complete"):
            return f"run {c['run']} record {c['seq']}: its provenance is {c['state']}"
        hit = next((p for p in c["prov"] if isinstance(p, dict) and p.get("field") in fields), None)
        if hit:
            src = (hit.get("source") or {}).get("run_seq")
            return f"run {c['run']} record {c['seq']}: its {hit['field']} came from record {src}"
        for f in fields:
            if c["args"].get(f) is not None and bad.intersection(values(c["args"][f])[0]):
                return f"run {c['run']} record {c['seq']}: its {f} carries a value untrusted content brought in " \
                       "another run"
    return None


def _occ(kind, project, key, cs, wasted, taint):
    c = cs[-1]
    return {"kind": kind, "project": project, "key": key, "id": lesson_id(kind, project, key, _text(kind, key)[:3]),
            "calls": cs, "wasted": wasted, "session": c["session"], "day": _day(cs[0]["ts"]), "ts": cs[0]["ts"],
            "taint": taint}


def detect(rows, tr):
    """-> (occurrences, idx, runs): every lookup, fix and told occurrence in `rows` (calls()), and what each session
    did, for the exposure a lesson's effect is measured over: idx[kind] = {(project, what): {session}} for files
    opened ("opened"), programs run ("ran"), failures by signature ("failed"), and the sentences each project's
    sessions typed ("said": project -> [(session, sentence)]), with the sessions of each project ("prompted")."""
    cs, runs = calls(rows, tr)
    bad, out = _untrusted(cs), []
    idx = {"opened": collections.defaultdict(set), "ran": collections.defaultdict(set),
           "failed": collections.defaultdict(set), "said": collections.defaultdict(list),
           "prompted": collections.defaultdict(set)}
    agents = collections.defaultdict(list)
    for c in cs:
        agents[c["run"], c["agent"]].append(c)
        if c["tool"] in OPEN and c["decision"] in RAN:
            idx["opened"][c["project"], _rel(c["args"].get(OPEN[c["tool"]]), c["cwd"])].add(c["session"])
        if c["tool"] == "Bash" and isinstance(c["args"].get("command"), str) and c["decision"] in RAN:
            plain, failed = _simple(c["args"]["command"]), _failure(c["error"]) if c["ok"] is False else None
            argv = plain[2] if plain else _argv(c["args"]["command"])
            idx["ran"][c["project"], os.path.basename(argv[0]) if argv else ""].add(c["session"])
            if plain and failed:
                idx["failed"][c["project"], os.path.basename(argv[0]), *failed[:2]].add(c["session"])
        idx["prompted"][c["project"]].add(c["session"])
    for seq in agents.values():
        seq.sort(key=lambda c: c["seq"] or 0)
        for i, c in enumerate(seq):
            x = _searched(c) if c["decision"] in RAN and not c["held"] else None
            if x:   # a lookup: the first read within PAIR_WITHIN calls, nothing written to it, denied or held between
                for j in range(i + 1, min(len(seq), i + 1 + PAIR_WITHIN)):
                    o = seq[j]
                    if o["decision"] not in RAN or o["held"]:
                        break   # what the agent read after a deny or a hold rests on it: never a lesson
                    if o["tool"] not in OPEN or o["ok"] is False:
                        continue
                    f = _rel(o["args"].get(OPEN[o["tool"]]), o["cwd"])
                    if isinstance(f, str) and TOKEN.fullmatch(f) and not any(
                            w["tool"] in WRITES and _rel(w["args"].get(WRITES[w["tool"]]), w["cwd"]) == f
                            for w in seq[i + 1:j]):
                        out.append(_occ("lookup", c["project"], [x, f], [c, o], seq[i:j],
                                        _taint([c, o], (SEARCH.get(c["tool"], "command"), OPEN[o["tool"]]), bad)))
                    break
            failed = _failure(c["error"]) if c["tool"] == "Bash" and c["ok"] is False and c["decision"] in RAN \
                and not c["held"] and _simple(c["args"].get("command")) else None
            if failed:   # a fix: the next shell call that worked, a change of FIXED's of this one, nothing between
                for j in range(i + 1, min(len(seq), i + 1 + FIX_WITHIN)):
                    o = seq[j]
                    if o["decision"] not in RAN or o["held"] or o["tool"] in WRITES:
                        break
                    if o["tool"] != "Bash" or o["ok"] is not True:
                        continue
                    shape = _fix_shape(c["args"]["command"], o["args"].get("command"))
                    if shape:
                        key = [_simple(c["args"]["command"])[2][0], *failed[:2], *shape]
                        if all(_named(v) for v in (key[0], key[2], key[4]) if v):   # the program, the error's name, the change
                            out.append(_occ("fix", c["project"], key, [c, o], seq[i:j],
                                            _taint(seq[i:j + 1], ("command",), bad)))
                        break
    for r in rows:   # told: the person's typed sentences
        v = r.get("v2") or {}
        if not (v.get("type") == "input.observed" and v.get("trust") == "trusted" and v.get("source") == TYPED
                and isinstance(v.get("value"), str) and r.get("session_id") in runs):
            continue
        session, project, _ = runs[r["session_id"]]
        idx["prompted"][project].add(session)
        for s in _sentences(v["value"]):
            idx["said"][project].append((session, s))
            c = {"run": r["session_id"], "seq": v.get("run_seq"), "hash": r.get("hash"), "ts": r.get("ts") or 0,
                 "session": session, "tool": "prompt", "args": {}}
            out.append(_occ("told", project, [" ".join(s.split())], [c], [], None))
    return out, idx, runs


def _seen(kind, project, key, idx, occ_sessions):
    """(sessions that hit, sessions exposed) for a lesson of `kind` and `key` in `project`: a lookup's searched first of
    those that opened its file, a fix's failed of those that ran its program, a told's said it of those prompted."""
    if kind == "lookup":
        return occ_sessions, idx["opened"].get((project, key[1]), set()) | occ_sessions
    if kind == "fix":
        hit = idx["failed"].get((project, os.path.basename(key[0]), key[1], key[2]), set())
        return hit, idx["ran"].get((project, os.path.basename(key[0])), set()) | hit
    if kind == "told":
        hit = {s for s, said in idx["said"].get(project, ()) if _jaccard(said, key[0]) >= SAME}
        return hit, idx["prompted"].get(project, set()) | hit
    return set(), set()


def _groups(occs):
    """The told occurrences of a project merged when their sentences are one instruction (SAME), under the earliest;
    every other kind by its key."""
    by = collections.OrderedDict()
    for o in sorted(occs, key=lambda o: o["ts"]):
        if o["kind"] == "told":
            first = next((g for g in by.values() if g[0]["kind"] == "told" and g[0]["project"] == o["project"]
                          and _jaccard(g[0]["key"][0], o["key"][0]) >= SAME), None)
            if first is not None:
                first.append(o)
                continue
        by.setdefault(o["id"], []).append(o)
    return list(by.values())


FIXED = {"program": "With `{}` in its place it worked.", "flag added": "With `{}` added it worked.",
         "flag removed": "Without `{}` it worked.", "setting": "With `{}` set it worked.", "cd": "Run from `{}` it worked."}


def _text(kind, key):
    """A lesson's (name, description, body, type, origin), from its key alone: templates over values a pattern read (an
    identifier, a path, a program, a flag, a setting, an error's name), or the person's own sentence; facts, not
    commands, and no count, so one id names one text (lesson_id)."""
    if kind == "lookup":
        x, f = key
        return (f"Where `{x}` is", f"When looking for {x} in this project", f"Searching for `{x}` here leads to `{f}`.",
                "reference", "run")
    if kind == "fix":
        prog, cls, var, shape, value = key
        failed = {c: said for c, _, said in ERRORS}[cls].format(var)
        return (f"When `{prog}` fails: {failed}", f"When running {os.path.basename(prog)} here",
                f"`{prog}` fails here: {failed}. " + FIXED[shape].format(value), "feedback", "run")
    said = key[0]
    return (said if len(said) <= 80 else said[:77] + "...", "The person's standing instruction here",
            f"The person said: “{said}”", "feedback", "you")


def _evidence(g):
    """The newest occurrences, as the page's EVIDENCE rows, and their records (newest first)."""
    rows, recs = [], []
    for o in sorted(g, key=lambda o: -o["ts"])[:8]:
        rows.append({"session": o["session"], "t": o["ts"], "calls": [
            {"run": c["run"], "seq": c["seq"], "hash": c.get("hash"), "what": _what(c)} for c in o["calls"]]})
        recs += [{"run": c["run"], "seq": c["seq"], "hash": c.get("hash")} for c in o["calls"]]
    return rows, recs[:8]


def _what(c):
    if c["tool"] == "prompt":
        return "the person's prompt (typed)"
    a = c["args"]
    v = a.get("command") or a.get("file_path") or a.get("pattern") or a.get("url") or a.get("query") or ""
    return f"{c['tool']} {_one(_rel(v, c.get('cwd')))[:160]}"


def propose(occs, idx, notes, cost=None, days=7):
    """(waiting, not proposed): the lessons the window's occurrences make, against the folder's `notes`: thresholds,
    taint, the never-evasion gate, duplicates and checks; at most SHOWN waiting per project, the told ones first, then
    by the calls each would save. `cost`: {tool_use id: USD of the step that made it}."""
    cost = cost or {}
    by_id = {n.get("id"): n for n in notes}
    active = [n for n in notes if n["status"] == "active"]
    waiting, nope = [], []
    for g in _groups(occs):
        kind, project, key, lid = g[0]["kind"], g[0]["project"], g[0]["key"], g[0]["id"]
        clean = [o for o in g if not o["taint"]]
        sessions, days_ = {o["session"] for o in clean}, {o["day"] for o in clean}
        need = {"lookup": (MIN_SESSIONS, MIN_DAYS, 1), "fix": (FIX_SESSIONS, 1, FIX_TIMES), "told": (1, 1, 1)}[kind]
        name, desc, body, typ, origin = _text(kind, key)
        card = {"id": lid, "kind": kind, "project": project, "key": key, "name": name, "description": desc,
                "text": body, "type": typ, "origin": origin, "tier": "signed+transcript", "file": f"{kind}-{lid[2:]}.md"}
        if kind == "told":   # one instruction: a note of the same words, in use or retired, is this one
            same = next((n for n in notes if n.get("kind") == "told" and n.get("project") == project
                         and _jaccard((n.get("key") or [""])[0], key[0]) >= SAME), None)
            by_id.setdefault(lid, same)
        had = by_id.get(lid)
        if had is not None and had["status"] in ("active", "retired", "superseded"):
            continue   # in use, or a person retired it: never proposed again
        if len(sessions) < need[0] or len(days_) < need[1] or len(clean) < need[2]:
            seen = {o["session"] for o in g}
            if any(o["taint"] for o in g) and len(seen) >= need[0] and len({o["day"] for o in g}) >= need[1] \
                    and len(g) >= need[2]:   # taint is what stopped it
                nope.append({**card, "rule": "tainted", "why": WORDS["tainted"].format(
                    where=next(o["taint"] for o in g if o["taint"]))})
            elif len(seen) >= 2:   # a near miss; one session alone is no candidate
                nope.append({**card, "rule": "one_session", "why": WORDS["one_session"].format(
                    s=f"{len(sessions)} session{'s' * (len(sessions) != 1)}", kind=kind,
                    d=f"{len(days_)} day{'s' * (len(days_) != 1)}",
                    need=f"{MIN_SESSIONS} sessions on {MIN_DAYS} days" if kind == "lookup" else
                    f"{FIX_TIMES} times in {FIX_SESSIONS} sessions")})
            continue
        all_text = " ".join((name, desc, body))
        bad = problems(render({**card, "body": body}))
        if bad:
            nope.append({**card, "rule": bad[0], "why": WORDS[bad[0]]})
            continue
        if evasive(all_text):   # (one that rests on a deny or a hold is no occurrence: detect stops there)
            nope.append({**card, "rule": "evasion", "why": WORDS["evasion"]})
            continue
        if any(" ".join(n["body"].lower().split()) == " ".join(body.lower().split()) for n in active):
            nope.append({**card, "rule": "duplicate", "why": WORDS["duplicate"]})
            continue
        hits, exposed = _seen(kind, project, key, idx, sessions)
        wasted = [c for o in clean for c in o["wasted"]]
        usd = sum(cost.get(c["tid"], 0) for c in wasted)
        rows, recs = _evidence(clean)
        # a lesson in use about the same thing (a lookup's identifier, a fix's failure) with another fact: this one
        # replaces it on approval
        older = [n for n in active if n.get("project") == project and n.get("kind") == kind and kind in SUBJECT
                 and (n.get("key") or [])[:SUBJECT[kind]] == key[:SUBJECT[kind]]]
        waiting.append({**card, "sessions": len(sessions), "days": len(days_), "times": len(clean),
                        "risky": risky(all_text), "evidence": rows, "records": recs,
                        "seen": {"hits": len(hits), "exposed": len(exposed)},
                        "supersedes": [{"id": n["id"], "file": n["file"], "name": n["name"]} for n in older],
                        "saving": {"calls": len(wasted), "usd": round(usd, 4) if cost else None,
                                   "seconds": round(sum(c["ms"] for c in wasted) / 1000)} if kind != "told" else
                        {"calls": 0, "usd": None, "seconds": None, "said": len(clean)},
                        "math": _math(kind, clean, wasted, usd, days, bool(cost)),
                        "approve": f"tracekit tips approve {lid}", "retire": f"tracekit tips retire {lid}"})
    waiting.sort(key=lambda w: (w["kind"] != "told", -w["saving"]["calls"], -w["sessions"]))
    shown, per = [], collections.Counter()
    for w in waiting:
        per[w["project"]] += 1
        (shown if per[w["project"]] <= SHOWN else nope).append(
            w if per[w["project"]] <= SHOWN else {**w, "rule": "shown", "why": WORDS["shown"]})
    return shown, nope


def _math(kind, occs, wasted, usd, days, priced):
    n = len({o["session"] for o in occs})
    if kind == "told":
        return [f"Typed by the person in {n} session{'s' * (n != 1)} (the hook's signed record of the prompt's typed "
                "part; never a paste or what the harness added)."]
    return [f"{len(occs)} occurrence{'s' * (len(occs) != 1)} in {n} session{'s' * (n != 1)} in the last {days} days, "
            "each from signed records of runs that verified.",
            f"Calls a session that had the lesson would not have made: {len(wasted)} ("
            + ("the search before the read" if kind == "lookup" else "the failing call and any before the one that "
               "worked") + f"); their signed run time {round(sum(c['ms'] for c in wasted) / 1000)} s.",
            (f"Each such call took a model step that re-read the session's context: about ${usd:.2f} at list prices."
             if priced else "Dollars need Claude Code's transcripts' token counts: not counted."),
            "An estimate: it assumes each session would have known it at once."]


# ----------------------------------------------------------------------------------------------- measurement


def given(rows, runs):
    """{lesson id: {session: when}} from the signed `tracekit:lessons` observes in `rows` whose kept value (the
    dev signer's vault) names it, whole or as a line; a run no transcript joins (it made no call yet) is a session of
    its own."""
    out = collections.defaultdict(dict)
    for r in rows:
        v = r.get("v2") or {}
        if v.get("type") != "input.observed" or v.get("source") != SOURCE or not isinstance(v.get("value"), dict):
            continue
        session = runs.get(r.get("session_id"), (r.get("session_id"),))[0]
        for lid in [*(v["value"].get("whole") or ()), *(v["value"].get("lines") or ())]:
            if isinstance(lid, str) and LESSON_ID.fullmatch(lid):
                out[lid].setdefault(session, r.get("ts") or 0)
    return out


def signed_state(note, rows, known=None):
    """Whether lesson `note` (in use) rests on the signed record of a person's answer it names (`signed`, run:run_seq):
    "signed" when that record is in `rows` and names this id and this text's sha256 (text_sha); "changed" when it
    names another; "unknown" when the store holds no such run (`known`, the store's run ids, when given); "not read"
    when it is outside the window read; "none" when the note names none. Only "signed" and "not read" can be given to
    an agent, and the hook asks the signer first (verified). -> (state, words)."""
    ref = str(note.get("signed") or "")
    if not SIGNED.fullmatch(ref):
        return "none", "No signed record of a person's answer: written some other way, never given to the agent."
    run, seq = ref.rsplit(":", 1)
    rec = next((r for r in rows if r.get("session_id") == run and (r.get("v2") or {}).get("run_seq") == int(seq)
                and (r.get("v2") or {}).get("source") == PERSON), None)
    if rec is None and known is not None and run not in known:
        return "unknown", f"It names run {run}, which the store doesn't hold: written by hand, never given to the agent."
    if rec is None:
        return "not read", f"Its signed record (run {run}, record {seq}) is outside the window read."
    v = (rec.get("v2") or {}).get("value")
    if not (isinstance(v, dict) and v.get("id") == note.get("id") and v.get("sha256") == text_sha(note)
            and v.get("action") in ANSWERS):
        return "changed", f"Its text is not what the signed record (run {run}, record {seq}) names: changed since."
    return "signed", f"{ {'approve': 'Approved', 'restore': 'Restored', 'add': 'Added'}[v['action']]} by a person: signed " \
                       f"(run {run}, record {seq})."


def effect(note, idx, occ_sessions, given_to):
    """A lesson in use measured on the detector that found it: `before` as recorded at its approval, `after` over the
    sessions the signed observe proves were given it from then on, for AFTER_S; shown once each side has MIN_EXPOSED
    sessions."""
    try:
        h0, n0 = (int(x) for x in str(note.get("before") or "").split("/"))
    except ValueError:
        h0 = n0 = None
    when = _epoch(note.get("approved"))
    got = {s for s, t in given_to.items() if when is None or when <= t <= when + AFTER_S}
    hits, exposed = _seen(note.get("kind"), note["project"], note.get("key") or [None, None, None], idx,
                          occ_sessions)
    h1, n1 = len(hits & got), len(exposed & got)
    out = {"given": len(got), "before": None if n0 is None else {"hits": h0, "exposed": n0},
           "after": {"hits": h1, "exposed": n1}, "basis": MEASURE, "kind": note.get("kind")}
    if note.get("kind") not in ("lookup", "fix", "told"):
        return dict(out, shown=False, why="A lesson you wrote has no detector to measure it on.")
    if n0 is None or n0 < MIN_EXPOSED or n1 < MIN_EXPOSED:
        least = min(n1, n0 if n0 is not None else 0)
        return dict(out, shown=False, why=f"{least} of {MIN_EXPOSED} sessions so far")
    r0, r1 = h0 / n0, h1 / n1
    return dict(out, shown=True, worse=r1 > r0, change=round(100 * (r1 - r0) / r0) if r0 else None)


def _epoch(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------------------------- the page


def page(rows, tr, folder, cost=None, now=None, since=None, cwds=None, known=None):
    """The LESSONS part of the TIPS page and of `tracekit tips`: what waits for a person's OK, what is in use and its
    effect, what isn't proposed and why, and what the next session of each project with lessons reads."""
    now = now or time.time()
    days = max(1, round((now - since) / 86400)) if since else 7
    if folder is None:
        return {"ok": False, "why": "Lessons read the dev signer's store and keep their folder in its data dir: run "
                                    "tracekit tips (or tracekit view) without --data-dir."}
    try:
        notes = folder.notes()
    except (Refused, OSError) as e:
        return {"ok": False, "why": f"The lessons folder can't be read: {e}"}
    occs, idx, runs = detect(rows, tr)
    if not runs and not notes:
        return {"ok": False, "why": "No signed call here joins a Claude Code session: lessons need the dev signer's "
                                    "records and Claude Code's transcripts (each run's project)."}
    waiting, nope = propose(occs, idx, notes, cost, days)
    sessions = collections.defaultdict(set)
    for o in occs:
        sessions[o["id"]].add(o["session"])
    got = given(rows, runs)
    states = {n.get("id"): dict(zip(("state", "why"), signed_state(n, rows, known))) for n in notes
              if n["status"] == "active"}
    active = []
    for n in sorted((n for n in notes if n["status"] == "active"), key=lambda n: n.get("approved") or "",
                    reverse=True):
        active.append({**{k: n.get(k) for k in ("id", "kind", "project", "name", "description", "type", "origin",
                                                  "approved", "evidence", "tier", "file")},
                       "text": n["body"].strip(), "supersedes": n.get("supersedes") or [],
                       "signed": states[n.get("id")],
                       "effect": effect(n, idx, sessions.get(n.get("id"), set()), got.get(n.get("id"), {})),
                       "retire": f"tracekit tips retire {n.get('id')}"})
    nxt = []
    for p in sorted({n["project"] for n in notes if n["status"] == "active"}):
        f = for_agent(project=p, folder=folder,   # as the hook gives it: what the signed records show, at most
                      check=lambda ns: {n["id"] for n in ns if states[n["id"]]["state"] in ("signed", "not read")})
        nxt.append({"project": p, "shown": (cwds or {}).get(p) or p, "bytes": f["bytes"], "budget": BUDGET,
                    "whole": f["given"]["whole"], "lines": f["given"]["lines"], "left_out": f["left_out"],
                    "block": f["block"]})
    shown = cwds or {}
    for x in waiting + nope + active:
        x["where"] = shown.get(x["project"]) or x["project"]
    return {"ok": True, "folder": folder.path, "commit": folder.head(), "budget": BUDGET, "measure": MEASURE,
            "waiting": waiting, "active": active,
            "earlier": [{k: n.get(k) for k in ("id", "kind", "project", "name", "status", "superseded_by")}
                        for n in notes if n["status"] in ("retired", "superseded")],
            "not_proposed": sorted(nope, key=lambda x: x["rule"] != "tainted")[:40], "not_proposed_n": len(nope),
            "not_proposed_by": dict(collections.Counter(x["rule"] for x in nope).most_common()),
            "next": nxt, "off": f"{OFF}=0"}
