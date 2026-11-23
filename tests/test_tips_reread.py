"""The TIPS page reading Claude Code's transcripts again (tips.read_transcripts with a tips.Transcripts): only what each
file gained since the last read, with the same answer as reading everything again.

    python3 -m pytest tests/test_tips_reread.py -v
"""
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from factories import cc_assistant, cc_result, iso, write_jsonl  # noqa: E402
from tracekit import tips  # noqa: E402

T0 = 1_791_590_400   # 2026-10-10, before the files' own times: every file is in the window


def tmp(test):
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, True)
    return d


def prompt(t):
    return {"type": "user", "timestamp": iso(t), "message": {"role": "user", "content": "go on"}}


def failed(tool_use_id, t, text):
    return {"type": "user", "timestamp": iso(t), "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": tool_use_id, "is_error": True, "content": [{"type": "text", "text": text}]}]}}


def m1(t=T0 + 1):   # Claude Code writes a line per content block, each with the message's usage
    return [cc_assistant("m1", t, write=900, out=40), {**cc_assistant("m1", t + 1, write=1000, out=50, tools=[
        ("toolu_1", "Bash", {"command": "pytest -q"})]), "cwd": "/Users/me/proj"}]


def append(path, lines):
    data = "".join(json.dumps(x) + "\n" for x in lines).encode()
    with open(path, "ab") as f:
        f.write(data)
    return len(data)


class Counted(io.FileIO):
    """A file that adds each byte it reads to `n`."""
    n = 0

    def readinto(self, b):
        got = super().readinto(b)
        Counted.n += got or 0
        return got

    def readall(self):
        data = super().readall()
        Counted.n += len(data)
        return data


def counted(path):
    f, err = real_open(path)
    if err:
        return f, err
    fd = os.dup(f.fileno())
    f.close()
    return io.BufferedReader(Counted(fd, "rb")), None


real_open = tips._safe_open


class Reread(unittest.TestCase):
    def setUp(self):
        self.root = tmp(self)
        p = os.path.join(self.root, "-Users-me-proj")
        self.main = write_jsonl(os.path.join(p, "s1.jsonl"), [
            prompt(T0), *m1(), cc_result("toolu_1", T0 + 5),
            cc_assistant("m2", T0 + 6, read=1000, write=200, tools=[("toolu_2", "Read", {"file_path": "/x"})])])
        self.sub = write_jsonl(os.path.join(p, "s1", "subagents", "agent-a1.jsonl"), [
            prompt(T0 + 2), cc_assistant("m3", T0 + 3, write=500, tools=[("toolu_3", "Grep", {})]),
            cc_result("toolu_3", T0 + 4)])
        # s1 resumed: its file starts with s1's messages again, which count once, in s1
        self.resumed = write_jsonl(os.path.join(p, "s2.jsonl"), [
            prompt(T0), *m1(), cc_result("toolu_1", T0 + 5), prompt(T0 + 19),
            cc_assistant("m4", T0 + 20, read=1200, write=300, tools=[("toolu_4", "Bash", {"command": "make lint"})])])
        self.cache = tips.Transcripts()
        Counted.n = 0
        patch = mock.patch.object(tips, "_safe_open", counted)
        patch.start()
        self.addCleanup(patch.stop)

    def read(self, since=T0 - 1, root=None):
        Counted.n = 0
        got = tips.read_transcripts(root or self.root, since, self.cache)
        return got, Counted.n

    def fresh(self, since=T0 - 1, root=None):
        return tips.read_transcripts(root or self.root, since)

    def test_a_refresh_reads_only_the_lines_a_transcript_gained_and_answers_as_a_fresh_read(self):
        first, n = self.read()
        self.assertEqual(first, self.fresh())
        self.assertEqual(n, sum(os.path.getsize(p) for p in (self.main, self.sub, self.resumed)))
        self.assertEqual(self.read(), (first, 0))   # nothing changed: nothing read
        # toolu_2's failed result lands in a later chunk, and s1 now holds m4 too: s1 comes first in the walk, so m4
        # counts in s1 and no longer in the resumed s2
        grew = append(self.main, [failed("toolu_2", T0 + 21, "Exit code 1\nno such file"), prompt(T0 + 22),
                                  cc_assistant("m4", T0 + 20, read=1200, write=300,
                                               tools=[("toolu_4", "Bash", {"command": "make lint"})]),
                                  cc_assistant("m5", T0 + 30, read=1500, write=100,
                                               tools=[("toolu_5", "Bash", {"command": "sleep 60"})])])
        second, n = self.read()
        self.assertEqual(n, grew)
        self.assertEqual(second, self.fresh())
        agents, calls, files, unreadable = second
        self.assertEqual([s["id"] for s in agents[next(k for k in agents if k.endswith("s1"))]["steps"]],
                         ["m1", "m2", "m4", "m5"])
        self.assertEqual((calls["toolu_2"]["t1"], calls["toolu_2"]["error"]), (T0 + 21, "Exit code 1\nno such file"))
        self.assertEqual(calls["toolu_4"]["agent"], next(k for k in agents if k.endswith("s1")))
        self.assertEqual((files, unreadable), (3, []))

    def test_a_file_that_shrank_or_was_replaced_is_read_again_from_its_start(self):
        def shrink():
            write_jsonl(self.main, [prompt(T0), *m1()])

        def replace():
            new = write_jsonl(self.main + ".new", [prompt(T0), *m1(), cc_result("toolu_1", T0 + 5),
                                                   cc_assistant("m9", T0 + 40, read=900, write=50, tools=[
                                                       ("toolu_9", "Edit", {})]), cc_result("toolu_9", T0 + 41)])
            os.replace(new, self.main)

        def rewritten(later):   # in place, to the same size
            st = os.stat(self.main)
            with open(self.main, "r+b") as f:
                data = f.read()
                f.seek(0)
                f.write(data.replace(b'"m2"', b'"m8"'))
            os.utime(self.main, ns=(st.st_atime_ns, st.st_mtime_ns + later * 10**9))

        def grew_back():   # larger, but written as an older file
            st = os.stat(self.main)
            append(self.main, [cc_assistant("m9", T0 + 40, write=50)])
            os.utime(self.main, ns=(st.st_atime_ns, st.st_mtime_ns - 10**9))

        for name, change in (("shrank", shrink), ("replaced", replace), ("rewritten", lambda: rewritten(1)),
                             ("rewritten, mtime put back", lambda: rewritten(0)),
                             ("rewritten, mtime went back", lambda: rewritten(-1)), ("grew, mtime went back", grew_back)):
            with self.subTest(name):
                self.read()
                change()
                got, n = self.read()
                self.assertEqual(n, os.path.getsize(self.main))
                self.assertEqual(got, self.fresh())

    def test_a_line_still_being_written_counts_once_it_ends(self):
        line = json.dumps(cc_assistant("m6", T0 + 50, read=1300, write=70, tools=[("toolu_6", "Read", {})])) + "\n"
        with open(self.main, "a") as f:
            f.write(line[:40])   # Claude Code's write, half done
        first, _ = self.read()
        self.assertEqual(first, self.fresh())
        self.assertNotIn("toolu_6", first[1])
        with open(self.main, "a") as f:
            f.write(line[40:])
        second, n = self.read()
        self.assertEqual(n, len(line))   # the half line again, then the rest
        self.assertEqual(second, self.fresh())
        self.assertIn("toolu_6", second[1])

    def test_a_last_line_without_its_newline_counts_as_a_fresh_read_counts_it(self):
        last = json.dumps(cc_assistant("m7", T0 + 60, read=1300, write=80))
        with open(self.main, "a") as f:
            f.write(last)   # a finished file, no newline
        first, _ = self.read()
        self.assertEqual(first, self.fresh())
        self.assertIn("m7", [s["id"] for a in first[0].values() for s in a["steps"]])
        with open(self.main, "a") as f:
            f.write("\n")
        grew = append(self.main, [cc_assistant("m8", T0 + 61, read=1400, write=10)])
        second, n = self.read()
        self.assertEqual(second, self.fresh())
        self.assertEqual(n, len(last) + 1 + grew)

    def test_the_window_moving_either_way_answers_as_a_fresh_read(self):
        self.read()
        for since in (T0 + 4, T0 + 21, T0 - 1):
            with self.subTest(since=since):
                self.assertEqual(self.read(since)[0], self.fresh(since))
        with self.subTest("a file grew as the window moved on"):
            append(self.main, [cc_assistant("m5", T0 + 30, read=1500, write=100)])
            self.assertEqual(self.read(T0 + 5)[0], self.fresh(T0 + 5))

    def test_a_file_the_window_left_or_that_went_away_is_forgotten(self):
        self.read()
        os.remove(self.sub)
        os.utime(self.resumed, (T0 - 86400, T0 - 86400))
        got, n = self.read()
        self.assertEqual((got, n), (self.fresh(), 0))
        self.assertEqual(got[2], 1)
        self.assertEqual({k[1] for k in self.cache.files}, {os.path.realpath(self.main)})

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "a mode root reads through")
    def test_a_file_that_can_no_longer_be_opened_is_said_so_as_a_fresh_read_says_it(self):
        self.read()
        os.chmod(self.sub, 0)   # neither its size nor its mtime changes
        self.addCleanup(os.chmod, self.sub, 0o600)
        got, _ = self.read()
        self.assertEqual(got, self.fresh())
        self.assertEqual((got[2], [u["path"] for u in got[3]]), (2, [os.path.realpath(self.sub)]))

    def test_two_folders_never_share_records(self):
        inner = os.path.join(self.root, "-Users-me-proj")   # the same files, read as another folder's
        for root, read in ((self.root, 3), (inner, 3), (self.root, 0), (inner, 0)):   # each keeps its own
            with self.subTest(root=root):
                got, n = self.read(root=root)
                self.assertEqual(got, self.fresh(root=root))
                self.assertEqual(n, sum(map(os.path.getsize, (self.main, self.sub, self.resumed))) if read else 0)

    def test_refreshes_at_once_read_the_new_lines_once_and_each_answers_as_a_fresh_read(self):
        self.read()
        grew = append(self.main, [cc_result("toolu_2", T0 + 21), cc_assistant("m5", T0 + 30, read=1500, write=100)])
        Counted.n = 0
        go, got = threading.Barrier(8), []

        def refresh():
            go.wait()
            got.append(tips.read_transcripts(self.root, T0 - 1, self.cache))
        threads = [threading.Thread(target=refresh) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(Counted.n, grew)
        self.assertEqual(got, [self.fresh()] * 8)

    def test_the_page_reads_only_what_was_added_between_its_refreshes(self):
        t = time.time() - 3600   # the page's window is the last week
        path = write_jsonl(os.path.join(tmp(self), "p", "s.jsonl"), [cc_assistant(f"m{i}", t + i, write=100)
                                                                       for i in range(3)])
        page = tips.Page(lambda: [], os.path.dirname(os.path.dirname(path)))
        before = json.loads(page())["sources"]["transcripts"]
        grew = append(path, [cc_assistant("m3", t + 3, write=100)])
        Counted.n = 0
        after = json.loads(page(fresh=True))["sources"]["transcripts"]
        self.assertEqual(Counted.n, grew)
        self.assertEqual((before["steps"], after["steps"]), (3, 4))


if __name__ == "__main__":
    unittest.main()
