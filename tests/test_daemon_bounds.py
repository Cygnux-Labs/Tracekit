"""The v1 signer daemon's state stays bounded by what it accepts (tracekit/daemon.py)."""
import os
import tempfile
import unittest
from unittest import mock

from factories import ev, make_signer, run_start
from tracekit.ledger import Keys, Ledger, read_records


class RefusedEvents(unittest.TestCase):
    def test_refused_events_leave_no_run_state(self):
        d = tempfile.mkdtemp()
        s = make_signer(os.path.join(d, "h"), mode="dev")
        before = len(s.runs)
        for i in range(200):   # refused: a findings run takes review events only
            r = s.handle({"op": "append", "cseq": 0, "event": ev(
                "tool.call", {"tool_use_id": f"t{i}", "name": "Bash", "input": {}}, run=f"findings:{i}")})
            self.assertFalse(r["ok"], r)
        self.assertEqual(len(s.runs), before)


class WrittenEvents(unittest.TestCase):
    def test_an_appended_event_is_ok_even_when_saving_the_run_state_fails(self):
        d = tempfile.mkdtemp()
        s = make_signer(os.path.join(d, "h"), mode="dev")
        with mock.patch.object(s, "_save_runs", side_effect=OSError(28, "No space left on device")):
            r = s.handle({"op": "append", "cseq": 0, "event": run_start(run="r1")})
        self.assertTrue(r["ok"], r)   # it is in the ledger: a retry would read as a replay
        self.assertEqual(s.write_errors, 1)


class LedgerWrites(unittest.TestCase):
    def test_a_partial_line_that_cannot_be_rolled_back_never_joins_the_next_record(self):
        d = tempfile.mkdtemp()
        led = Ledger(os.path.join(d, "ledger.jsonl"), Keys.load_or_create(os.path.join(d, "keys")))
        self.addCleanup(led.close)
        write = led._fh.write

        def half(data):   # a full disk: half the line reaches the file, then the write fails
            write(bytes(data[:len(data) // 2]))
            raise OSError(28, "No space left on device")
        with mock.patch.object(led._fh, "write", half), mock.patch("os.ftruncate", side_effect=OSError(5, "EIO")), \
                self.assertRaises(OSError):
            led.append(ev("tool.call", {"tool_use_id": "t0", "name": "Bash", "input": {}}, run="r1"))
        led.append(ev("tool.call", {"tool_use_id": "t1", "name": "Bash", "input": {}}, run="r1"))
        ids = [rec["event"]["data"]["tool_use_id"] for _, rec, _ in read_records(led.path) if isinstance(rec, dict)]
        self.assertEqual(ids, ["t1"])

if __name__ == "__main__":
    unittest.main()
