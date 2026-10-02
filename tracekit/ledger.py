"""Signer-side ledger: the only code that writes records. Runs inside tracekitd as the
`tracekit` user, so the agent's user can read the ledger but cannot change it."""
import json
import os

from . import crypto
from .core import GENESIS, b64d, b64e, event_hash, sig_message
from .locking import lock_file, unlock_file


class Keys:
    def __init__(self, secret, public):
        self.secret, self.public, self.kid = secret, public, crypto.kid(public)

    @classmethod
    def load_or_create(cls, keydir):
        os.makedirs(keydir, mode=0o700, exist_ok=True)
        os.chmod(keydir, 0o700)
        sk, pk = os.path.join(keydir, "signer.key"), os.path.join(keydir, "signer.pub")
        if os.path.exists(sk):
            if os.name != "nt" and (os.stat(sk).st_mode & 0o077):
                os.chmod(sk, 0o600)  # a group/world-readable signing key defeats the whole design
            with open(sk, "rb") as f:
                secret = f.read()
            try:
                public = crypto.public_from_secret(secret)
            except ValueError as e:
                raise RuntimeError(f"{sk} is not a valid Ed25519 key ({len(secret)} bytes); refusing to replace it "
                                   "(that would fork the chain). Restore it from backup.") from e
        else:
            secret, public = crypto.generate()
            fd = os.open(sk, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secret)
        with open(pk, "wb") as f:
            f.write(public)
        os.chmod(pk, 0o644)
        return cls(secret, public)


def make_record(event, keys):
    h = event_hash(event)
    return {"v": 1, "event": event, "hash": h, "kid": keys.kid,
            "sig": b64e(crypto.sign(keys.secret, sig_message(h, event["prev_hash"], event["seq"])))}


def verify_record_sig(rec, public):
    if rec.get("elided"):
        h, prev, seq = rec["hash"], rec["prev_hash"], rec["seq"]
    else:
        h, prev, seq = rec["hash"], rec["event"]["prev_hash"], rec["event"]["seq"]
    try:
        return crypto.verify(public, sig_message(h, prev, seq), b64d(rec["sig"]))
    except Exception:
        return False


def read_records(path):
    """Yield (lineno, record_or_None, raw_line)."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield i, json.loads(line), line
            except ValueError:
                yield i, None, line


class Ledger:
    """Append-only, fsync'd, single-writer (the daemon holds a lock for its lifetime)."""

    def __init__(self, path, keys):
        self.path, self.keys = path, keys
        self._fh = None
        self._lock_fh = None
        self._locked = False
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._fh = open(path, "ab", buffering=0)  # unbuffered: a failed write never lingers in a buffer
            os.chmod(path, 0o644)
            self._lock_fh = open(path + ".lock", "a+b")
        except BaseException:
            self.close()
            raise
        try:
            lock_file(self._lock_fh, blocking=False)
            self._locked = True
        except OSError as e:
            self.close()
            raise RuntimeError(f"another tracekitd holds {path}") from e
        try:
            self.seq, self.head, self.torn = -1, GENESIS, False
            for _, rec, _raw in read_records(path):
                self.torn = not isinstance(rec, dict)  # only a torn *final* line means a crash since the last start
                if self.torn:
                    continue
                try:
                    seq = rec["seq"] if rec.get("elided") else rec["event"]["seq"]
                    self.seq, self.head = seq, rec["hash"]
                except (KeyError, TypeError):
                    self.torn = True
            needs_nl = False
            if os.path.getsize(path):
                with open(path, "rb") as f:
                    f.seek(-1, os.SEEK_END)
                    needs_nl = f.read(1) != b"\n"
            if self.torn or needs_nl:  # isolate a torn/unterminated line so the next record starts cleanly
                self._fh.write(b"\n")
        except BaseException:
            self.close()
            raise

    def close(self):
        lock_fh = self._lock_fh
        ledger_fh = self._fh
        try:
            if lock_fh is not None and not lock_fh.closed and self._locked:
                unlock_file(lock_fh)
        finally:
            self._locked = False
            if lock_fh is not None and not lock_fh.closed:
                lock_fh.close()
            if ledger_fh is not None and not ledger_fh.closed:
                ledger_fh.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def append(self, event):
        event = dict(event)
        event["seq"] = self.seq + 1
        event["prev_hash"] = self.head
        rec = make_record(event, self.keys)
        data = (json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8")
        size = os.fstat(self._fh.fileno()).st_size
        try:
            view = memoryview(data)
            while view:
                n = self._fh.write(view)
                view = view[n:]
            os.fsync(self._fh.fileno())
        except OSError:
            # full disk / I/O error: roll back the partial line so the chain stays clean, and
            # leave seq/head unchanged; the caller reports the failure (E2)
            try:
                self._fh.seek(0, os.SEEK_END)
                os.ftruncate(self._fh.fileno(), size)
            except OSError:
                pass
            raise
        self.seq, self.head = event["seq"], rec["hash"]
        return rec
