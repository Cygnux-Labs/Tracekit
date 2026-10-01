"""Cross-platform advisory locks for Tracekit's small state and append-only ledgers."""
import errno
import time

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover
    msvcrt = None


def lock_file(file, blocking=True):
    if fcntl is not None:
        operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        fcntl.flock(file.fileno(), operation)
        return
    if msvcrt is not None:
        operation = msvcrt.LK_NBLCK
        contention = {errno.EACCES, errno.EAGAIN}
        if hasattr(errno, "EDEADLK"):
            contention.add(errno.EDEADLK)
        if hasattr(errno, "EDEADLOCK"):
            contention.add(errno.EDEADLOCK)
        while True:
            file.seek(0)
            try:
                msvcrt.locking(file.fileno(), operation, 1)
                return
            except OSError as e:
                if not blocking or e.errno not in contention:
                    raise
                time.sleep(0.05)
    raise RuntimeError("Tracekit requires fcntl or msvcrt for inter-process file locking")


def unlock_file(file):
    if fcntl is not None:
        fcntl.flock(file.fileno(), fcntl.LOCK_UN)
    elif msvcrt is not None:
        file.seek(0)
        msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)