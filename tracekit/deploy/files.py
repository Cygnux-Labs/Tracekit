"""File writes for the installer that never follow symlinks and never race.

Directories are opened once with O_NOFOLLOW and every file is created relative to that fd: a temp file with an
unpredictable name, O_CREAT | O_EXCL | O_NOFOLLOW and its final mode from creation, then fsync and rename within the
same directory. Ownership and mode are set on the open fd. Writes into another user's directory made as root run in
a forked child that has dropped to that user (as_user), so the kernel enforces that user's permissions.
Where the OS has no *at() calls (Windows) the same steps run on paths.
"""
import errno
import json
import os
import secrets
import stat
import time

_AT = os.open in os.supports_dir_fd and os.rename in os.supports_dir_fd
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class UnsafePath(OSError):
    """A directory or file Tracekit refuses to write through (a symlink, not a directory, or an unexpected owner)."""


def _at(d, name):
    return (name, {"dir_fd": d}) if isinstance(d, int) else (os.path.join(d, name), {})


def _check_dir(fd_or_path, label, owners):
    st = os.fstat(fd_or_path) if isinstance(fd_or_path, int) else os.lstat(fd_or_path)
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafePath(f"{label} is not a directory; Tracekit did not write to it")
    if owners is not None and hasattr(st, "st_uid") and os.name != "nt" and st.st_uid not in owners:
        raise UnsafePath(f"{label} is owned by uid {st.st_uid}, expected {sorted(owners)}; Tracekit did not write to it")


def _open_dir(path, label, owners, **at):
    if not _AT:
        if os.path.islink(path):
            raise UnsafePath(f"{label} is a symlink; Tracekit did not write through it")
        _check_dir(path, label, owners)
        return path
    try:
        fd = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, **at)
    except OSError as e:
        try:
            link = stat.S_ISLNK(os.stat(path, follow_symlinks=False, **at).st_mode)
        except OSError:
            link = False
        if link:
            raise UnsafePath(f"{label} is a symlink; Tracekit did not write through it") from e
        raise
    try:
        _check_dir(fd, label, owners)
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_dir(path, owners=None):
    """Open an existing directory without following a symlink at its last component. owners: allowed uids."""
    return _open_dir(path, path, owners)


def subdir(d, name, mode=0o700, owners=None):
    """Open (creating it with mode if missing) directory `name` inside d, refusing a symlink."""
    path, at = _at(d, name)
    try:
        os.mkdir(path, mode, **at)
    except FileExistsError:
        pass
    return _open_dir(path, name, owners, **at)


def close(d):
    if isinstance(d, int):
        os.close(d)


def read(d, name):
    """Contents of file `name` in d, or None if it does not exist. Refuses a symlink or anything but a regular file."""
    path, at = _at(d, name)
    if not _NOFOLLOW and os.path.islink(path):
        raise UnsafePath(f"{name} is a symlink; Tracekit did not touch it")
    try:
        fd = os.open(path, os.O_RDONLY | _NONBLOCK | _NOFOLLOW | _CLOEXEC | _BINARY, **at)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise UnsafePath(f"{name} is a symlink; Tracekit did not touch it") from e
        raise
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise UnsafePath(f"{name} is not a regular file; Tracekit did not touch it")
        return f.read()


def _create(d, name, data, mode, uid, gid):
    path, at = _at(d, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC | _BINARY, mode, **at)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)  # the umask can only narrow the creation mode; this makes it exact
        if uid is not None and hasattr(os, "fchown"):
            os.fchown(fd, uid, -1 if gid is None else gid)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(path, **at)
        except OSError:
            pass
        raise
    os.close(fd)


def write(d, name, data, mode=0o600, uid=None, gid=None):
    """Atomically replace file `name` in d with data. Refuses if `name` is a symlink or not a regular file."""
    path, at = _at(d, name)
    try:
        if not stat.S_ISREG(os.stat(path, follow_symlinks=False, **at).st_mode):
            raise UnsafePath(f"{name} is not a regular file (a symlink?); Tracekit did not replace it")
    except FileNotFoundError:
        pass
    tmp = f".{name}.{secrets.token_hex(8)}.tmp"
    _create(d, tmp, data, mode, uid, gid)
    tmp_path, _ = _at(d, tmp)
    try:
        if isinstance(d, int):
            os.replace(tmp, name, src_dir_fd=d, dst_dir_fd=d)
            os.fsync(d)
        else:
            _replace_retrying(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path, **at)
        except OSError:
            pass
        raise


def _replace_retrying(src, dst, tries=20):
    """os.replace, retried briefly: on Windows it fails with access denied while another process has dst open."""
    for i in range(tries):
        try:
            return os.replace(src, dst)
        except PermissionError:
            if os.name != "nt" or i == tries - 1:
                raise
            time.sleep(0.05)


def backup(d, name, data):
    """Save data as a new `name.bak-<time>-<random>` file in d, created exclusively. Returns the backup name."""
    bak = f"{name}.bak-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}"
    _create(d, bak, data, 0o600, None, None)
    return bak


def json_bytes(obj):
    return (json.dumps(obj, indent=2) + "\n").encode("utf-8")


def write_json(path, obj, mode=0o600, uid=None, gid=None, owners=None):
    """write() for a full path: the parent directory must already exist and is opened without following a symlink."""
    d = open_dir(os.path.dirname(os.path.abspath(path)), owners)
    try:
        write(d, os.path.basename(path), json_bytes(obj), mode, uid, gid)
    finally:
        close(d)


def as_user(pw, fn, *args, errors=()):
    """Run fn(*args) as user pw: in a forked child that dropped to pw's uid, gid and groups when we are root, inline
    otherwise. The child reports back as JSON (never pickle: a process running as pw could forge the reply).
    Returns fn's JSON-able result; an exception whose class is UnsafePath or in `errors` is re-raised by name."""
    if pw is None or not hasattr(os, "fork") or os.geteuid() != 0 or pw.pw_uid == 0:
        return fn(*args)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            try:
                os.initgroups(pw.pw_name, pw.pw_gid)
                os.setgid(pw.pw_gid)
                os.setuid(pw.pw_uid)
                out = {"ok": True, "result": fn(*args)}
            except BaseException as e:  # noqa: BLE001  reported to the parent
                out = {"ok": False, "error": type(e).__name__, "message": str(e)}
            with os.fdopen(w, "wb") as f:
                f.write(json.dumps(out).encode("utf-8"))
        finally:
            os._exit(0)
    os.close(w)
    with os.fdopen(r, "rb") as f:
        raw = f.read()
    os.waitpid(pid, 0)
    try:
        out = json.loads(raw)
    except ValueError:
        raise RuntimeError(f"writing as {pw.pw_name} failed: the child process gave no result") from None
    if not isinstance(out, dict) or not out.get("ok"):
        out = out if isinstance(out, dict) else {}
        cls = {c.__name__: c for c in (UnsafePath, *errors)}.get(out.get("error"), RuntimeError)
        raise cls(str(out.get("message") or f"writing as {pw.pw_name} failed"))
    return out.get("result")
