"""A C2SP tlog-witness v1.1.0 client: `add-checkpoint`, returning the witness's verified cosignature lines.

    POST <url>/add-checkpoint
    old <size>\\n<base64 consistency proof hash>\\n...\\n\\n<checkpoint note>

The witness gets the note text and the log's Ed25519 signature only (any other line, such as a hybrid signature, is
stripped), in a body of at most 10 KiB (litewitness's limit). A 409 carries the size the witness last cosigned: the
client resends once from that size with a matching proof. Every other failure raises WitnessError, `retryable` for
network errors, timeouts, a second 409 (a race), 429 and 5xx; not for 400/403/404/422 (malformed, unknown key or origin, inconsistent tree)
or a bad cosignature."""
import base64
import binascii
import urllib.error
import urllib.request

from tracekit.format import checkpoint

MAX_BODY = 10 * 1024
TIMEOUT_S = 10.0


class WitnessError(Exception):
    def __init__(self, msg, retryable):
        super().__init__(msg)
        self.retryable = retryable


def signed_by(lines, vkey):
    """The signature lines (each ending in a newline) of `vkey`'s key among `lines` (a note's signature block)."""
    name, kid, _, _ = checkpoint.parse_vkey(vkey)
    out = ""
    for line in lines.splitlines():
        parts = line.split(" ")
        try:
            if len(parts) == 3 and parts[:2] == ["—", name] and base64.b64decode(parts[2], validate=True)[:4] == kid:
                out += line + "\n"
        except binascii.Error:
            continue
    return out


def log_signed(note, log_vkey):
    """The note text and its signature by `log_vkey` alone."""
    text, sigs = note.split("\n\n", 1)
    line = signed_by(sigs, log_vkey).partition("\n")[0]
    if not line:
        raise ValueError(f"the note has no signature by {log_vkey.split('+')[0]}")
    return f"{text}\n\n{line}\n"


class TlogWitness:
    def __init__(self, url, vkey, timeout=TIMEOUT_S):
        """`vkey` is the witness's cosignature (type 0x04) verifier key; its name names the witness."""
        name, _, type_, _ = checkpoint.parse_vkey(vkey)
        if type_ != checkpoint.COSIGNATURE:
            raise ValueError(f"witness {name}: not a cosignature vkey")
        self.url, self.vkey, self.name, self.timeout = url.rstrip("/"), vkey, name, timeout

    def _post(self, old, hashes, signed):
        body = (f"old {old}\n" + "".join(base64.b64encode(h).decode() + "\n" for h in hashes) + "\n"
                + signed).encode("utf-8")
        if len(body) > MAX_BODY:
            raise WitnessError(f"{self.name}: request body of {len(body)} bytes is over {MAX_BODY}", False)
        req = urllib.request.Request(self.url + "/add-checkpoint", data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, r.read(MAX_BODY).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(256).decode("utf-8", "replace")
        except (OSError, ValueError) as e:   # refused, reset, timeout
            raise WitnessError(f"{self.name}: {e}", True) from None

    def _fail(self, status, resp):
        return WitnessError(f"{self.name}: HTTP {status}: {resp.strip()[:200]}", status in (409, 429) or status >= 500)

    def _size(self, resp, at_most):
        size = resp.strip()
        if not size.isdigit() or int(size) > at_most:
            raise WitnessError(f"{self.name}: witness is at size {size[:32]!r}, past {at_most}", False)
        return int(size)

    def add_checkpoint(self, note, log_vkey, old, proof):
        """Submit `note` (signed by `log_vkey`) as the successor of the witness's checkpoint of size `old`;
        `proof(n)` gives the consistency proof (raw hashes) from size n to the note's size. Returns (the witness's
        cosignature lines, verified, as one string; the old size the witness turned out to hold)."""
        signed = log_signed(note, log_vkey)
        size = int(signed.split("\n")[1])
        status, resp = self._post(old, proof(old) if 0 < old < size else [], signed)
        if status == 409:
            old = self._size(resp, size)
            status, resp = self._post(old, proof(old) if 0 < old < size else [], signed)
        if status != 200:
            raise self._fail(status, resp)
        lines = signed_by(resp, self.vkey)
        try:
            if not checkpoint.open_note(signed + lines, [log_vkey], [self.vkey])[3]:
                raise checkpoint.NoteError("no cosignature from its key")
        except checkpoint.NoteError as e:
            raise WitnessError(f"{self.name}: {e}", False) from None
        return lines, old

    def latest(self, empty_note, log_vkey):
        """(the size this witness last cosigned for the log, None: the protocol gives no root). `empty_note` is the
        log's signed checkpoint of size 0, sent from old 0: a witness further along answers 409 with its size."""
        status, resp = self._post(0, [], log_signed(empty_note, log_vkey))
        if status == 409:
            return self._size(resp, float("inf")), None
        if status != 200:
            raise self._fail(status, resp)
        return 0, None
