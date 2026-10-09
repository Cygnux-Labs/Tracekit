"""Claude Code hook (v0.2). Maps lifecycle events to schema-v1 events and sends them to
tracekitd. It never writes the ledger. Policy is evaluated locally before a tool runs.

Fail mode (policy `fail_mode`, recorded in run.start):
  open   (default) signer down -> the tool call proceeds; a capture.gap is recorded later
  closed           signer down -> every tool call is blocked
A policy deny always blocks, whether or not the signer is reachable.

    python -I -m tracekit.hook   (wired by `tracekit init`)
"""
import getpass
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

from .core import read_text
from . import client, privacy
from . import policy as policy_mod
from .core import now_ts
from .locking import lock_file, unlock_file

AGENT_NAME = "claude-code"
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")


def _git(args, cwd):
    try:
        r = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=3)
        return r.stdout.strip() or None if r.returncode == 0 else None
    except Exception:
        return None


def _as_dict(v):
    """tool_input should be an object; if a harness sends anything else, record it rather than crash."""
    if isinstance(v, dict):
        return v
    return {} if v is None else {"value": v}


def _base(p):
    aid = p.get("agent_id")
    return {"run_id": p["session_id"], "agent_id": aid or "main",
            "parent_id": "main" if aid else None, "source": "hook", "ts": now_ts()}


def _started_flag(run_id):
    return os.path.join(client.client_dir(), "runs", client.state_name(run_id) + ".started")


def run_start_event(p, pol, cwd):
    cfg = client.client_config()
    remote = _git(["config", "--get", "remote.origin.url"], cwd) if cwd else None
    red_remote = privacy.redact_text(remote)[0] if remote else None
    sources = ["hook"] + (["proxy"] if cfg.get("proxy") else []) + (["transcript"] if pol.get("reasoning_capture") else [])
    return {**_base(p), "agent_id": "main", "parent_id": None, "type": "run.start", "data": {
        "agent": {"name": AGENT_NAME, "version": os.environ.get("CLAUDE_CODE_VERSION")},
        "model": p.get("model"), "repo": red_remote, "commit": _git(["rev-parse", "HEAD"], cwd) if cwd else None,
        "cwd": cwd, "host": socket.gethostname(), "os_user": getpass.getuser(),
        "fail_mode": pol.get("fail_mode", "open"),
        "policy": {"version": str(pol.get("version", "unversioned")), "hash": policy_mod.policy_hash(pol)},
        "capture_sources": sources, "sandbox": os.environ.get("TRACEKIT_SANDBOX", "unknown"),
        "content_capture": pol.get("content_capture", "hashed"),
        "reasoning_capture": bool(pol.get("reasoning_capture", False)),
        "signer_isolation": cfg.get("signer_isolation", "same-user")}}


def _transcript_events(p, pol):
    """Opt-in (reasoning_capture): model text read from the harness transcript. Lower trust."""
    path = p.get("transcript_path")
    if not pol.get("reasoning_capture") or not path or not os.path.exists(path):
        return []
    off_file = _started_flag(p["session_id"]) + ".txoff"
    try:
        off = int(read_text(off_file))
    except (OSError, ValueError):
        off = 0
    out = []
    with open(path, "rb") as f:
        f.seek(off)
        for line in f:
            if not line.endswith(b"\n"):
                break
            off += len(line)
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if not isinstance(e, dict) or e.get("type") != "assistant":
                continue
            msg = e.get("message")
            msg = msg if isinstance(msg, dict) else {}
            blocks = msg.get("content")
            for b in (blocks if isinstance(blocks, list) else []):
                if not isinstance(b, dict):
                    continue
                kind = {"text": "text", "thinking": "thinking"}.get(b.get("type"))
                if kind == "thinking" and not (b.get("thinking") or "").strip():
                    kind = "thinking_withheld"
                if not kind:
                    continue
                txt = b.get("text") if kind == "text" else b.get("thinking", "")
                out.append({**_base(p), "source": "transcript", "type": "model.message",
                            "data": {"kind": kind, "message_id": msg.get("id"),
                                     "content": privacy.content(txt or "", pol.get("content_capture", "hashed"))}})
    with open(off_file, "w") as f:
        f.write(str(off))
    return out


# ---------- C2: transcript prefix hashing ----------
def _path_part(name):
    """True when name is a single path component, so joining it cannot leave the directory."""
    return (isinstance(name, str) and name not in ("", ".", "..") and "/" not in name and "\\" not in name
            and not os.path.splitdrive(name)[0])


def transcript_path_for(p):
    """The transcript of the agent that fired this hook (sub-agents have their own file)."""
    path = p.get("transcript_path")
    if not path:
        return None
    aid, sid = p.get("agent_id"), p.get("session_id")
    if aid and _path_part(sid) and _path_part(f"agent-{aid}.jsonl"):
        sub = os.path.join(os.path.dirname(path), sid, "subagents", f"agent-{aid}.jsonl")
        if os.path.exists(sub):
            return sub
    return path


def _acks_path():
    return os.path.join(client.client_dir(), "runs", "transcript-acks.json")


def _load_acks():
    try:
        with open(_acks_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_ack(path, length):
    if length is None:
        return
    lk = open(_acks_path() + ".lock", "a")
    locked = False
    try:
        lock_file(lk)
        locked = True
        acks = _load_acks()
        if True:  # the signer is the authority on what it has seen (it also keeps a history for races)
            acks[path] = length
            tmp = _acks_path() + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(acks, f)
            os.replace(tmp, _acks_path())
    finally:
        try:
            if locked:
                unlock_file(lk)
        finally:
            lk.close()


def transcript_mark(path):
    """{path, length, hash, prefix_length, prefix_hash} for the transcript as it is now.
    prefix_* covers the first N bytes, where N is the length the signer last acknowledged.
    The file is streamed once, so a multi-hundred-MB transcript costs time, not memory."""
    ack = _load_acks().get(path)
    if not isinstance(ack, int) or isinstance(ack, bool) or ack < 0:
        ack = None
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return {"path": path, "length": 0, "hash": "sha256:" + hashlib.sha256(b"").hexdigest(), "missing": True,
                "prefix_length": ack, "prefix_hash": None}
    except OSError:
        return None
    full, prefix, total, prefix_hash = hashlib.sha256(), hashlib.sha256(), 0, None
    with f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            if ack is not None and prefix_hash is None:
                room = ack - total
                if room >= len(chunk):
                    prefix.update(chunk)
                else:
                    prefix.update(chunk[:room])
                    prefix_hash = "sha256:" + prefix.hexdigest()
            full.update(chunk)
            total += len(chunk)
    if ack is not None and prefix_hash is None:  # the file is shorter than what was acknowledged
        prefix_hash = "sha256:" + prefix.hexdigest()
    return {"path": path, "length": total, "hash": "sha256:" + full.hexdigest(), "prefix_length": ack,
            "prefix_hash": prefix_hash}


# ---------- C8: approvals ----------
def wait_for_approval(ev_call, decision, pol):
    """Hold a tool call until a human approves it from outside the agent's session.
    Returns (approved: bool, message)."""
    d = ev_call["data"]
    shown = ""
    for k in ("command", "file_path", "url"):
        v = (d["input"].get(k) or {}).get("value")
        if v:
            shown = f"{k}={v}"
            break
    timeout = float(pol.get("approval_timeout_s", 120))
    try:
        r = client.rpc({"op": "approval_request", "run_id": ev_call["run_id"], "agent_id": ev_call["agent_id"],
                        "tool_use_id": d["tool_use_id"], "summary": f"{d['name']} {shown}"[:400],
                        "rule_ids": decision["rule_ids"], "timeout_s": timeout})
    except client.SignerUnavailable as e:
        return False, f"approval needed but the signer is unavailable ({e}); rejected"
    if not r.get("ok"):
        return False, f"approval request failed: {r.get('error')}"
    aid = r["approval_id"]
    print(f"[tracekit] waiting for approval {aid}: {d['name']} {shown[:200]} "
          f"({'; '.join(decision['reasons'])}). From another terminal: tracekit approve {aid}  |  tracekit reject {aid}",
          file=sys.stderr, flush=True)
    end = time.time() + timeout + 5
    while time.time() < end:
        try:
            w = client.rpc({"op": "approval_wait", "approval_id": aid, "wait_s": 20}, timeout=30)
        except client.SignerUnavailable as e:
            return False, f"signer unavailable while waiting for approval ({e}); rejected"
        dec = w.get("decision")
        if dec == "approve":
            return True, f"approved by {w.get('approver')} ({w.get('channel')})"
        if dec in ("reject", "timeout"):
            return False, f"{'rejected by ' + str(w.get('approver')) if dec == 'reject' else 'no approval within ' + str(int(timeout)) + 's'}"
    return False, "approval timed out"


def build_events(p, pol):
    """Return (events, attach_for_first, deny_decision_or_None)."""
    name = p.get("hook_event_name")
    cwd = p.get("cwd")
    cc = pol.get("content_capture", "hashed")
    b = _base(p)
    evs, deny = [], None
    flag = _started_flag(b["run_id"])
    phash = policy_mod.policy_hash(pol)
    if name == "SessionStart" or not os.path.exists(flag):
        evs.append(run_start_event(p, pol, cwd))
        try:
            os.makedirs(os.path.dirname(flag), exist_ok=True)
            with open(flag, "w") as f:
                f.write(phash)  # the policy this run started with
        except OSError:
            pass  # read-only client dir: every hook then re-sends run.start; the signer flags it as a gap
    try:
        start_hash = read_text(flag).strip()
    except OSError:
        start_hash = ""
    evs += _transcript_events(p, pol)
    if name == "UserPromptSubmit":
        evs.append({**b, "type": "user.prompt", "data": {"content": privacy.content(p.get("prompt") or "", cc)}})
    elif name == "PreToolUse":
        tool, ti, tid = p.get("tool_name") or "?", _as_dict(p.get("tool_input")), p["tool_use_id"]
        d = policy_mod.evaluate(pol, tool, ti, cwd)
        evs.append({**b, "type": "tool.call", "data": {"tool_use_id": tid, "name": tool, "input": privacy.tool_input(tool, ti, cc)}})
        dec = {**b, "type": "policy.decision", "data": {"tool_use_id": tid, "decision": d["decision"],
                                                        "rule_ids": d["rule_ids"], "reasons": d["reasons"] + d["flags"],
                                                        "policy_hash": phash, "policy_version": str(pol.get("version", "unversioned"))}}
        if phash != start_hash:
            dec["_attach_policy"] = True  # the policy changed during the run: send the new snapshot with this decision
        evs.append(dec)
        if d["decision"] in ("deny", "ask"):
            deny = d
    elif name in ("PostToolUse", "PostToolUseFailure"):
        failed = name == "PostToolUseFailure"
        resp = p.get("tool_response") if not failed else {"error": p.get("error"), "response": p.get("tool_response")}
        ok = not failed and not (isinstance(resp, dict) and (resp.get("is_error") or resp.get("interrupted")))
        dur = p.get("duration_ms")
        ti = _as_dict(p.get("tool_input"))
        dotenv = privacy.mentions_dotenv(ti.get("command"), ti.get("file_path"), ti.get("path"), ti.get("pattern"))
        evs.append({**b, "type": "tool.result", "data": {"tool_use_id": p["tool_use_id"], "ok": bool(ok),
                                                         "output": privacy.content(resp if resp is not None else "", cc, dotenv),
                                                         "duration_ms": int(dur) if isinstance(dur, (int, float)) else None}})
    elif name == "SessionEnd":
        evs.append({**b, "agent_id": "main", "parent_id": None, "type": "run.end", "data": {"reason": str(p.get("reason") or "session end")}})
        try:
            os.remove(flag)
        except OSError:
            pass
    if pol.get("transcript_hashing", True) and evs:
        tp = transcript_path_for(p)
        mark = transcript_mark(tp) if tp else None
        if mark:
            evs[-1]["transcript"] = mark   # checked by the signer against the previous mark (C2)
    return evs, deny


def main(harness_reasoning=True):
    """harness_reasoning=False: the harness is not Claude Code, so its transcript format is unknown: hash it, never parse it."""
    raw = sys.stdin.read()
    try:
        p = json.loads(raw) if raw.strip() else {}
    except ValueError:
        p = {}
    try:
        pol, pol_raw = policy_mod.load()
    except policy_mod.PolicyError as e:
        # an unusable policy never silently means "no rules": block tool calls, say why
        if p.get("hook_event_name") == "PreToolUse":
            print(f"[tracekit] {e}; blocking tool calls until the policy is fixed", file=sys.stderr)
            return 2
        return 0
    name = p.get("hook_event_name") if isinstance(p, dict) else None
    missing = [k for k in ("session_id",) + (("tool_use_id",) if name in TOOL_EVENTS else ())
               if not isinstance(p.get(k), str) or not p[k]] if isinstance(p, dict) else ["payload"]
    if missing:
        print(f"[tracekit] hook payload has no {', '.join(missing)}; event not recorded", file=sys.stderr)
        if name != "PreToolUse":
            return 0
        d = policy_mod.evaluate(pol, p.get("tool_name") or "?", _as_dict(p.get("tool_input")), p.get("cwd"))
        return 2 if pol.get("fail_mode") == "closed" or d["decision"] in ("deny", "ask") else 0
    evs, deny = build_events(p, pol if harness_reasoning else dict(pol, reasoning_capture=False))
    signer_down = rejected = None
    for ev in evs:
        try:
            attach_pol = ev.pop("_attach_policy", False) or ev["type"] == "run.start"
            resp = client.send(ev, {"policy": pol_raw} if attach_pol else None)
            if not resp.get("ok"):
                print(f"[tracekit] signer rejected event: {resp.get('error')}", file=sys.stderr)
                if ev["type"] == "tool.call":
                    rejected = str(resp.get("error"))
                    client.send({**_base(p), "type": "capture.gap", "data": {
                        "reason": f"signer rejected tool call {ev['data']['tool_use_id']}: {rejected}"[:900],
                        "kind": "client_rejected"}})
            elif ev.get("transcript") and "transcript_ack" in resp:
                save_ack(ev["transcript"]["path"], resp["transcript_ack"])
        except client.SignerUnavailable as e:
            signer_down = str(e)
    if deny and deny["decision"] == "ask":
        call = next(e for e in evs if e["type"] == "tool.call")
        ok, msg = wait_for_approval(call, deny, pol)
        if not ok:
            print(f"Held by tracekit policy ({'; '.join(deny['rule_ids'])}) and not approved: {msg}", file=sys.stderr)
            return 2
        print(f"[tracekit] {msg}", file=sys.stderr)
        return 0
    if deny:
        print("Blocked by tracekit policy: " + "; ".join(f"{i} {r}" for i, r in zip(deny["rule_ids"], deny["reasons"])),
              file=sys.stderr)
        return 2
    if signer_down and p.get("hook_event_name") == "PreToolUse" and pol.get("fail_mode") == "closed":
        print(f"[tracekit] signer unavailable ({signer_down}); fail_mode=closed blocks tool calls", file=sys.stderr)
        return 2
    if rejected and pol.get("fail_mode") == "closed":
        print(f"[tracekit] signer rejected the tool call ({rejected}); fail_mode=closed blocks it", file=sys.stderr)
        return 2
    return 0


def fail_closed():
    """True when the configured fail mode (env, system config or policy) says a Tracekit failure must block."""
    if os.environ.get("TRACEKIT_FAIL_CLOSED") == "1" or client.system_fail_closed():
        return True
    try:
        return policy_mod.load()[0].get("fail_mode") == "closed"
    except Exception:
        return False


def _entry():
    try:
        return main()
    except Exception as e:  # a crash in Tracekit must follow the configured fail mode
        closed = fail_closed()
        print(f"[tracekit] hook error ({e}); " + ("blocking (fail-closed)" if closed else "allowing (fail-open)"), file=sys.stderr)
        return 2 if closed else 0


if __name__ == "__main__":
    sys.exit(_entry())
