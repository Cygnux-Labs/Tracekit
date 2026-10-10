/**
 * Claude Agent SDK (TS): every tool call is decided by the signer before it runs and recorded after, as
 * tracekit/integrations/claude_agent_sdk.py does in Python.
 *
 *   import { query } from "@anthropic-ai/claude-agent-sdk";
 *   import { Client } from "@cygnux/tracekit/v2";
 *   import { tracekitHooks, tracekitSessionStore } from "@cygnux/tracekit/v2/claude-agent-sdk";
 *   const run = await new Client().registerRun("my-agent");
 *   query({ prompt, options: { hooks: tracekitHooks(run), sessionStore: tracekitSessionStore(myStore, run) } });
 *
 * The gate is the PreToolUse hook, not `canUseTool`: the CLI skips `canUseTool` for every call its permission mode or
 * allow rules approve, while PreToolUse runs for every call. `deny` blocks the call with the reason, which the model
 * gets as the tool's error result, and the session goes on. `ask` holds the call in the hook until a person decides in
 * the signer, for at most APPROVAL_WAIT_MS, below the hook's own timeout (HOOK_TIMEOUT_S, set on the matcher); a call
 * not approved by then is blocked. PostToolUse and PostToolUseFailure complete the call; SessionEnd closes the run.
 * The tools run in the CLI subprocess, so the signer's coding packs apply to them.
 */
import { randomUUID } from "node:crypto";
import { RPCError, SignerUnavailable, type Frame, type RunHandle } from "../client.js";
import { digest } from "../jcs.js";
import { BLOCKED, Gate, commitment, failure, warn } from "./gate.js";

export const HOOK_TIMEOUT_S = 600;       // the SDK's default (60 s) is too short to wait for a person
export const APPROVAL_WAIT_MS = 540_000; // below HOOK_TIMEOUT_S, so the hook answers before the CLI gives up on it

const deny = (why: string) => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: why } });

/** The `hooks` option of `query()`. To add hooks of your own, extend the lists. */
export function tracekitHooks(run: RunHandle) {
  const gate = new Gate(run);

  async function pre(inp: any, toolUseID?: string) {
    const id = inp.tool_use_id ?? toolUseID;
    if (!id) return deny(BLOCKED + "the hook got no tool_use_id");   // never defaulted: a result could not be bound to its decision
    const why = await gate.admit(id, inp.tool_name ?? "?", inp.tool_input, { waitMs: APPROVAL_WAIT_MS });
    return why === null ? {} : deny(why);
  }

  async function post(inp: any, toolUseID?: string) {
    const id = inp.tool_use_id ?? toolUseID, resp = inp.tool_response;
    if (inp.hook_event_name === "PostToolUseFailure") await gate.complete(id, "error", { error: String(inp.error ?? "").slice(0, 4096) });
    else await gate.complete(id, resp?.is_error || resp?.interrupted ? "error" : "ok", commitment(resp));
    return {};
  }

  async function end(inp: any) {
    try {
      await run.close(String(inp.reason ?? "session end").slice(0, 256));
    } catch (e) {
      // the session is over either way: the signer closes the run on its idle timeout
      if (!(e instanceof RPCError && e.code === "run_closed")) warn(`tracekit: could not close the run: ${(e as Error).message}`);
    }
    return {};
  }

  return { PreToolUse: [{ hooks: [pre], timeout: HOOK_TIMEOUT_S }], PostToolUse: [{ hooks: [post] }],
    PostToolUseFailure: [{ hooks: [post] }], SessionEnd: [{ hooks: [end] }] };
}

type Key = { sessionId: string; subpath?: string };
type Store = { append(key: Key, entries: unknown[]): Promise<void>; load(key: Key): Promise<unknown[] | null> };

/** A SessionStore that commits each saved transcript to the signer (L1): after every append a `state_write` of the
 * transcript's digest, from the digest it had when this process last saw it. A transcript changed in the store
 * between two writes (seen on `load`, when a session resumes) makes the signer record a `state_tamper` gap. */
export function tracekitSessionStore<S extends Store>(store: S, run: RunHandle): S {
  // lean: a new stream per process, so each process that resumes the run opens one (the signer allows 64 per run)
  const stream = "claude-agent-sdk-" + randomUUID().replaceAll("-", "");
  let seq = 0, queue = Promise.resolve();
  // lean: one digest per transcript for the store's life; prune at session end if one process serves many
  const digests = new Map<string, string | null>();   // what the store holds now; null once an entry is not canonical JSON
  const acked = new Map<string, string | null>();     // what the signer last recorded: the next state_write's prev_digest
  const lost = new Map<string, [Frame, string]>();    // the state_write whose answer was lost, sent again before the next
  const keyOf = (k: Key) => "claude-agent-sdk:" + k.sessionId + (k.subpath ? "/" + k.subpath : "");

  /** The digest of a transcript after `entries`, from its digest before them; canonical JSON per entry, as a store
   * may give entries back with their keys reordered. */
  const chain = (k: string, entries: unknown[], d: string | null = digest([])) => {
    try {
      for (const e of entries) d = digest([d, e]);
      return d;
    } catch (e) {   // e.g. a number JSON can't hold: no digest to commit
      warn(`transcript ${k} is not canonical JSON (${failure(e)}); not committed`);
      return null;
    }
  };

  const load = async (key: Key) => {
    const entries = await store.load(key), k = keyOf(key), d = chain(k, entries ?? []);
    digests.set(k, d);
    acked.set(k, d);
    return entries;
  };

  /** False when the signer could not be reached: it may have recorded the write, so the same request (request_id and
   * client_seq) goes again before the next one, and a write it recorded never reads as tampering. */
  const write = async (k: string, req: Frame, d: string) => {
    try {
      await run.call("state_write", req);
    } catch (e) {
      warn(`transcript commitment for ${k} not recorded: ${failure(e)}`);
      if (!(e instanceof SignerUnavailable)) return true;
      lost.set(k, [req, d]);
      return false;
    }
    acked.set(k, d);
    return true;
  };

  const append = async (key: Key, entries: unknown[]) => {
    const k = keyOf(key);
    if (!digests.has(k)) await load(key);   // the first write this process makes to it: from what the store holds
    await store.append(key, entries);       // never throw after this: the SDK would append the entries again
    const d = digests.get(k) === null ? null : chain(k, entries, digests.get(k));
    digests.set(k, d);
    if (d === null) return;
    // one write at a time, so client_seq reaches the signer in order
    await (queue = queue.then(async () => {
      const l = lost.get(k);
      lost.delete(k);
      if (l && !(await write(k, ...l))) return;   // the signer is still away: the next write commits these entries too
      await write(k, { request_id: randomUUID().replaceAll("-", ""), stream, client_seq: seq++, key: k, value_digest: d,
        prev_digest: acked.get(k) ?? null }, d);
    }));
  };

  return new Proxy(store, {
    get(t, p) {   // listSessions, delete, ...: the wrapped store's
      if (p === "append") return append;
      if (p === "load") return load;
      const v = Reflect.get(t, p, t);
      return typeof v === "function" ? v.bind(t) : v;
    },
  });
}
