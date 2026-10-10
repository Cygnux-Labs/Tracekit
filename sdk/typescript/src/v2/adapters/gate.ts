/**
 * What every framework adapter does with a tool call (04-design §7.3), over one run: decide on the model's arguments,
 * have the signer consume an approval (or agree that none is needed), run the call, complete it against its decision.
 *
 * A signer that cannot be reached when a call is decided: the call runs unrecorded if register_run's `fail_modes` say
 * `open`, else it is refused. Any other failure to decide or approve (a refusal, a run the signer closed after its idle
 * timeout) refuses the call. A failure to record an outcome warns and changes nothing the framework sees.
 */
import type { Decision, Frame, RunHandle } from "../client.js";
import { argsDigest, digest } from "../jcs.js";

export const BLOCKED = "Tool call blocked by policy: ";
const MAX_OPEN_CALLS = 4096;   // per-call entries kept between a framework's hooks for one call

/** Sets m[k]; drops the oldest entry past MAX_OPEN_CALLS. */
export function keep<K, V>(m: Map<K, V>, k: K, v: V): void {
  // lean: an entry for a call that never reaches its next hook (a run abandoned mid-call) stays until pushed out
  m.delete(k);
  m.set(k, v);
  if (m.size > MAX_OPEN_CALLS) m.delete(m.keys().next().value as K);
}

/** m[k], removed. */
export function take<K, V>(m: Map<K, V>, k: K): V | undefined {
  const v = m.get(k);
  m.delete(k);
  return v;
}

export const refusal = (ruleIds: string[], reason?: string) => BLOCKED + (ruleIds.join(", ") || "deny") + (reason ? `: ${reason}` : "");
export const failure = (e: unknown) => (e instanceof Error ? `${e.name}: ${e.message}` : String(e)).slice(0, 4096);

/** The run's approvals by tool call id: requested, approved, rejected or expired. */
export async function approvalStates(run: RunHandle): Promise<Map<string, string>> {
  // lean: the first page of approval_list (the signer's default limit); follow `cursor` if runs hold more
  const { approvals } = await run.client.call("approval_list", { run_id: run.runId });
  const states = new Map<string, string>();
  for (const a of approvals) if (!states.has(a.tool_call_id)) states.set(a.tool_call_id, a.state);
  return states;
}

export class Gate {
  private attempts = new Map<string, number>();   // tool_call_id -> the attempt its next execution is
  private passed = new Map<string, boolean>();    // tool_call_id -> let through (false: unrecorded, fail open)

  constructor(readonly run: RunHandle) {}

  attempt(id: string): number {
    return this.attempts.get(id) ?? 0;
  }

  /** The signer's decision for the call's next attempt; a refusal rejects (RPCError). */
  decide(id: string, tool: string, args: unknown): Promise<Decision> {
    return this.run.decide(id, tool, args, { attempt: this.attempt(id) });
  }

  /** Null when the call may run now, else the refusal the model gets instead of its result. `d` is the decision made
   * for it earlier in this process, `hint` the approval id the framework carried; `waitMs` holds an `ask` until a
   * person decides, for at most that long. */
  async admit(id: string, tool: string, args: unknown, { d, hint, waitMs }: { d?: Decision; hint?: string; waitMs?: number } = {}): Promise<string | null> {
    const attempt = this.attempt(id);
    try {
      d ??= await this.decide(id, tool, args);
    } catch (e) {
      return BLOCKED + `signer refused the call: ${failure(e)}`;
    }
    if (d.unavailable) {
      if (d.decision !== "allow") return BLOCKED + d.reason;
      keep(this.passed, id, false);
      return null;
    }
    if (d.decision === "deny") return refusal(d.rule_ids);
    try {
      if (d.decision === "ask" && waitMs !== undefined) {
        hint = (await this.run.approvalRequest(id, { attempt })).approval_id as string;
        let state = "requested";
        for (const end = Date.now() + waitMs; state === "requested" && Date.now() < end;)
          state = (await this.run.approvalWait(hint, Math.min(end - Date.now(), 300_000))).state;
        if (state !== "approved") return refusal(d.rule_ids, `not approved: ${state}`);
      }
      // every call, allowed or approved: nothing the framework saved vouches that no approval is needed
      const c = await this.run.call("approval_consume", { tool_call_id: id, attempt, tool, args,
        args_source: typeof args === "string" ? "raw" : "parsed", ...(hint ? { approval_id_hint: hint } : {}) });
      if (!c.ok) return refusal(c.rule_ids, c.reason);
    } catch (e) {   // no fail mode once decided: a refusal or an approval that can't be had blocks
      return BLOCKED + `signer error: ${failure(e)}`;
    }
    keep(this.passed, id, true);
    return null;
  }

  /** Records the outcome of a call admit() let through. Never rejects. */
  async complete(id: string, status: "ok" | "error", fields: Frame = {}): Promise<void> {
    const recorded = take(this.passed, id);
    if (recorded === undefined) return;
    const attempt = this.attempt(id);
    keep(this.attempts, id, attempt + 1);
    if (recorded) await this.run.complete(id, status, { attempt, ...fields });
  }

  /** Runs `fn` for a call admit() let through and completes it; its result or exception reaches the caller unchanged. */
  async execute<T>(id: string | undefined, fn: () => T | Promise<T>): Promise<T> {
    if (id === undefined || !this.passed.has(id)) throw new Error(BLOCKED + "the call was not admitted");
    let out: T;
    try {
      out = await fn();
    } catch (e) {
      await this.complete(id, "error", { error: failure(e) });
      throw e;
    }
    await this.complete(id, "ok", commitment(out));
    return out;
  }
}

/** A `tool_uses` entry of a model_event: a call the model asked for, run by this process or by the provider. */
export function toolUse(id: string, name: string, input: unknown, byProvider = false): Frame {
  if (byProvider) return { id, name, executed_by: "provider" };
  const args_source = typeof input === "string" ? "raw" : "parsed";
  try {
    return { id, name, executed_by: "client", args_source, args_digest: argsDigest(name, input) };
  } catch {
    return { id, name, executed_by: "client", args_source, args_unparseable: true };
  }
}

export function warn(message: string): void {
  process.emitWarning(`tracekit: ${message}`, "TracekitWarning");
}

/** `o` without its undefined fields and empty arrays. */
export const defined = (o: Frame): Frame => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && !(Array.isArray(v) && !v.length)));

/** A model response as a model_event (T3: what the model asked for, hosted tool calls included), with the fields
 * `fields()` returns. Never rejects. */
export async function recordResponse(run: RunHandle, provider: string, model: string, fields: () => Frame): Promise<void> {
  try {
    await run.modelEvent(String(provider).slice(0, 64), String(model).slice(0, 128), "response", defined(fields()));
  } catch (e) {
    warn(`model response not recorded: ${failure(e)}`);
  }
}

/** `result` as a digest (a commitment, not the result), or nothing when it is not JSON. */
export function commitment(out: unknown): Frame {
  try {
    return { result: digest(out ?? null) };
  } catch {
    return {};
  }
}
