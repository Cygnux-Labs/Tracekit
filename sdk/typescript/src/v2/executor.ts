/**
 * The actions of a tool executor (`tracekit executor`, docs/executor.md) as framework tools. The agent holds only its
 * run: the executor holds the actions' credentials and decides, runs and records each call in the signer (tier T2).
 *
 *   import { tool } from "@openai/agents";
 *   import { jsonSchema } from "ai";
 *   import { executorActions, openaiAgentsTool, vercelTool } from "@cygnux/tracekit/v2/executor";
 *   const actions = await executorActions("https://executor.internal:8090", run, { headers: { authorization: `Bearer ${token}` } });
 *   new Agent({ tools: actions.map((a) => openaiAgentsTool(tool, a)) });
 *   generateText({ tools: Object.fromEntries(actions.map((a) => [a.name, vercelTool(a, jsonSchema)])) });
 *
 * `headers` authenticate the agent to the executor (a bearer or service-account token); for a client certificate pass
 * a `fetch` that presents one. The tools carry EXECUTOR, so the Tracekit adapters leave them to the executor, which
 * decides and records them (T2). A
 * refusal (deny, an approval not given, the signer unreachable) throws ExecutorRefused with the executor's message,
 * which the framework hands the model as the tool's error.
 */
import type { Frame, RunHandle } from "./client.js";

export class ExecutorRefused extends Error {}

/** Set on the tools built here: the Tracekit adapters don't gate them. */
export const EXECUTOR = Symbol.for("tracekit.executor");
/** The Claude Agent SDK hooks leave the tools of an MCP server of this name (mcp__tracekit-executor__<action>) alone. */
export const SERVER = "tracekit-executor";

export type Action = {
  name: string;
  description: string;
  args: Frame;   // the action's JSON Schema
  /** {status: the upstream's HTTP status, result: its JSON or text}; rejects with ExecutorRefused when it did not run. */
  call(args: unknown, toolCallId?: string): Promise<Frame>;
};

type Options = { headers?: Record<string, string>; fetch?: typeof globalThis.fetch };

/** Why `url` may not receive the run token and the agent's credential, or null: https, or plain http to loopback. */
function remoteUrlError(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return "invalid URL";
  }
  if (u.username || u.password) return "URL must not contain user@ credentials";
  if (u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname))) return null;
  return "URL must use https (plain http only for localhost, 127.0.0.1 or ::1)";
}

/** The executor's actions, each callable for `run`. */
export async function executorActions(url: string, run: RunHandle, { headers = {}, fetch = globalThis.fetch }: Options = {}): Promise<Action[]> {
  const why = remoteUrlError(url);
  if (why) throw new Error(`${url.slice(0, 256)}: ${why}`);   // the run token and the credential never go in clear
  let base = url;
  while (base.endsWith("/")) base = base.slice(0, -1);
  // the agent's credential for the executor never follows a redirect
  const get = async (path: string, init: RequestInit = {}) => {
    const r = await fetch(base + path, { ...init, redirect: "manual", headers: { ...headers, ...(init.headers as Record<string, string>) } });
    const body = await r.json().catch(() => null);
    if (!r.ok) throw new ExecutorRefused(body?.error?.message ?? `tracekit executor: HTTP ${r.status}`);
    return body;
  };
  const { actions } = await get("/v1/actions");
  return actions.map((a: Frame) => ({
    ...a,
    call: (args: unknown, toolCallId?: string) => get(`/v1/actions/${encodeURIComponent(a.name)}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-tracekit-run": `${run.runId}.${run.runToken}` },
      body: JSON.stringify({ args, ...(toolCallId ? { tool_call_id: toolCallId } : {}) }),
    }),
  }));
}

/** An @openai/agents function tool; `build` is the SDK's `tool`. */
export const openaiAgentsTool = <T>(build: (options: any) => T, a: Action): T => Object.assign(build({
  name: a.name, description: a.description, parameters: a.args, strict: false,
  execute: async (input: unknown, _ctx?: unknown, details?: any) => JSON.stringify(await a.call(input, details?.toolCall?.callId)),
}) as object, { [EXECUTOR]: true }) as T;

/** A Vercel AI SDK tool; `jsonSchema` is the `ai` package's. */
export const vercelTool = (a: Action, jsonSchema: (s: any) => unknown) => ({
  [EXECUTOR]: true, description: a.description, inputSchema: jsonSchema(a.args),
  execute: (input: unknown, opts?: { toolCallId?: string }) => a.call(input, opts?.toolCallId),
});
