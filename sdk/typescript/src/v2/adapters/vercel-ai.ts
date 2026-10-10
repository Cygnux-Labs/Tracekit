/**
 * Vercel AI SDK v7: every tool call is decided by the signer before it runs and recorded after.
 *
 *   import { generateText, wrapLanguageModel } from "ai";
 *   import { Client } from "@cygnux/tracekit/v2";
 *   import { tracekitAI } from "@cygnux/tracekit/v2/vercel-ai";
 *   const tk = tracekitAI(await new Client().registerRun("assistant"));
 *   const model = wrapLanguageModel({ model: openai("gpt-5"), middleware: tk.middleware });
 *   const r = await generateText({ model, tools: tk.tools({ pay }), toolApproval: tk.toolApproval, messages });
 *   // once a person decided the asks in the signer:
 *   messages.push(...r.response.messages, { role: "tool", content: await tk.approvalResponses(r.content) });
 *
 * The same options work for `streamText` and `ToolLoopAgent`. `tk.middleware` (for `wrapLanguageModel`) records each
 * model response as a signed model_event (V3 usage, the tool calls asked for) and keeps each call's raw arguments
 * string by `toolCallId`, so the signer decides on what the model sent. `tk.toolApproval` decides each call: `deny`
 * becomes a `denied` status (the model gets the refusal and the loop goes on), `ask` opens an approval in the signer
 * and becomes `user-approval`. `tk.approvalResponses(parts)` turns the `tool-approval-request` parts the signer's
 * approvers decided into `tool-approval-response` parts to resume with. `tk.tools(tools)` wraps each tool's `execute`:
 * every call, allowed or approved, runs only after the signer's `approval_consume` agrees, so an approval response the
 * client forged or replayed runs nothing; `experimental_toolApprovalSecret` (the SDK's HMAC over its approval
 * requests) can be set as well and does not replace this. Without `tk.toolApproval` an `ask` is refused.
 *
 * Tools without `execute` and provider-executed tools are not gated; they are recorded in the model responses.
 */
import type { Decision, Frame, RunHandle } from "../client.js";
import { digest } from "../jcs.js";
import { BLOCKED, Gate, approvalStates, defined, failure, keep, recordResponse, refusal, take, toolUse } from "./gate.js";

/** LanguageModelV3/V4 usage as the signer's usage buckets (input_tokens without cache reads). */
function usage(u: any): Frame | undefined {
  return u?.inputTokens && defined({ input_tokens: u.inputTokens.noCache ?? u.inputTokens.total, output_tokens: u.outputTokens?.total,
    cache_read_tokens: u.inputTokens.cacheRead, cache_write_tokens: u.inputTokens.cacheWrite, reasoning_tokens: u.outputTokens?.reasoning });
}

const stop = (fr: any) => (typeof fr === "string" ? fr : fr?.unified);

export function tracekitAI(run: RunHandle) {
  const gate = new Gate(run);
  const raw = new Map<string, string>();             // toolCallId -> the model's arguments string
  const decided = new Map<string, Decision>();       // toolCallId -> its decision, from toolApproval to execute
  const seen = (p: any) => {
    if (p?.type === "tool-call" && !p.providerExecuted && typeof p.input === "string") keep(raw, p.toolCallId, p.input);
  };
  const toolUses = (parts: any[]) => parts.filter((p) => p?.type === "tool-call")
    .map((p) => toolUse(p.toolCallId, p.toolName, p.input, !!p.providerExecuted)).slice(0, 128);

  return {
    middleware: {
      specificationVersion: "v4" as const,
      async wrapGenerate({ doGenerate, model }: any) {
        const r = await doGenerate();
        (r.content ?? []).forEach(seen);
        await recordResponse(run, model.provider, model.modelId, () => ({ content_digest: digest(r.content ?? []),
          stop_reason: stop(r.finishReason), usage: usage(r.usage), tool_uses: toolUses(r.content ?? []) }));
        return r;
      },
      async wrapStream({ doStream, model }: any) {
        const r = await doStream(), calls: any[] = [];
        let finish: any;
        return { ...r, stream: r.stream.pipeThrough(new TransformStream({
          transform(p: any, c) {
            seen(p);
            if (p?.type === "tool-call") calls.push(p);
            if (p?.type === "finish") finish = p;
            c.enqueue(p);
          },
          // lean: a stream the caller abandons is not recorded
          flush: () => recordResponse(run, model.provider, model.modelId, () => ({ streamed: true,
            stop_reason: stop(finish?.finishReason), usage: usage(finish?.usage), tool_uses: toolUses(calls) })),
        })) };
      },
    },

    /** For `toolApproval:` on generateText, streamText and ToolLoopAgent. */
    async toolApproval({ toolCall }: any) {
      const id = toolCall.toolCallId;
      let d;
      try {
        d = await gate.decide(id, toolCall.toolName, raw.get(id) ?? toolCall.input);
      } catch (e) {
        return { type: "denied" as const, reason: BLOCKED + `signer refused the call: ${failure(e)}` };
      }
      if (d.decision === "deny") return { type: "denied" as const, reason: d.unavailable ? BLOCKED + d.reason : refusal(d.rule_ids) };
      keep(decided, id, d);
      if (d.decision !== "ask") return "not-applicable" as const;   // execute consumes
      try {
        await run.approvalRequest(id, { attempt: gate.attempt(id) });
      } catch {
        return "not-applicable" as const;   // no approval to wait for: execute's approval_consume refuses the call
      }
      return { type: "user-approval" as const, reason: d.rule_ids.join(", ") };
    },

    /** `tools` with each `execute` gated by the signer. */
    tools<T extends Record<string, any>>(tools: T): T {
      return Object.fromEntries(Object.entries(tools).map(([name, t]) => [name, !t?.execute ? t : {
        ...t,
        async execute(input: unknown, opts: any) {
          const id = opts?.toolCallId;
          const why = await gate.admit(id, name, take(raw, id) ?? input, { d: take(decided, id) });
          if (why !== null) throw new Error(why);
          return gate.execute(id, () => t.execute(input, opts));
        },
      }])) as T;
    },

    /** `tool-approval-response` parts for the `tool-approval-request` parts the signer's approvers decided. */
    async approvalResponses(parts: any[]): Promise<Frame[]> {
      const states = await approvalStates(run);
      return parts.filter((p) => p?.type === "tool-approval-request").flatMap((p) => {
        const s = states.get(p.toolCall?.toolCallId ?? p.toolCallId);
        if (s === "approved") return [{ type: "tool-approval-response", approvalId: p.approvalId, approved: true }];
        if (s === "rejected" || s === "expired") return [{ type: "tool-approval-response", approvalId: p.approvalId, approved: false, reason: `Tool call ${s} in Tracekit` }];
        return [];
      });
    },
  };
}
