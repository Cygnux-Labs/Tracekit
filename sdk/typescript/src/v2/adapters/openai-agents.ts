/**
 * OpenAI Agents SDK (JS): every function tool call is decided by the signer before it runs and recorded after, as
 * tracekit/integrations/openai_agents.py does in Python.
 *
 *   import { Agent, Runner, tool } from "@openai/agents";
 *   import { Client } from "@cygnux/tracekit/v2";
 *   import { TracekitAgents } from "@cygnux/tracekit/v2/openai-agents";
 *   const tk = new TracekitAgents(await new Client().registerRun("payer"));
 *   const agent = new Agent({ name: "payer", model: "gpt-5", tools: [tk.tool(tool, { name: "pay", description, parameters, execute })] });
 *   const result = await new Runner().run(agent, "pay acct-42 $15", { context: {} });
 *   await tk.recordResponses(result.rawResponses, "gpt-5");
 *
 * `tk.tool(tool, options)` builds the tool with the SDK's own `tool()`; the signer's policy replaces `needsApproval`,
 * and a tool input guardrail (after the app's own) gates the call on the model's raw arguments. `deny` gives the model a
 * refusal as the tool output and the run goes on. `ask` interrupts the run; once a person has decided in the signer,
 * `await tk.applyDecisions(result.state)` approves or rejects the paused calls and the app resumes with
 * `runner.run(agent, result.state)`. The RunState JSON is not authenticated, so it carries the approval id only as a
 * hint in `context.tracekit.approvals`: every call runs only after the signer's `approval_consume` agrees. Leave the
 * runner's `toolExecution.preApprovalInputGuardrails` off: the guardrail consumes the approval.
 *
 * Not gated: hosted tools (web and file search, code interpreter, hosted MCP, hosted shell), shell, apply_patch and
 * computer tools and handoffs run outside function tools; they are recorded (T3) only in the signed model responses
 * that `recordResponses` writes.
 */
import type { Decision, RunHandle } from "../client.js";
import { digest } from "../jcs.js";
import { Gate, approvalStates, keep, recordResponse, take, toolUse } from "./gate.js";

type Options = { name?: string; execute: (input: any, context?: any, details?: any) => unknown; inputGuardrails?: unknown[]; [k: string]: unknown };

export class TracekitAgents {
  readonly gate: Gate;
  private decided = new Map<string, Decision>();   // call id -> its decision, from needsApproval to the guardrail

  constructor(readonly run: RunHandle) {
    this.gate = new Gate(run);
  }

  /** `build({...options})` (the SDK's `tool`), gated by the signer. */
  tool<T extends { name: string }>(build: (options: any) => T, options: Options): T {
    const name = options.name ?? options.execute.name;
    return build({
      ...options,
      name,
      needsApproval: (ctx: any, input: unknown, callId?: string) => this.ask(ctx, callId, name, input),
      inputGuardrails: [...(options.inputGuardrails ?? []), { name: "tracekit", run: (data: any) => this.guard(data, name) }],
      execute: (input: unknown, ctx?: unknown, details?: any) =>
        this.gate.execute(details?.toolCall?.callId, () => options.execute(input, ctx, details)),
    });
  }

  /** needsApproval: decide; on ask, open an approval and keep its id in the run context as a hint. */
  private async ask(ctx: any, callId: string | undefined, tool: string, input: unknown): Promise<boolean> {
    if (!callId) return false;   // the guardrail decides, and refuses
    let d;
    try {
      d = await this.gate.decide(callId, tool, input);
    } catch {
      return false;   // the guardrail decides again, and refuses
    }
    keep(this.decided, callId, d);
    if (d.decision !== "ask") return false;   // a deny is refused by the guardrail, before the call runs
    let approval_id;
    try {
      ({ approval_id } = await this.run.approvalRequest(callId, { attempt: this.gate.attempt(callId) }));
    } catch {
      return false;   // no approval to wait for: the guardrail's approval_consume refuses the call
    }
    const c = ctx?.context;
    if (c && typeof c === "object") ((c.tracekit ??= {}).approvals ??= {})[callId] = approval_id;
    return true;
  }

  private async guard({ context, toolCall }: any, tool: string) {
    const id = toolCall.callId, hint = context?.context?.tracekit?.approvals?.[id];
    const why = await this.gate.admit(id, tool, toolCall.arguments, { d: take(this.decided, id), hint: typeof hint === "string" ? hint : undefined });
    return { behavior: why === null ? { type: "allow" } : { type: "rejectContent", message: why } };
  }

  /** Approve or reject the paused calls of a RunState as the signer's approvers decided; returns the calls still
   * waiting. Resuming with a call approved some other way runs nothing: the signer refuses it. */
  async applyDecisions(state: any): Promise<any[]> {
    const states = await approvalStates(this.run), waiting = [];
    for (const item of state.getInterruptions()) {
      const s = states.get(item.rawItem?.callId);
      if (s === "approved") state.approve(item);
      else if (s === "rejected" || s === "expired") state.reject(item, { message: `Tool call ${s} in Tracekit` });
      else waiting.push(item);
    }
    return waiting;
  }

  /** T3: each model response (`result.rawResponses`) as a signed commitment, hosted tool calls included. Never rejects. */
  async recordResponses(responses: any[], model = ""): Promise<void> {
    for (const r of responses)
      await recordResponse(this.run, "openai", model, () => ({
        content_digest: digest(r.output),
        usage: r.usage && { input_tokens: r.usage.inputTokens, output_tokens: r.usage.outputTokens },
        // lean: function and hosted tool calls; shell, apply_patch and computer calls are in content_digest only
        tool_uses: r.output.flatMap((i: any) => (i.type === "function_call" ? [toolUse(i.callId, i.name, i.arguments)]
          : i.type === "hosted_tool_call" && i.id ? [toolUse(i.id, i.name, null, true)] : [])).slice(0, 128),
      }));
  }
}
