/**
 * @cygnux/tracekit: Tracekit for TypeScript/JavaScript agents.
 *
 *   import { Tracekit, instrumentOpenAI } from "@cygnux/tracekit";
 *   const tk = await Tracekit.start({ agent: "research-bot" });
 *   const openai = instrumentOpenAI(new OpenAI(), tk);             // every model call: signed request + response
 *   const out = await tk.tool("Bash", { command: "ls" }, () => run("ls"));   // policy-gated before it runs
 *   await tk.end();
 *
 * The SDK drives Tracekit's Python engine through `python -m tracekit.bridge` (stdio, JSON lines), so policy, redaction,
 * the signer client and the event format are exactly those of the Python SDK. It needs the `tracekit` Python package and
 * a configured signer (`tracekit init --dev`). Set TRACEKIT_PYTHON (or `python`) to choose the interpreter.
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

export class TracekitDenied extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TracekitDenied";
  }
}

export interface StartOptions {
  agent?: string;
  sessionId?: string;
  cwd?: string;
  python?: string;
  env?: Record<string, string>;
  /** Per-request timeout for the bridge (default 30 s). */
  timeoutMs?: number;
  /** Timeout for a tool call held for approval (default 61 min: the signer caps an approval at one hour). */
  approvalTimeoutMs?: number;
}

export interface Usage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens?: number | null;
  cache_write_tokens?: number | null;
  reasoning_tokens?: number | null;
}

export interface ModelEnd {
  response?: unknown;
  error?: string | null;
  status?: number | null;
  stop_reason?: string | null;
  tool_uses?: { id: string; name: string }[];
  usage?: Usage | null;
  model?: string | null;
  first_byte_ms?: number | null;
}

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void };

class BridgeClosed extends Error {}

class Bridge {
  private proc: ChildProcessWithoutNullStreams;
  private pending = new Map<number, Pending>();
  private next = 1;
  private ready: Promise<void>;
  private closed = false;

  constructor(python: string, env: Record<string, string> | undefined) {
    this.proc = spawn(python, ["-m", "tracekit.bridge"], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, ...env } });
    let readyResolve!: () => void;
    let readyReject!: (e: Error) => void;
    this.ready = new Promise((res, rej) => { readyResolve = res; readyReject = rej; });
    let stderr = "";
    this.proc.stderr.on("data", (d: Buffer) => { stderr = (stderr + d.toString()).slice(-4000); process.stderr.write(d); });
    this.proc.on("error", (e) => readyReject(new Error(`could not start the Tracekit bridge (${python}): ${e.message}`)));
    this.proc.on("exit", (code) => {
      this.closed = true;
      const err = new BridgeClosed(`Tracekit bridge exited (code ${code}). ${stderr.trim().split("\n").slice(-3).join(" ")}`);
      readyReject(err);
      for (const p of this.pending.values()) p.reject(err);
      this.pending.clear();
    });
    createInterface({ input: this.proc.stdout }).on("line", (line) => {
      let msg: any;
      try { msg = JSON.parse(line); } catch { return; }
      if (msg.id === 0 && msg.ready) return readyResolve();
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      if (msg.ok) p.resolve(msg);
      else p.reject(msg.denied ? new TracekitDenied(msg.error) : new Error(`Tracekit: ${msg.error}`));
    });
  }

  async call(op: string, args: Record<string, unknown>, timeoutMs: number): Promise<any> {
    const id = this.next++;
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_res, rej) => {
      timer = setTimeout(() => {
        this.pending.delete(id);
        rej(new Error(`Tracekit: bridge request ${op} timed out after ${timeoutMs} ms`));
      }, timeoutMs);
    });
    try {
      return await Promise.race([this.send(id, op, args, timeoutMs), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async send(id: number, op: string, args: Record<string, unknown>, timeoutMs: number): Promise<any> {
    await this.ready;
    if (this.closed) throw new BridgeClosed("Tracekit bridge is closed");
    const p = new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
    this.proc.stdin.write(JSON.stringify({ id, op, timeout_s: timeoutMs / 1000, ...args }) + "\n");
    return p;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    const done = new Promise<void>((res) => this.proc.once("exit", () => res()));
    this.proc.stdin.end();
    await done;
  }
}

export class Tracekit {
  readonly sessionId: string;
  /** Recording failures after a wrapped call had already succeeded: reported on stderr, never thrown. */
  recordFailures = 0;
  private warnedClosed = false;
  private constructor(private bridge: Bridge, private run: string, sessionId: string, private failMode: string,
                      private timeoutMs: number, private approvalTimeoutMs: number) {
    this.sessionId = sessionId;
  }

  /** Start a run. One Tracekit per run; call end() when the agent is done. */
  static async start(opts: StartOptions = {}): Promise<Tracekit> {
    const python = opts.python ?? process.env.TRACEKIT_PYTHON ?? "python3";
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const bridge = new Bridge(python, opts.env);
    const r = await bridge.call("start", { agent: opts.agent ?? "ts-agent", session_id: opts.sessionId, cwd: opts.cwd ?? process.cwd() }, timeoutMs);
    return new Tracekit(bridge, r.run, r.session_id, r.fail_mode, timeoutMs, opts.approvalTimeoutMs ?? 3_660_000);
  }

  /**
   * One bridge request. If the bridge has exited, the run's fail mode decides: open returns null (the caller proceeds
   * unrecorded, with a warning), closed refuses with TracekitDenied.
   */
  private async call(op: string, args: Record<string, unknown>, timeoutMs = this.timeoutMs): Promise<any> {
    try {
      return await this.bridge.call(op, args, timeoutMs);
    } catch (e: any) {
      if (!(e instanceof BridgeClosed)) throw e;
      if (this.failMode === "closed") throw new TracekitDenied(`${e.message}; fail_mode=closed refuses the call`);
      if (!this.warnedClosed) {
        this.warnedClosed = true;
        process.stderr.write(`[tracekit] ${e.message}; fail_mode=open, continuing unrecorded\n`);
      }
      return null;
    }
  }

  /** Record after the wrapped call succeeded: a failure here is reported, never thrown over the call's result. */
  async settle(p: Promise<unknown>): Promise<void> {
    try {
      await p;
    } catch (e: any) {
      this.recordFailures++;
      process.stderr.write(`[tracekit] could not record a completed call: ${e?.message ?? e}\n`);
    }
  }

  prompt(text: string): Promise<void> { return this.call("prompt", { run: this.run, text }).then(() => undefined); }
  say(text: string): Promise<void> { return this.call("say", { run: this.run, text }).then(() => undefined); }
  think(text: string): Promise<void> { return this.call("think", { run: this.run, text }).then(() => undefined); }

  /**
   * Run a tool through the policy gate. The policy decision is made and signed before `fn` runs; a denied (or held and
   * not approved) call throws TracekitDenied and `fn` never runs. The result or error is recorded afterwards.
   * Pass the model's tool-call id as toolUseId to link the execution to the model request that asked for it.
   */
  async tool<T>(name: string, args: Record<string, unknown>, fn: () => T | Promise<T>, opts: { toolUseId?: string } = {}): Promise<T> {
    const c = await this.call("tool_begin", { run: this.run, name, args, tool_use_id: opts.toolUseId }, this.approvalTimeoutMs);
    if (c === null) return fn();
    let result: T;
    try {
      result = await fn();
    } catch (e: any) {
      await this.settle(this.call("tool_end", { call: c.call, error: String(e?.stack ?? e) }));
      throw e;
    }
    await this.settle(this.call("tool_end", { call: c.call, result: toJSON(result) }));
    return result;
  }

  /** Low level: record a model call yourself. begin() is written before the request is sent. Null: not recorded. */
  async modelBegin(provider: string, operation: string, model: string | null, request: unknown, streamed = false): Promise<string | null> {
    const r = await this.call("model_begin", { run: this.run, provider, operation, model, request: toJSON(request), streamed });
    return r === null ? null : r.exchange;
  }

  async modelEnd(exchange: string | null, end: ModelEnd): Promise<void> {
    if (exchange === null) return;
    await this.call("model_end", { exchange, ...end, response: toJSON(end.response) });
  }

  async end(reason = "done"): Promise<void> {
    try { await this.call("end", { run: this.run, reason }); } finally { await this.bridge.close(); }
  }
}

function toJSON(v: unknown): unknown {
  if (v === undefined) return null;
  try { return JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x))); } catch { return String(v); }
}

// ------------------------------------------------------------------ usage normalisation (same buckets as tracekit/usage.py)

export function usageFromOpenAI(u: any): Usage | null {
  if (!u) return null;
  if (u.prompt_tokens != null || u.completion_tokens != null) {
    const cached = u.prompt_tokens_details?.cached_tokens ?? 0;
    return { input_tokens: Math.max(0, (u.prompt_tokens ?? 0) - cached), output_tokens: u.completion_tokens ?? 0,
             cache_read_tokens: cached || null, reasoning_tokens: u.completion_tokens_details?.reasoning_tokens ?? null };
  }
  if (u.input_tokens != null) {
    const cached = u.input_tokens_details?.cached_tokens ?? 0;
    return { input_tokens: Math.max(0, u.input_tokens - cached), output_tokens: u.output_tokens ?? 0, cache_read_tokens: cached || null,
             reasoning_tokens: u.output_tokens_details?.reasoning_tokens ?? null };
  }
  return null;
}

export function usageFromAnthropic(u: any): Usage | null {
  if (!u || (u.input_tokens == null && u.output_tokens == null)) return null;
  return { input_tokens: u.input_tokens ?? 0, output_tokens: u.output_tokens ?? 0, cache_read_tokens: u.cache_read_input_tokens ?? null,
           cache_write_tokens: u.cache_creation_input_tokens ?? null };
}

function mergeUsage(a: Usage | null, b: Usage | null): Usage | null {
  if (!a) return b;
  if (!b) return a;
  const out: any = { ...a };
  for (const [k, v] of Object.entries(b)) if (v) out[k] = v;
  return out;
}

// ------------------------------------------------------------------ provider instrumentation

function isAsyncIterable(x: any): x is AsyncIterable<any> {
  return x != null && typeof x[Symbol.asyncIterator] === "function";
}

/** Wrap a stream so the response is recorded when it ends, errors, or is abandoned (return()). */
function wrapStream<S extends AsyncIterable<any>>(stream: S, onItem: (x: any) => void, finish: (err?: string) => Promise<void>): S {
  const origIter = stream[Symbol.asyncIterator].bind(stream);
  let done = false;
  const end = async (err?: string) => { if (!done) { done = true; await finish(err); } };
  (stream as any)[Symbol.asyncIterator] = () => {
    const it = origIter();
    return {
      async next() {
        try {
          const r = await it.next();
          if (r.done) await end(); else onItem(r.value);
          return r;
        } catch (e: any) { await end(String(e?.message ?? e)); throw e; }
      },
      async return(v?: any) { await end("stream abandoned"); return it.return ? it.return(v) : { done: true, value: v }; },
      async throw(e?: any) { await end(String(e)); if (it.throw) return it.throw(e); throw e; },
      [Symbol.asyncIterator]() { return this; },
    };
  };
  return stream;
}

function statusOf(e: any): number | null {
  const s = e?.status ?? e?.statusCode;
  return typeof s === "number" ? s : null;
}

/** OpenAI SDK: chat.completions.create and responses.create, streaming included. Returns the same client. */
export function instrumentOpenAI<C extends Record<string, any>>(client: C, tk: Tracekit): C {
  const wrap = (holder: any, method: string, operation: string) => {
    if (!holder?.[method] || holder[method].__tracekit) return;
    const orig = holder[method].bind(holder);
    const wrapped = async (body: any, options?: any) => {
      const t0 = Date.now();
      const x = await tk.modelBegin("openai", operation, body?.model ?? null, body, !!body?.stream);
      let out: any;
      try { out = await orig(body, options); } catch (e: any) {
        await tk.settle(tk.modelEnd(x, { error: String(e?.message ?? e), status: statusOf(e) }));
        throw e;
      }
      if (body?.stream && isAsyncIterable(out)) {
        const tools = new Map<string, string>(), byIndex = new Map<number, string>();
        let model: string | null = null, stop: string | null = null, usage: Usage | null = null, first: number | null = null, text = "";
        return wrapStream(out, (ch: any) => {
          first ??= Date.now() - t0;
          model ??= ch.model ?? ch.response?.model ?? null;
          usage = mergeUsage(usage, usageFromOpenAI(ch.usage ?? ch.response?.usage));
          for (const c of ch.choices ?? []) {
            if (c.finish_reason) stop = c.finish_reason;
            if (typeof c.delta?.content === "string" && text.length < 1_000_000) text += c.delta.content;
            for (const tc of c.delta?.tool_calls ?? []) {
              if (tc.id) byIndex.set(tc.index ?? 0, tc.id);
              const id = tc.id ?? byIndex.get(tc.index ?? 0);
              if (id && tc.function?.name) tools.set(id, tc.function.name);
            }
          }
          if (ch.type === "response.output_item.added" && ch.item?.type === "function_call") tools.set(ch.item.call_id ?? ch.item.id, ch.item.name);
          if (ch.type === "response.completed") stop = ch.response?.status ?? stop;
        }, (err) => tk.settle(tk.modelEnd(x, { response: { text }, error: err ?? null, model, stop_reason: stop, usage, first_byte_ms: first,
                                                   tool_uses: [...tools].map(([id, name]) => ({ id, name })) })));
      }
      const tools: { id: string; name: string }[] = [];
      for (const c of out?.choices ?? []) for (const tc of c.message?.tool_calls ?? []) tools.push({ id: tc.id, name: tc.function?.name ?? tc.type });
      for (const it of out?.output ?? []) if (it.type === "function_call") tools.push({ id: it.call_id ?? it.id, name: it.name });
      await tk.settle(tk.modelEnd(x, { response: out, model: out?.model ?? null, stop_reason: out?.choices?.[0]?.finish_reason ?? out?.status ?? null,
                                       usage: usageFromOpenAI(out?.usage), tool_uses: tools, status: 200 }));
      return out;
    };
    (wrapped as any).__tracekit = true;
    holder[method] = wrapped;
  };
  wrap((client as any).chat?.completions, "create", "chat");
  wrap((client as any).responses, "create", "responses");
  return client;
}

/** Anthropic SDK: messages.create, streaming (stream: true) included. Returns the same client. */
export function instrumentAnthropic<C extends Record<string, any>>(client: C, tk: Tracekit): C {
  const holder = (client as any).messages;
  if (!holder?.create || holder.create.__tracekit) return client;
  const orig = holder.create.bind(holder);
  const wrapped = async (body: any, options?: any) => {
    const t0 = Date.now();
    const x = await tk.modelBegin("anthropic", "messages", body?.model ?? null, body, !!body?.stream);
    let out: any;
    try { out = await orig(body, options); } catch (e: any) {
      await tk.settle(tk.modelEnd(x, { error: String(e?.message ?? e), status: statusOf(e) }));
      throw e;
    }
    if (body?.stream && isAsyncIterable(out)) {
      const tools: { id: string; name: string }[] = [];
      let model: string | null = null, stop: string | null = null, usage: Usage | null = null, first: number | null = null, text = "";
      return wrapStream(out, (ev: any) => {
        first ??= Date.now() - t0;
        if (ev.type === "message_start") { model = ev.message?.model ?? null; usage = mergeUsage(usage, usageFromAnthropic(ev.message?.usage)); }
        if (ev.type === "content_block_start" && ["tool_use", "server_tool_use", "mcp_tool_use"].includes(ev.content_block?.type))
          tools.push({ id: ev.content_block.id, name: ev.content_block.name });
        if (ev.type === "content_block_delta" && typeof ev.delta?.text === "string" && text.length < 1_000_000) text += ev.delta.text;
        if (ev.type === "message_delta") { stop = ev.delta?.stop_reason ?? stop; usage = mergeUsage(usage, usageFromAnthropic(ev.usage)); }
      }, (err) => tk.settle(tk.modelEnd(x, { response: { text }, error: err ?? null, model, stop_reason: stop, usage, first_byte_ms: first, tool_uses: tools })));
    }
    const tools = (out?.content ?? []).filter((b: any) => ["tool_use", "server_tool_use", "mcp_tool_use"].includes(b.type))
      .map((b: any) => ({ id: b.id, name: b.name }));
    await tk.settle(tk.modelEnd(x, { response: out, model: out?.model ?? null, stop_reason: out?.stop_reason ?? null,
                                     usage: usageFromAnthropic(out?.usage), tool_uses: tools, status: 200 }));
    return out;
  };
  (wrapped as any).__tracekit = true;
  holder.create = wrapped;
  return client;
}

/**
 * Vercel AI SDK language-model middleware (use with wrapLanguageModel({ model, middleware: tracekitMiddleware(tk) })).
 * Works with the v4 (promptTokens/toolCalls) and v5 (inputTokens/content parts) result shapes.
 */
export function tracekitMiddleware(tk: Tracekit, provider = "ai-sdk") {
  const usageOf = (u: any): Usage | null => {
    if (!u) return null;
    const inp = u.inputTokens ?? u.promptTokens, out = u.outputTokens ?? u.completionTokens;
    if (inp == null && out == null) return null;
    const cached = u.cachedInputTokens ?? 0;
    return { input_tokens: Math.max(0, (inp ?? 0) - cached), output_tokens: out ?? 0, cache_read_tokens: cached || null,
             reasoning_tokens: u.reasoningTokens ?? null };
  };
  const toolsOf = (r: any) => {
    const t: { id: string; name: string }[] = [];
    for (const c of r?.toolCalls ?? []) t.push({ id: c.toolCallId, name: c.toolName });
    for (const c of r?.content ?? []) if (c?.type === "tool-call") t.push({ id: c.toolCallId, name: c.toolName });
    return t;
  };
  return {
    wrapGenerate: async ({ doGenerate, params, model }: any) => {
      const x = await tk.modelBegin(model?.provider ?? provider, "generate", model?.modelId ?? null, params, false);
      let r: any;
      try { r = await doGenerate(); } catch (e: any) { await tk.settle(tk.modelEnd(x, { error: String(e?.message ?? e), status: statusOf(e) })); throw e; }
      const fr = r?.finishReason;
      await tk.settle(tk.modelEnd(x, { response: { text: r?.text, content: r?.content }, model: model?.modelId ?? null,
                                       stop_reason: typeof fr === "string" ? fr : fr?.unified ?? null, usage: usageOf(r?.usage), tool_uses: toolsOf(r), status: 200 }));
      return r;
    },
    wrapStream: async ({ doStream, params, model }: any) => {
      const t0 = Date.now();
      const x = await tk.modelBegin(model?.provider ?? provider, "stream", model?.modelId ?? null, params, true);
      let res: any;
      try { res = await doStream(); } catch (e: any) { await tk.settle(tk.modelEnd(x, { error: String(e?.message ?? e), status: statusOf(e) })); throw e; }
      const tools: { id: string; name: string }[] = [];
      let usage: Usage | null = null, stop: string | null = null, first: number | null = null, text = "", ended = false;
      const finish = async (err?: string) => {
        if (ended) return;
        ended = true;
        await tk.settle(tk.modelEnd(x, { response: { text }, error: err ?? null, model: model?.modelId ?? null, stop_reason: stop, usage, first_byte_ms: first, tool_uses: tools }));
      };
      const transform = new TransformStream({
        transform(part: any, controller) {
          first ??= Date.now() - t0;
          if (part?.type === "tool-call") tools.push({ id: part.toolCallId, name: part.toolName });
          if ((part?.type === "text-delta" || part?.type === "text") && text.length < 1_000_000) text += part.textDelta ?? part.delta ?? part.text ?? "";
          if (part?.type === "finish") { usage = usageOf(part.usage); const fr = part.finishReason; stop = typeof fr === "string" ? fr : fr?.unified ?? null; }
          if (part?.type === "error") void finish(String(part.error));
          controller.enqueue(part);
        },
        async flush() { await finish(); },
      });
      return { ...res, stream: res.stream.pipeThrough(transform) };
    },
  };
}

// ------------------------------------------------------------------ browser agents

/**
 * Stagehand: wrap page/stagehand methods (act, extract, observe, goto by default) so every browser action is a
 * policy-checked, signed `browser:<method>` step. A denied action throws TracekitDenied and never reaches the browser.
 * Works on any object with those methods (Stagehand v2 `page`, or the v3 `stagehand` instance). Returns the same object.
 */
export function instrumentStagehand<P extends Record<string, any>>(page: P, tk: Tracekit, methods: string[] = ["act", "extract", "observe", "goto"]): P {
  for (const m of methods) {
    const original = page[m];
    if (typeof original !== "function" || (original as any).__tracekit) continue;
    const wrapped = function (this: unknown, ...args: unknown[]) {
      const first = args[0];
      const recorded: Record<string, unknown> = { input: typeof first === "object" && first !== null ? toJSON(first) : first ?? null };
      if (args.length > 1) recorded.options = toJSON(args[1]);
      return tk.tool(`browser:${m}`, recorded, () => original.apply(this ?? page, args));
    };
    (wrapped as any).__tracekit = true;
    (page as any)[m] = wrapped;
  }
  return page;
}
