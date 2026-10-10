/**
 * Native client for the v2 signer RPC (tracekit/sdk/client.py in TypeScript), Node built-ins only.
 *
 *   import { Client, withRun } from "@cygnux/tracekit/v2";
 *   const run = await new Client().registerRun("my-agent");
 *   const d = await run.decide("call-1", "Bash", '{"command": "ls"}');
 *   if (d.decision === "allow") await run.complete("call-1", "ok");
 *   await run.close();
 *
 * The signer is the Unix socket in $TRACEKIT_SIGNER, `tcp://host:port` with $TRACEKIT_SIGNER_TOKEN (the loopback dev
 * transport, mutual HMAC proof of the token), or an `https://host:port` URL (each call is one POST /v2/rpc;
 * $TRACEKIT_SIGNER_TOKEN_FILE names a bearer token file re-read per call, $TRACEKIT_SIGNER_CERT/_KEY a client
 * certificate for mTLS, $TRACEKIT_SIGNER_CA the signer's CA). In system mode the signer is the one the root-owned
 * /etc/tracekit/client.json names, and a $TRACEKIT_SIGNER naming another is refused. Without either, the same-user dev
 * signer of the runtime dir is used, started with `python -m tracekit up --json` ($TRACEKIT_PYTHON) when none answers.
 * Requests go out in order on one connection and are answered in order; `approval_wait` gets a connection of its own.
 * Every request is validated against the RPC contract before it is sent. Calls that change state carry a `request_id`
 * and are resent with it when the connection drops. Event calls carry this client's `stream` and a `client_seq` per run.
 * The client writes nothing to disk.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { execFile } from "node:child_process";
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";
import { Agent, request } from "node:https";
import { createConnection, type Socket } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import { argsDigest } from "./jcs.js";
import { REQUESTS, RPC_VERSION } from "./rpc_schema.js";
import { validate } from "./validate.js";

export { RPC_VERSION };
export { argsDigest, canonicalize, digest, strictParse, StrictJSONError } from "./jcs.js";

export const SYSTEM_CONFIG = "/etc/tracekit/client.json";
const CONNECT_TIMEOUT_MS = 2000;
const RETRIES = 3;

export type Frame = Record<string, any>;

export class SignerUnavailable extends Error {
  name = "SignerUnavailable";
}

/** The signer answered but does not speak this client's protocol version. It is left running. */
export class Incompatible extends Error {
  name = "Incompatible";
}

/** A refusal from the signer (or of a request that fails the contract before it is sent). */
export class RPCError extends Error {
  name = "RPCError";
  constructor(readonly code: string, message: string, readonly retryAfterMs?: number) {
    super(`${code}: ${message}`);
  }
}

class ConnectionLost extends Error {}

const newId = () => randomUUID().replaceAll("-", "");
const hmac = (token: string, label: string, nonce: string) => createHmac("sha256", token).update(`${label}\n${nonce}`).digest("hex");

function warn(message: string) {
  process.emitWarning(message, "TracekitWarning");
}

function withTimeout<T>(p: Promise<T>, ms: number, onTimeout: () => void): Promise<T> {
  let timer: NodeJS.Timeout;
  const t = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      onTimeout();
      reject(new SignerUnavailable(`no answer from the signer within ${ms / 1000}s`));
    }, ms);
  });
  return Promise.race([p, t]).finally(() => clearTimeout(timer));
}

/** Newline-delimited JSON frames on one socket; answers are matched to requests in order. */
class Conn {
  private pending: { resolve: (f: Frame) => void; reject: (e: Error) => void }[] = [];
  private buf = "";

  constructor(readonly sock: Socket) {
    sock.setEncoding("utf8");
    sock.unref();   // an idle connection does not keep the process alive
    sock.on("data", (d: string) => {
      this.buf += d;
      for (let n; (n = this.buf.indexOf("\n")) >= 0;) {
        const line = this.buf.slice(0, n), p = this.pending.shift();
        this.buf = this.buf.slice(n + 1);
        let frame;
        try {
          frame = JSON.parse(line);
        } catch {
          frame = null;
        }
        if (!p || typeof frame !== "object" || frame === null) {   // an answer nobody asked for, or not a frame
          if (p) this.pending.unshift(p);
          return void sock.destroy();
        }
        if (!this.pending.length) sock.unref();
        p.resolve(frame);
      }
    });
    sock.on("error", () => {});   // "close" follows
    sock.on("close", () => {
      for (const p of this.pending.splice(0)) p.reject(new ConnectionLost());
    });
  }

  write(frame: Frame) {
    this.sock.write(JSON.stringify(frame) + "\n");
  }

  send(frame: Frame): Promise<Frame> {
    return new Promise((resolve, reject) => {
      if (this.sock.destroyed) return reject(new ConnectionLost());
      this.pending.push({ resolve, reject });
      this.sock.ref();
      this.write(frame);
    });
  }
}

function open(sock: Socket): Promise<Socket> {
  return new Promise((resolve, reject) => {
    sock.setTimeout(CONNECT_TIMEOUT_MS, () => sock.destroy(new Error("connect timed out")));
    sock.once("connect", () => {
      sock.setTimeout(0);
      resolve(sock);
    });
    sock.once("error", reject);
  });
}

function check(hello: Frame, where: string) {
  const proto = hello?.proto;
  if (!(Array.isArray(proto) && proto.length === 2 && proto[0] <= RPC_VERSION && RPC_VERSION <= proto[1]))
    throw new Incompatible(`the Tracekit signer ${hello?.version ?? "?"} (pid ${hello?.pid ?? "?"}, protocol ` +
      `${JSON.stringify(proto)}) at ${where} cannot serve this client (protocol ${RPC_VERSION}). It was left running. ` +
      "Stop it with `tracekit down`, or replace it with `tracekit up --replace`");
}

/** A connection to the signer at `path` (a Unix socket or tcp://host:port) and its hello, after the version check. */
export async function connect(path: string, token?: string): Promise<{ conn: Conn; hello: Frame }> {
  let conn: Conn | undefined, hello: Frame;
  try {
    if (path.startsWith("tcp://")) {
      const hostPort = path.slice(6), k = hostPort.lastIndexOf(":"), host = hostPort.slice(0, k);
      if (!["127.0.0.1", "::1", "localhost"].includes(host))   // frames after the handshake are plaintext
        throw new SignerUnavailable(`${path}: tcp:// signers must be on loopback (127.0.0.1, ::1 or localhost)`);
      token ||= process.env.TRACEKIT_SIGNER_TOKEN;
      if (!token) throw new SignerUnavailable(`${path}: tcp:// signers need TRACEKIT_SIGNER_TOKEN`);
      conn = new Conn(await open(createConnection({ host, port: Number(hostPort.slice(k + 1)) })));
      // the signer proves it holds the token over our nonce before we prove it over its own (transport/tcp_dev.py)
      const nonce = randomBytes(16).toString("hex");
      const reply = await withTimeout(conn.send({ method: "hello", nonce }), CONNECT_TIMEOUT_MS, () => conn!.sock.destroy());
      const proof = Buffer.from(String(reply.proof)), want = Buffer.from(hmac(token, "signer", nonce));
      if (proof.length !== want.length || !timingSafeEqual(proof, want)) throw new Error("dev token proof mismatch");
      if (typeof reply.nonce !== "string" || reply.nonce.length < 16 || reply.nonce.length > 128)
        throw new Error("handshake needs a nonce of 16-128 characters");
      conn.write({ proof: hmac(token, "client", reply.nonce) });
    } else if (process.platform !== "win32") {
      conn = new Conn(await open(createConnection(path)));
    } else {
      throw new SignerUnavailable(`this platform has no Unix sockets: name the signer tcp://host:port, not ${path}`);
    }
    const c = conn;
    hello = await withTimeout(c.send({ method: "hello" }), CONNECT_TIMEOUT_MS, () => c.sock.destroy());
  } catch (e) {
    conn?.sock.destroy();
    if (e instanceof SignerUnavailable && !conn) throw e;
    throw new SignerUnavailable(`no signer answering at ${path}: ${(e as Error).message}`);
  }
  try {
    check(hello, path);
  } catch (e) {
    conn.sock.destroy();
    throw e;
  }
  return { conn, hello };
}

/** The root-owned system-mode client config, or null when there is none; throws when it exists but can't be trusted. */
export function systemConfig(path = SYSTEM_CONFIG): Frame | null {
  if (process.platform === "win32") return null;   // no root-owned config there, as in the Python client
  let st;
  try {
    st = statSync(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error(`${path} cannot be read: ${(e as Error).message}`);
  }
  if (st.uid !== 0 || st.mode & 0o022) throw new Error(`${path} must be owned by root and not group- or world-writable`);
  let cfg;
  try {
    cfg = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`${path} cannot be parsed: ${(e as Error).message}`);
  }
  if (typeof cfg !== "object" || cfg === null || Array.isArray(cfg)) throw new Error(`${path} must hold a JSON object`);
  return cfg;
}

/** $TRACEKIT_SIGNER, or in system mode the system signer: there a $TRACEKIT_SIGNER that names another is refused. */
export function defaultSigner(env: NodeJS.ProcessEnv = process.env, system = systemConfig()): string | null {
  const mine = env.TRACEKIT_SIGNER || null, theirs = system?.signer || null;
  if (theirs && mine && mine !== theirs)
    throw new SignerUnavailable(`TRACEKIT_SIGNER=${mine.slice(0, 256)} is not the system signer ${theirs}; refused`);
  return theirs || mine;
}

/** The dev signer's runtime dir, as tracekit/sdk/autospawn.py `runtime_dir` names it. */
export function runtimeDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.TRACEKIT_RUNTIME_DIR) return env.TRACEKIT_RUNTIME_DIR;
  if (process.platform === "win32") return join(env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "tracekit", "run");
  if (process.platform === "darwin") {
    const d = join(homedir(), "Library/Application Support/tracekit/run");
    return Buffer.byteLength(join(d, "signer.sock")) > 103 ? `/tmp/tk-${process.getuid!()}` : d;   // macOS: 104-byte socket paths
  }
  return env.XDG_RUNTIME_DIR ? join(env.XDG_RUNTIME_DIR, "tracekit") : `/tmp/tracekit-${process.getuid!()}`;
}

/** The runtime dir of the same-user dev signer; refused in system mode, as tracekit/sdk/autospawn.py `ensure` does. */
export function devRuntimeDir(system = SYSTEM_CONFIG): string {
  if (existsSync(system)) throw new SignerUnavailable("dev auto-spawn is off when TRACEKIT_SIGNER is set or in system mode");
  return runtimeDir();
}

/** [path, token] of the dev signer in runtime dir `d`; SignerUnavailable while there is none or the dir isn't private. */
function devAddress(d: string): [string, string?] {
  try {
    if (process.platform !== "win32") {
      const st = lstatSync(d);
      if (!st.isDirectory() || st.uid !== process.getuid!() || st.mode & 0o077)
        throw new SignerUnavailable(`${d} must be a directory owned by you with mode 0700`);
      return [join(d, "signer.sock")];
    }
    const ep = JSON.parse(readFileSync(join(d, "endpoint.json"), "utf8"));
    if (!Number.isInteger(ep?.port) || typeof ep?.token !== "string") throw new Error("no port and token yet");
    return [`tcp://127.0.0.1:${ep.port}`, ep.token];
  } catch (e) {
    if (e instanceof SignerUnavailable) throw e;
    throw new SignerUnavailable(`no dev signer in ${d}: ${(e as Error).message}`);
  }
}

class Https {
  private agent: Agent;
  private url: URL;
  hello: Frame | null = null;

  constructor(signer: string) {
    const env = process.env, file = (p?: string) => (p ? readFileSync(p) : undefined);
    this.url = new URL("/v2/rpc", signer);
    const cert = env.TRACEKIT_SIGNER_CERT;   // its key in TRACEKIT_SIGNER_KEY, or in the same file
    this.agent = new Agent({ keepAlive: true, ca: file(env.TRACEKIT_SIGNER_CA), cert: file(cert),
      key: cert ? file(env.TRACEKIT_SIGNER_KEY || cert) : undefined });
  }

  /** The answer frame; ConnectionLost when the request may not have arrived, SignerUnavailable on a timeout. */
  post(frame: Frame, timeoutMs: number): Promise<Frame> {
    const body = JSON.stringify(frame), tokenFile = process.env.TRACEKIT_SIGNER_TOKEN_FILE;
    const headers: Record<string, string | number> = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) };
    if (tokenFile) {
      try {
        headers.Authorization = "Bearer " + readFileSync(tokenFile, "utf8").trim();   // re-read: a rotated token is picked up
      } catch (e) {
        throw new SignerUnavailable(`cannot read the signer token file: ${(e as Error).message}`);
      }
    }
    return new Promise((resolve, reject) => {
      const req = request(this.url, { method: "POST", agent: this.agent, headers, timeout: timeoutMs }, (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (d) => (data += d));
        res.on("error", () => reject(new ConnectionLost()));
        res.on("end", () => {
          try {
            const f = JSON.parse(data);
            if (typeof f !== "object" || f === null) throw new Error();
            resolve(f);
          } catch {
            reject(new ConnectionLost());
          }
        });
      });
      req.on("timeout", () => {
        reject(new SignerUnavailable(`no answer from the signer within ${timeoutMs / 1000}s`));
        req.destroy();
      });
      req.on("error", () => reject(new ConnectionLost()));
      req.end(body);
    });
  }

  async rpc(frame: Frame, timeoutMs: number): Promise<Frame> {
    if (!this.hello) {
      const hello = await this.post({ method: "hello" }, timeoutMs);
      if (hello.error) throw new RPCError(hello.error.code, hello.error.message ?? "");
      check(hello, this.url.origin);
      this.hello = hello;
    }
    return this.post(frame, timeoutMs);
  }
}

export interface ClientOptions {
  /** A Unix socket path, tcp://host:port or https://host:port; by default as described above. */
  signer?: string;
  /** Per-call timeout (default 30 s), plus a call's own `timeout_ms`. */
  timeoutMs?: number;
}

/** Methods take the request object of an RPC and return its response, or reject with RPCError (a refusal),
 * SignerUnavailable or Incompatible. */
export class Client {
  readonly signer: string | null;
  readonly stream = newId();
  readonly timeoutMs: number;
  hello: Frame | null = null;
  private https: Https | null;
  private conn: Promise<Conn> | null = null;
  private seqs = new Map<string, number>();
  private inflight = new Set<Promise<unknown>>();

  constructor(opts: ClientOptions = {}) {
    this.signer = opts.signer ?? defaultSigner();
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.https = this.signer?.startsWith("https://") ? new Https(this.signer) : null;
  }

  /** Register a run (`agent` is a name or {name, version}); the handle holds its run token. */
  async registerRun(agent: string | { name: string; version?: string }, fields: Frame = {}): Promise<RunHandle> {
    return new RunHandle(this, await this.call("register_run", { agent: typeof agent === "string" ? { name: agent } : agent, ...fields }));
  }

  /** `request_id`, `stream` and `client_seq` are filled in when missing. */
  call(method: string, req: Frame = {}): Promise<Frame> {
    return this.waitUntil(this.send(method, { ...req }));
  }

  /** Resolves once every call made so far, and every promise given to waitUntil, has settled. */
  async flush(): Promise<void> {
    while (this.inflight.size) await Promise.allSettled([...this.inflight]);
  }

  /** Have flush() and close() wait for `p` too (for serverless hosts that freeze the process after a response). */
  waitUntil<T>(p: Promise<T>): Promise<T> {
    this.inflight.add(p);
    const done = () => this.inflight.delete(p);
    p.then(done, done);
    return p;
  }

  /** Waits for what is in flight, then closes the connection. */
  async close(): Promise<void> {
    await this.flush();
    const conn = this.conn;
    this.conn = null;
    conn?.then((c) => c.sock.destroy(), () => {});
  }

  private async send(method: string, req: Frame): Promise<Frame> {
    const schema = REQUESTS[method];
    if (!schema) throw new RPCError("invalid_request", `unknown method ${method.slice(0, 64)}`);
    if ("request_id" in schema.properties) req.request_id ??= newId();
    let claim = "client_seq" in schema.properties && !("client_seq" in req);
    if (claim) Object.assign(req, { stream: this.stream, client_seq: this.seqs.get(req.run_id) ?? 0 });
    const errs = validate(schema, req);
    if (errs.length) throw new RPCError("invalid_request", errs.join("; "));
    const frame = () => {   // the event takes its client_seq as it goes out: in the order of the wire
      if (claim) {
        req.client_seq = this.seqs.get(req.run_id) ?? 0;
        this.seqs.set(req.run_id, req.client_seq + 1);
        claim = false;
      }
      return { method, ...req };
    };
    const timeout = this.timeoutMs + (req.timeout_ms ?? 0);
    for (let i = 0; i < RETRIES; i++) {
      let reply: Frame;
      try {
        if (this.https) {
          reply = await this.https.rpc(frame(), timeout);
          this.hello = this.https.hello;
        } else if ("timeout_ms" in schema.properties) {
          reply = await this.poll(frame(), timeout);
        } else {
          const conn = await this.connection();
          reply = await withTimeout(conn.send(frame()), timeout, () => conn.sock.destroy());
        }
      } catch (e) {
        if (e instanceof ConnectionLost) continue;
        throw e;
      }
      if (reply.error) {
        const e = reply.error;
        if (["run_closed", "unknown_run"].includes(e.code)) this.seqs.delete(req.run_id);   // no more events for it
        throw new RPCError(e.code, e.message ?? "", e.retry_after_ms);
      }
      if (method === "close_run") this.seqs.delete(req.run_id);
      return reply;
    }
    throw new SignerUnavailable(`lost the connection to the signer ${RETRIES} times`);
  }

  /** One request on a connection of its own, closed after the answer. */
  private async poll(frame: Frame, timeout: number): Promise<Frame> {
    const { conn } = await this.dial();
    try {
      return await withTimeout(conn.send(frame), timeout, () => {});
    } finally {
      conn.sock.destroy();
    }
  }

  private connection(): Promise<Conn> {
    if (!this.conn) {
      const p: Promise<Conn> = this.dial().then(({ conn }) => {
        conn.sock.on("close", () => this.conn === p && (this.conn = null));
        return conn;
      }, (e) => {
        if (this.conn === p) this.conn = null;
        throw e;
      });
      this.conn = p;
    }
    return this.conn;
  }

  private async dial() {
    let c;
    if (this.signer) {
      c = await connect(this.signer);
    } else {
      const d = devRuntimeDir();
      try {
        c = await connect(...devAddress(d));
      } catch (e) {
        if (!(e instanceof SignerUnavailable)) throw e;
        await startDevSigner();
        c = await connect(...devAddress(d));
      }
    }
    this.hello = c.hello;
    return c;
  }
}

/** `tracekit up --json`: find or start the same-user dev signer (it takes the locks, not this client). */
function startDevSigner(): Promise<void> {
  const python = process.env.TRACEKIT_PYTHON ?? "python3";
  return new Promise((resolve, reject) => {
    execFile(python, ["-m", "tracekit", "up", "--json"], { timeout: 30_000 }, (err, _out, stderr) =>
      err ? reject(new SignerUnavailable(`no dev signer, and \`${python} -m tracekit up\` failed: ${stderr.trim() || err.message}`)) : resolve());
  });
}

/** Whether a call of `toolClass` may run while the signer cannot be reached: its entry in register_run's
 * `fail_modes`, else their `default`, else closed. A refusal from the signer is never a reason to fail open. */
export function failOpen(failModes: Record<string, string> | undefined, toolClass?: string): boolean {
  const modes = failModes ?? {};
  return ((toolClass !== undefined && Object.hasOwn(modes, toolClass) ? modes[toolClass] : modes.default) ?? "closed") === "open";
}

export interface Decision extends Frame {
  decision: "allow" | "deny" | "ask";
  rule_ids: string[];
  /** Set when the signer could not be reached: the decision is the run's fail mode, and nothing was recorded. */
  unavailable?: true;
}

/** A registered run. Its methods fill in run_id and run_token; `fields` adds optional request fields. */
export class RunHandle {
  readonly runId: string;
  readonly runToken: string;
  readonly failModes: Record<string, string> | undefined;
  closed = false;
  private decided = new Map<string, { decision_id: string; args_digest: string }>();

  constructor(readonly client: Client, readonly registered: Frame) {
    this.runId = registered.run_id;
    this.runToken = registered.run_token;
    this.failModes = registered.fail_modes;
  }

  /** Any per-run RPC with this run's id and token. */
  call(method: string, fields: Frame = {}): Promise<Frame> {
    return this.client.call(method, { run_id: this.runId, run_token: this.runToken, ...fields });
  }

  /** `args` is the model's raw arguments string, or an already parsed value. Only when the signer can't be reached
   * does the run's fail mode for `fields.tool_class_hint` decide; a refusal rejects. */
  async decide(toolCallId: string, tool: string, args: unknown, fields: Frame = {}): Promise<Decision> {
    let d;
    try {
      d = await this.call("decide", { tool_call_id: toolCallId, tool, args, args_source: typeof args === "string" ? "raw" : "parsed", ...fields });
    } catch (e) {
      if (!(e instanceof SignerUnavailable)) throw e;
      const open = failOpen(this.failModes, fields.tool_class_hint);
      warn(`tracekit: ${tool} ${open ? "runs unrecorded (fail open)" : "is denied (fail closed)"}: ${e.message}`);
      return { decision: open ? "allow" : "deny", rule_ids: [], reason: `signer unavailable: ${e.message}`.slice(0, 1024), unavailable: true };
    }
    try {
      this.decided.set(toolCallId, { decision_id: d.decision_id, args_digest: argsDigest(tool, args) });
    } catch {
      // the signer has no args digest to bind either; complete needs explicit fields
    }
    return d as Decision;
  }

  /** Never rejects: a failure to record a call that already ran is a warning. Defaults decision_id and args_digest to
   * those of the last `decide` for this tool call. */
  async complete(toolCallId: string, status: "ok" | "error" = "ok", fields: Frame = {}): Promise<Frame | null> {
    const decided = this.decided.get(toolCallId);
    this.decided.delete(toolCallId);
    try {
      return await this.call("complete", { tool_call_id: toolCallId, status, ...decided, ...fields });
    } catch (e) {
      warn(`tracekit: the result of ${toolCallId} was not recorded: ${(e as Error).message}`);
      return null;
    }
  }

  approvalRequest(toolCallId: string, fields: Frame = {}): Promise<Frame> {
    return this.call("approval_request", { tool_call_id: toolCallId, ...fields });
  }

  /** Waits up to `timeoutMs` (signer cap 300 s) for a decision, on a connection of its own. */
  approvalWait(approvalId: string, timeoutMs?: number): Promise<Frame> {
    return this.call("approval_wait", { approval_id: approvalId, ...(timeoutMs === undefined ? {} : { timeout_ms: timeoutMs }) });
  }

  stateWrite(key: string, valueDigest: string, fields: Frame = {}): Promise<Frame> {
    return this.call("state_write", { key, value_digest: valueDigest, ...fields });
  }

  modelEvent(provider: string, model: string, phase: "request" | "response", fields: Frame = {}): Promise<Frame> {
    return this.call("model_event", { provider, model, phase, ...fields });
  }

  async close(reason?: string): Promise<void> {
    if (!this.closed) {
      await this.call("close_run", reason ? { reason } : {});
      this.closed = true;
    }
  }
}

const current = new AsyncLocalStorage<RunHandle>();

/** Runs `fn` with `handle` as the current run of everything it awaits. */
export function withRun<T>(handle: RunHandle, fn: () => T): T {
  return current.run(handle, fn);
}

export function currentRun(): RunHandle | undefined {
  return current.getStore();
}
