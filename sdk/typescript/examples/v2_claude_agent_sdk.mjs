// Claude Agent SDK (TS) on the v2 signer, offline: the hooks are called the way the CLI calls them around two Bash
// tool uses (a real session needs the CLI and a model: query({ prompt, options: { hooks, sessionStore } })). The
// signer's default policy allows `ls` and denies `sudo rm -rf /`; each turn is committed through the session store.
// Needs `npm run build` and Python with tracekit (a dev signer is started on demand).
//   node examples/v2_claude_agent_sdk.mjs
import { Client } from "../dist/v2/client.js";
import { tracekitHooks, tracekitSessionStore } from "../dist/v2/adapters/claude-agent-sdk.js";

const client = new Client(), run = await client.registerRun("claude-example");
const hooks = tracekitHooks(run);
const saved = [];
const sessionStore = tracekitSessionStore({ async append(_key, entries) { saved.push(...entries); }, async load() { return null; } }, run);

const fire = async (event, input) => {   // as the CLI runs each matcher's hooks
  const out = {};
  for (const m of hooks[event]) for (const h of m.hooks) Object.assign(out, await h({ hook_event_name: event, session_id: "s1", ...input }, input.tool_use_id, { signal: AbortSignal.timeout((m.timeout ?? 60) * 1000) }));
  return out;
};

for (const [id, command] of [["toolu_1", "ls"], ["toolu_2", "sudo rm -rf /"]]) {
  const use = { tool_name: "Bash", tool_input: { command }, tool_use_id: id };
  const pre = (await fire("PreToolUse", use)).hookSpecificOutput;
  if (pre?.permissionDecision === "deny") {
    console.log(id, "blocked:", pre.permissionDecisionReason);
  } else {
    const stdout = `(pretend) ran ${command}`;
    await fire("PostToolUse", { ...use, tool_response: { stdout } });
    console.log(id, stdout);
  }
  await sessionStore.append({ projectKey: "example", sessionId: "s1" }, [{ type: "assistant", uuid: id, message: use }]);
}
await fire("SessionEnd", { reason: "other" });
console.log(`${saved.length} transcript entries saved and committed`);
await client.close();
