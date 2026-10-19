# Gemini CLI's sandbox

> **Experimental:** Tracekit's Gemini CLI hooks are experimental ([support](../support.md)). Tested: `TK-A004` and
> `tracekit doctor` against arguments and settings as Gemini CLI's source defines them; not yet against the hook payload of
> a real permission expansion ([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

Gemini CLI has two sandboxes, both off by default:

- **The tool sandbox** (`security.toolSandboxing`) runs each shell command inside an operating-system sandbox:
  bubblewrap and seccomp on Linux, Seatbelt on macOS, a restricted token on Windows. A command can write the workspace
  and has no network unless it's granted more (below). Gemini CLI itself, and the hooks it runs, stay outside.
- **The whole-CLI sandbox** (`tools.sandbox`, `GEMINI_SANDBOX` or `-s`) re-runs all of Gemini CLI, its hooks
  included, inside a container (Docker, Podman, gVisor, LXC) or under Seatbelt on macOS.

Use the tool sandbox with Tracekit; the whole-CLI one doesn't work with it (below). The two do different jobs and
work together:

| | Gemini CLI's tool sandbox | Tracekit |
|---|---|---|
| What it does | Limits what a shell command can write and reach while it runs | Decides each call before it runs, holds risky ones for a person, and signs a record of every call and approval |
| Where | Inside Gemini CLI, around each command | A signer outside the agent ([dev or system mode](../limits.md#dev-mode-vs-system-mode)) |
| What a third party can check later | Nothing signed; Gemini keeps its own session files | A signed, hash-chained bundle, verified offline |

## Setup

Turn both on. Tracekit first (`tracekit init --dev --v2 --agent gemini`, [coding agents](../coding-agents.md)), then
the tool sandbox in `~/.gemini/settings.json`, next to the hooks init wrote, and restart Gemini CLI:

```json
{
  "security": {
    "toolSandboxing": true
  }
}
```

Leave `tools.sandbox` unset, and don't set `GEMINI_SANDBOX` or pass `-s`. `tracekit doctor` reads Gemini's settings
files when they hold Tracekit's hooks (`D-GEMINI-SANDBOX`, [doctor](../doctor.md)): it warns when they turn on the
whole-CLI sandbox, and reports the tool sandbox when it's on. It can't see `GEMINI_SANDBOX` or `-s` given at launch,
which override `tools.sandbox`.

## Not the whole-CLI sandbox

The whole-CLI sandbox runs Tracekit's hooks inside it, or not at all:

- **In a container**, the hooks `tracekit init` writes to `~/.gemini/settings.json` aren't there: Docker, Podman and
  gVisor get a copy of that file without its `hooks`, and LXC mounts the workspace, not `~/.gemini`. No Tracekit hook
  runs, so the session isn't recorded, and no gap marks it: the signer never hears of the run. Project hooks
  (`--project`) would run inside the container, which has neither Tracekit nor its signer.
- **Under Seatbelt**, the hooks run inside Gemini's profile, which lets a process write only the workspace, temporary
  and cache directories. Tracekit's hook can't keep its state there, so it blocks every call.

## Sandbox expansion requests (TK-A004)

With the tool sandbox on, Gemini's shell tool takes an `additional_permissions` argument: `network: true`, or paths
under `fileSystem.read` and `fileSystem.write`. Gemini tells the model to use it when a command failed with "Operation
not permitted", and the command then runs with that network access and those paths. Whether Gemini asks you first
(a Sandbox Expansion Request) depends on its approval mode and policy rules; in YOLO mode it approves every call.

Gemini's `BeforeTool` hook sends the call's arguments, `additional_permissions` included, before Gemini's own policy
and prompt. The coding pack's `TK-A004` (an `ask` rule) holds every call whose `additional_permissions` turns the
network on or names a path, until a person approves it from outside the agent's session, and signs the decision.
The call waits; from another terminal:

```text
tracekit approvals list                     # pending approvals
tracekit approvals show apr-…               # the command and the permissions it asks for
tracekit approvals approve apr-…
```

The approval is bound to the exact arguments, the requested permissions included, used once, and recorded with who
approved it, like every Tracekit approval ([approvals](../approvals.md)). The signed decision names `TK-A004`, so a
bundle shows which calls asked for more than the sandbox allows and who approved each. Gemini's own approval step
still follows. To allow expansions without asking, override `TK-A004` in your own policy ([policy](../policy-v2.md)).

## What Tracekit sees and doesn't

- **Sees:** every call Gemini sends to its hooks, with its arguments (`additional_permissions` included), the decision,
  any approval, and the result. Records commit to the arguments rather than store them ([privacy](../privacy.md)).
- **Doesn't see:** permissions Gemini grants outside a call's arguments: what its approval mode allows, an expansion
  Gemini proposes itself for a command it knows needs more (such as `npm install`), and one you allowed for good,
  which later runs of that command get without asking. What the sandbox blocked shows only in the command's
  output.
- **Doesn't record:** Gemini's sandbox settings. They aren't signed into the run; `tracekit doctor` reads them on the
  machine.
- **Doesn't check:** `GEMINI_SANDBOX` or `-s` at launch, or whether Gemini trusts the folder (it ignores an untrusted
  project's settings). `D-GEMINI-SANDBOX` merges the files it reads key by key ([doctor](../doctor.md)).

[Limits](../limits.md) lists these with what to do.
