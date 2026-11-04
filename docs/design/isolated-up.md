# One command to real separation: `tracekit up --isolated`

Status: prototype (experimental), issue #591.

Today a laptop setup ends at `isolation: same-user`: the agent runs as you, so it can read the signer's key, stop
the signer or rewrite its store. The setups that separate them take days. This note compares three ways to get a
real separation from one command, and picks one for laptops.

## The three paths

| | (a) The agent in a container, the signer outside | (b) One-command system mode | (c) A published signer image |
|---|---|---|---|
| What separates them | The container's mounts and network: it gets the project, a token and the signer's TLS certificate, and reaches only its relay to the signer | OS users: the signer runs as its own user, the agent as a second, non-admin user | The signer's container; the agent is wherever you run it |
| Protects against | The boxed agent reading the key, stopping the signer, rewriting the store or policy, answering its own approvals, reaching the Docker socket or the host's services, turning its hooks off, planting what the host runs | The same, measured by the socket's peer uid, against any process of the agent's user | Nothing on a laptop unless the agent is in a container too, which is (a) |
| What breaks it | Giving the container the Docker socket or your home; running the agent outside it; anything running as you on the host (it can use the box's token and read the key); root on the host or in the Docker VM; a container escape; project files you run that the box changed | Running the agent as you, not as the second user; on a Mac you are an admin, and an admin is a password away from root; root | The registry or the image's build; whoever runs the Docker host |
| What you need | Docker (colima or Docker Desktop on a Mac, Docker Engine on Linux); the first run builds the box image | root, a second user, project files shared with it, the agent's login set up again as that user; macOS is experimental | an image release process: build, sign, publish by digest |
| First run | measured on an M-series Mac with colima, from a fresh install, the base image already pulled: 197 s for the first `up --isolated` (building the box image with Claude Code, TLS, signer start, two hooked calls); a few seconds for each later one | 10 minutes to an hour, mostly the second user (judgment, not measured) | a pull (about 50 MB), then as (a) |
| Work | a command, an image it builds on first use (Claude Code and Tracekit's hooks), a relay, a doctor check, docs | a wrapper around `tracekit init --v2 --user` that creates the user and runs the agent as it | release work; no laptop change |

## The choice: (a), the agent in a container

It is the only path that works whether or not you are an admin, needs no second user and no root, and changes
nothing in how you install Tracekit. The separation comes from what the container is given, not from users, so a
Mac admin's rights don't undercut it. (b) stays the right setup for a shared Linux host; (c) is the right setup for
servers (Compose, Kubernetes), and the image there is built from `deploy/docker/Dockerfile`.

How it works:

1. `tracekit up --isolated` sets up a signer of its own the first time, next to the dev signer's data dir
   (`<dev data dir>-box`): its keys and store, a TLS key and certificate, and a token store. It starts that signer as
   you, or reuses it. The dev signer is not touched.
2. It issues a box token (`token:box-<id>`, 12 hours; on Linux taken only from the box's relay's address) and runs
   the image with the project at `/work`, the token and the certificate read-only, as your uid, every capability
   dropped, no new privileges, pids and memory limits. What the host runs from the project on its own is read-only:
   `.git` and `.claude` always (an empty placeholder when missing), the hook frameworks' configs (husky, pre-commit,
   lefthook), every coding agent's project config Tracekit knows (one list, `agent_hooks`), `.mcp.json`, `.vscode`,
   `.idea`. A symlink among them stops `up`.
3. The box is on an internal Docker network: no internet and none of the host's services. Its one way out is its
   relay, a container that forwards the signer's port; the hooks reach `https://host.docker.internal:8443`, which is
   the relay. `--network` adds Docker's bridge: the internet (Claude Code needs it for its API and its login), and on a
   Mac every service on the host's 127.0.0.1.
4. The image's hooks are in Claude Code's managed settings with the signer's variables pinned there, and a root-owned
   `/etc/tracekit/client.json` names the signer, so a project setting can't point the hooks elsewhere.
5. You answer the box's held calls on the box signer's socket, as your uid (`approvals.approvers`); the box's token
   has no `approval_decide`.
6. When `up` exits or is stopped (SIGTERM, SIGHUP), the box and its relay are removed and the token revoked; a token
   whose `up` was killed outright is revoked by the next `up`. `up` then lists the files the box changed that the host
   may run on its own (build files, executables, workflows), and any file it copied its token into.

What the signer records, and what verify says: the signer can't tell the boxed agent from any other holder of the
box's token, and anything that runs as you on the host can read that token (or the key). So it records a box run's
isolation as `unknown`, with a signed `ext.box` naming the token (format 1.6, non-critical: a verifier that doesn't
read it claims nothing). A verifier that reads it says exactly what it proves, and no more: `PROOF AGAINST THE BOXED
AGENT: the signing key was outside its box`, not proof against a process of the signer's own user on the host.

## Limits

- **The box is only as good as what you give it.** A container started by hand with the Docker socket, your home,
  `~/.ssh`, `~/.aws`, `~/.claude` or the signer's data mounted loses the separation. `up --isolated` refuses a project
  dir that holds or sits in your home's root or a signer's files, and `tracekit doctor` checks every running box.
  Never mount `~/.claude` into a box: it holds your login and your own hooks. Log in inside the box instead
  (`--network`, then `claude`, `/login`); the login isn't kept between boxes.
- **Proof against the boxed agent only.** An agent run outside the box is in dev mode (`same-user`). Anything that
  runs as you on the host can read the box signer's key and the box's token: you are its operator. On a Mac the token
  isn't bound to an address (every connection reaches the signer from 127.0.0.1).
- **Root on the host, and root in colima's or Docker Desktop's VM, can reach the keys.** A witness on another host
  detects a rewrite of what it cosigned.
- **Code the agent writes into the project runs when you run it.** What the host runs on its own is read-only; build
  scripts, tests and other files are not. Read the files `up` lists before you build or test on the host.
- **With `--network`, the box reaches the internet and, on a Mac, the host's 127.0.0.1 services.**
- **Inside the box, the agent can still act outside its hooks** (a background process); that is contained to the
  project, and to the network with `--network`, and recorded only if it goes through a hook.
- Linux is written but not yet run.
