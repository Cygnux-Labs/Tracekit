# One command to real separation: `tracekit up --isolated`

Status: prototype (experimental), issue #591.

Today a laptop setup ends at `isolation: same-user`: the agent runs as you, so it can read the signer's key, stop
the signer or rewrite its store. The setups that separate them take days. This note compares three ways to get a
real separation from one command, and picks one for laptops.

## The three paths

| | (a) The agent in a container, the signer outside | (b) One-command system mode | (c) A published signer image |
|---|---|---|---|
| What separates them | The container's mounts: it gets the project, a token and the signer's TLS certificate, and nothing else of the host | OS users: the signer runs as its own user, the agent as a second, non-admin user | The signer's container; the agent is wherever you run it |
| Protects against | The agent reading the key, stopping the signer, rewriting the store or policy, answering its own approvals, reaching the Docker socket, turning its hooks off | The same, measured by the socket's peer uid | Nothing on a laptop unless the agent is in a container too, which is (a) |
| What breaks it | Giving the container the Docker socket or your home; running the agent outside it; root on the host or in the Docker VM; a container escape; code the agent leaves in the project that you then run on the host | Running the agent as you, not as the second user; on a Mac you are an admin, and an admin is a password away from root; root | The registry or the image's build; whoever runs the Docker host |
| What you need | Docker (colima or Docker Desktop on a Mac, Docker Engine on Linux) | root, a second user, project files shared with it, the agent's login set up again as that user; macOS is experimental | an image release process: build, sign, publish by digest |
| First run | measured on an M-series Mac with colima, from a fresh install, the base image already pulled: 197 s for the first `up --isolated` (building the box image with Claude Code, TLS, signer start, two hooked calls); about 3 s for each later one | 10 minutes to an hour, mostly the second user (judgment, not measured) | a pull (about 50 MB), then as (a) |
| Work | a command, an image it builds on first use (Claude Code and Tracekit's hooks), a doctor check, docs | a wrapper around `tracekit init --v2 --user` that creates the user and runs the agent as it | release work; no laptop change |

## The choice: (a), the agent in a container

It is the only path that works whether or not you are an admin, needs no second user and no root, and changes
nothing in how you install Tracekit. The separation comes from what the container is given, not from users, so a
Mac admin's rights don't undercut it. (b) stays the right setup for a shared Linux host; (c) is the right setup for
servers (Compose, Kubernetes), and the image there is built from `deploy/docker/Dockerfile`.

How it works:

1. `tracekit up --isolated` sets up a signer of its own the first time, next to the dev signer's data dir
   (`<dev data dir>-box`): its keys and store, a TLS key and certificate, and a token store. It starts that signer as
   you, or reuses it. The dev signer is not touched.
2. It issues a token for this box (`token:box-<id>`, 12 hours), then runs the image with the project at `/work`,
   the token and the certificate mounted read-only, as your uid, with every capability dropped and no new
   privileges. The project's `.git` and `.claude`, when present, are mounted read-only, so the agent can't leave a
   git hook or a Claude Code hook that runs on the host later.
3. The hooks in the container reach the signer at `https://host.docker.internal:PORT` (colima and Docker Desktop
   forward it to the host's loopback; on Linux the signer listens on the Docker bridge's address). The image's hooks
   are in Claude Code's managed settings, which the agent can't change from the project.
4. You answer the box's held calls on the box signer's socket, as your uid (`approvals.approvers`); the box's token
   has no `approval_decide`, so the agent can't answer its own.
5. When the container exits, the token is revoked.

What the signer records, and why it is honest: the signer measures its caller itself. A caller that authenticates
with a token the signer issued, over its HTTPS listener, is recorded `isolation: remote`, the value Compose and central
signers already record for the same kind of caller. The container sends no isolation value, and nothing it sends
changes the label. The signer can't tell a container from any other holder of the token; it can tell that the caller
is not a process of its own user on its socket. A `container` value would need the signer to check the container
itself (its mounts, through the Docker API) when a run registers; that is left until someone needs it.

## Limits

- **The box is only as good as what you give it.** A container started by hand with the Docker socket, your home or
  the signer's data mounted loses the separation. `up --isolated` refuses a project dir that contains your home or
  the signer's files, and `tracekit doctor` checks every running box's mounts.
- **An agent run outside the box is in dev mode.** Its runs go to the dev signer and say `same-user`. Anything that
  runs as you on the host can also read the box signer's key and the box's token: you are its operator.
- **Root on the host, and root in colima's or Docker Desktop's VM, can reach the keys.** A witness on another host
  detects a rewrite of what it cosigned.
- **Code the agent writes into the project runs when you run it.** `.git` and `.claude` are read-only in the box;
  build scripts, editor tasks and other files are not. Read the diff before you run the project on the host.
- **The box reaches the network, and on a Mac the host's loopback services** (colima and Docker Desktop forward
  `host.docker.internal` to them). Don't run services on 127.0.0.1 that trust every local caller.
- **Inside the box, the agent can still act outside its hooks** (a background process); that is contained to the
  project and the network, and recorded only if it goes through a hook.
- Claude Code in the box keeps no login between boxes: log in in each one. Linux is written but not yet run.
