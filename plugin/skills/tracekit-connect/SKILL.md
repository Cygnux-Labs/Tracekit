---
name: tracekit-connect
description: Connects this machine's Tracekit to the team's Tracekit Cloud space with `tracekit connect` (Tracekit 1.7.1 or later), so the team sees each finished run's signed records in one place. Use when the person asks to connect to Tracekit Cloud, share runs with their team, or check, pause or stop that connection. The person runs connect and approves it in their browser; the agent checks, explains and hands over the commands.
---

# Connect to Tracekit Cloud

`tracekit connect`, new in Tracekit 1.7.1, links this machine's Tracekit signer to the team's Tracekit Cloud space.
A person signs in and approves it in a browser; from then on, each finished run's signed records go to that space.
Prompts, code, file contents, command output and keys stay on this machine. What follows describes connect as its
help does; where the help on this machine says otherwise, follow the help.

**The fixed rule.** You never approve, reject or change a held call, and never change Tracekit's policy, signer,
hooks or files. When a call is held, give the person the exact command from the message (`tracekit approvals approve
<id>`, or `reject`) to run themselves, and wait for their answer. Tracekit enforces this too: its policy blocks an
agent's own approval (TK-D012) and any change to its files (TK-D007).

Where the records go is the person's choice, so the person runs every `tracekit connect` command, `--status`
included. You don't run it, not even with `--help`.

## 1. Check that this Tracekit has it

```bash
tracekit help connect
```

- It prints `usage: tracekit connect …`: go on, and read that usage for the exact options.
- It says there is no command named `connect`: tell the person, in one line, "Connecting to Tracekit Cloud needs
  Tracekit 1.7.1 or later; this machine has <what `tracekit --version` prints>." Give them the upgrade command
  (`pip install -U tracekit-ai`, or `uv tool upgrade tracekit-ai`) and stop.
- `tracekit` isn't found: Tracekit isn't installed. Offer the tracekit-setup skill first.

## 2. Say what will happen

Tell the person, before they run anything:

1. They run `tracekit connect` in their own terminal. If the usage line takes a URL, it is their team's Cloud
   address; ask them for it rather than guess.
2. It prints this signer's key fingerprint, a link and a code, then waits.
3. They open the link, sign in to the team's space, check that the page shows the same fingerprint, and approve.
4. After that, a small background service (`tracekit sync`) sends each finished run's signed records to the space,
   and the space cosigns the signer's log checkpoints, so a later rewrite of the log would show.

What leaves the machine, as connect's help and the Tracekit docs describe it: each finished run's signed records, with
the agent's name, the person's OS user id, the tools called, each decision and its rule, times, sizes, model names and
token counts, gaps, and hashes in place of every argument, result and prompt. What never leaves: prompts, code and file
contents, commands and their output, the signing keys. Nothing is sent before the person approves.

## 3. Hand over the commands

Give the person the first command ready to paste, with the address filled in, and the others for later:

- `tracekit connect <their team's Cloud address>`: connect, as the usage line shows (`--label NAME` names this
  machine on the approval page).
- `tracekit connect --status`: what is connected, and when sync last sent.
- `tracekit connect --pause`, then `--resume`: stop sending for a while.
- `tracekit connect --off`: disconnect; removes the token and the sync service.

When they say it's done, ask what `tracekit connect --status` printed and explain it in plain words. Runs from before
the connection are sent too. After `--off` the team space keeps what it already received; its owner can delete it.
