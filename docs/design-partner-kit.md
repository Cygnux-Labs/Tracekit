# Design-partner kit

For a team trying Tracekit on real agent work and telling us what breaks. Plan for about two weeks of light use.

## What you get and what we ask

You get a hands-on setup with the maintainers and a say in what gets built. We ask for honest findings: the
confusing moments matter as much as the bugs. Nothing leaves your machines: Tracekit has no telemetry, and
bundles are files you choose to share.

## Day 0: setup (30 minutes)

1. `pip install tracekit-ai` (or the plugin: `/plugin marketplace add Cygnux-Labs/Tracekit`).
2. Run `tracekit demo` and open the replay it writes. Confirm the tampered bundle fails.
3. Pick the mode that matches your threat. Dev mode (`tracekit init --dev`) is for trying it out: the agent's own
   user can rewrite the ledger. Linux system mode (`sudo tracekit init`) gives a separate signer user.
4. Set an off-host witness (`--witness git:/path@git@host:team/witness.git`) if you want the evidence to mean
   anything against the agent's host. [docs/witnesses.md](witnesses.md).
5. Decide privacy settings with [docs/privacy.md](privacy.md): content is hashed by default; reasoning capture is off.

## Week 1: use it

- Work normally. Run `tracekit status` daily and `tracekit export` at the end of anything you care about.
- Verify one bundle with `tracekit verify run.tkb --key signer.pub` on a different machine.
- Trigger the policy gate on purpose once (ask the agent to run `sudo id`), and once by accident if it happens.
- Try an approval: add an `ask` rule and approve from a second terminal.

## Week 2: break it

- Edit a bundle and a ledger by hand and check the verifier notices.
- Stop the signer mid-session and read what the bundle says about the gap.
- Use a tool the hooks do not see (a subprocess, a background job) and see how coverage reports it.

## What to send back

| Question | |
|---|---|
| What did the verdict say that you did not understand? | |
| Where did a warning cry wolf, or stay quiet when it should not have? | |
| Which policy rules blocked legitimate work? (rule ids) | |
| What would you need to hand a bundle to an auditor or a customer? | |
| What did you expect Tracekit to prove that it does not? | |
| What stopped you from deploying it (platform, key custody, witness, process)? | |

Send a bundle only if you are comfortable sharing it: with content capture on its default it holds hashes, tool
names and paths, not file contents or prompts. Report security problems privately (see `SECURITY.md`).
