# A Mastra workflow on the v2 signer

Runs offline: a scripted model asks for three tool calls, so there is no API key, and the tool only pretends to run
them. Mastra's telemetry is off, so nothing is sent to Mastra.

1. **Each tool call goes through `decide` first.** The workflow's `tool` step runs once per call (`.foreach`) and asks
   the signer before anything runs: `ls infra` is allowed, `rm -rf ~` is denied (the step returns the rule ids).
2. **A held call suspends the step.** `terraform destroy` waits for a person (TK-A001): the step requests an approval
   and calls Mastra's `suspend()` with the approval id. The workflow stops there until a person answers.
3. **Resuming passes the approval id to `approval_consume`.** Once the approval is answered, `resume()` hands the step
   the approval id, and the call runs only if the signer's `approval_consume` agrees. Allowed calls go through
   `approval_consume` too, so nothing the workflow saved can let a call skip the signer.

Then the run is closed, exported, and verified with the TypeScript verifier.

Needs Node >= 22.13 (Mastra's own minimum; the Tracekit client alone needs 18) and Python with Tracekit
(`pip install tracekit-ai`); a dev signer is started on demand. From a checkout:

```sh
cd sdk/typescript && npm ci && npm run build
cd examples/mastra && npm ci     # @mastra/core 1.79.0 and zod, pinned in package-lock.json
node workflow.mjs
```

```
ls infra: (pretend) ran it
rm -rf ~: denied (TK-D004, TK-F003)
terraform destroy: held (TK-A001); the workflow is suspended. In another terminal:
  tracekit approvals approve apr-…     (or: tracekit approvals reject apr-…)
```

Answer it from another terminal, as a person (`tracekit approvals approve <id>`). The workflow resumes, runs the
approved call (a rejected one doesn't run, and the workflow still finishes) and closes its run. Export the run, then
verify it with the TypeScript verifier:

```sh
tracekit last -o mastra.tkb                                   # also writes mastra.trust.json, pinning the dev signer
node ../../bin/tracekit.mjs verify mastra.tkb --trust mastra.trust.json
```

`npx @cygnuxlabs/tracekit verify` runs the same verifier from the published package.

The suspended run's snapshot is in Mastra's in-memory store, so this process waits for the answer and resumes it. To
resume in another process, give Mastra a store that persists, and save the Tracekit run's id and token with the
workflow's run id: re-attach with `new RunHandle(new Client(), { run_id, run_token })`, as the
[Vercel AI resume example](../v2_vercel_ai_resume.mjs) does.
