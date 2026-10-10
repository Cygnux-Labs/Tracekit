# Known limits and trade-offs

Every limit of Tracekit is written down next to the feature it belongs to, which makes it easy to miss when you read
only one page. This page collects them in one place. Each release's notes link here, and a doc that adds a "Limits"
section must be linked from this page (`tests/test_docs.py` checks it).

Each row says what the limit is, why it is so, what to do about it, and where the details are. Rows marked
**(1.1, in review)** describe behaviour in an open pull request that has not been released yet.

## Evidence and verification

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| A verified bundle doesn't prove intent. | A record says a call was made, not why. | Read decisions, approvals and reasons alongside the records. | [FAQ](faq.md#what-cant-tracekit-prove) |
| A verified bundle doesn't prove that everything the agent did was recorded. | An action that crosses no capture layer (a subprocess, code that skips the adapter, a call around a gateway that isn't mandatory) leaves no record. | Read the `coverage`, `tiers` and gap lines; add an out-of-process layer (the [LLM gateway](gateway.md), a T2 executor). | [FAQ](faq.md#what-cant-tracekit-prove), [verdicts](verdicts.md#informational-lines-always-pass) |
| A verified bundle doesn't prove that a tool result the agent reported is true. | In-process capture (T1) records what the agent's process reported; only out-of-process capture (T2) sees what crossed a boundary. | Prefer T2 evidence for calls that matter; use `executor: t2` approvals. | [FAQ](faq.md#what-cant-tracekit-prove), [approvals](approvals.md#tiers-t1-and-t2-executors) |
| Imported OpenTelemetry (T3) proves only that spans were received. | Spans are exported after the work is done, by the application. | Gate calls with an adapter or hook; treat T3 runs as a log, not evidence of completeness. | [OpenTelemetry](otel.md#receiving-traces-tier-t3-import) |
| Tracekit is tamper-evident, not tamper-proof: a deletion shows, it isn't prevented. | Prevention would need attested hardware (a TEE), which Tracekit doesn't claim. | Keep independent witnesses and a monitor so a rewrite is detected. | [FAQ](faq.md#what-cant-tracekit-prove) |
| Whoever holds the signer's key can rewrite or fork its log; nothing in the bundle alone shows it. | Signatures prove who signed, not that the key holder didn't sign again. | Pin a witness the operator doesn't run (`witnessed`) and a monitor (`witnessed+monitored`). | [server threat model](threat-model-server.md#s4-the-operator-organisation-and-the-exporter) |
| Records after the last cosigned checkpoint are unproven. | A witness vouches only for what it has cosigned. | Export after the next checkpoint; read the `log tail` warning. | [verdicts](verdicts.md#warnings---strict-exits-3), [witnesses](witnesses.md#trust-model-per-witness-type) |
| A bundle exported before its run is finalised verifies only `TO HEAD n (open)`. | The signer finalises a run a few seconds after it closes. | Re-export after `run.final`; for audits require `VERIFIED`. | [quickstart](quickstart-v2.md#4-export-and-verify), [verdicts](verdicts.md#integrity) |
| A single run's bundle doesn't show that no other run was left out. | The exporter chooses which runs to export. | Ask for the tenant's run-set bundle and require `run-set: COMPLETE`. | [auditor guide](auditor-guide.md#3-get-the-bundles) |
| A withheld key retirement isn't visible unless a run-set from registry size 0 reaches the bundle. | Only the registry log proves which `key.retire` records exist. | Check for the `retirements not proven complete` warning. | [verdicts](verdicts.md#warnings---strict-exits-3) |
| `key assurance` is `asserted` unless a record-key issuer certifies the keys. | Without an issuer the log declares its own record keys. | Run an [issuer](issuer.md) and pin it in the trust config. | [issuer](issuer.md#verifying) |
| The verifier doesn't fetch revocations. | Verification is offline and takes trust only from the verifier's side. | Pass the issuer's log with `--revocations`. | [issuer](issuer.md#limits) |
| A trust config the operator supplies proves nothing about the operator. | The bundle carries no code or trust (I9); whoever writes the trust config decides what verifies. | Build `trust.json` from independent sources and install the verifier yourself. | [auditor guide](auditor-guide.md#2-build-the-trust-config-from-independent-sources) |
| A v1 bundle verified without `--key` or `--witness` is only internally consistent (`UNANCHORED`). | A bundle carries its own public key, so a bundle forged with a fresh key is consistent too. | Pin the signer's key or an independent witness. | [laptop threat model](threat-model-laptop.md#trust-roots-for-verification) |
| v1: the exporter can replace a selected record with an elided stub, and `manifest.json` is unsigned. | v1 stubs are not bound to a run; the manifest is an index, recomputed from signed records. | Use v2 bundles; read the "run completeness unproven" warning. | [laptop threat model](threat-model-laptop.md#open-problems) |
| Record timestamps come from the signer host's clock; `seq` and the chain prove order only. | Only witnesses and RFC 3161 timestamps give independent time. | Read cosignature and anchor times in the `Assurance` line. | [laptop threat model](threat-model-laptop.md#what-each-attack-comes-to), [witnesses](witnesses.md#v2-rekor-v2-anchors-and-rfc-3161-timestamps) |
| A v1 record after a v1 → v2 bridge is reported only with `--v1-ledger`. | The frozen v1 verifier sees bridge records as ordinary gaps. | Verify bridged logs with `--v1-ledger`. | [format v2](format-v2.md#12-v1--v2-bridge) |

## Dev mode vs system mode

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| Same-user dev mode protects nothing against the agent itself. | The dev signer runs as your user, so an agent that runs commands as you can read its key, stop it, or rewrite and re-sign its store. Policy rules (`TK-D007`, `TK-D013`) are tripwires. | Use system mode, a sidecar or a central signer for anything you need to rely on; dev bundles say `isolation: same-user`. | [FAQ](faq.md#what-does-same-user-dev-mode-protect), [quickstart](quickstart-v2.md#what-dev-assurance-means) |
| `Assurance` describes checkpoint cosigning, not isolation: a same-user signer with a witness verifies as `witnessed`. | The two are independent properties. | Read `isolation` as well as `Assurance`. | [verdicts](verdicts.md#assurance), [witnesses](witnesses.md#v2-c2sp-tlog-witnesses) |
| A system-mode signer without a witness verifies as `Assurance: dev`. | Nothing outside the host shows the log wasn't rolled back. | Add a witness on another host that the operator doesn't run. | [deployment](deploy.md#what-decides-a-bundles-assurance) |
| System mode doesn't protect against root on the machine. | Root can read the key and rewrite the store. | Witnesses on another host detect a rewrite of what they cosigned. | [deployment](deploy.md#laptop-system-mode) |
| In system mode the agent can remove the hook from its own `~/.claude/settings.json`, or act outside Claude Code, with no record and no gap. | The hook lives in the agent user's settings. | Use admin-managed settings (`init --managed`, v1) or an out-of-process record (gateway). | [quickstart](quickstart-v2.md#system-mode-linux-macos-experimental) |
| Without harness binding, any process of the agent's user can write into the agent's runs or start runs of its own. | The signer knows the caller by uid; run tokens are readable by that uid. | Register the harness (`--harness`, Linux). | [quickstart](quickstart-v2.md#system-mode-linux-macos-experimental) |
| System mode requires an agent user that is not root and not in a sudo, wheel, admin, docker or similar group. | Such a user could take over the signer. | `tracekit doctor` (`D-AGENT-PRIV`) checks it. | [doctor](doctor.md#v2-checks) |
| When the transcript tailer's ACL or sudo rule can't be set up, every run records a `tailer_lost` gap instead. | The tailer needs read access to the agent's transcripts. | Fix the setup init reports. | [deployment](deploy.md#laptop-system-mode) |

## Signer and capture

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| A tool class set to fail `open` runs unrecorded while the signer is down. | It is the setting you choose when an outage must not stop the agent; the next call writes a signed gap for exactly the missed calls. | Keep `fail_modes` closed (the default); the report lists every fail-open class. | [FAQ](faq.md#what-happens-when-the-signer-is-down) |
| v1 coding-agent hooks allow a call when the payload can't be parsed or the harness is unknown. | Broken input never blocks an agent in v1. | Set `TRACEKIT_FAIL_CLOSED=1` or `fail_mode: closed`, or use the v2 hooks, which block. | [coding agents](coding-agents.md) |
| The signer can't tell a real event from a well-formed fake sent by the agent's identity. | Anything that can call the signer as the agent can submit plausible events. | Cross-check with an independent layer: the gateway (`gateway_mandatory`) or, in v1, the model proxy. | [laptop threat model](threat-model-laptop.md#two-properties-kept-apart), [signing](signing.md#what-the-signer-checks-before-signing) |
| Compromised application code can skip the adapter for some calls, and suppress in-process autotrace (L3) too. | Both run in the agent's process. | Run the LLM gateway outside the agent; read `reconcile.*` and `(L3 absent)` in the report. | [server threat model](threat-model-server.md#s2-compromised-application-code) |
| Capture layers L4–L6 are not shipped. | Out-of-process capture beyond the L3 gateway isn't built yet. | Use the [LLM gateway](gateway.md) as the out-of-process record. | [server threat model](threat-model-server.md#known-limits) |
| SDK and adapter capture is opt-in per call: only wrapped calls are seen and gated. | An adapter sees only the calls routed through it. | Wrap every tool; each integration lists what it doesn't cover. | [laptop threat model](threat-model-laptop.md#two-properties-kept-apart), [OpenAI Agents](integrations/openai-agents.md#not-covered), [MCP](integrations/mcp.md#not-covered), [Browser Use](integrations/browser-use.md#not-covered), [Claude Agent SDK](integrations/claude-agent-sdk.md#not-covered) |
| Actions inside subprocesses and background processes, and faked command output, aren't observed. | Only the command line is seen; tool results are what the harness reports. | OS-level capture (a sandbox, audit) is outside Tracekit. | [laptop threat model](threat-model-laptop.md#open-problems) |
| Nothing is recorded after the session's last hook, including transcript edits. | Nothing runs to see it. | Treat the run's end as the last observed point. | [laptop threat model](threat-model-laptop.md#open-problems) |
| Harness binding doesn't stop a process the agent starts inside the harness session, or the agent's user starting its own instance of the registered harness. | Both are legitimately below, or are, the registered program, running as the agent's user. | Run the harness under another user, or use a mandatory gateway. | [FAQ](faq.md#what-does-harness-binding-not-stop) |
| The LLM gateway's record is complete only when the agent can't reach the model around it. | The gateway sees only requests sent to it. | Let only the gateway reach the provider (network policy) and set `gateway_mandatory: true`. | [gateway](gateway.md#calling-it) |
| With `durability: ack-on-write` (the default), a power loss can drop records already acknowledged. | Acknowledging before fsync is faster. | Set `durability: ack-on-fsync` in production. | [doctor](doctor.md#v2-checks) |
| A data directory on NFS, SMB, FUSE or similar can't be trusted for locking and fsync. | Those file systems don't give the guarantees the store needs. | Put `data_dir` on a local disk (`D-DATA-FS`). | [doctor](doctor.md#v2-checks) |
| Gemini CLI tool calls carry no call id; Tracekit pairs them by tool and arguments, first in first out. | The harness doesn't send one. | None needed; be aware when reading paired results. | [coding agents](coding-agents.md) |
| Reasoning capture reads only Claude Code's transcript, and the v1 model proxy fronts only the Anthropic API. | Other harnesses use other formats and APIs. | Use the v2 gateway or OpenTelemetry for model-side cross-checks. | [coding agents](coding-agents.md) |
| v1 OTLP receiver and ingest gateway are experimental. | They are being rebuilt; they run only with `--experimental`. | Use the v2 signer's OTLP import. | [OpenTelemetry](otel.md#receiving-traces) |
| v1 OTLP policy is evaluated after the fact: a call a rule would deny is recorded as `flag`, not stopped. | Spans arrive when the work is done. | Block with hooks, an SDK `tool()` or an adapter. | [OpenTelemetry](otel.md#what-it-means) |

## Policy

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| Policy rules are tripwires that make attempts visible, not the protection itself. | They match strings; a rewording a rule doesn't anticipate isn't matched. The protection is the signer's isolation, its storage and the witnesses. | Rely on isolation and witnesses; read E3's misses. | [policy](policy-v2.md#packs-shipped), [evaluation](evaluation.md#e3-policy-gate) |
| Shell variables are not expanded and encodings are not decoded. | Static parsing can't know runtime values. | Opaque commands ask (`TK-SHELL-PARSE`); keep them held. | [policy](policy-v2.md#what-a-rule-matches-the-subject) |
| A relative path, or one with `..`, is unverifiable; rules match its certain suffix. | A symlink could redirect it. | Write path rules that also work on suffixes. | [policy](policy-v2.md#what-a-rule-matches-the-subject) |
| Path rules are matched casefolded. | The agent's file system may ignore case whatever the signer's does. | Write path rules in lower case, or with both cases of a letter. | [policy](policy-v2.md#what-a-rule-matches-the-subject) |
| Patterns must stay inside an RE2 subset. | A decision must not depend on which engine is installed. | `tracekit policy lint` rejects the rest. | [policy](policy-v2.md#patterns-the-re2-subset) |
| Without `google-re2`, a large subject can exhaust the 1 s budget: the decision denies and is marked `nondeterministic: true`, so the two engines can decide differently. | The fallback `regex` engine backtracks; RE2 is linear. | Install `google-re2` on the signer. | [policy](policy-v2.md#patterns-the-re2-subset) |
| A rule's subject over 64 KiB is never cut: the rule's own section decides. | Cutting or windowing would let content hide past the cut. | Expect large arguments to be flagged, held or denied by the matching section. | [policy](policy-v2.md#decisions) |
| URL rules read the URL text; a public name that resolves to an internal address isn't caught. | The signer doesn't resolve names. | Add network egress controls. | [Browser Use](integrations/browser-use.md) |
| The server pack's allowlists (`TK-N002`, `TK-B011`) name `example.com` until you redefine them. | Allowlists are deployment-specific. | Redefine those rules by id in your policy. | [policy](policy-v2.md#packs-shipped) |
| Cloud-SDK-shaped tools other than CLIs and MCP tools aren't covered by the cloud pack. | Their argument shapes vary. | Map them under `tools` and add rules of your own. | [policy](policy-v2.md#packs-shipped) |
| The `payment` class doesn't extract `new_payee` yet. | Not built. | Match payees with your own rules. | [policy](policy-v2.md#classes-and-fields) |
| `unless` on a whole command line could exempt a different target. | The subject holds several targets. | Use `unless` only where the subject is one target. | [policy](policy-v2.md#what-a-rule-matches-the-subject) |
| v1 rules (`tracekit/policy/default.yaml`) match raw strings, so quoted text that mentions a risky command can trip them. | The v1 engine doesn't parse commands. | Use the v2 signer's policy; add exceptions for known false positives. | [evaluation](evaluation.md#e3-policy-gate) |

## Provenance (1.1, in review)

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| **(1.1, in review)** Provenance matches values verbatim: a value the model paraphrases, splits or re-encodes reads as a new value. | It is a tripwire on the commonest way injected instructions act, not information-flow control. | To prevent the flow, use information-flow control (CaMeL, FIDES) in the agent. | [policy](policy-v2.md#provenance-untrusted-and-from-untrusted) |
| **(1.1, in review)** Only untrusted tools' results and observed inputs are indexed: a page fetched with a tool the policy doesn't list as untrusted (`curl` in a shell) isn't seen. | Results of other tools can echo the agent's own arguments, so they aren't counted either way. | List such tools under `untrusted`, or observe the content with `run.observe`. | [policy](policy-v2.md#provenance-untrusted-and-from-untrusted) |
| **(1.1, in review)** Only an input observed as trusted makes a value trusted: a value from your own data that also appears in untrusted content (a customer's address from the CRM that is also in their ticket) is held. | Counting other tool output as trusted could launder an injected value. | Observe the record you looked up as `trusted`, or answer the hold. | [policy](policy-v2.md#provenance-untrusted-and-from-untrusted) |
| **(1.1, in review)** After a signer restart a run's provenance is `unavailable`, and `from: untrusted` rules don't match for the rest of that run. | The index lives in memory only. | Watch `provenance_state` on decisions; keep other rules for those calls. | [policy](policy-v2.md#provenance-untrusted-and-from-untrusted) |
| **(1.1, in review)** Past 20,000 values a run's index is `truncated`, and `from: untrusted` rules don't match for the rest of that run. | The index is bounded per run. | Same as above; split very long runs. | [policy](policy-v2.md#provenance-untrusted-and-from-untrusted) |

## Approvals

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| In dev mode (no `approvals` section) the requester can answer its own approval. | The dev signer has no separate approver. | Configure `approvals: {approvers: [...]}`; such answers cap assurance at `dev` and show `approvals: self`. | [approvals](approvals.md#who-may-answer) |
| A T1 approval binds the arguments the agent reported, and the agent's process runs the call. | The adapter runs in the agent. | Use `approval: {executor: t2}` so an executor outside the agent runs the approved arguments. | [approvals](approvals.md#tiers-t1-and-t2-executors) |
| Approvers answering through the web viewer or Slack are vouched for by the bridge (`attested: false`). | The signer authenticates the bridge, not the person. | Grant `approval_decide_on_behalf` only to bridges you run; read `via` on each approval. | [approvals](approvals.md#web-approvals-and-passkeys), [approvals](approvals.md#slack) |
| The signer takes the bridge's word for who registers a passkey, and keeps a person's first passkey. | It has no proof of its own of the person behind a session. | Have each approver register right after onboarding; check `passkeys.json` against the approver list. | [approvals](approvals.md#web-approvals-and-passkeys) |
| Break-glass answers aren't available through Slack. | Break-glass needs a reason and a direct identity. | Answer break-glass approvals from the CLI. | [approvals](approvals.md#slack) |
| After a restart the Slack bridge posts the approvals still pending again. | It keeps which messages it posted in memory. | Expect duplicate messages after a restart. | [approvals](approvals.md#slack) |
| An approval expires one hour after it was requested. | Nothing should consume a stale approval. | Answer within the hour, or request again. | [approvals](approvals.md#expiry-and-abandon) |
| An adapter without saved state (MCP, Browser Use, the Claude Agent SDK hook) holds a call while waiting; the wait doesn't survive the process, and a long wait ends in a denial. | There is no resumable state to carry the approval. | Answer within the adapter's wait; use a framework with saved state for long waits. | [MCP](integrations/mcp.md#not-covered), [Claude Agent SDK](integrations/claude-agent-sdk.md#not-covered) |
| OpenAI Agents' `LocalShellTool` and `ApplyPatchTool` can't wait for an approval: an `ask` for them is refused. | The SDK gives no approval hook for them. | Allow or deny them by policy. | [OpenAI Agents](integrations/openai-agents.md#not-covered) |
| v1 approvals name the held call, not its exact arguments. | v1 approvals predate argument binding. | Use the v2 signer, which binds approvals to the exact arguments. | [laptop threat model](threat-model-laptop.md#open-problems) |

## Witnesses and monitor

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| A witness you run yourself (`operator` class) gives only `Assurance: local`. | Whoever runs the stack runs the witness too. | Have someone else run a witness (`customer`, `public`) on infrastructure you can't change. | [deploy compose](deploy-compose.md#what-witnessed-needs) |
| Witness classes come from the verifier's judgement, never from the bundle. | The bundle's producer can't vouch for its own witnesses. | Get each witness key from the witness's operator. | [auditor guide](auditor-guide.md#2-build-the-trust-config-from-independent-sources) |
| A git witness without a remote, or a file witness on the same host, adds little. | Whoever controls the host can rewrite it. | Use a remote with a protected branch, or storage the host can't rewrite. | [witnesses](witnesses.md#trust-model-per-witness-type) |
| An unreachable witness delays cosigning; the gap is signed, not prevented. | The signer can't force a witness to answer. | Watch `witness_failed` gaps and `tracekit_signer_witness_lag_records`. | [witnesses](witnesses.md#v2-c2sp-tlog-witnesses) |
| The v1 Rekor witness is experimental, off by default and not run against the live service. | It is tested offline only. | Treat its first real run as validation. | [witnesses](witnesses.md#rekor-experimental) |
| Rekor entries are public and permanent and reveal activity timing; the publishing key links a signer's anchors. | Rekor is a public transparency log. | Use Rekor only where that is acceptable. | [witnesses](witnesses.md#v2-rekor-v2-anchors-and-rfc-3161-timestamps) |
| Rekor v2 anchoring needs a signing config that lists a Rekor v2 log; the TUF files are pinned local copies, not fetched. | Production Sigstore may not list one yet; TUF fetching isn't built. | Start on staging; refresh the files when Sigstore rotates a shard. | [witnesses](witnesses.md#v2-rekor-v2-anchors-and-rfc-3161-timestamps) |
| macOS's system `openssl` (LibreSSL) can't verify the RFC 3161 timestamps. | It fails on their ESSCertIDv2 attribute. | Use OpenSSL 3 or `tracekit verify`. | [witnesses](witnesses.md#v2-rekor-v2-anchors-and-rfc-3161-timestamps) |
| A monitor sees the log the signer serves it: a split view shows only at equal tree sizes, or to witnesses. | A smaller checkpoint isn't proven consistent with the report's tree. | Run monitors and witnesses the operator doesn't control. | [server threat model](threat-model-server.md#known-limits) |
| A monitor the operator controls vouches for nothing, and a monitor report never raises `dev` or `local`. | Monitoring adds to independent witnessing, it doesn't replace it. | Run it somewhere the operator can't change; pin it as non-`operator`. | [monitor](monitor.md#verifying-with-it) |
| With an issuer, the monitor flags each `signer.epoch` after seq 0 as an unannounced key. | Rotating kids can't be listed in advance with `--allow`. | Expect those conflicts until the monitor can pin issuers. | [issuer](issuer.md#limits) |
| A Rekor entry the signer wrote but got no reply for shows as a monitor conflict. | It matches no stored anchor. | Check the signer's `witness_failed` gaps for that outage first. | [monitor](monitor.md#what-it-checks) |
| The issuer handles one issuance at a time and re-reads its log for each. | Fine at record-key volumes. | Past ~100k certificates it needs an index. | [issuer](issuer.md#limits) |
| If the issuer can't be reached at start, the signer doesn't start; records signed after a key's `not_after` fail verification. | Certificates are short-lived. | Keep the issuer available; watch renewals. | [issuer](issuer.md#the-signer) |

## Privacy

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| Commands, paths, URLs and search queries are recorded in clear (after redaction). | A reviewer needs to see what the agent acted on. | Deny sensitive patterns in policy, or keep bundles internal. | [privacy](privacy.md#what-hashes-and-metadata-still-leak) |
| Redaction is pattern-based and misses secrets it doesn't recognise. | It can only match known shapes. | Deny the pattern in policy, or keep bundles internal. | [privacy](privacy.md#redaction-patterns) |
| v1 hashes are unsalted, so low-entropy content (a short prompt, a known file) can be confirmed by hashing guesses. | Reviewers can match known files. | Use the v2 signer, which publishes salted commitments. | [privacy](privacy.md#what-hashes-and-metadata-still-leak) |
| Sizes, timing and correlation still leak: the same file in two runs links them. | Hashes and commitments hide content, not activity. | Treat bundles as activity records. | [privacy](privacy.md#what-hashes-and-metadata-still-leak) |
| `content_capture: full` stores content (redacted) in the log and in bundles. | Readable content is what the setting is for. | Protect such bundles as you would the data. | [privacy](privacy.md#content-capture-hashed-or-full) |
| Revealing a v2 record's salt lets anyone holding the content check that record's commitments. | That is how an auditor checks content; one salt opens one record. | Reveal only the records an audit needs. | [privacy](privacy.md#the-v2-signer) |
| A run-set bundle carries the tenant's registry salt, so it allows testing guessed run ids against that tenant's leaves. | The verifier needs the salt to check completeness. | Share run-set bundles only with that tenant's auditors. | [auditor guide](auditor-guide.md#3-get-the-bundles) |
| With `serve_records: true` the metrics port serves every tenant's records (run ids, tool names, commitments). | The monitor reads every record. | Expose that port only to the monitor. | [monitor](monitor.md#run-it) |
| Witnesses learn when checkpoints happen and how many records exist. | That is what they cosign. | Choose witnesses accordingly. | [privacy](privacy.md#what-hashes-and-metadata-still-leak) |

## Deployment

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| A sidecar doesn't protect against whoever administers the node or the PVC. | They can reach the signer's volume. | A witness off the node detects rollback. | [deployment](deploy.md#container-and-kubernetes-sidecar) |
| A KMS log key doesn't belong in the agent's pod. | Workload identity gives the pod's cloud credentials to every container, the agent's too. | Keep KMS keys on a central signer (`D-K8S-WORKLOAD-IDENTITY`). | [deployment](deploy.md#container-and-kubernetes-sidecar), [doctor](doctor.md#kubernetes-checks---k8s) |
| The sidecar chart runs one replica with the `Recreate` strategy. | The signer holds its data volume's storage lock. | Size the pod for the agent's load. | [Kubernetes](deploy-kubernetes.md#sidecar) |
| `persistence.enabled: false` keeps the log in an emptyDir that dies with the pod. | It is for development. | Keep persistence on outside development. | [Kubernetes](deploy-kubernetes.md#sidecar) |
| The sidecar's NetworkPolicy covers the whole pod, the agent's ports included. | NetworkPolicy selects pods, not containers. | Account for it when the agent serves ports. | [Kubernetes](deploy-kubernetes.md#sidecar) |
| Central: scaling down closes the last replica's log for good, and that ordinal needs a new log before it runs again. | Each replica is the only writer of its own log. | Leave `autoscaling.scaleDown` off unless you plan for it. | [Kubernetes](deploy-kubernetes.md#central) |
| Central: calls that name no run or approval reach one replica. | Runs are routed by their replica prefix. | List each replica's approvals through its own Service. | [Kubernetes](deploy-kubernetes.md#central) |
| Central and compose don't protect against an operator with no independent witness and monitor, or against the cloud provider. | Detection needs both; the provider is out of scope. | Add both; keep witnesses on other parties' infrastructure. | [deployment](deploy.md#central), [server threat model](threat-model-server.md#s6-cloud-provider) |
| On compose, root on the Docker host is the operator. | It controls every container and volume. | Use an independent witness. | [deployment](deploy.md#compose) |
| The compose stack's first start writes a `degraded_unanchored` gap. | The witness doesn't know the log yet. | Expected once; check later gaps. | [deploy compose](deploy-compose.md#the-witness) |
| The compose end-to-end test runs only where Docker and root (or passwordless sudo) are available; elsewhere it is skipped. | It brings up the real stack. | Run `deploy/compose/e2e.sh` on a Docker host before relying on a change. | [deploy compose](deploy-compose.md#end-to-end-test) |
| `tracekit doctor` output is advice about the host, not evidence. | Nothing it prints is signed or read by a verifier. | Rely on the bundle and the verifier's trust config. | [doctor](doctor.md) |

## Viewer

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| The viewer's verdicts are operator-side, not evidence. | The viewer runs on the operator's side. | Download the bundle and verify it with your own verifier and trust config. | [viewer](viewer.md#pages-and-api) |
| v2 records keep a call's arguments only as a salted commitment, so the viewer shows rule reasons, not arguments; for other policies, only rule ids. | Records never hold arguments. | Ask for `tracekit signer reveal` on the record when an audit needs it. | [viewer](viewer.md#laptop-viewer) |
| A run that fails verification shows only its failure report. | Records of a failed run aren't shown as if they were evidence. | Investigate with `tracekit verify`. | [viewer](viewer.md#pages-and-api) |
| A run stays `PENDING` until a checkpoint covers its last record. | The verdict needs a checkpoint. | Wait for the next checkpoint. | [viewer](viewer.md#laptop-viewer) |
| The viewer's printed token is one operator credential over every tenant's runs. | It is the local operator's access. | Use OIDC roles for auditors and approvers. | [viewer](viewer.md#who-sees-what) |
| The timeline is scaled to the calls shown, not the clock. | It shows sequence, not duration. | Read times from the records. | [viewer](viewer.md#laptop-viewer) |

## Platforms

| Limit | Why it is so | What to do | Details |
|---|---|---|---|
| Windows: dev mode only, with no caller attestation; v1 approvals are refused. | Python exposes no peer-credential or process-tree call there. | Point the witness at storage the agent's user can't rewrite. | [platforms](portability.md#windows) |
| macOS system mode is experimental and not validated on hardware. | `launchd` and user creation are unit-tested with mocks only. | Use `--experimental-macos` knowingly; Linux for production. | [platforms](portability.md#macos-system-mode) |
| Harness binding works on Linux system mode only. | It reads the process tree from `/proc`. | Use a separate user or a gateway elsewhere. | [platforms](portability.md) |
| The Claude Code plugin's hooks don't run on Windows, and managed settings aren't wired up there. | The wrapper is POSIX shell. | Use `tracekit init --dev` on Windows. | [platforms](portability.md) |
| CI blocks merges on Linux only; macOS and Windows jobs are advisory. | Root-only and `/proc` tests need Linux. | Treat a green macOS or Windows run as advisory. | [platforms](portability.md#what-tested-means-here) |
| The committed performance numbers are from one macOS machine with `--quick`; the latency gate is enforced on Linux only, and that run missed it. | Linux is where the gates run. | Run `make eval` or `eval/e9_signer_perf.py` on your own hardware. | [FAQ](faq.md#how-much-does-it-slow-an-agent-down) |
| Not measured: a separate-user signer's throughput, the HTTPS transport, cross-host throughput, adversarial-model bypasses, Windows and macOS system mode, an external review. | Not built or not run yet. | Measure what you depend on. | [evaluation](evaluation.md#what-is-not-measured) |
| The LangChain, MCP and OpenAI Agents adapters need Python 3.10 or newer. | Their frameworks require it. | Use Python 3.10+ for those adapters. | [platforms](portability.md#python-versions), [MCP](integrations/mcp.md#install) |
| The threat models haven't been reviewed by anyone outside the project yet. | Issue #1 tracks the review. | Read the [review packet](review-packet.md). | [laptop threat model](threat-model-laptop.md#open-problems) |
