# `tracekit doctor`

```bash
sudo tracekit doctor                 # system mode: run it as root, so it can probe as the agent's user
tracekit doctor                      # the v2 dev signer
tracekit doctor --config signer.yaml # one v2 signer, by its config
tracekit doctor --json               # [{"id", "status": "ok" | "warn" | "fail", "detail", "fix"}]
tracekit doctor --k8s                # inside a pod: the pod and its service account, read from the API server
tracekit doctor --k8s --manifests DIR   # rendered manifests (helm template, kustomize build) instead
tracekit doctor --config signer.yaml --issuer-key alias/tracekit-ca   # also: may this principal sign with the CA key?
```

Doctor works out which setup it's looking at and runs the checks that apply:

- **v1 system mode:** `/etc/tracekit/client.json` names a `socket`.
- **v2 system mode:** `client.json` names a `signer` (`tracekit init --v2`). Doctor reads `/etc/tracekit/signer.yaml`.
- **v2 dev:** there's no `client.json`. Doctor checks the same-user dev signer under the `dev` profile, where things a
  dev setup can't have, like a separate user or witnesses, are warnings.
- **`--config`:** checks that signer.yaml.
- **`--k8s`:** the Kubernetes checks below, of the pod doctor runs in (it needs `get` on its pod and service account) or
  of the manifests under `--manifests DIR`. With `--config` it runs that signer's checks too.

Exit codes: 0 when every check is ok, 1 when any check fails, 2 when there are only warnings.

**Doctor output is advice, not evidence.** It describes the host at the moment you run it. Nothing it prints is signed,
and a verifier never reads it. What a bundle proves comes from its signatures, its checkpoints and the verifier's own
trust config (`docs/signing.md`, `docs/witnesses.md`).

`eval/e16_doctor.py` builds over 20 broken setups, 19 broken Kubernetes deployments and 5 broken Postgres grant sets
in temp dirs (the Postgres ones on a throwaway cluster: `TRACEKIT_TEST_PG_DSN`, or `initdb` and `pg_ctl` on PATH; else
skipped with the reason) and checks that doctor flags each one. It also checks that each clean setup passes
(`make eval`).

## v2 checks

| Id | Checks | Fails or warns when | Fix |
|---|---|---|---|
| `D-CONFIG` | signer.yaml | it doesn't load, or the agent's user could change it (not root-owned, or it or a directory above it is group- or world-writable) | fix the file; `sudo chown root:root`, `chmod go-w` |
| `D-AGENT-PRIV` | the agent's user (from `client.json`) | it is root or in a sudo, wheel, admin, docker, lxd, libvirt, disk or tracekit group, so it could take over the signer (warn: no agent user known) | trace an unprivileged user |
| `D-ANALYZER-AGENT` | `analyzers` in signer.yaml, against the agent's uid | the agent's uid is listed, so it can register findings runs and sign findings about its own runs, which verifiers then label self-asserted: the agent's word about itself (warn) | remove it; run `tracekit analyze --v2` as an operator identity |
| `D-PROCESS-BOUNDARY` | the data dir's owner | the agent's user owns it (dev profile: always a warning, because the dev signer runs as you) | system mode: `sudo tracekit init --v2 --user AGENT` |
| `D-AGENT-PROBE` | the agent's user's actual access | as that user (doctor forks and drops to its uid), it can read or write the data dir, the keys dir or a key, or write signer.yaml, the policy or `client.json` (warn: doctor isn't running as root or the agent) | `chmod o-rwx`, `go-w`; owner root or the signer's user |
| `D-CODE-TRUST` | the root-owned venv `/opt/tracekit` | a file in it, or a directory above it, isn't root-owned or is group- or world-writable, or the venv is missing | re-run init to reinstall it |
| `D-KEYS-MODE` | `data_dir` and `data_dir/keys` | either one isn't 0700, or a key isn't a 0600 file owned by the keys dir's owner (warn: doctor can't read them, so run it as root) | `chmod 700` the dirs, `chmod 600` the keys |
| `D-CONTENT-VAULT` | `content` in signer.yaml and `keys/content.key` | the `content` section isn't valid (as the signer checks it), or the vault is on and its key isn't a 0600 file of the signer's user (warn: no key yet, or doctor can't read it; the vault off while runs kept before are still retained: "off, N runs still retained"). The detail says whether the vault is on and its retention | fix `content`; `chmod 600`, chown to the signer's user; erase the retained runs or keep them |
| `D-KEYS-DISTINCT` | `keys/log.key` and `keys/record.key` | they're the same key (warn: none yet); ok when `log_key` names a KMS key | move both away and restart the signer: new keys start a new log |
| `D-KMS-LOG-KEY` | `log_key: {aws_kms}`, with this host's AWS credentials | the key isn't an `ECC_NIST_EDWARDS25519` `SIGN_VERIFY` key (warn: not checked, without boto3, credentials or access) | create the log key with that spec |
| `D-KMS-ISSUER-SIGN` | `--issuer-key KEY_ID`, the record key issuer's CA key | this principal may call `kms:Sign` on it (a `DryRun` Sign succeeds); only the issuer may (warn: the answer was neither allowed nor denied) | remove `kms:Sign` on it from the signer's IAM role |
| `D-PG-SIGNER-ROLE` | `storage: {postgres}`: the role of `dsn_file`'s DSN | it is superuser or has UPDATE, DELETE or TRUNCATE on `tracekit_records`, `_registry`, `_notes` or `_anchors` (warn: not checked, without psycopg or a connection) | grant it only `tracekit.storage.postgres.GRANTS` |
| `D-PG-READER-ROLES` | every other role | one that is neither superuser nor the tables' owner can INSERT, UPDATE, DELETE or TRUNCATE a log table | give readers SELECT only |
| `D-KEY-HYGIENE` | `data_dir/hygiene.json`, written by the signer on start | the signer process may dump core (RLIMIT_CORE not 0), is dumpable (Linux `PR_SET_DUMPABLE`), or could not mlock its key files (warn; also when the signer never started) | run it with `tracekit signer serve`; raise `LimitMEMLOCK` |
| `D-UNIT-HARDENING` | `tracekit-signer.service` (or the launchd plist) | a hardening directive that init writes is missing: the detail gives the score and lists the missing directives (warn) | re-run init to rewrite the service file |
| `D-HARNESS-HELPER` | `tracekit-harness-helper.service` (or its launchd plist), when signer.yaml has `harness_binding` | the file is missing, or its capability bounding set is anything but `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH` | re-run init with `--harness` |
| `D-HOOKS-PRESENT` | the agent's Claude Code settings, and whether they enable the Tracekit plugin (`enabledPlugins`, whose hooks count); Codex's, Gemini CLI's, Cursor's, goose's, Qwen Code's, Factory Droid's and Antigravity CLI's v2 hooks and OpenCode's v2 plugin count too | a tool event (PreToolUse, PostToolUse, PostToolUseFailure) has no v2 hook, the plugin isn't enabled and no other coding agent has v2 hooks; or the plugin and init's hooks both run, so every approved call is blocked | re-run init; with both, keep one (`tracekit uninstall`, or `/plugin disable` with the plugin key the check names, e.g. `tracekit@tracekit`) |
| `D-HOOKS-EVENT` | Claude Code, Codex, Cursor, Gemini CLI, goose, Qwen Code, Factory Droid and Antigravity CLI hook commands (OpenCode's JavaScript plugin isn't checked) | a hook command doesn't name its configured event (installed before 1.2), so a pre-tool payload the hook can't read lets the call through unrecorded; a hook other than the pre-tool one blocks its event when it can't run (installed before 1.3); or, for the other coding agents, a call can run that no hook decided: no Tracekit v2 hook is on the pre-tool event, Cursor's `preToolUse` hook has no `failClosed: true`, or goose's `PreToolUse` hook has no `on_failure: "block"` (warn) | re-run init for the active mode: `tracekit init --dev --v2 --agent NAME` in dev, or `sudo tracekit init --v2 --user AGENT --agent NAME` in system mode |
| `D-HOOKS-VENV` | the hook commands | a hook isn't the command init writes for the root-owned venv: another Python, or written by init before 1.3 | re-run init |
| `D-HOOKS-TIMEOUT` | Claude Code, Codex, Cursor, Gemini CLI, goose, Qwen Code, Factory Droid and Antigravity CLI pre-tool hook timeouts (seconds; milliseconds for Gemini CLI and Qwen Code) | it's below the hook's approval wait (540 s), so the harness would kill a call that's waiting for approval (warn for the other coding agents) | re-run init for the active mode (`tracekit init --dev --v2 --agent NAME` in dev, or `sudo tracekit init --v2 --user AGENT --agent NAME` in system mode): 600 s, or 600000 ms for Gemini CLI and Qwen Code |
| `D-AGY-HOOKS-RUN` | with Antigravity CLI's v2 hooks: `"enabled"` on Tracekit's `tracekit` hook in the hooks file doctor found, the user's `~/.gemini/config/hooks.json` and the working directory's `.agents/hooks.json`; `modelProvider` in `~/.gemini/antigravity-cli/settings.json`; `enableAdc` under `userSettings` in `~/.gemini/config/config.json`; `AGY_ADC_AUTH` in doctor's environment | agy would load the hooks and never run them, so no agy call is decided or recorded and agy doesn't say so: Tracekit's hook is `"enabled": false`, or agy signs in with a Gemini API key (`"modelProvider": "gemini"`, antigravity-cli#893) or Application Default Credentials (`"enableAdc": true` or `AGY_ADC_AUTH=true`, antigravity-cli#1310) (warn). Doctor reads its own environment and working directory, which are agy's only when you run it from agy's shell | sign agy in with a Google account (remove `modelProvider: gemini`, `enableAdc` and `AGY_ADC_AUTH`), remove the `tracekit` hook from any other hooks file the check names, then re-run init for the active mode (`tracekit init --dev --v2 --agent antigravity` in dev) |
| `D-CODEX-REASONING` | `model_reasoning_summary` in the `config.toml` beside Codex's v2 hooks, with the content vault on | Codex's hooks are installed and the vault keeps each response, but the setting is unset or `none` (Codex's current models default to `none`), so its reasoning is kept sealed (warn) | `model_reasoning_summary = "auto"` at the top of `~/.codex/config.toml` (`tracekit init --dev --v2 --agent codex` adds it) |
| `D-GEMINI-THOUGHTS` | `includeThoughts` in the `modelConfigs` of the settings with Gemini CLI's v2 hooks, with the content vault on | the settings turn thoughts off, so Gemini CLI records none (warn) | remove `includeThoughts: false` (Gemini CLI includes thoughts by default) |
| `D-THINKING-SUMMARIES` | `showThinkingSummaries` in the agent's Claude Code settings files (user, project, local, managed: the last one that sets it wins, as in Claude Code), with Claude Code's hooks (init's or the plugin's) and the content vault on | Claude Code's hooks are installed and the vault keeps each transcript line, but thinking summaries are off, so Claude Code keeps the model's thinking sealed and `tracekit analyze --v2` can't read it (warn) | `"showThinkingSummaries": true` in the settings (`tracekit init --dev --v2` sets it); headless: `claude -p --thinking-display summarized` |
| `D-SIGNER-ENV` | `env.TRACEKIT_SIGNER` in the agent's settings | it names a socket other than the system one, so the hook refuses it and blocks every call | remove it |
| `D-CLAUDE-SANDBOX` | Claude Code's `sandbox` settings, shown only when they turn the sandbox on: dev mode reads the user settings, the working directory's `.claude/settings.json` and `settings.local.json`, and the managed settings; system mode the agent's `~/.claude/settings.json`, the settings file its hooks are in, and the managed ones. A later file wins each key, which is not all of Claude Code's precedence | `failIfUnavailable` isn't `true`, so Claude Code runs commands unsandboxed when the sandbox can't start and no hook sees it; or a custom proxy port is set, so Claude Code's network allowlist stops applying to that proxy's traffic (warn) | set `"failIfUnavailable": true`; remove the ports unless your proxy enforces an allowlist ([Claude Code's sandbox](integrations/claude-code-sandbox.md)) |
| `D-GEMINI-SANDBOX` | Gemini CLI's `tools.sandbox` and `security.toolSandboxing`, shown only when Gemini's settings hold Tracekit's hooks and turn a sandbox on: its system defaults, the user's `~/.gemini/settings.json`, the working directory's `.gemini/settings.json` (dev mode) or the settings file its hooks are in (system mode), and its system settings. A later file wins each key; `GEMINI_SANDBOX` or `-s` at launch and Gemini's folder trust aren't seen | `tools.sandbox` runs the whole CLI in a container, where Tracekit's hooks don't run, or under Seatbelt, where they block every call (warn) | remove `tools.sandbox` and set `"toolSandboxing": true` under `"security"` ([Gemini CLI's sandbox](integrations/gemini-sandbox.md)) |
| `D-POLICY-TRUST` | the policy signer.yaml names (else the built-in pack) | the agent's user could change it | make it root-owned in root-owned directories |
| `D-POLICY-ENGINE` | the policy, compiled by policy2 | it doesn't compile, or neither `google-re2` nor `regex` is installed | `tracekit policy lint FILE`; `pip install tracekit-ai` (a `--no-deps` install leaves the engine out) |
| `D-DURABILITY` | `durability` | it's `ack-on-write` in a production profile, so a power loss can drop records that were already acknowledged (warn) | `durability: ack-on-fsync` |
| `D-FAIL-MODES` | `fail_modes` and `client.json` `fail_mode` | a tool class, or the system config, fails open (warn) | set them to `closed` unless an outage must not stop the agent |
| `D-WITNESS-CONFIGURED` | `witnesses` | there are none, so checkpoints aren't cosigned and assurance stays `dev` (`local` when `anchors` is set) (dev: warn) | add a witness (`docs/witnesses.md`) |
| `D-WITNESS-OWNERSHIP` | the witnesses' ownership classes | every witness is `operator`: the default production profile needs at least one `public`, `customer` or `tracekit` witness (dev: warn) | add a non-operator witness |
| `D-WITNESS-FRESH` | `store/witness-queue.json` against the latest checkpoint | a witness has never cosigned the latest checkpoint, or has been failing for longer than the witness gap window (300 s) (warn) | check the witness is reachable and accepts this log |
| `D-CLOCK-SKEW` | this clock against the latest cosignature timestamp | this clock is more than 300 s behind it (warn) | sync the clock (NTP) |
| `D-DATA-FS` | the data dir's file system | it's NFS, SMB/CIFS, AFP, WebDAV, 9p or FUSE, where file locking and fsync can't be trusted | put `data_dir` on a local disk |

Ids are stable. A check that doesn't apply to the setup isn't listed. For example, the dev profile has no agent-user,
venv or unit checks. If there's no service file, `D-UNIT-HARDENING` warns.

## Kubernetes checks (`--k8s`)

A pod is checked when it runs a signer (its image is `tracekit-signer`, or its command is `signer serve`) or an agent:
a container with a `TRACEKIT_*` environment variable, or one that mounts the volume the signer mounts at its socket dir.
Other containers of a signer's pod (a mesh proxy, a vault agent) are not agents. Native
sidecars (init containers with `restartPolicy: Always`) count; other init containers don't. The signer's socket dir
and data dir are the image's, `/run/tracekit-signer` and `/var/lib/tracekit-signer`, and its user 10001.

| Id | Fails when |
|---|---|
| `D-K8S-WORKLOADS` | never; warns when a manifest doesn't parse, no pod runs a signer or agent, or doctor can't read its pod from the API server |
| `D-K8S-HOST-ACCESS` | the pod has a `hostPath` volume, `hostPID`, `hostIPC` or `hostNetwork` |
| `D-K8S-SECURITY-CONTEXT` | a signer or agent container may run as root, is privileged, has a writable root file system, allows privilege escalation, or doesn't drop `ALL` capabilities |
| `D-K8S-RUN-AS-USER` | the agent container's `runAsUser` isn't set, or is the signer's |
| `D-K8S-SHARED-VOLUME` | the agent and signer containers share a volume other than the socket dir |
| `D-K8S-SIGNER-DATA` | an agent container, in any pod, mounts what the signer mounts at its data dir (the same claim, secret, config map or host path) |
| `D-K8S-WORKLOAD-IDENTITY` | the agent's pod gets cloud credentials, which reach every container: its service account has `iam.gke.io/gcp-service-account` (GKE Workload Identity) or `eks.amazonaws.com/role-arn` (IRSA), an EKS `PodIdentityAssociation` names it, or a container has the AWS variables they inject |
| `D-K8S-SA-TOKEN` | the agent gets a service account token (automounted or projected) that has cloud identity; warns when the token has none, since only its RBAC limits it |

KMS keys in the agent's pod are the case to avoid: keep the signer that holds them central, outside the pod.

## v1 checks

| Id | Fails when |
|---|---|
| `D-SYSTEM-CONFIG` | `/etc/tracekit/client.json` is missing, unreadable, or not root-owned |
| `D-V1-SIGNER-PYTHON`, `D-V1-VENV-CONFIG`, `D-V1-RUNTIME`, `D-V1-UNIT-FILE`, `D-V1-POLICY-FILE` | the file, a file below it, or a directory above it isn't root-owned or is group- or world-writable |
| `D-V1-HOOKS` | never: lists the Tracekit hooks it found (ok) |
| `D-HARNESS-HELPER` | a harness is registered and `tracekitd-harness-helper.service` is missing or its capability bounding set is anything but `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH` (fix: `sudo tracekit migrate --system`) |

Fix: re-run `sudo /usr/bin/python3 -m tracekit init --user AGENT`. For the policy, make it root-owned, then run
`sudo tracekit migrate --system`.
