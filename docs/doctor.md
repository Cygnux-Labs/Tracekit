# `tracekit doctor`

```bash
sudo tracekit doctor                 # system mode: run it as root, so it can probe as the agent's user
tracekit doctor                      # the v2 dev signer
tracekit doctor --config signer.yaml # one v2 signer, by its config
tracekit doctor --json               # [{"id", "status": "ok" | "warn" | "fail", "detail", "fix"}]
```

Doctor works out which setup it's looking at and runs the checks that apply:

- **v1 system mode:** `/etc/tracekit/client.json` names a `socket`.
- **v2 system mode:** `client.json` names a `signer` (`tracekit init --v2`). Doctor reads `/etc/tracekit/signer.yaml`.
- **v2 dev:** there's no `client.json`. Doctor checks the same-user dev signer under the `dev` profile, where things a
  dev setup can't have, like a separate user or witnesses, are warnings.
- **`--config`:** checks that signer.yaml.

Exit codes: 0 when every check is ok, 1 when any check fails, 2 when there are only warnings.

**Doctor output is advice, not evidence.** It describes the host at the moment you run it. Nothing it prints is signed,
and a verifier never reads it. What a bundle proves comes from its signatures, its checkpoints and the verifier's own
trust config (`docs/signing.md`, `docs/witnesses.md`).

`eval/e16_doctor.py` builds over 20 broken setups in temp dirs and checks that doctor flags each one. It also checks
that a clean setup passes (`make eval`).

## v2 checks

| Id | Checks | Fails or warns when | Fix |
|---|---|---|---|
| `D-CONFIG` | signer.yaml | it doesn't load, or the agent's user could change it (not root-owned, or it or a directory above it is group- or world-writable) | fix the file; `sudo chown root:root`, `chmod go-w` |
| `D-AGENT-PRIV` | the agent's user (from `client.json`) | it is root or in a sudo, wheel, admin, docker, lxd, libvirt, disk or tracekit group, so it could take over the signer (warn: no agent user known) | trace an unprivileged user |
| `D-PROCESS-BOUNDARY` | the data dir's owner | the agent's user owns it (dev profile: always a warning, because the dev signer runs as you) | system mode: `sudo tracekit init --v2 --user AGENT` |
| `D-AGENT-PROBE` | the agent's user's actual access | as that user (doctor forks and drops to its uid), it can read or write the data dir, the keys dir or a key, or write signer.yaml, the policy or `client.json` (warn: doctor isn't running as root or the agent) | `chmod o-rwx`, `go-w`; owner root or the signer's user |
| `D-CODE-TRUST` | the root-owned venv `/opt/tracekit` | a file in it, or a directory above it, isn't root-owned or is group- or world-writable, or the venv is missing | re-run init to reinstall it |
| `D-KEYS-MODE` | `data_dir` and `data_dir/keys` | either one isn't 0700, or a key isn't a 0600 file owned by the keys dir's owner (warn: doctor can't read them, so run it as root) | `chmod 700` the dirs, `chmod 600` the keys |
| `D-KEYS-DISTINCT` | `keys/log.key` and `keys/record.key` | they're the same key (warn: none yet); ok when `log_key` names a KMS key | move both away and restart the signer: new keys start a new log |
| `D-KEY-HYGIENE` | `data_dir/hygiene.json`, written by the signer on start | the signer process may dump core (RLIMIT_CORE not 0), is dumpable (Linux `PR_SET_DUMPABLE`), or could not mlock its key files (warn; also when the signer never started) | run it with `tracekit signer serve`; raise `LimitMEMLOCK` |
| `D-UNIT-HARDENING` | `tracekit-signer.service` (or the launchd plist) | a hardening directive that init writes is missing: the detail gives the score and lists the missing directives (warn) | re-run init to rewrite the service file |
| `D-HARNESS-HELPER` | `tracekit-harness-helper.service` (or its launchd plist), when signer.yaml has `harness_binding` | the file is missing, or its capability bounding set is anything but `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH` | re-run init with `--harness` |
| `D-HOOKS-PRESENT` | the agent's Claude Code settings | a tool event (PreToolUse, PostToolUse, PostToolUseFailure) has no v2 hook | re-run init |
| `D-HOOKS-VENV` | the hook commands | a hook runs a Python other than the root-owned venv's | re-run init |
| `D-HOOKS-TIMEOUT` | the PreToolUse hook's timeout | it's below the hook's approval wait (540 s), so Claude Code would kill a call that's waiting for approval | set it to 600 (re-run init) |
| `D-SIGNER-ENV` | `env.TRACEKIT_SIGNER` in the agent's settings | it names a socket other than the system one, so the hook refuses it and blocks every call | remove it |
| `D-POLICY-TRUST` | the policy signer.yaml names (else the built-in pack) | the agent's user could change it | make it root-owned in root-owned directories |
| `D-POLICY-ENGINE` | the policy, compiled by policy2 | it doesn't compile, or neither `google-re2` nor `regex` is installed | `tracekit policy lint FILE`; `pip install 'tracekit-ai[signer]'` |
| `D-DURABILITY` | `durability` | it's `ack-on-write` in a production profile, so a power loss can drop records that were already acknowledged (warn) | `durability: ack-on-fsync` |
| `D-FAIL-MODES` | `fail_modes` and `client.json` `fail_mode` | a tool class, or the system config, fails open (warn) | set them to `closed` unless an outage must not stop the agent |
| `D-WITNESS-CONFIGURED` | `witnesses` | there are none, so checkpoints aren't cosigned and assurance stays `local` (dev: warn) | add a witness (`docs/witnesses.md`) |
| `D-WITNESS-OWNERSHIP` | the witnesses' ownership classes | every witness is `operator`: the default production profile needs at least one `public`, `customer` or `tracekit` witness (dev: warn) | add a non-operator witness |
| `D-WITNESS-FRESH` | `store/witness-queue.json` against the latest checkpoint | a witness has never cosigned the latest checkpoint, or has been failing for longer than the witness gap window (300 s) (warn) | check the witness is reachable and accepts this log |
| `D-CLOCK-SKEW` | this clock against the latest cosignature timestamp | this clock is more than 300 s behind it (warn) | sync the clock (NTP) |
| `D-DATA-FS` | the data dir's file system | it's NFS, SMB/CIFS, AFP, WebDAV, 9p or FUSE, where file locking and fsync can't be trusted | put `data_dir` on a local disk |

Ids are stable. A check that doesn't apply to the setup isn't listed. For example, the dev profile has no agent-user,
venv or unit checks. If there's no service file, `D-UNIT-HARDENING` warns.

## v1 checks

| Id | Fails when |
|---|---|
| `D-SYSTEM-CONFIG` | `/etc/tracekit/client.json` is missing, unreadable, or not root-owned |
| `D-V1-SIGNER-PYTHON`, `D-V1-VENV-CONFIG`, `D-V1-RUNTIME`, `D-V1-UNIT-FILE`, `D-V1-POLICY-FILE` | the file, a file below it, or a directory above it isn't root-owned or is group- or world-writable |
| `D-V1-HOOKS` | never: lists the Tracekit hooks it found (ok) |
| `D-HARNESS-HELPER` | a harness is registered and `tracekitd-harness-helper.service` is missing or its capability bounding set is anything but `CAP_SYS_PTRACE CAP_DAC_READ_SEARCH` (fix: `sudo tracekit migrate --system`) |

Fix: re-run `sudo /usr/bin/python3 -m tracekit init --user AGENT`. For the policy, make it root-owned, then run
`sudo tracekit migrate --system`.
