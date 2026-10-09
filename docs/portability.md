# Platforms

| | Linux | macOS | Windows |
|---|---|---|---|
| `tracekit verify`, `export`, replay, observer | supported | supported | supported |
| Dev mode (`init --dev`, same-user signer) | supported | supported | supported (TCP + token) |
| System mode (signer as a separate OS user) | supported | **experimental** | not available |
| Caller attestation (who connected to the signer) | `SO_PEERCRED` | `LOCAL_PEERCRED` + `LOCAL_PEERPID` | none: events are labelled unattested |
| Process-tree check for approvals | `/proc` | `ps(1)` | none: approvals are refused |
| Harness binding (`init --harness`) | system mode | not available | not available |
| Managed Claude Code settings | `/etc/claude-code/` | `/Library/Application Support/ClaudeCode/` | not wired up |
| Hooks via the Claude Code plugin | supported | supported | no (the wrapper is POSIX shell) |

## What "tested" means here

The CI workflow runs the whole suite on Linux, macOS and Windows (Python 3.9, 3.12, 3.13). The macOS and Windows
jobs are `continue-on-error`, so a failure there is visible but does not block a merge. Two more Linux jobs block
merges: the root-only tests, and E8 (insider attacks against a real system-mode signer, docs/evaluation.md).

Tested locally:

- Linux, Python 3.11 to 3.13: the full suite, plus a real separate-user signer.
- macOS 26 on Apple silicon, Python 3.9.6: the full suite (174 passed, 5 skipped for Linux-only cases), the demo,
  and a real `LOCAL_PEERCRED` / `LOCAL_PEERPID` lookup on a Unix socket.

Not tested on real hardware: macOS system mode (`launchd`, `dscl` user creation, which is unit-tested with mocks and
is why it needs `--experimental-macos`), Windows, and the Claude Code plugin loading inside a live Claude Code.

## macOS system mode

```bash
sudo tracekit init --experimental-macos --user "$USER"
```

It creates a hidden `_tracekit` account (a free id in 200-399, shell `/usr/bin/false`), generates the signing key as
that account, writes `/Library/LaunchDaemons/dev.tracekit.tracekitd.plist` and loads it with `launchctl bootstrap`.
Things to check on first use, because they depend on the machine:

- The Python interpreter and the `tracekit` package must be readable by `_tracekit`. A Python under your home
  directory is not, and the daemon will fail to start; look at `/var/lib/tracekit/tracekitd.log`.
- `tracekit status` should show `signer_isolation: separate-user` and the ledger owned by `_tracekit`.
- A quick isolation test: `echo x >> /var/lib/tracekit/ledger/ledger.jsonl` as your own user must fail.

If any of that is wrong, please open an issue with the output. Until it has been validated on hardware the
documentation treats macOS system mode as unproven.

## Windows

Dev mode only. The signer listens on `127.0.0.1` with a random port and a token kept in the client config, since
Windows has no peer-credential call that Python exposes. Because the signer shares the agent's user, a Windows
deployment's evidence is only as strong as its witness: point `--witness` at a repository or share the agent's user
cannot rewrite (docs/witnesses.md).

## Python versions

3.9 to 3.13 are declared. A static check finds nothing newer than 3.7 in the package, and CI is set up to run 3.9, but
3.9 has not been executed yet. The LangChain adapter's tests need Python 3.10 or newer (LangChain's own requirement)
and are skipped on 3.9.
