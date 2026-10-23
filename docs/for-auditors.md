# Tracekit for auditors

A `.tkb` file packages recorded actions, digital signatures and supporting evidence
from an agent run. The signer is the service that signs these records. `VERIFIED`
means the records passed the verifier's checks against the keys you trust. It does
not prove correct behaviour, true reported results, or capture of every action.
A replacement signed with a stolen key needs evidence held elsewhere to detect.

## Who could change the record?

| Isolation | What it means for trust |
|---|---|
| `same-user` (dev mode) | The agent and signer share a computer account. The agent could read the signing key and replace the record. |
| `separate-user` | A different computer account separates the signer from the agent. Administrators can still reach its keys. |
| `remote` | The signer runs on another machine. Its administrators still control its keys and log. |
| `unknown` | The report does not establish this separation. |

V2 reports show an `isolation` check line. The v1 sample below describes isolation
in `Assurance:`. Isolation alone does not establish independent assurance.

An independent witness keeps or cosigns a checkpoint: a signed summary of the log.
With monitoring, it helps expose later rewrites or conflicting versions, even by
its operator. It does not judge the actions. Obtain trusted witness keys independently
of the party supplying the evidence.

## Check these three report lines first

1. `Integrity:` Look for exactly `Integrity: VERIFIED.` Read any extra wording:
   `open` means no recorded ending, and `WITH GAPS` needs investigation.
   Failure means a check failed. `UNVERIFIABLE` or `UNUSABLE BUNDLE` means the verifier cannot decide.
2. `Assurance:` The sample's `dev` warns that the agent could rewrite the record.
   In v2, `dev` and `local` provide no independent checkpoint assurance.
   `witnessed` needs witnesses you trust as independent, even if isolation is `same-user`.
   `witnessed+monitored` also checks a monitor's report.
3. `coverage` (a check line above the summaries): Read its warnings about missing
   calls and unseen actions. V2's `coverage matrix` also names actions only reported or not covered.

For an audit decision, use the [auditor guide](auditor-guide.md) and
[report reference](verdicts.md), including their checks for gaps and omitted runs.

## Try the sample in two commands

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) for your
operating system. Download this repository through **Code → Download ZIP** on
[GitHub](https://github.com/Cygnux-Labs/Tracekit), then extract it.
Open Terminal (macOS/Linux) or PowerShell (Windows).
Type `cd `, drag the extracted folder containing `README.md` and `docs` into the
window, and press Enter. Paste each command separately and press Enter:

```sh
uvx --python 3.13 --from tracekit-ai==1.4.1 tracekit --version
uvx --python 3.13 --from tracekit-ai==1.4.1 tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub
```

The first command downloads the verifier and Python if needed, then prints its
version. The second checks the shipped v1 sample. Expect `Integrity: VERIFIED.`
and `Assurance: dev`, with warnings about coverage, key storage and an older
replay viewer. Its checkpoints come only from the bundle, with no independent
witness copy. The [sample notes](sample/README.md) explain these warnings.
For real evidence, obtain trusted keys independently. V2 bundles use a `--trust`
file prepared through the [auditor guide](auditor-guide.md#2-build-the-trust-config-from-independent-sources).
