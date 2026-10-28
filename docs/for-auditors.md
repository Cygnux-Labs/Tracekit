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
| `remote` | The agent called the signer over HTTPS with its own credential (service account, mTLS, OIDC or token). The label does not say where the signer runs; the operator's deployment does. Whoever administers the signer's host still controls its keys and log. |
| `unknown` | The report does not establish this separation. |

V2 reports show an `isolation` check line. The v1 sample below describes isolation
in `Assurance:`. Isolation alone does not establish independent assurance.

An independent witness keeps or cosigns a checkpoint: a signed summary of the log.
Once it has, a later rewrite or rollback of that history shows, even one by the signer's operator; records after
the last checkpoint it holds are not covered. A monitor (`witnessed+monitored`) also checks that no one was shown a
conflicting version. A witness does not judge the actions. Obtain trusted witness keys independently of the party
supplying the evidence.

## Check these three report lines first

1. `Integrity:` Look for exactly `Integrity: VERIFIED.` Read any extra wording:
   `open` means the run has no recorded ending, so later records may be missing, and `WITH GAPS` needs
   investigation. `FAILED` (v1: `VERIFICATION FAILED`) means a check failed; the `[FAIL]` lines say which.
   `UNVERIFIABLE` or `UNUSABLE BUNDLE` means the record could not be confirmed; the words after it say why (a newer
   verifier needed, a revoked key, a file it cannot read). Treat it as not verified.
2. `Assurance:` The sample's `dev` warns that the agent could rewrite the record.
   In v2, `dev` and `local` provide no independent checkpoint assurance.
   `witnessed` means witnesses (or public log anchors) you trust as independent cosigned the checkpoint, as many as
   your trust file requires; it can show even when isolation is `same-user`.
   `witnessed+monitored` also checks a monitor's report.
3. `coverage` (a check line above the summaries): Read its warnings about missing
   calls and unseen actions. V2's `coverage matrix` also names actions only reported or not covered.

For an audit decision, use the [auditor guide](auditor-guide.md) and
[report reference](verdicts.md), including their checks for gaps and omitted runs.

## Try the sample in two commands

Open Terminal (macOS/Linux) or PowerShell (Windows). Install [uv](https://docs.astral.sh/uv/getting-started/installation/)
with the one command its installation page gives for your system, then close the window and open a new one.
Download this repository through **Code → Download ZIP** on [GitHub](https://github.com/Cygnux-Labs/Tracekit), then
extract it. In the new window, type `cd `, drag the extracted folder containing `README.md` and `docs` into the
window, and press Enter. Paste each command separately and press Enter:

```sh
uvx --python 3.13 --from tracekit-ai==1.5.0 tracekit --version
uvx --python 3.13 --from tracekit-ai==1.5.0 tracekit verify docs/sample/demo-run.tkb --key docs/sample/signer.pub
```

The first command downloads the verifier and Python if needed, then prints its
version. The second checks the shipped v1 sample. Expect `Integrity: VERIFIED.`
and `Assurance: dev`, with warnings about key storage, harness attribution, coverage and an
older replay viewer. Its checkpoints come only from the bundle, with no independent
witness copy. The [sample notes](sample/README.md) explain these warnings.
For real evidence, obtain trusted keys independently. V2 bundles use a `--trust`
file prepared through the [auditor guide](auditor-guide.md#2-build-the-trust-config-from-independent-sources).
