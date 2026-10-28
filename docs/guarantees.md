# What Tracekit guarantees

Tracekit makes a record of what an agent did that can't be changed without the change showing, and that anyone can
check offline. How much of the agent's activity that record holds, and who could have rewritten it, depends on where
the signer runs. This page says, per deployment, what you can rely on and what you can't. Every limit, with what to do
about it, is in [limits](limits.md). How this evidence bears on the EU AI Act, ISO/IEC 42001, the NIST AI RMF and
OWASP's lists: [compliance mapping](compliance/README.md).

## Everywhere

- **A verified bundle proves the records weren't changed since they were signed and checkpointed.** It does not prove
  intent, that every action was captured, or that a tool result the agent reported was true
  ([FAQ](faq.md#what-cant-tracekit-prove)).
- **A record doesn't stop an action.** Every path the agent is allowed to use, the model gateway included, can carry
  data out or carry instructions in, hidden in ordinary requests. Tracekit records those requests exactly. It doesn't
  flag what they mean.
- **Policy rules are tripwires.** They match text, tool names and extracted fields; a determined agent can reword a
  command ([policy](policy-v2.md)). The protection is a signer the agent can't reach.
- **Without an independent witness, the key holder can rewrite history**, and a cut-off tail shows nothing. No public
  witness runs yet, so `witnessed` needs a witness you or a partner run
  ([witnesses](witnesses.md#the-public-witness)).

## Dev mode (`tracekit up`, `tracekit.instrument()`, `tracekit init --dev --v2`)

The signer runs as your user, the same user as the agent.

| You can rely on | You can't |
|---|---|
| A record of every call the hooks and adapters report, decided against the policy before it runs. | Anything against the agent itself: it can read the key, stop the signer, and rewrite and re-sign the store. Every report says `isolation: same-user`. |
| A bundle that fails verification if someone edits it after export. | That the hooks stayed installed: they live in the agent's own settings. |

Dev mode is for trying Tracekit and watching your own agent. It is not protection
([limits](limits.md#dev-mode-vs-system-mode)).

## Linux system mode (`tracekit init --v2 --user AGENT` as root)

The signer runs as its own OS user from a root-owned install. The agent runs as another, unprivileged user.

| You can rely on | You can't |
|---|---|
| The agent can't read the signing key or rewrite the store; edits to the store become signed tamper records. | That every action was reported: the agent can remove the hook from its own settings, or act outside its harness, and leave no record and no gap ([limits](limits.md#dev-mode-vs-system-mode)). |
| Calls of a fail-closed class are blocked, not run unrecorded, while the signer is down. | That an event came from the real harness and not from the agent's own process: anything that can call the signer as the agent can send well-formed fakes ([limits](limits.md#signer-and-capture)). |
| With a witness on another host, a rewrite of witnessed history is detected. | Processes, files and environment reads inside a command: only the command line is seen, unless a Tetragon or Falco [import](integrations/tetragon.md) (experimental) covers the run, which signs the processes, connections and file writes the sensor saw, as the sensor's word. Nothing captures environment reads or services (L5) yet. |

macOS system mode is experimental; Windows has dev mode only ([support](support.md)).

## A mediated deployment

The agent's host holds no secrets: no provider keys, cloud credentials or tokens. Its only route out goes through
Tracekit's [LLM gateway](gateway.md), [tool executor](executor.md), [MCP gateway](mcp-gateway.md) and
[egress observer](egress.md), enforced outside the host (network policy, security groups), not by the host's OS. All
of these services are experimental.

| You can rely on | You can't |
|---|---|
| Model calls, credentialed actions and MCP calls are recorded by services outside the agent, even if the agent controls its own machine: the credentials it would need live only in those services. | That the route really is the only one: the coverage matrix's `enforced` is the operator's assertion, recorded as not attested ([egress](egress.md#posture)). |
| Network connections are recorded by host, port and bytes; a host no call explains is a signed `reconcile.unexplained_effect`. | What was inside a connection: the egress observer doesn't intercept TLS. |
| An edited tool result for a call the signer already completed, or one sent before its call completed, is a signed `reconcile.result_mismatch`, and one the gateway didn't compare (past what it digests per request) a signed `capture.gap{result_unchecked}`, when signer.yaml sets `verify_tool_results` ([gateway](gateway.md#verified-tool-results)). | Text the agent adds outside tool results, tool calls it writes into the history itself, and covert content in allowed requests, including requests to the model itself ([limits](limits.md#signer-and-capture)). |

## Outside every deployment

- **Things the agent creates:** a CI workflow, a scheduled job, a cloud function, an OAuth app or API key. Tracekit
  records the call that creates it, and a policy can hold that call for a person. It does not follow what the thing
  does later on someone else's infrastructure.
- **People:** an agent can persuade the person who approves its held calls, or someone who acts for it outside any
  record. A person's actions carry no record unless they go through Tracekit too.
- **The machine under the signer:** root on the signer's host, the cloud provider and the hypervisor are outside the
  threat model ([server threat model](threat-model-server.md#s6-cloud-provider),
  [laptop threat model](threat-model-laptop.md)). An agent that escapes its VM reaches the host's network directly.

## Not yet

- A public witness.
- Capture of services (L5), and of processes and files beyond the experimental kernel sensor import (Linux,
  Tetragon or Falco), which is recorded but not reconciled against the calls.
- Hooks the agent can't remove in v2 system mode.
