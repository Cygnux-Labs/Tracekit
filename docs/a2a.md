# A2A gateway

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

`tracekit a2a-gateway serve` is a reverse proxy for configured A2A (Agent2Agent, JSON-RPC over HTTP) servers. Send requests to it instead of to the receiver. It asks the signer before forwarding a request, holds an `ask` for a person, uses credentials held only by the gateway, and records the result as `source: gateway`, tier T2. If the signer is unavailable, it forwards nothing.

The gateway is planned as Tracekit's A2A binding of PCM 0.1 (spec published separately); today it does not check PCM parts. A PCM part in an A2A message has media type `application/vnd.pcm+json`.

```bash
tracekit a2a-gateway serve --config a2a-gateway.yaml
```

## Configure

```yaml
http:
  listen: 0.0.0.0:8092
  cert: tls/a2a.pem
  key: tls/a2a.key
  authenticators: [mtls, k8s_sa, token]
signer: https://signer.internal:8443
approval_wait_s: 300
max_body: 1048576
upstreams:
  - name: researcher                 # [a-z0-9-]{1,64}
    url: https://researcher.internal/a2a
    card: https://researcher.internal/.well-known/agent-card.json
    headers: {authorization: secrets/researcher.header}
```

Paths are relative to the config file. The gateway reads every Agent Card at startup and refuses to start if it cannot read one. It refuses plain HTTP beyond loopback before it fetches a card. It reaches the signer as itself (`TRACEKIT_SIGNER_TOKEN_FILE`, or `TRACEKIT_SIGNER_CERT` and `_KEY`); grant that identity as a gateway:

```yaml
gateways: ["mtls:spiffe://acme.org/tracekit-a2a-gateway"]
authorize: {"mtls:spiffe://acme.org/tracekit-a2a-gateway": [decide, complete, approval_request, approval_wait, approval_consume, observe]}
```

## Policy

`coding.yaml` maps `a2a:*` to class `a2a`; `dev.yaml`, `server.yaml` and `strict.yaml` extend it. A policy composed only from `server.yaml`'s component packs needs that mapping itself. `server.yaml` and `strict.yaml` ask for every A2A call. To let an approved pair through unattended, a deployment replaces the inherited `TK-S011` ask rule by id with an equivalent route allowlist; a deny rule's `unless` only exempts that deny rule.

| Field | Meaning |
|---|---|
| `sender`, `receiver` | The authenticated caller and configured upstream name. |
| `route` | `sender->receiver`. A transfer adds ` via projector`. |
| `skills` | Sorted skill ids offered by the receiver's Agent Card. |
| `kinds`, `hosts` | Message part kinds and hosts of file-part URIs. |
| `size` | Canonical JSON-RPC params bytes, or transfer bytes. |
| `modality`, `projector`, `weights` | Transfer modality, adapter id and measured fuser-weight hash. |

Names (sender, receiver, projector, modality, weights, skill ids and part kinds) are read in lower case. Rules with `class: a2a` therefore match names in any case. A name that is not printable ASCII without spaces is refused with `TK-A2A-NAME`, whatever other rules say; its fixed reason and remedy do not repeat the name. Signed arguments retain the original spelling.

```yaml
extends: server.yaml  # or strict.yaml

ask:
  # Replaces server.yaml's TK-S011: the listed pair does not ask.
  - id: TK-S011
    class: a2a
    field: route
    pattern: '.'
    unless: '^mtls:spiffe://acme\.org/planner->(researcher|writer)$'

tools:
  'a2a:*': a2a
deny:
  - id: A2A-PAIRS
    class: a2a
    field: route
    pattern: '.'
    unless: '^mtls:spiffe://acme\.org/planner->(researcher|writer)$'
  - id: A2A-SIZE
    class: a2a
    field: size
    pattern: '^[0-9]{6,}$'
```

A2A messages do not name the skill requested. A skill rule sees the skills the receiver's card offers, not a requested skill.

## Calling it

POST JSON-RPC to `https://<gateway>:8092/a2a/<upstream>`, with the agent identity and `X-Tracekit-Run: <run_id>.<run_token>` as at the [LLM gateway](gateway.md#calling-it). The gateway does not serve Agent Cards (`GET` is 405); point the client at the gateway endpoint, for example with a copy of the receiver card whose URL is the gateway URL.

Only these methods are relayed. Others receive `-32601`, with no decision and nothing sent.

| Method | Tool | Record |
|---|---|---|
| `message/send` | `a2a:<upstream>/message/send` | Decision, then answer as `tool.result`. |
| `message/stream` | `a2a:<upstream>/message/stream` | Decision; each event as an observed input; all events as the final result. |
| `tasks/get` | `a2a:<upstream>/tasks/get` | Decision, then task as `tool.result`. |

## What is recorded

The decision commits to `{sender, receiver, agent_card, skills, params}`. An allowed request sends the signer's copy of `params`; an ask approved with a T2 executor also sends that signer-held copy. A deny, rejected or unanswered ask, other refusal, or unavailable signer returns `-32000` and never reaches the receiver. `message/send` refuses a `configuration.pushNotificationConfig.url` with `-32602`, before a decision or send. Answers complete the call as redacted T2 results. An upstream connection failure says the message was not sent; an unreadable answer after sending says it may have been acted on. Both complete the call as errors. If that result cannot be recorded, `message/send` still delivers it and the signer leaves a `held_call_unresolved` gap, as the executor does; `message/stream` withholds an event it cannot record.

For `message/stream`, every JSON-RPC event is first recorded as an `input.observed` with source `a2a:<upstream>/message/stream#<tool_call_id>` and trust `untrusted`, then passed to the agent. An error, message, `final` update, or terminal task state completes the call with all events as its result before the final event goes to the agent.

A stream cut before that final event (upstream ends or is idle for 10 minutes, an event cannot be recorded or is not JSON-RPC, or events exceed `max_body`) gives the agent a `-32603` error event and has no `tool.result`. It records only the decision and observed events already passed to the agent. At run finalisation, the signer writes the call's `capture.gap` of kind `held_call_unresolved`; until then it looks in flight. The cut reason is not recorded.

The caller's headers are not forwarded upstream. Gateway-held receiver credentials never reach the caller or signer, and configured header values are cut from decoded answers, events and errors before recording or returning them.

## Limits

- Custody covers only requests routed through this gateway. Keep receiver credentials in it and fence agent egress.
- Push notifications sent outside the gateway are not seen. It relays only the three methods above; push configuration methods, `tasks/cancel` and `tasks/resubscribe` are refused, and `message/send` refuses a push URL.
- The gateway checks task ownership only for `tasks/get`'s `id` and messages' `taskId`, `contextId` and `referenceTaskIds`. Those ids are non-empty strings of at most 1,024 characters; `referenceTaskIds` has at most 64 unique ids. Up to 1,024 task ids per caller (and 1,024 callers) are retained; an evicted id cannot be read or continued through the gateway. It forwards `params.metadata` unchanged and does not check values there. Do not put a receiver that reads task references from metadata behind the gateway; otherwise deny such metadata in an A2A policy, for example:

  ```yaml
  deny:
    - id: R-METADATA-TASK
      class: a2a
      field: target
      pattern: '"metadata":.*"(taskId|contextId|referenceTaskIds)":'
  ```
- Cards are read once at startup. Restart after a card changes.
- A cut stream's `held_call_unresolved` gap is written at run end; its reason is not in the record.
- Messages name no skill, so rules see the card's offered skills.
- Names match in case-insensitively for this class; non-printable-ASCII or space-containing names are refused as `TK-A2A-NAME`.
- `message/send` waits 60 seconds for an answer. Use a stream or non-blocking send for long tasks.

See [limits](limits.md#custody-12).
