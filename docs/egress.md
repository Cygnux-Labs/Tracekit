# Egress observation

`tracekit egress serve` is a forward and CONNECT proxy outside the agent. Every connection an agent makes to the
outside goes through it, and it tells the v2 signer which hosts each run reached, on which port, how many bytes each
way and when. The signer writes that as signed `effect.observed` records in the run and reconciles them against the
run's calls: a host nothing explains is a signed `reconcile.unexplained_effect`. Side effects beneath a recorded call
(a shell command that opens connections, a tool's own network calls) no longer leave no trace.

It does not intercept TLS: it sees hosts and ports, never paths, headers or content.

## Configure

`egress.yaml` (relative paths are from the file):

```yaml
http:                                  # the same section, and identity plugins, as the signer's https listener
  listen: 0.0.0.0:3128
  cert: tls/egress.pem
  key: tls/egress.key
  client_ca: {acme.org: tls/acme-ca.pem}
  authenticators: [mtls, k8s_sa]
signer: https://signer.internal:8443   # the observer's own identity: TRACEKIT_SIGNER_TOKEN_FILE or _CERT/_KEY
allow: [10.0.0.7, doh.internal]        # raw IPs and DNS-over-HTTPS endpoints agents may reach anyway
```

Or `listen: 127.0.0.1:3128` instead of `http`: plain HTTP on a loopback address, as [system mode](#linux-system-mode)
uses it.

In `signer.yaml`, give the observer's identity its grant, never a default, and keep it out of every agent's hands:

```yaml
authorize: {"mtls:spiffe://acme.org/tracekit-egress": [observe_effect]}
tenants: {"mtls:spiffe://acme.org/tracekit-egress": acme}   # the tenant whose runs it covers
posture: {network: enforced, gateway_mandatory: true}      # optional: see Posture
observe_grace_s: 120                                        # optional: see Late observations
```

The signer refuses an observation from an identity that owns the run it is about: an observer is never the agent.

## Attribution

Each request through the proxy is attributed to a run:

- **by token**: `Proxy-Authorization: Basic base64(<run_id>:<run token>)`, which clients send when
  `HTTPS_PROXY=https://<run_id>:<run token>@egress:3128` is set for the agent's processes. With
  `TRACEKIT_EGRESS_PROXY=https://egress:3128` in its environment, the Python and TypeScript SDKs set it (and
  `HTTP_PROXY`) on every `register_run`, so commands the agent starts are attributed to its run; set `NO_PROXY` for the
  signer and custody services it reaches directly. When the connection also
  presents a client certificate, that identity goes with it as `client`: a gateway's or the executor's connection for
  a run is then explained by it.
- **by identity**: the identity the authenticators accept (a client certificate, or `Proxy-Authorization: Bearer
  <token>`), or on Linux the uid that owns a loopback client's socket. The signer gives the observation to that
  identity's latest open run (`attribution: identity` in the record).
- neither: the proxy answers 407 with what to send.

An observation whose token the signer did not issue, is for another run or tenant, or whose identity has no open run,
goes into the tenant's signer run as a `capture.gap{kind: effect_outside_run}` naming the host, the traffic and why,
so a [run-set](format-v2.md#7-registry-logs-and-run-sets) shows it. Nothing an observer reports is dropped.

## What is refused

- `CONNECT host:port` whose TLS ClientHello names another server (SNI) than `host`: the tunnel is closed before
  anything reaches the host, and the proxy says so on stderr.
- a raw IP address and the public DNS-over-HTTPS endpoints (`dns.google`, `cloudflare-dns.com`, ...): 403, with what
  to do. List one in `allow` to let agents reach it; an allowed host needs no SNI, so any protocol passes.
- a host name that resolves to a loopback, private or link-local address (cluster services, cloud metadata): 403,
  naming the address, unless `allow` lists it. The proxy connects to the addresses it checked.
- a host name `observe_effect` would not take (other characters than `a-z 0-9 . _ : -`, or over 253): 400.

Plain HTTP requests in absolute form (`GET http://host/path`) are forwarded with `Connection: close`; a body needs a
`Content-Length`.

## What is recorded

The proxy keeps totals per run attribution, host, port and minute: bytes out, bytes in, connections opened, first
and last activity. Each minute's totals go to the signer (`observe_effect`) at the first heartbeat after the minute
ends (every 30 s); a heartbeat goes out with nothing to report too. Totals the signer can't take now wait for the next
heartbeat; on SIGTERM every total is sent, the current minute's included.

The signer writes, in the run:

```text
effect.observed {observer, kind: net, host, port, bytes_out, bytes_in, connections, first_ts, last_ts,
                 attribution: token|identity, explained_by?: call|gateway|explains}
reconcile.unexplained_effect {layers: [L6], observer, kind, host, port, detail}   # once per host and run
```

## Explains

A host is explained by:

- an http or browser call to it the run decided (not denied), or a model call to its provider's API host
  (`api.openai.com`, `api.anthropic.com`): `explained_by: call`;
- a gateway or the executor (a signer `gateways` identity) that made the connection for the run: `gateway`;
- an entry of the policy's `explains`: `explains`.

```yaml
explains:
  - {label: package-install, hosts: ["pypi.org", "*.pythonhosted.org"]}   # a rule label the run's decisions carry
  - {tool: fetch, hosts: ["cdn.example.net"]}                             # a tool (glob) the run called
```

Each entry names one `tool` (a glob over tool names) or one `label` (a rule's label; flag rules give labels to
allowed calls) and the hosts (globs) that tool's own dependencies reach: CDNs, redirects, package indexes. A host
glob that would match nearly anything (`*`, `*.*`) is a lint error. Anything else is `reconcile.unexplained_effect`, a
detection trigger (`respond: [{trigger: unexplained_effect, ...}]`); the server pack notifies on it in shadow mode
until your `explains` list is tuned.

## Heartbeats and coverage

Every `observe_effect` call is the observer's heartbeat, on the same machinery as the
[transcript tailer's](coding-agents.md#what-the-signer-records-as-a-gap-12). An observer covers each run of its tenant
registered while it is alive. When it makes no call for 90 s while a run it covers is open, the signer writes a
signed `capture.gap{kind: observer_lost}` in that run, and the run's network is no longer `observed`.

## Late observations

A run an observer covers waits `observe_grace_s` (default 120 s) after it closes for the observer's last reports,
which come up to a minute and a heartbeat after the traffic. An observation that comes after `run.final` goes into
the tenant's signer run as `capture.gap{effect_outside_run}` naming the run, unreconciled; export it with
`tracekit export --v2 --run-set`.

## Posture

`posture` in `signer.yaml` is what the operator says about the deployment: `network: enforced` (agents reach the
outside only through the egress proxy, for example by the central chart's `agentEgress` NetworkPolicy) or `open`, and
`gateway_mandatory` (the LLM gateway, holding the provider key, is the agents' only way to their model). Each
`run.registered` records it with `attested: false`: the signer can't check it.

## The coverage matrix

`run.final` carries `matrix`: per action class, how the run was covered, from what actually ran.

| Class | `enforced` | `observed` | `reported` | `none` |
|---|---|---|---|---|
| `model_calls` | the LLM gateway recorded them and posture says `gateway_mandatory` (asserted) | the LLM gateway recorded them | only the agent's process did | no model call recorded |
| `tool_calls` | every decision came through the executor or the MCP gateway | — | some came from the agent's process (hook, adapter) | no call recorded |
| `network` | an egress observer covered the run throughout and posture says `network: enforced` (asserted) | an egress observer covered the run throughout | no observer, but the run's http calls name hosts | neither |
| `processes`, `services` | — | — | — | not covered yet |

Each class lists the layers behind it (`gateway`, `adapter`, `hook`, `egress`, ...) and `asserted: true` where the
status rests on posture. The verifier prints it as a `coverage matrix` line and never says a run is complete
([verdicts](verdicts.md#informational-lines-always-pass)).

## Deploy

- **Kubernetes** (central chart): `egress.enabled: true` (and `tlsSecretName`) runs the observer as
  `<release>-egress`; grant `k8s_sa:system:serviceaccount:<namespace>:<release>-egress` `observe_effect`. With
  `agentEgress.enabled`, the agents' NetworkPolicy lets them reach only the signers, the custody services, the egress
  observer and DNS ([Kubernetes](deploy-kubernetes.md#custody)).
- **Compose**: the `egress` service (profile `custody`, uid 10014, granted `observe_effect` in the generated
  signer.yaml) is the agent network's way out; put its `egress.yaml` in `custody/egress/`
  ([compose](deploy-compose.md)).
- <a id="linux-system-mode"></a>**Linux system mode**: `sudo tracekit init --v2 --user AGENT --egress` runs the
  observer as its own user on `127.0.0.1:3128`, sets `HTTPS_PROXY` in Claude Code's settings, and installs a firewall
  unit (`tracekit-egress-firewall`) whose owner-match rule lets the agent's uid reach only loopback: its outside
  traffic goes through the observer, attributed by uid, or nowhere. A stopped observer leaves the agent's traffic
  blocked, never unobserved. `sudo tracekit uninstall --v2` removes the rule, the units and the settings. Needs
  iptables with the owner match. Laptops without it are `reported`.

## Limits

Every limit is a row in [limits.md](limits.md#egress-observation-12).
