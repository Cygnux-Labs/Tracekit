# Egress observation

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

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
posture: {network: enforced, tool_calls: enforced}         # optional: see Posture
observe_grace_s: 120                                        # optional: see Late observations
```

The signer refuses an observation from an identity that owns the run it is about: an observer is never the agent.

## Attribution

Each request through the proxy is attributed to a run:

- **by token**: `Proxy-Authorization: Basic base64(<run_id>:<run token>)`, which clients send when their proxy is
  `https://<run_id>:<run token>@egress:3128`. With `TRACEKIT_EGRESS_PROXY=https://egress:3128` in the agent's
  environment, a Python or TypeScript SDK run's `proxy_env` (`proxyEnv`) holds `HTTPS_PROXY` and `HTTP_PROXY` with its
  credentials: give it to the commands the run starts (`subprocess.run(cmd, env={**os.environ, **run.proxy_env})`)
  or to an HTTP client as its proxy. The SDKs never change the process's own environment, so the agent's other
  connections go where they went before. The proxy asks the signer whether it issued that token for that run before
  it opens anything: one it didn't is refused (407), and while the signer can't be asked the request is refused
  (503), saying so. A check costs the observer none of its event quota, and a client address past its failed checks
  (the signer's per-address failed-authentication limit) gets 429 without the signer being asked, so made-up tokens
  can't crowd out the checks and heartbeats of every run.
- **by identity**: the identity the authenticators accept (a client certificate, or `Proxy-Authorization: Bearer
  <token>`), or on Linux the uid that owns a loopback client's socket. The signer gives the observation to that
  identity's latest open run (`attribution: identity` in the record).
- neither: the proxy answers 407 with what to send.

The connection's identity goes with a run token too: when the token was issued to another identity, the signer
attributes the observation by the connection's identity instead.

Either listener takes SOCKS5 on the same port (inside TLS on the `http` one), as the outbound proxies of
[microsandbox](integrations/microsandbox.md) and [E2B](integrations/e2b.md) speak it: CONNECT, with the run id and its
run token as the username and password (by token), or no credentials (by identity). A host name is resolved and
checked as CONNECT's. An address is reached only through the server name of its TLS ClientHello, which must resolve to
it on the observer's host; that name is the host recorded.

To send the agent process's own traffic through the observer too, set `HTTPS_PROXY` (and `HTTP_PROXY`) for it. In
[system mode](#linux-system-mode) that needs no run token: the observer reads the agent's uid. Over the network (the
central chart, compose) the observer knows a client only by what it sends, and proxy settings carry no identity: a
request with no run token is refused (407) unless the client sends `Proxy-Authorization: Bearer <token>` or a client
certificate the authenticators accept, so give the agent process a run's `proxy_env` URL instead. Tracekit's own
clients (the SDKs' signer connections, the Python executor tools) never use a proxy, but other clients in the agent
that honour `HTTPS_PROXY` (a model SDK pointed at the LLM gateway, an MCP client) would send requests for the
cluster's own services to the observer, which refuses them as private addresses (403). List the signers and custody
services in `NO_PROXY`: `.svc,.cluster.local` on Kubernetes, the service names (`signer,gateway,executor,mcp-gateway`)
in compose. A run's `proxy_env` merged over `os.environ` keeps that `NO_PROXY` for its commands.

An observation no open run takes (a token the signer did not issue for that run, or issued to another identity, with
no open run of the connection's identity to fall back to; an identity with no open run; a run already final) goes into
the tenant's signer run as a `capture.gap{kind: effect_outside_run}` naming the host, the traffic, why, and the run the
client named, so a [run-set](format-v2.md#7-registry-logs-and-run-sets) shows it. The proxy splits a call the signer
refuses until each refused total is on its own, says why on stderr, and sends those again with every heartbeat. It
keeps at most 10,000 of them: past that it drops the oldest and says how many on stderr
([limits](limits.md#egress-observation-12)).

## What is refused

- `CONNECT host:port` whose TLS ClientHello names another server (SNI) than `host`: the tunnel is closed before
  anything reaches the host, and the proxy says so on stderr. So is a tunnel whose ClientHello doesn't arrive within
  30 seconds of its request, and one more tunnel of an attribution (its connection's identity, else its run) that
  has 64 open already.
- a connection that doesn't send what attributes it (an HTTP request's head; SOCKS5's greeting and credentials)
  within 5 seconds, and on Linux one more connection from a loopback client whose uid has 64 open already, counted
  from accept: closed, so one agent's half-open connections can't take the 256 its shared address gets.
- a raw IP address, in any form the resolver reads as one (`8.8.8.8`, `134744072`, `0x08080808`, `8.8.2056`, `::1`),
  and the public DNS-over-HTTPS endpoints (`dns.google`, `cloudflare-dns.com`, ...): 403, with what to do. List one in
  `allow` to let agents reach it; an allowed host needs no SNI, so any protocol passes.
- a host name that resolves to a loopback, private or link-local address (cluster services, cloud metadata): 403,
  naming the address, unless `allow` lists it. The proxy connects to the addresses it checked.
- a host name `observe_effect` would not take (other characters than `a-z 0-9 . _ : -`, or over 253): 400.
- a run id or token that can't be one (a token is 1 to 1024 of `A-Z a-z 0-9 . _ ~ + / = -`): 407.
- over SOCKS5: a client with neither a run token nor an identity, or a token the signer refuses (the handshake fails);
  any command but CONNECT (`command not supported`); a host name refused as above (`connection not allowed`,
  `host unreachable`); and an address whose TLS server name is missing or resolves elsewhere on the observer's host
  (closed before anything reaches it), unless `allow` lists the address. SOCKS5 carries no reason: each refusal is a
  line on stderr.

Plain HTTP requests in absolute form (`GET http://host/path`) are forwarded with `Connection: close`; a body needs a
`Content-Length` (at most 32 MiB; send larger uploads over HTTPS) and is streamed through as it arrives, never held
whole.

## What is recorded

The proxy keeps totals per run attribution, host, port and minute: bytes out, bytes in, connections opened, first
and last activity. Each minute's totals go to the signer (`observe_effect`) at the first heartbeat after the minute
ends (every 30 s); a heartbeat goes out with nothing to report too. Totals the signer can't take now wait for the next
heartbeat; on SIGTERM every total is sent, the current minute's included. Each call names the proxy's process, so the
signer sees a restart (see [Heartbeats](#heartbeats-and-coverage)).

The signer writes, in the run:

```text
effect.observed {observer, kind: net, host, port, bytes_out, bytes_in, connections, first_ts, last_ts,
                 attribution: token|identity, explained_by?: call|explains}
reconcile.unexplained_effect {layers: [L6], observer, kind, host, port, detail}   # once per host and run
```

## Explains

A host is explained by:

- an http or browser call to it the run allowed, or asked for and had approved (an approval only requested explains
  nothing), or a model call to its provider's API host
  (`api.openai.com`, `api.anthropic.com`): `explained_by: call`;
- an entry of the policy's `explains`: `explains`.

```yaml
explains:
  - {label: package-install, hosts: ["pypi.org", "*.pythonhosted.org"]}   # a rule label the run's decisions carry
  - {tool: fetch, hosts: ["cdn.example.net"]}                             # a tool (glob) the run called
```

Each entry names one `tool` (a glob over tool names) or one `label` (a rule's label; flag rules give labels to
allowed calls) and the hosts (globs) that tool's own dependencies reach: CDNs, redirects, package indexes. After its
last wildcard a host glob needs a dot and two or more labels: `*.pythonhosted.org`, not `*.com` or `*pypi.org` (lint
errors). A glob over a public suffix (`*.co.uk`) passes and explains every host under it: write the narrowest host you
mean. Anything else is `reconcile.unexplained_effect`, a
detection trigger (`respond: [{trigger: unexplained_effect, ...}]`); the server pack notifies on it in shadow mode
until your `explains` list is tuned.

## Heartbeats and coverage

Every `observe_effect` call is the observer's heartbeat, on the same machinery as the
[transcript tailer's](coding-agents.md#what-the-signer-records-as-a-gap). An observer covers each run of its tenant
registered while it is alive. When it makes no call for 90 s while a run it covers is open, or another process of
it takes over (a restart: the old one's unreported totals may be gone), the signer writes a signed
`capture.gap{kind: observer_lost}` in that run, and the run's network is no longer `observed`. The process taken over
from is refused from then on (`conflict`): two proxies under one identity stop each other, so give each its own.

## Late observations

A run an observer covers waits `observe_grace_s` (default 120 s) after it closes for the observer's last reports,
which come up to a minute and a heartbeat after the traffic. An observation that comes after `run.final` goes into
the tenant's signer run as `capture.gap{effect_outside_run}` naming the run, unreconciled; export it with
`tracekit export --v2 --run-set`.

## Posture

`posture` in `signer.yaml` is what the operator says about the deployment: `network: enforced` (agents reach the
outside only through the egress proxy, for example by the central chart's `agentEgress` NetworkPolicy) or `open`, and
`tool_calls: enforced` (agents act only through the executor and the MCP gateway) or `open`. With the top-level
`gateway_mandatory` (the LLM gateway, holding the provider key, is the agents' only way to their model), each
`run.registered` records it as `posture{network, tool_calls, gateway_mandatory, attested: false}`: the signer can't
check it.

## The coverage matrix

`run.final` carries `matrix`: per action class, how the run was covered, from what actually ran.

| Class | `enforced` | `observed` | `reported` | `none` |
|---|---|---|---|---|
| `model_calls` | the LLM gateway recorded them and posture says `gateway_mandatory` (asserted) | the LLM gateway recorded them | only the agent's process did | no model call recorded |
| `tool_calls` | every decision came through the executor or the MCP gateway and posture says `tool_calls: enforced` (asserted) | — | otherwise, when calls were recorded | no call recorded |
| `network` | an egress observer covered the run throughout and posture says `network: enforced` (asserted) | an egress observer covered the run throughout | no observer, but the run's http calls name hosts | neither |
| `processes` | — | a Tetragon or Falco [import](integrations/tetragon.md) covered the run throughout (experimental, Linux) | — | otherwise |
| `services` | — | — | — | always: nothing covers them yet |

Each class lists the layers behind it (`gateway`, `adapter`, `hook`, `egress`, ...) and `asserted: true` where the
status rests on posture. The verifier prints it as a `coverage matrix` line and never says a run is complete
([verdicts](verdicts.md#informational-lines-always-pass)).

## Deploy

- **Kubernetes** (central chart): `egress.enabled: true` (and `tlsSecretName`) runs the observer as
  `<release>-egress`; grant `k8s_sa:system:serviceaccount:<namespace>:<release>-egress` `observe_effect`. It
  attributes by run token only, unless a client sends `Proxy-Authorization: Bearer <a service account token of
  audience <audience>-egress>`: plain `HTTPS_PROXY` clients need a run's `proxy_env`. With
  `agentEgress.enabled`, the agents' NetworkPolicy lets them reach only the signers, the custody services, the egress
  observer and DNS ([Kubernetes](deploy-kubernetes.md#custody)).
- **Compose**: the `egress` service (profile `custody`, uid 10014, granted `observe_effect` in the generated
  signer.yaml) is the agent network's way out; put its `egress.yaml` in `custody/egress/`
  ([compose](deploy-compose.md)). As on Kubernetes, clients without a run token need an identity the
  authenticators accept.
- <a id="linux-system-mode"></a>**Linux system mode**: `tracekit init --v2 --user AGENT --egress`, run as root
  ([laptop system mode](deploy.md#laptop-system-mode)), runs the
  observer as its own user on `127.0.0.1:3128`, sets `HTTPS_PROXY` in Claude Code's settings, and installs a firewall
  unit (`tracekit-egress-firewall`) whose owner-match rule lets the agent's uid reach only loopback: its outside
  traffic goes through the observer, attributed by uid, or nowhere, except what a loopback service sends on for it
  (a local DNS stub's lookups, see [limits](limits.md#egress-observation-12)). A stopped observer leaves the agent's
  traffic blocked, never unobserved. `sudo /opt/tracekit/bin/python -I -m tracekit uninstall --v2` removes the rule, the units and the settings. Needs
  iptables with the owner match. Laptops without it are `reported`.

## Limits

Every limit is a row in [limits.md](limits.md#egress-observation-12).
