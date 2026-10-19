# sandbox-runtime's proxy on its own

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> Tested: the decider against a stand-in that speaks srt-proxy's protocol as its source does; not yet against a released
> srt ([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

Anthropic's [sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (`srt`) can run its HTTP proxy on its
own, with no sandboxed command: `srt-proxy`, also `srt proxy`. A host that runs the workload elsewhere (a VM, a
container, another sandbox) points the workload's traffic at it. Before srt-proxy forwards a request, it asks a
separate process, the decider, and it forwards nothing without one (sandbox-runtime's
[docs/srt-proxy.md](https://github.com/anthropics/sandbox-runtime/blob/main/docs/srt-proxy.md)).
`tracekit srt-decider` is that decider. The Tracekit signer's policy decides each request, holds the ones it asks
about for a person, and signs a record of each one into a run.

| | srt-proxy | Tracekit |
|---|---|---|
| What it does | Accepts the workload's connections and decrypts its HTTPS with your CA. It refuses hosts outside the decider's list and checks the address it resolves before dialling | Decides each request srt-proxy asks about, holds risky ones for a person, signs a record of each decision and approval |
| Where | A process the host starts | A signer outside the workload ([dev or system mode](../limits.md#dev-mode-vs-system-mode)) |
| What a third party can check later | Nothing: it keeps no record | A signed, hash-chained bundle, verified offline |

This page is for srt used without Claude Code. With Claude Code, use
[Claude Code's sandbox](claude-code-sandbox.md) with Tracekit's hooks; how the two differ is [below](#claude-code-is-different).

## Setup

Linux and macOS. You need srt-proxy (decider protocol version 1, as in sandbox-runtime 0.0.80; it runs on Node 22.12
or later), a signer (`tracekit up` starts
the dev signer; `TRACEKIT_SIGNER` names another) and a CA for srt-proxy to decrypt HTTPS with. Without a CA,
srt-proxy refuses every `CONNECT`. srt-proxy needs an RSA key; this is the command sandbox-runtime's own test CA was
made with:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout ca.key -out ca.crt -days 30 \
  -subj '/CN=srt-proxy CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash'
cat ca.key ca.crt > ca.pem
```

Start srt-proxy through Tracekit, naming the hosts the workload may reach:

```sh
tracekit srt-decider --allow-domain api.github.com --allow-domain '*.pythonhosted.org' --allow-domain pypi.org \
  -- srt-proxy --listen 127.0.0.1:3128 --ca-fd 3 3<ca.pem
```

`tracekit srt-decider` registers a run (agent `srt-proxy`; `--agent NAME` to change it). It then starts the command
after `--`, adding `--decider-fd` with one end of a socket pair. srt-proxy inherits the descriptors Tracekit got from
your shell, so its own `--ca-fd`, `--listen-fd` and `--lifeline-fd` work as they do without Tracekit. When srt-proxy
exits, Tracekit closes the run and exits with srt-proxy's exit code. When Tracekit exits, srt-proxy refuses whatever is
waiting and exits too. The signer closes a run with no request for `idle_s` (an hour by default); Tracekit refuses
the next request and stops srt-proxy, so run it under a supervisor that restarts it. `--listen` binds a loopback
address and is for development; in production, hand srt-proxy a listening socket with `--listen-fd`.

The `--allow-domain` hosts are the list srt-proxy holds requests to (`*.example.com` for subdomains). srt-proxy
refuses every other host itself, with `403` and `X-Deny-Reason: host_not_allowed`, and never asks Tracekit, so
Tracekit records nothing of those requests. Its protocol has no entry that matches every host.

Point the workload at the proxy and make it trust the CA, for example:

```sh
export HTTPS_PROXY=http://127.0.0.1:3128 HTTP_PROXY=http://127.0.0.1:3128
export SSL_CERT_FILE=$PWD/ca.crt NODE_EXTRA_CA_CERTS=$PWD/ca.crt REQUESTS_CA_BUNDLE=$PWD/ca.crt
```

### Under srt's own sandbox

To run the workload in srt's sandbox as well, set `network.httpProxyPort` in `~/.srt-settings.json`:

```json
{
  "network": {"allowedDomains": [], "deniedDomains": [], "httpProxyPort": 3128},
  "filesystem": {"denyRead": [], "allowWrite": ["."], "denyWrite": []}
}
```

srt then starts no HTTP proxy of its own and points the command's `HTTP_PROXY` and `HTTPS_PROXY` at that port. Its
`allowedDomains` don't apply to that traffic: srt's settings schema says "the external proxy must handle domain
filtering". Here srt-proxy's list and Tracekit's policy do that. The command still has to trust the CA
(`srt -- env SSL_CERT_FILE=$PWD/ca.crt curl https://api.github.com`).

## What is decided

Each request is decided as the tool `srt:request`, class `http`, with these arguments:

```json
{"method": "POST", "url": "https://api.github.com/repos/o/r/issues?x=1", "body": "sha256:3f5a…"}
```

- `url` is `https://` when the request came through a decrypted tunnel with a TLS server name, else `http://`.
  srt-proxy's request has no scheme field. The path and query are as the client spelled them.
- `body` is the SHA-256 of the request body. It is there for a request other than GET, HEAD or OPTIONS whose headers
  announce a body. Tracekit asks srt-proxy for the body (up to 32 MiB) and refuses a longer one (`413`).
- The policy's `http` rules apply. The dev pack allows every request and flags it (`TK-F002`, `TK-F012`). The
  server pack denies internal addresses and names (`TK-N001`, `TK-N003`) and data sent outside its allowlist
  (`TK-N002`) ([policy](../policy-v2.md#packs-shipped)). Write `ask` rules for the requests a person should see. A
  policy that extends no shipped pack maps the tool itself (`tools: {'srt:request': http}`).

| Decision | srt-proxy answers the workload |
|---|---|
| allow | forwards the request |
| deny | `403`, with the rule ids in the reason |
| ask | `403` with the approval id: `held for a person's approval (apr-…)`; the decider prints the same id |
| signer unreachable | `503`, whatever the run's fail mode says |
| a request Tracekit can't read | `400` |

srt-proxy waits 5 seconds for each answer, too short for a person. So an `ask` is refused at once, and its approval
waits in the signer:

```text
[tracekit] POST api.github.com: waiting for approval apr-… (TK-…)
tracekit approvals approve apr-…            # from another terminal
```

Once a person approves it, the same request sent again (same method, URL and body) is allowed, once. The next one
asks again. A request that differs in any of them is a new request with its own approval. A rejected approval is
reported on the next try, and the try after that asks again ([approvals](../approvals.md)).

## Claude Code is different

Claude Code runs srt inside its own process. Its sandbox settings set the allowlist, and its own prompts ask about new
hosts. Setting `sandbox.network.httpProxyPort` hands that traffic to your proxy, and Claude Code's allowlist,
prompts and local-address check stop applying to it ([Claude Code's sandbox](claude-code-sandbox.md)). srt-proxy with
`tracekit srt-decider` is a proxy that enforces an allowlist, but we haven't tested Claude Code pointed at it. With
Claude Code, keep its own proxy and use Tracekit's hooks, which already decide every call Claude makes.

## What Tracekit sees and doesn't

- **Sees:** each request srt-proxy asks about: its method, host, port, path, query and the body's digest. It also
  sees the decision and any approval. The run's records commit to these arguments rather than store them
  ([privacy](../privacy.md)).
- **Doesn't see:** requests to hosts outside `--allow-domain`, which srt-proxy refuses itself. It doesn't see the
  response to an allowed request, or whether srt-proxy forwarded it: srt-proxy can still refuse an allowed request,
  for instance when the host resolves to a private address or the answer came after its 5 seconds. The record says
  the request was allowed and that Tracekit doesn't see the response.
- **Doesn't bind:** request headers, and the body of a GET, HEAD or OPTIONS. An approval covers the method, URL and
  body digest.
- **Doesn't attribute:** which process sent a request. srt-proxy's request names no client, so one decider is one
  run. Run one srt-proxy per agent run.

[Limits](../limits.md) lists these with what to do.
