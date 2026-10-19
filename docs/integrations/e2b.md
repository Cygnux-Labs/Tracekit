# E2B

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).

[E2B](https://e2b.dev) runs each sandbox as a Firecracker microVM on its nodes. With `network.egressProxy` ("bring your
own proxy"), E2B sends a sandbox's outbound TCP through a SOCKS5 proxy you run. The tunnelling happens on the host,
after E2B's `allowOut` and `denyOut` filtering. In the words of E2B's SDK, "code running there can neither see the
proxy nor route around it", and connections fail rather than go direct when the proxy can't be reached
([E2B SDK](https://github.com/e2b-dev/E2B/blob/main/packages/js-sdk/src/sandbox/sandboxApi.ts)). Point it at the
[egress observer](../egress.md) and the run gets a signed record of every host its sandbox reached, made outside the
sandbox.

| | E2B | Tracekit's egress observer |
|---|---|---|
| What it does | Runs the agent's code in a microVM; filters its traffic, then opens each TCP connection through the proxy | Attributes each connection to a run, checks the host, relays the bytes, and reports per-minute totals to the signer |
| Where | E2B's nodes | `tracekit egress serve` on an address E2B can reach |
| What a third party can check later | Nothing: it keeps no signed record | `effect.observed` records in the run's signed bundle |

**Where it works:** E2B Cloud and BYOC deployments, for teams that have `egressProxy` enabled. Without it, E2B's API
refuses the sandbox ("Egress proxy (network.egressProxy) is not enabled for this team"). Deployments built from the
open-source [e2b-dev/runtime](https://github.com/e2b-dev/runtime) reject it as unsupported. E2B's proxy client isn't
open source, so Tracekit is tested against E2B's API description (SOCKS5 with RFC 1929 credentials, a host name for a
flow `allowOut` matched by domain, the option of TLS), not against E2B itself.

Without `egressProxy`, E2B documents no other way to send a sandbox's traffic through your proxy. An `HTTPS_PROXY` set
in the sandbox's environment (`envs`) is up to the code in the sandbox, which the agent controls: it can ignore or unset
it, so its traffic can bypass the observer.

## Setup

1. Run the observer on an address E2B's infrastructure can reach: E2B rejects a proxy address that resolves to a
   private or internal range. Off loopback the observer takes SOCKS5 only inside TLS, on its `http` listener:

   ```yaml
   # egress.yaml
   http:
     listen: 0.0.0.0:1080
     cert: tls/egress.pem             # a certificate for egress.example.com
     key: tls/egress.key
     authenticators: [token]          # bearer tokens for HTTP clients; E2B's connections carry run tokens
     token_file: egress-bearer
   signer: https://signer.internal:8443   # the observer's identity: TRACEKIT_SIGNER_TOKEN_FILE or _CERT/_KEY
   ```

   In `signer.yaml`, grant that identity `observe_effect` and nothing else, and never give it to the agent
   ([egress](../egress.md#configure)).

2. Create each sandbox with its run's id and token as the SOCKS5 credentials, inside TLS. E2B's API takes `tls` in
   `network.egressProxy` ([API spec](https://github.com/e2b-dev/runtime/blob/main/spec/openapi.yml)). The JS and Python
   SDKs send only the address, username and password, so create the sandbox through the API
   (`POST https://api.e2b.app/sandboxes`, header `X-API-Key`):

   ```json
   {
     "templateID": "base",
     "network": {
       "egressProxy": {
         "address": "egress.example.com:1080",
         "username": "<run id>",
         "password": "<run token>",
         "tls": {"enabled": true}
       }
     }
   }
   ```

   The run id and token are `run.run_id` and `run.run_token` of a run registered with the Python SDK
   (`Client().run(...)`). Add `tls.serverName` or `tls.caCert` when the observer's certificate doesn't match its
   address or comes from a private CA. Without `tls` the TLS handshake fails, and E2B fails closed: the sandbox has no
   network.

3. Keep the E2B API key away from the agent. Whoever holds it can create a sandbox without the proxy, or change the
   proxy on a running sandbox (`PUT /sandboxes/{sandboxID}/network`).

## What the run gets

For a flow its `allowOut` matched by domain, E2B sends the host name. The observer resolves and checks it as it does
for CONNECT (public addresses only, no DNS-over-HTTPS endpoints, unless `allow` lists them), and the connection's TLS
server name must be that name. For any other flow E2B sends an address. The observer names that host by the
connection's TLS server name, and only when the name resolves to that address on the observer's host. Anything else is
closed before it reaches the host, and the observer says why on stderr.

Each minute, per run, host and port, the signer writes a signed record naming the observer's identity:

```text
effect.observed {observer, kind: net, host, port, bytes_out, bytes_in, connections, first_ts, last_ts,
                 attribution: token}
```

A host none of the run's calls or the policy's `explains` covers is also a `reconcile.unexplained_effect`; an observer
that stops is a signed `observer_lost` gap ([egress](../egress.md#heartbeats-and-coverage)).

## What the observer doesn't see

- **Content:** paths, headers and bodies. It doesn't intercept TLS.
- **UDP:** E2B tunnels TCP only. DNS and QUIC/HTTP3 leave the sandbox directly.
- **Plain HTTP and other non-TLS TCP:** they reach only hosts and addresses `allow` lists.
- **The sandbox:** nothing about processes or files inside the microVM.

[Limits](../limits.md#egress-observation-12) lists each with what to do.
