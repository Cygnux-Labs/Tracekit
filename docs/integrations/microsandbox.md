# microsandbox

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> Tested: SOCKS5 connections made as microsandbox's source sends them, into a real signer; not yet run against a released microsandbox ([#312](https://github.com/Cygnux-Labs/Tracekit/issues/312)).

[microsandbox](https://github.com/superradcompany/microsandbox) runs each sandbox as a microVM (libkrun: KVM on Linux,
Hypervisor.framework on macOS). The sandbox's network stack runs in the `msb` process on the host, and its
[outbound proxy](https://github.com/superradcompany/microsandbox/blob/main/docs/networking/outbound-proxy.mdx) sends
each TCP connection the guest opens through an HTTP CONNECT, SOCKS4 or SOCKS5 proxy, from the host. Code in the guest
can't see that proxy or go around it. Point it at the [egress observer](../egress.md) and the run gets a signed record
of every host its sandbox reached, made outside the guest.

| | microsandbox | Tracekit's egress observer |
|---|---|---|
| What it does | Runs the agent's code in a microVM; resolves names, applies its network policy, opens each TCP connection through the proxy | Attributes each connection to a run, checks the host, relays the bytes, and reports per-minute totals to the signer |
| Where | The `msb` process on the host | `tracekit egress serve` on the same host, as its own user |
| What a third party can check later | Nothing: its logs aren't signed | `effect.observed` records in the run's signed bundle |

## Setup

The observer's plain loopback listener takes SOCKS5 as well as HTTP: the same port serves both. Use microsandbox's
`socks5` protocol. Its `http_connect` sends no credentials, and it sends an address, which the observer refuses over
CONNECT (403); SOCKS4 isn't taken.

1. Run the observer on the microsandbox host, as its own user, with its own signer identity:

   ```yaml
   # egress.yaml
   listen: 127.0.0.1:3128
   signer: https://signer.internal:8443   # the observer's identity: TRACEKIT_SIGNER_TOKEN_FILE or _CERT/_KEY
   ```

   In `signer.yaml`, grant that identity `observe_effect` and nothing else, and never give it to the agent
   ([egress](../egress.md#configure)). Linux system mode's observer (`tracekit init --v2 --egress`) already listens on
   `127.0.0.1:3128`.

2. Give each sandbox its run's id and token as SOCKS5 credentials, from the code that creates the sandbox. microsandbox
   reads the password from a host environment variable when the sandbox starts, so set it just before `create`:

   ```python
   import asyncio
   import os

   from microsandbox import OutboundProxy, Sandbox, SecretSource
   from tracekit.sdk.client import Client


   async def main():
       with Client().run(agent="my-agent") as run:
           os.environ["TRACEKIT_RUN_TOKEN"] = run.run_token
           proxy = OutboundProxy.socks5("127.0.0.1:3128").credentials(run.run_id, SecretSource.env("TRACEKIT_RUN_TOKEN"))
           async with await Sandbox.create("agent-1", image="python", proxy=proxy) as sb:
               await sb.shell("pip install --quiet requests")   # the sandbox's work, while the run is open


   asyncio.run(main())
   ```

   With the CLI: `msb run python --proxy socks5://127.0.0.1:3128 --socks5-username <run id>
   --socks5-password-env TRACEKIT_RUN_TOKEN`. When several runs start at once in one process, give each its own
   variable name.

3. To make every sandbox on the host use the observer whatever the code creating it says, enforce the proxy in
   microsandbox's [managed configuration](https://github.com/superradcompany/microsandbox/blob/main/docs/enterprise/corporate-networking.mdx)
   (`/etc/microsandbox/managed.json` on Linux):

   ```json
   {
     "version": 1,
     "overrides": {
       "sandbox_defaults": {
         "outbound_proxy": {"protocol": "socks5", "address": "127.0.0.1:3128"}
       }
     }
   }
   ```

   A managed proxy replaces each sandbox's own, credentials included, so per-run credentials can't be combined with
   it. Without credentials the observer attributes by identity: on Linux, the uid that runs `msb`; the signer gives each
   connection to that uid's latest open run. On macOS the observer can't read the uid, so it refuses every connection
   without credentials, and the sandboxes have no network.

On Linux the uid that runs `msb` goes with the run token too: register the run as that same user (through its signer
socket), or the signer attributes the connections by the uid instead of by the token
([egress](../egress.md#attribution)).

## What the run gets

microsandbox sends the observer the address it resolved and checked against its own network policy, never a host name
(`crates/network/lib/proxy/socks.rs`). The observer names the host by the server name in the connection's TLS
ClientHello, and only when that name resolves to the same address on the observer's host (a public one, unless `allow`
lists it). It then relays the connection to that address. A connection without a TLS server name, or whose name
resolves elsewhere, is closed before anything reaches the host, and the observer says why on stderr.

Each minute, per run, host and port, the signer writes a signed record naming the observer's identity:

```text
effect.observed {observer, kind: net, host, port, bytes_out, bytes_in, connections, first_ts, last_ts,
                 attribution: token}
```

A host none of the run's calls or the policy's `explains` covers is also a `reconcile.unexplained_effect`. While the
observer heartbeats, the run's coverage matrix says `network: observed` (`enforced` with `posture: {network: enforced}`
in signer.yaml); an observer that stops is a signed `observer_lost` gap ([egress](../egress.md#heartbeats-and-coverage)).

## What the observer doesn't see

- **Content:** paths, headers and bodies. It doesn't intercept TLS.
- **Names microsandbox resolves:** its DNS forwarder doesn't use the proxy, and connections to
  `host.microsandbox.internal` skip it.
- **Plain HTTP and other non-TLS TCP:** they reach only addresses `allow` lists. The observer has no name to record for
  them.
- **UDP:** microsandbox sends non-DNS UDP as SOCKS5 UDP ASSOCIATE, which the observer refuses, so it fails.
- **The guest:** nothing about processes or files inside the microVM.

[Limits](../limits.md#egress-observation-12) lists each with what to do.
