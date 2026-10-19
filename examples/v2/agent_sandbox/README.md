# An agent in a Kubernetes agent-sandbox Sandbox

The agent runs in an [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) `Sandbox` in namespace `agents`;
the Tracekit signer runs in namespace `tracekit` with its own volume and keys. The agent authenticates with its
service account, its run is recorded off the pod, and after the Sandbox and its pod are deleted the run is exported and
verified offline.

| File | What |
|---|---|
| `signer.yaml` | The signer: ServiceAccount (TokenReview), ConfigMap (signer.yaml), PVC, Deployment, Service `tk` |
| `sandbox.yaml` | The agent: ServiceAccount `support-agent` and the `Sandbox` |
| `agent.py` | The agent program (mounted from a ConfigMap): decides an allowed and a denied call, then waits |
| `e2e.sh` | All of it on a throwaway kind cluster |

```sh
sh examples/v2/agent_sandbox/e2e.sh     # needs docker, kind, kubectl and a python with tracekit ($PY)
```

The walkthrough, what the bundle shows and what it doesn't: [docs/integrations/agent-sandbox.md](../../../docs/integrations/agent-sandbox.md).
