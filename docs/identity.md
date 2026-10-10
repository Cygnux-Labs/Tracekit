# Identity

The signer's HTTPS transport (`http` in signer.yaml, `tracekit/transport/http.py`) establishes who calls it with one of
its `authenticators`: `k8s_sa` (Kubernetes service-account tokens), `mtls` (SPIFFE client certificates), `token`
(bearer secrets) and `oidc` (OpenID Connect tokens of the issuers you configure). An identity proves the workload or
person that calls, not the tenant or the end user a run acts for: those are attested only from inputs the signer can
verify, and labelled app-asserted otherwise.

## OIDC issuers

```yaml
http:
  listen: 0.0.0.0:8443
  cert: tls/server.crt
  key: tls/server.key
  authenticators: [oidc, k8s_sa]      # oidc passes on a JWT whose issuer it does not know
  oidc:
    corp:                             # issuer alias
      issuer: https://login.corp.example
      audience: tracekit-signer
      discovery: https://...          # default <issuer>/.well-known/openid-configuration
      ca: corp-ca.pem                 # default: the system CAs
      person_claim: email             # the stable person id (default sub); with email, tokens need email_verified: true
      person_ns: corp                 # person ids are <person_ns>/<claim>; issuers that share it share people
      groups_claim: groups            # default groups
      tenant_claim: tenant            # optional: the identity's tenant
```

A token is accepted when it is a JWT signed with RS256, ES256 or EdDSA under a `kid` of its issuer's JWKS, and its
`iss` is the pinned issuer, its `aud` the audience, and `exp` and `nbf` hold within 30 s. `alg: none`, HMAC algorithms,
a missing or unknown `kid` and a key of another algorithm than the header names are refused. The discovery document's
`issuer` must be the pinned one and its `jwks_uri` HTTPS. Keys are cached for 5 minutes, fetched again for an unknown
`kid` at most every 30 s (so a rotated key is picked up), and no longer trusted once a fetch has not succeeded for an
hour.

An OIDC token gives the identity `oidc:<alias>/<sub>` with:

- a person id `<person_ns>/<person_claim>`: two tokens with the same person id are the same person, whatever their
  subjects (aliases), for every self-approval and requester check;
- groups `<alias>/<name>`;
- a tenant, from `tenant_claim`, when `tenants` does not name one.

`tenants`, `authorize` and `approvals` match an OIDC identity by `oidc:<alias>/<sub>`, `person:<person id>` and
`group:<alias>/<name>` (exact, or a prefix ending in `:*` or `/*`):

```yaml
authorize: {"group:corp/agents": [register_run, decide, complete, close_run], "group:corp/approvers": [approval_list,
            approval_get, approval_decide]}
approvals: {self_approval: deny, approvers: ["group:corp/approvers", "person:corp/ann@corp.example"],
            break_glass: ["group:corp/oncall"]}
```

## Attested principals

`register_run` takes `principal` (app-asserted: recorded with `principal_attested: false`) or `principal_token`, the
end user's ID or access token for one of the `oidc` issuers. The signer checks the token as above and records the
user's person id as the run's `principal` with `principal_attested: true`; the token itself is never recorded. The
`oidc` section checks principal tokens also when `oidc` is not among the `authenticators`.

`tracekit verify` reports each run's principal as `attested` or `app-asserted`.

## Approvals

Approvals are answered with `approval_decide` over the RPC by an authenticated identity ([approvals.md](approvals.md)).
With OIDC: an approver is named by person id or group; the requester and the run's owner (and their aliases) answer
only with `self_approval: allow`; the run's attested principal never answers its run's approvals, as an approver or
under break glass; break glass (by group) needs a reason and is recorded `break_glass`. The `approval` record carries the
approver's identity with its person id.

## Viewer login

`tracekit view --config signer.yaml` signs people in with one of the `http.oidc` issuers when the config has a `view`
section:

```yaml
view:
  oidc:
    issuer: corp                      # an alias of http.oidc
    client_id: tracekit-viewer        # the ID token's audience
    client_secret_file: viewer-secret   # optional: a confidential client
    redirect_uri: https://view.corp.example/callback
    roles: {auditor: ["group:corp/auditors"], approver: ["group:corp/approvers"]}
```

`/login` starts an authorization code flow with PKCE (S256), a `state` held in a login cookie and a `nonce`;
`/callback` exchanges the code, checks the ID token and opens a server-side session (a random `HttpOnly;
SameSite=Strict` cookie, 8 hours). A person needs a role and the issuer's tenant claim; both roles see, read-only, the
runs of that tenant only. Approvers answer approvals over the RPC, not in the viewer. The token URL the viewer prints
keeps working for the laptop. The viewer serves the `redirect_uri` host name besides its own; off loopback it needs
`--tls-cert` and `--tls-key` ([security-checklist.md](security-checklist.md)).
