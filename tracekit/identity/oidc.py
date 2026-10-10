"""OpenID Connect identities (docs/identity.md): ID or access tokens (JWT) of configured issuers, for the signer's HTTPS
transport (approvers, operators), a run's end user (`register_run` with `principal_token`) and the viewer's login.

signer.yaml, `http` section:
    authenticators: [oidc, k8s_sa]          # oidc first: it passes on a JWT whose issuer it does not know
    oidc:
      corp:                                 # issuer alias: identity oidc:corp/<sub>
        issuer: https://login.corp.example  # pinned: the token's iss and the discovery document's issuer
        audience: tracekit-signer
        discovery: https://...              # default <issuer>/.well-known/openid-configuration
        ca: corp-ca.pem                     # default: the system CAs
        person_claim: email                 # the stable person id's claim (default sub)
        person_ns: corp                     # person id <person_ns>/<claim value>; issuers that share a namespace
                                            # share people (default: the alias)
        groups_claim: groups                # a list of group names (default groups): group:<alias>/<name>
        tenant_claim: tenant                # optional: the identity's tenant, signed by the issuer

The discovery document is fetched with the keys (k8s_sa.Jwks: cached, refetched for an unknown kid at most every
REFETCH_S, refused once older than JWKS_MAX_AGE_S); its issuer must be the pinned one and its jwks_uri HTTPS.
RS256, ES256 and EdDSA only, `kid` required; iss, aud, exp and nbf with k8s_sa.SKEW_S. Config tables (`tenants`,
`authorize`, `approvals`) match an identity by `keys()`: oidc:<alias>/<sub>, person:<person id>, group:<alias>/<name>.
"""
import json
import ssl
import time

from tracekit.identity.base import CallerIdentity, bearer
from tracekit.identity.k8s_sa import Jwks, _https, _unb64, verify_jwt
from tracekit.signer.rpc_schema import RPCError

ALGS = ("RS256", "ES256", "EdDSA")
ISSUER_KEYS = {"issuer", "audience", "discovery", "ca", "person_claim", "person_ns", "groups_claim", "tenant_claim"}
MAX_GROUPS = 64


def _refuse(why):
    return RPCError("unauthenticated", f"OIDC token refused: {why}")


def keys(identity):
    """What config tables match `identity` by: scheme:subject, then for an OIDC identity person:<id> and its groups."""
    c = identity.claims if identity.scheme == "oidc" else {}
    return ([f"{identity.scheme}:{identity.subject}"] + ([f"person:{c['person']}"] if c.get("person") else [])
            + [f"group:{g}" for g in c.get("groups", ())])


def person(identity):
    """The stable person id of an OIDC identity, else None."""
    return identity.claims.get("person") if identity.scheme == "oidc" else None


class Issuer:
    def __init__(self, alias, issuer=None, audience=None, discovery=None, ca=None, person_claim="sub", person_ns=None,
                 groups_claim="groups", tenant_claim=None, clock=time.time):
        if not (isinstance(alias, str) and alias and "/" not in alias and ":" not in alias):
            raise ValueError(f"oidc: issuer alias {alias!r}: a name without / or :")
        if not (isinstance(issuer, str) and issuer.startswith("https://")):
            raise ValueError(f"oidc.{alias}: issuer must be an https:// URL")
        if not (isinstance(audience, str) and audience):
            raise ValueError(f"oidc.{alias}: needs an audience")
        self.discovery = discovery or issuer.rstrip("/") + "/.well-known/openid-configuration"
        if not self.discovery.startswith("https://"):
            raise ValueError(f"oidc.{alias}: discovery must be an https:// URL")
        self.alias, self.issuer, self.audience, self.clock = alias, issuer, audience, clock
        self.person_claim, self.person_ns = person_claim, person_ns or alias
        self.groups_claim, self.tenant_claim = groups_claim, tenant_claim
        self.ctx = ssl.create_default_context(cafile=ca)
        self._doc = None
        self._jwks = Jwks(lambda: self.document(fresh=True)["jwks_uri"], self.ctx, clock, "OIDC")

    def document(self, fresh=False):
        """The issuer's discovery document (fetched again with `fresh`); ValueError or OSError when it fails."""
        if fresh or self._doc is None:
            doc = _https("GET", self.discovery, self.ctx)
            if not (isinstance(doc, dict) and doc.get("issuer") == self.issuer
                    and str(doc.get("jwks_uri", "")).startswith("https://")):
                raise ValueError(f"{self.discovery}: not the discovery document of {self.issuer}")
            self._doc = doc
        return self._doc

    def verify(self, token, nonce=None):
        """The identity of a token this issuer signed; RPCError unauthenticated (or unavailable) otherwise. `nonce`:
        the one an ID token from a login must carry."""
        claims = verify_jwt(token, self._jwks.key, ALGS, self.issuer, self.audience, self.clock(), _refuse)
        sub, who = claims.get("sub"), claims.get(self.person_claim)
        if not (isinstance(sub, str) and sub and isinstance(who, str) and who):
            raise _refuse(f"no sub or {self.person_claim} claim")
        if nonce is not None and claims.get("nonce") != nonce:
            raise _refuse("nonce")
        groups = claims.get(self.groups_claim)
        out = {"person": f"{self.person_ns}/{who}"[:256],
               "groups": sorted({f"{self.alias}/{g}"[:256] for g in groups[:MAX_GROUPS] if isinstance(g, str) and g}
                                if isinstance(groups, list) else ())}
        tenant = self.tenant_claim and claims.get(self.tenant_claim)
        if isinstance(tenant, str) and tenant:
            out["tenant"] = tenant[:128]
        return CallerIdentity("oidc", f"{self.alias}/{sub}", True, out)


class OidcAuthenticator:
    """The `oidc` section of the signer's `http` config: issuer alias -> Issuer arguments."""

    def __init__(self, issuers, clock=time.time):
        if not isinstance(issuers, dict) or not issuers:
            raise ValueError("oidc: a mapping of issuer alias to {issuer, audience, ...}")
        self.issuers = {}
        for alias, cfg in issuers.items():
            if not isinstance(cfg, dict) or set(cfg) - ISSUER_KEYS:
                raise ValueError(f"oidc.{alias}: takes {sorted(ISSUER_KEYS)}")
            i = Issuer(alias, clock=clock, **cfg)
            if i.issuer in self.issuers:
                raise ValueError(f"oidc: two aliases for {i.issuer}")
            self.issuers[i.issuer] = i

    def _issuer(self, token):
        """The configured issuer the (unverified) iss of a JWT names, else None."""
        try:
            iss = json.loads(_unb64(token.split(".")[1])).get("iss")
        except (ValueError, AttributeError):
            return None
        return self.issuers.get(iss) if isinstance(iss, str) else None

    def authenticate(self, conn, frame):
        """None for a request without a JWT of a configured issuer (another authenticator's credential)."""
        token = bearer(conn)
        issuer = self._issuer(token) if token and token.count(".") == 2 else None
        return issuer and issuer.verify(token)

    def validate(self, token):
        """The identity of `token` (an end user's, say); RPCError unauthenticated unless a configured issuer signed it."""
        issuer = self._issuer(token) if token.count(".") == 2 else None
        if issuer is None:
            raise _refuse("not a JWT of a configured issuer")
        return issuer.verify(token)
