"""Kubernetes projected service-account tokens, for the central signer over HTTPS (a sidecar uses the peer uid).

Two modes, by config:
    k8s_sa: {audience: tracekit-signer, issuer: https://..., jwks_uri: https://.../openid/v1/jwks, ca: jwks-ca.pem}
    k8s_sa: {audience: tracekit-signer, tokenreview: https://kubernetes.default.svc, token_file: ..., ca: ...}
JWKS (cross-cluster): the issuer's keys are fetched over HTTPS and cached; RS256 and ES256 only, then iss, aud (the
signer's own audience), exp and nbf with SKEW_S. TokenReview (in-cluster): the API server checks the token, asked with
the signer's own token; a positive answer is cached for at most min(REVIEW_TTL_S, the token's remaining lifetime), a
negative one never. The subject is `system:serviceaccount:<namespace>:<name>`.
"""
import hashlib
import http.client
import json
import ssl
import threading
import time
import urllib.parse
from base64 import urlsafe_b64decode
from collections import OrderedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from tracekit.identity.base import CallerIdentity, bearer
from tracekit.signer.rpc_schema import RPCError

SKEW_S = 30
JWKS_TTL_S = 300
REFETCH_S = 30        # least time between two JWKS fetches, also when a token names an unknown kid
REVIEW_TTL_S = 60
CACHE_MAX = 1024      # TokenReview results kept, least recently used evicted
KEYS_MAX = 64
FETCH_MAX = 1 << 20
TIMEOUT_S = 5
SA_PREFIX = "system:serviceaccount:"


def _unb64(s):
    return urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int(s):
    return int.from_bytes(_unb64(s), "big")


def _refuse(why):
    return RPCError("unauthenticated", f"service-account token refused: {why}")


def _https(method, url, ctx, body=None, headers=None):
    """The JSON answer of one HTTPS request; no redirects."""
    u = urllib.parse.urlsplit(url)
    c = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=TIMEOUT_S)
    try:
        c.request(method, (u.path or "/") + (f"?{u.query}" if u.query else ""), body, headers or {})
        r = c.getresponse()
        if not 200 <= r.status < 300:
            raise ValueError(f"{url}: HTTP {r.status}")
        return json.loads(r.read(FETCH_MAX))
    finally:
        c.close()


def _jwk(jwk):
    """(alg, public key) of a JWK this verifier accepts, else None."""
    if jwk.get("kty") == "RSA":
        return "RS256", rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        return "ES256", ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1()).public_key()
    return None


def _identity(username, pod_name=None, pod_uid=None):
    u = str(username)
    ns, _, name = u[len(SA_PREFIX):].partition(":") if u.startswith(SA_PREFIX) else ("", "", "")
    if not ns or not name or ":" in name:
        raise _refuse(f"subject {str(username)[:128]!r} is not a service account")
    claims = {"namespace": ns, "service_account": name}
    if pod_name:
        claims["pod_name"] = str(pod_name)[:256]
    if pod_uid:
        claims["pod_uid"] = str(pod_uid)[:64]
    return CallerIdentity("k8s_sa", f"{SA_PREFIX}{ns}:{name}", True, claims)


class K8sSaAuthenticator:
    def __init__(self, audience=None, issuer=None, jwks_uri=None, tokenreview=None, token_file=None, ca=None,
                 clock=time.time):
        if not isinstance(audience, str) or not audience:
            raise ValueError("k8s_sa needs an audience")
        if bool(jwks_uri) == bool(tokenreview):
            raise ValueError("k8s_sa needs exactly one of jwks_uri (with issuer) and tokenreview (with token_file)")
        if jwks_uri and not issuer or tokenreview and not token_file:
            raise ValueError("k8s_sa: jwks_uri needs issuer, tokenreview needs token_file")
        if not str(jwks_uri or tokenreview).startswith("https://"):
            raise ValueError("k8s_sa: jwks_uri and tokenreview must be https:// URLs")
        self.audience, self.issuer, self.jwks_uri, self.tokenreview = audience, issuer, jwks_uri, tokenreview
        self.token_file, self.clock = token_file, clock
        self.ctx = ssl.create_default_context(cafile=ca)
        self._lock = threading.Lock()
        self._keys, self._fetched, self._tried = {}, None, None
        self._cache = OrderedDict()   # sha256(token) -> (expires at, identity)

    def authenticate(self, conn, frame):
        """None when the request carries no JWT-shaped bearer token (another authenticator's credential)."""
        token = bearer(conn)
        if token is None or token.count(".") != 2:
            return None
        return self._verify(token) if self.jwks_uri else self._review(token)

    # --- JWKS ---

    def _key(self, kid):
        with self._lock:
            now = self.clock()
            due = self._fetched is None or now - self._fetched >= JWKS_TTL_S or kid not in self._keys
            if due and (self._tried is None or now - self._tried >= REFETCH_S):
                self._tried = now
                try:
                    jwks = _https("GET", self.jwks_uri, self.ctx)
                    keys = {}
                    for jwk in jwks["keys"][:KEYS_MAX]:
                        try:
                            k = _jwk(jwk)
                        except (AttributeError, KeyError, TypeError, ValueError):
                            continue
                        if k and isinstance(jwk.get("kid"), str):
                            keys[jwk["kid"]] = k
                    self._keys, self._fetched = keys, now
                except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as e:
                    if self._fetched is None:
                        raise RPCError("unavailable", f"JWKS fetch failed: {e}") from None
            return self._keys.get(kid)

    def _verify(self, token):
        h64, p64, s64 = token.split(".")
        try:
            header, claims, sig = json.loads(_unb64(h64)), json.loads(_unb64(p64)), _unb64(s64)
        except ValueError:
            raise _refuse("malformed") from None
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise _refuse("malformed")
        alg = header.get("alg")
        if alg not in ("RS256", "ES256"):
            raise _refuse(f"alg {str(alg)[:16]!r}")
        kid = header.get("kid")
        key = self._key(kid) if isinstance(kid, str) else None
        if key is None or key[0] != alg:
            raise _refuse("unknown kid")
        msg = f"{h64}.{p64}".encode()
        try:
            if alg == "RS256":
                key[1].verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            elif len(sig) == 64:
                der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
                key[1].verify(der, msg, ec.ECDSA(hashes.SHA256()))
            else:
                raise InvalidSignature()
        except InvalidSignature:
            raise _refuse("bad signature") from None
        now, aud, exp, nbf = self.clock(), claims.get("aud"), claims.get("exp"), claims.get("nbf", 0)
        if claims.get("iss") != self.issuer:
            raise _refuse("issuer")
        if self.audience not in ([aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []):
            raise _refuse("audience")
        if not isinstance(exp, (int, float)) or now >= exp + SKEW_S:
            raise _refuse("expired")
        if not isinstance(nbf, (int, float)) or now < nbf - SKEW_S:
            raise _refuse("not yet valid")
        k8s = claims.get("kubernetes.io") if isinstance(claims.get("kubernetes.io"), dict) else {}
        pod = k8s.get("pod") if isinstance(k8s.get("pod"), dict) else {}
        return _identity(claims.get("sub"), pod.get("name"), pod.get("uid"))

    # --- TokenReview ---

    def _review(self, token):
        h, now = hashlib.sha256(token.encode()).digest(), self.clock()
        with self._lock:
            hit = self._cache.pop(h, None)
            if hit and hit[0] > now:
                self._cache[h] = hit
                return hit[1]
        with open(self.token_file, encoding="utf-8") as f:   # re-read: the kubelet rotates it
            own = f.read().strip()
        body = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                           "spec": {"token": token, "audiences": [self.audience]}})
        try:
            out = _https("POST", self.tokenreview.rstrip("/") + "/apis/authentication.k8s.io/v1/tokenreviews", self.ctx,
                         body, {"Authorization": f"Bearer {own}", "Content-Type": "application/json"})
            st = out["status"]
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as e:
            raise RPCError("unavailable", f"TokenReview failed: {e}") from None
        if not isinstance(st, dict) or st.get("authenticated") is not True or self.audience not in (st.get("audiences") or []):
            raise _refuse("TokenReview did not authenticate it for this audience")
        user = st.get("user") if isinstance(st.get("user"), dict) else {}
        extra = user.get("extra") if isinstance(user.get("extra"), dict) else {}

        def first(k):
            v = extra.get(f"authentication.kubernetes.io/{k}")
            return v[0] if isinstance(v, list) and v else None
        identity = _identity(user.get("username"), first("pod-name"), first("pod-uid"))
        try:
            exp = json.loads(_unb64(token.split(".")[1]))["exp"]   # checked by the API server; bounds the cache only
            ttl = min(REVIEW_TTL_S, float(exp) - now)
        except (ValueError, KeyError, TypeError):
            ttl = 0
        if ttl > 0:
            with self._lock:
                self._cache[h] = (now + ttl, identity)
                while len(self._cache) > CACHE_MAX:
                    self._cache.popitem(last=False)
        return identity
