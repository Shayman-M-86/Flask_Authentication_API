import base64
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Optional

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import abort, g, request

"""JWT verification helpers for consumer services.

This module provides:
    - a JWKSKeyProvider that fetches and caches Ed25519 public keys from the
        Authentication API's JWKS endpoint, and
    - a RequiresAuth decorator that verifies bearer JWTs, validates their
        claims, and exposes them on flask.g for downstream view functions.
"""


ViewFunc = Callable[..., Any]


def _b64url_decode(s: str) -> bytes:
    """Decode base64url text (without padding) into raw bytes."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass(frozen=True, slots=True)
class JWTClaims:
    """Strongly-typed subset of JWT claims used by the application."""

    sub: int
    kid: str
    id: str
    alg: str
    iat: int
    exp: int


_G_CLAIMS_KEY = "jwt_claims"


def set_current_claims(claims: JWTClaims) -> None:
    """Store verified JWT claims on flask.g for the current request."""
    setattr(g, _G_CLAIMS_KEY, claims)


def get_current_claims() -> JWTClaims:
    """Retrieve current-request JWT claims or abort with 401 if missing."""
    claims = getattr(g, _G_CLAIMS_KEY, None)
    if not isinstance(claims, JWTClaims):
        abort(401, description="Missing JWT claims in request context")
    return claims


class JWKSKeyProvider:
    """Cache and resolve public keys by kid using the Auth API JWKS endpoint."""

    def __init__(
        self, jwks_url: str, api_key: str, *, timeout: float = 5.0, cache_ttl: int = 300
    ) -> None:
        self.jwks_url = jwks_url
        self.api_key = api_key
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._keys: dict[
            str, tuple[Ed25519PublicKey, int]
        ] = {}  # kid -> (key, exp)

    def get(self, kid: str) -> Ed25519PublicKey:
        """Return a public key for the given kid, refreshing cache if needed."""
        now = int(time.time())

        cached = self._keys.get(kid)
        if cached:
            key, exp = cached
            if exp > now:
                return key
            # expired
            self._keys.pop(kid, None)

        # cache miss -> fetch jwks
        self._refresh_cache()

        cached = self._keys.get(kid)
        if not cached:
            raise KeyError(f"kid not found: {kid}")

        key, exp = cached
        if exp <= now:
            raise KeyError(f"kid expired: {kid}")
        return key

    def _refresh_cache(self) -> None:
        """Fetch JWKS from the auth service and update the in-memory cache."""
        headers = {
            "X-API-Key": self.api_key,
        }
        r = requests.get(self.jwks_url, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()

        keys_val = data.get("keys")
        if isinstance(keys_val, list):
            keys = keys_val
        elif isinstance(data.get("key"), dict):
            keys = [data["key"]]
        else:
            keys = []
        now = int(time.time())
        new_cache: dict[str, tuple[Ed25519PublicKey, int]] = {}

        for jwk in keys:
            try:
                # Expect OKP Ed25519 JWK
                if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                    continue
                kid = jwk["kid"]
                x = jwk["x"]  # base64url public key bytes
                pub_bytes = _b64url_decode(x)
                pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

                # Cache TTL: simple time-based. If you provide "ver"/"verify_until", you can use it.
                exp = now + self.cache_ttl
                new_cache[kid] = (pub_key, exp)
            except Exception:
                continue

        # merge/update cache
        self._keys.update(new_cache)


class RequiresAuth:
    """Decorator-based JWT auth using JWKS-resolved Ed25519 public keys.

    It extracts the bearer token, loads the matching public key by ``kid``,
    verifies the signature, validates custom claims, and attaches them to
    flask.g so view functions can access the authenticated user.
    """

    def __init__(
        self,
        key_provider: JWKSKeyProvider,
        *,
        algorithms: Optional[list[str]] = None,
        debug: bool = False,
    ):
        """Configure auth with a key provider and allowed algorithms."""
        self.key_provider = key_provider
        self.algorithms = algorithms or ["EdDSA"]
        self.debug = debug

    def __call__(self, f: ViewFunc) -> ViewFunc:
        """Allow instance to be used directly as a ``@RequiresAuth(...)`` decorator."""

        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            self._authenticate_and_store()
            return f(*args, **kwargs)

        return wrapper

    def require(
        self,
        *,
        match_sub: bool = False,
        route_param: str = "sub",
    ) -> Callable[[ViewFunc], ViewFunc]:
        """Return a decorator enforcing authentication and optional user-id match.

        When ``match_sub`` is True, the claim ``sub`` must equal the
        route parameter identified by ``route_param`` or the request is
        rejected with 403.
        """

        def decorator(f: ViewFunc) -> ViewFunc:
            @wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                claims = self._authenticate_and_store()

                if match_sub:
                    if route_param not in kwargs:
                        abort(400, description=f"Route param '{route_param}' not found")
                    if str(claims.sub) != str(kwargs[route_param]):
                        abort(403, description="Forbidden")
                return f(*args, **kwargs)

            return wrapper

        return decorator

    def _authenticate_and_store(self) -> JWTClaims:
        """Verify the bearer token, store claims on flask.g, and return them."""
        token = self._get_token_auth_header()

        # 1) read header without verifying
        try:
            header = jwt.get_unverified_header(token)
        except Exception:
            abort(401, description="Invalid token header")

        kid = header.get("kid")
        if not kid:
            abort(401, description="Missing kid in token header")

        # 2) get key (cached, or fetches jwks)
        try:
            public_key = self.key_provider.get(kid)
        except Exception:
            abort(401, description="Unknown signing key")

        # 3) verify + decode
        try:
            payload = jwt.decode(
                token,
                key=public_key,
                algorithms=self.algorithms,
                options={"verify_exp": False},  # you use exp, not exp
            )
        except jwt.InvalidTokenError:
            abort(401, description="Invalid token")

        # 4) validate claims + expiry
        claims = self._validate_payload(payload)
        set_current_claims(claims)
        return claims

    def _validate_payload(self, payload: dict[str, Any]) -> JWTClaims:
        """Validate payload structure and custom expiry, returning JWTClaims."""
        required = (
            "sub",
            "kid",
            "id",
            "alg",
            "iat",
            "exp",
        )
        missing = [k for k in required if payload.get(k) is None]
        if missing:
            abort(401, description="Invalid token")

        try:
            claims = JWTClaims(
                sub=int(payload["sub"]),
                kid=str(payload["kid"]),
                id=str(payload["id"]),
                alg=str(payload["alg"]),
                iat=int(payload["iat"]),
                exp=int(payload["exp"]),
            )
        except Exception:
            abort(401, description="Invalid token")

        if claims.exp <= int(time.time()):
            abort(401, description="Token expired")

        return claims

    @staticmethod
    def _get_token_auth_header() -> str:
        """Extract the bearer token from the Authorization header or abort."""
        auth = request.headers.get("Authorization")
        if not isinstance(auth, str):
            abort(401, description="Authorization header is expected")

        parts = auth.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            abort(401, description="Malformed Authorization header")

        return parts[1]
