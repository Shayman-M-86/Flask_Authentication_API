import base64
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Optional

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import abort, g, request


ViewFunc = Callable[..., Any]


def _b64url_decode(s: str) -> bytes:
    # base64url without padding
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass(frozen=True, slots=True)
class JWTClaims:
    user_id: int
    signature_id: str
    id: str
    algorithm: str
    created_at: int
    expires_at: int


_G_CLAIMS_KEY = "jwt_claims"


def set_current_claims(claims: JWTClaims) -> None:
    setattr(g, _G_CLAIMS_KEY, claims)


def get_current_claims() -> JWTClaims:
    claims = getattr(g, _G_CLAIMS_KEY, None)
    if not isinstance(claims, JWTClaims):
        abort(401, description="Missing JWT claims in request context")
    return claims


class JWKSKeyProvider:
    """
    Caches public keys by kid. Fetches JWKS from the Auth API when kid is missing.
    """

    def __init__(
        self, jwks_url: str, api_key: str, *, timeout: float = 5.0, cache_ttl: int = 300
    ) -> None:
        self.jwks_url = jwks_url
        self.api_key = api_key
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._keys: dict[
            str, tuple[Ed25519PublicKey, int]
        ] = {}  # kid -> (key, expires_at)

    def get(self, kid: str) -> Ed25519PublicKey:
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
        print(f"Fetched new key for kid={kid}, expires_at={exp}")  # Debugging statement
        return key

    def _refresh_cache(self) -> None:
        headers = {
            "X-API-Key": self.api_key,
        }
        r = requests.get(self.jwks_url, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        print(f"JWKS fetch data: {data}")  # Debugging statement

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
    """
    JWT auth that:
      - extracts bearer token
      - reads kid from header
      - fetches public key from Auth API JWKS if needed
      - verifies token
      - validates payload format
      - stores claims on g
    """

    def __init__(
        self,
        key_provider: JWKSKeyProvider,
        *,
        algorithms: Optional[list[str]] = None,
        debug: bool = False,
    ):
        self.key_provider = key_provider
        self.algorithms = algorithms or ["EdDSA"]
        self.debug = debug

    def __call__(self, f: ViewFunc) -> ViewFunc:
        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            self._authenticate_and_store()
            return f(*args, **kwargs)

        return wrapper

    def require(
        self,
        *,
        match_user_id: bool = False,
        route_param: str = "user_id",
    ) -> Callable[[ViewFunc], ViewFunc]:
        def decorator(f: ViewFunc) -> ViewFunc:
            @wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                claims = self._authenticate_and_store()

                if match_user_id:
                    if route_param not in kwargs:
                        abort(400, description=f"Route param '{route_param}' not found")
                    if str(claims.user_id) != str(kwargs[route_param]):
                        abort(403, description="Forbidden")
                return f(*args, **kwargs)

            return wrapper

        return decorator

    def _authenticate_and_store(self) -> JWTClaims:
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
                options={"verify_exp": False},  # you use expires_at, not exp
            )
        except jwt.InvalidTokenError:
            abort(401, description="Invalid token")

        # 4) validate claims + expiry
        claims = self._validate_payload(payload)
        set_current_claims(claims)
        return claims

    def _validate_payload(self, payload: dict[str, Any]) -> JWTClaims:
        required = (
            "user_id",
            "signature_id",
            "id",
            "algorithm",
            "created_at",
            "expires_at",
        )
        missing = [k for k in required if payload.get(k) is None]
        if missing:
            abort(401, description="Invalid token")

        try:
            claims = JWTClaims(
                user_id=int(payload["user_id"]),
                signature_id=str(payload["signature_id"]),
                id=str(payload["id"]),
                algorithm=str(payload["algorithm"]),
                created_at=int(payload["created_at"]),
                expires_at=int(payload["expires_at"]),
            )
        except Exception:
            abort(401, description="Invalid token")

        if claims.expires_at <= int(time.time()):
            abort(401, description="Token expired")

        return claims

    @staticmethod
    def _get_token_auth_header() -> str:
        auth = request.headers.get("Authorization")
        if not isinstance(auth, str):
            abort(401, description="Authorization header is expected")

        parts = auth.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            abort(401, description="Malformed Authorization header")

        return parts[1]
