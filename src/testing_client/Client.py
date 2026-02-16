# auth_client_test.py
from __future__ import annotations

import jwt

import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


class AuthClientError(Exception):
    pass


@dataclass
class Tokens:
    access_token: str
    refresh_token: str


class AuthClient:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.tokens: Optional[Tokens] = None

    def register(self, username: str, email: str, password: str) -> Dict[str, Any]:
        payload = {"username": username, "email": email, "password": password}
        r = self.session.post(
            f"{self.base_url}/register", json=payload, timeout=self.timeout
        )
        return self._handle_json(r)

    def login(self, username: str, password: str, email: str) -> Tokens:
        payload = {"username": username, "password": password, "email": email}
        r = self.session.post(
            f"{self.base_url}/login", json=payload, timeout=self.timeout
        )
        data = self._handle_json(r)

        token = data.get("token")
        refresh_token = data.get("refresh_token")
        if not token or not refresh_token:
            raise AuthClientError(f"Login response missing tokens: {data}")

        self.tokens = Tokens(access_token=token, refresh_token=refresh_token)
        return self.tokens

    def refresh(self) -> Tokens:
        if not self.tokens:
            raise AuthClientError("No tokens set. Call login() first.")

        # Your API uses GET with JSON body
        r = self.session.get(
            f"{self.base_url}/refresh",
            json={"refresh_token": self.tokens.refresh_token},
            timeout=self.timeout,
        )
        data = self._handle_json(r)

        token = data.get("token")
        refresh_token = data.get("refresh_token")
        if not token or not refresh_token:
            raise AuthClientError(f"Refresh response missing tokens: {data}")

        self.tokens = Tokens(access_token=token, refresh_token=refresh_token)
        return self.tokens

    def auth_headers(self) -> Dict[str, str]:
        if not self.tokens:
            raise AuthClientError("No access token.")
        return {"Authorization": f"Bearer {self.tokens.access_token}"}

    def _get_json(
        self, url: str, *, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        print(f"GET {url} with headers={headers}")  # Debugging statement
        jwtt = headers.get("Authorization") if headers else None
        if jwtt:
            decoded = jwt.decode(jwtt.split(" ")[1], options={"verify_signature": False})
            print(f"Decoded JWT: {decoded}")

        r = self.session.get(url, headers=headers, timeout=self.timeout)
        return self._handle_json(r)

    @staticmethod
    def _handle_json(r: requests.Response) -> Dict[str, Any]:
        try:
            data = r.json()
        except Exception:
            raise AuthClientError(f"Non-JSON response ({r.status_code}): {r.text}")

        status_code = r.status_code
        if status_code >= 400:
            raise AuthClientError(f"HTTP {status_code}: {data}")

        return data


# ---------- test helpers ----------


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")


def decode_jwt_header(token: str) -> Dict[str, Any]:
    import base64
    import json

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    pad = "=" * (-len(parts[0]) % 4)
    raw = base64.urlsafe_b64decode(parts[0] + pad)
    return json.loads(raw.decode("utf-8"))


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    import base64
    import json

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    pad = "=" * (-len(parts[1]) % 4)
    raw = base64.urlsafe_b64decode(parts[1] + pad)
    return json.loads(raw.decode("utf-8"))


# ---------- main test ----------


def main() -> None:
    auth_base = os.getenv("AUTH_BASE_URL", "http://127.0.0.1:5000")
    app_base = os.getenv("APP_BASE_URL", "http://127.0.0.1:5001")

    username = os.getenv("AUTH_TEST_USER", "shayman")
    email = os.getenv("AUTH_TEST_EMAIL", "shayman@example.com")
    password = os.getenv("AUTH_TEST_PASSWORD", "password123")

    client = AuthClient(auth_base)
    failed = False

    # 1) Register
    try:
        res = client.register(username, email, password)
        ok(f"register -> {res.get('message', res)}")
    except AuthClientError as e:
        if "exists" in str(e).lower():
            ok("register -> already exists")
        else:
            fail(f"register -> {e}")
            failed = True

    # 2) Login
    try:
        tokens = client.login(username, password, email)
        ok("login -> received tokens")
    except AuthClientError as e:
        fail(f"login -> {e}")
        sys.exit(1)

    # 3) Validate JWT header
    try:
        header = decode_jwt_header(tokens.access_token)
        if "kid" not in header:
            raise ValueError("Missing kid in header")
        ok(f"jwt header -> alg={header.get('alg')} kid present")
    except Exception as e:
        fail(f"jwt header -> {e}")
        failed = True

    # 4) Extract user_id (for /health2/<int:user>)
    user_id: Optional[int] = None
    try:
        payload = decode_jwt_payload(tokens.access_token)
        # your payload uses user_id; fallback to sub if you ever switch
        uid = payload.get("user_id", payload.get("sub"))
        if uid is None:
            raise ValueError("Token payload missing user_id (or sub)")
        user_id = int(uid)
        ok(f"token payload -> user_id={user_id}")
    except Exception as e:
        fail(f"token payload -> {e}")
        failed = True

    # 5) Test the app endpoint /health2/<int:user>
    if user_id is not None:
        try:
            url = f"{app_base}/health2/{user_id}"
            data = client._get_json(url, headers=client.auth_headers())
            ok(f"app GET {url} -> {data}")
        except AuthClientError as e:
            fail(f"app /health2/{user_id} -> {e}")
            failed = True

    # 6) Refresh
    try:
        new_tokens = client.refresh()
        ok("refresh -> success")
        if new_tokens.access_token == tokens.access_token:
            fail("refresh -> token did not change")
            failed = True
        else:
            ok("refresh -> token rotated")
    except AuthClientError as e:
        fail(f"refresh -> {e}")
        failed = True

    # Exit status
    if failed:
        sys.exit(1)

    print("\nAll tests passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
