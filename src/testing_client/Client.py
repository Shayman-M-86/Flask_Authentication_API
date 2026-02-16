# auth_client_test.py
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional
import base64
import json

import jwt
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

        r = self.session.post(
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

    def logout(self) -> Dict[str, Any]:
        """Logout current session (revoke this refresh token)."""
        if not self.tokens:
            raise AuthClientError("No tokens set. Call login() first.")
        r = self.session.post(
            f"{self.base_url}/logout",
            json={"refresh_token": self.tokens.refresh_token},
            timeout=self.timeout,
        )
        data = self._handle_json(r)
        # After logout, refresh token should be invalid, so clear locally too
        self.tokens = None
        return data

    def logout_all(self, user_id: int) -> Dict[str, Any]:
        """Logout all sessions for a user."""
        r = self.session.post(
            f"{self.base_url}/logout_all",
            json={"refresh_token": self.tokens.refresh_token} if self.tokens else {},
            timeout=self.timeout,
        )
        data = self._handle_json(r)
        self.tokens = None
        return data

    def auth_headers(self) -> Dict[str, str]:
        if not self.tokens:
            raise AuthClientError("No access token.")
        return {"Authorization": f"Bearer {self.tokens.access_token}"}

    def _get_json(
        self, url: str, *, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        r = self.session.get(url, headers=headers, timeout=self.timeout)
        return self._handle_json(r)

    @staticmethod
    def _handle_json(r: requests.Response) -> Dict[str, Any]:
        try:
            data = r.json()
        except Exception:
            raise AuthClientError(f"Non-JSON response ({r.status_code}): {r.text}")

        if not r.ok:
            raise AuthClientError(f"HTTP {r.status_code}: {data}")

        return data


# ---------- test helpers ----------


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")


def decode_jwt_header(token: str) -> Dict[str, Any]:

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    pad = "=" * (-len(parts[0]) % 4)
    raw = base64.urlsafe_b64decode(parts[0] + pad)
    return json.loads(raw.decode("utf-8"))


def decode_jwt_payload(token: str) -> Dict[str, Any]:

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

    # 4) Extract user_id (for /health/<int:user>)
    user_id: Optional[int] = None
    try:
        payload = decode_jwt_payload(tokens.access_token)
        uid = payload.get("user_id", payload.get("sub"))
        if uid is None:
            raise ValueError("Token payload missing user_id (or sub)")
        user_id = int(uid)
        ok(f"token payload -> user_id={user_id}")
    except Exception as e:
        fail(f"token payload -> {e}")
        failed = True

    # 5) Test the app endpoint /health/<int:user>
    if user_id is not None:
        try:
            url = f"{app_base}/health/{user_id}"
            data = client._get_json(url, headers=client.auth_headers())
            value = data.values()
            ok(f"app GET {url} -> {value}")
        except AuthClientError as e:
            fail(f"app /health/{user_id} -> {e}")
            failed = True

    # 6) Refresh (should rotate)
    old_access = tokens.access_token
    old_refresh = tokens.refresh_token
    try:
        new_tokens = client.refresh()
        ok("refresh -> success")
        if new_tokens.access_token == old_access:
            fail("refresh -> access token did not change")
            failed = True
        else:
            ok("refresh -> access token rotated")
        if new_tokens.refresh_token == old_refresh:
            fail("refresh -> refresh token did not change")
            failed = True
        else:
            ok("refresh -> refresh token rotated")
    except AuthClientError as e:
        fail(f"refresh -> {e}")
        failed = True

    # 7) Logout (single session) then refresh should FAIL
    # Save refresh token before logout (client.logout clears tokens)
    refresh_to_test = client.tokens.refresh_token if client.tokens else None
    try:
        res = client.logout()
        ok(f"logout -> {res.get('message', res)}")
    except AuthClientError as e:
        fail(f"logout -> {e}")
        failed = True

    if refresh_to_test:
        try:
            # attempt refresh using the revoked token
            r = client.session.post(
                f"{auth_base}/refresh",
                json={"refresh_token": refresh_to_test},
                timeout=client.timeout,
            )
            if r.ok:
                fail(f"refresh after logout -> unexpectedly succeeded: {r.json()}")
                failed = True
            else:
                ok(f"refresh after logout -> failed as expected ({r.status_code})")
        except Exception as e:
            fail(f"refresh after logout -> request error: {e}")
            failed = True

    # 8) Login again, then logout_all, then refresh should FAIL
    try:
        tokens2 = client.login(username, password, email)  # noqa: F841
        ok("login (for logout_all) -> received tokens")
    except AuthClientError as e:
        fail(f"login (for logout_all) -> {e}")
        sys.exit(1)

    refresh_to_test2 = client.tokens.refresh_token if client.tokens else None

    if user_id is not None:
        try:
            res = client.logout_all(user_id)
            ok(f"logout_all -> {res.get('message', res)}")
        except AuthClientError as e:
            fail(f"logout_all -> {e}")
            failed = True

        if refresh_to_test2:
            try:
                r = client.session.post(
                    f"{auth_base}/refresh",
                    json={"refresh_token": refresh_to_test2},
                    timeout=client.timeout,
                )
                if r.ok:
                    fail(
                        f"refresh after logout_all -> unexpectedly succeeded: {r.json()}"
                    )
                    failed = True
                else:
                    ok(
                        f"refresh after logout_all -> failed as expected ({r.status_code})"
                    )
            except Exception as e:
                fail(f"refresh after logout_all -> request error: {e}")
                failed = True

    # Exit status
    if failed:
        sys.exit(1)

    print("\nAll tests passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
