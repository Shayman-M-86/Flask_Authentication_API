from __future__ import annotations

import logging
import os
from typing import Any

from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS

from src.Application.extensions.JWT_authentication import (
    JWKSKeyProvider,
    RequiresAuth,
    get_current_claims,
)

logger = logging.getLogger(__name__)

load_dotenv()  # Load environment variables from .env file


DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 100

AUTH_JWKS_URL = "http://127.0.0.1:5000/.well-known/jwks.json"
API_KEY = os.getenv(
    "SERVICE_PASSWORD", "default_service_password"
)  # Ensure this is set in .env
key_provider = JWKSKeyProvider(AUTH_JWKS_URL, API_KEY, cache_ttl=300)
requires_auth = RequiresAuth(key_provider)


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)

    # Prefer configuring CORS here instead of manually setting headers
    CORS(
        app,
        resources={r"/*": {"origins": ["http://localhost:5001"]}},
        supports_credentials=True,
    )

    # ---------- Helpers ----------

    # ---------- Routes ----------

    @app.route("/health", methods=["GET"])
    @requires_auth
    def health_check():
        claims = get_current_claims()
        message = f"Hello, user {claims.sub}! Your token is valid."
        return jsonify(
            {"success": True, "message": f"API is healthy. Payload: {message}"}
        ), 200

    @app.route("/health/<int:user>", methods=["GET"])
    @requires_auth
    def health_check_with_id(user: int):
        claims = get_current_claims()
        return jsonify(
            {
                "success": True,
                "message": f"API is healthy. Payload: {claims.sub}, ID: {user}",
            }
        ), 200

    return app
