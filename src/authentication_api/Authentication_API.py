import logging
import os
from functools import wraps
from typing import Any, Callable, Dict

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from src.authentication_api.extensions import db, migrate
from src.authentication_api.models.jwt import (
    JWTHandler,
    RefreshTokenInvalid,
    TokenStorageError,
)
from src.authentication_api.models.signing_keys import RsaSigningKeysManager
from src.authentication_api.models.user import UserDB, UserSchema, PepperHandler

"""Flask application factory for the authentication API.

This module wires together database extensions, JWT key management, and
HTTP routes for user registration, login, logout, token refresh, and
JWKS key discovery.
"""

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
load_dotenv()


def extract_password() -> str:
    """Read and return the SECRET_PASSWORD used to encrypt signing keys."""
    load_dotenv()
    secret = os.getenv("SECRET_PASSWORD")
    if not secret:
        raise RuntimeError("SECRET_PASSWORD env var must be set")
    return secret


def require_service_password() -> None:
    """Validate the X-API-Key header against SERVICE_PASSWORD or raise."""
    expected = os.getenv("SERVICE_PASSWORD")
    provided = request.headers.get("X-API-Key")
    if not expected or provided != expected:
        # keep it generic
        raise PermissionError("Unauthorized service")


def service_protected(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that restricts a route to callers with the service password."""

    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            require_service_password()
        except PermissionError:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return wrapper


def get_json_or_400() -> Dict[str, Any]:
    """Return request JSON as a dict or raise ValueError on bad/missing body."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object body")
    return data


def create_app() -> Flask:
    """Application factory configuring DB, JWT handler, and HTTP routes."""
    app = Flask(__name__)

    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("AUTH_DB")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    

    db.init_app(app)
    migrate.init_app(app, db)

    secret_password = extract_password()
    key_manager = RsaSigningKeysManager(secret_password)
    jwt_handler = JWTHandler(key_manager)
    pepper_handler = PepperHandler()

    with app.app_context():
        db.create_all()

    # -------------------- routes --------------------
    @app.post("/logout")
    def logout():
        """Revoke a single refresh token, logging out the associated session."""
        try:
            data = get_json_or_400()
            refresh_token = data.get("refresh_token")
            if not refresh_token:
                return jsonify({"error": "refresh_token is required"}), 400
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        try:
            jwt_handler.revoke_refresh_token_by_refresh_token(refresh_token)
            return jsonify({"message": "Logout successful"}), 200
        except RefreshTokenInvalid as e:
            return jsonify({"error": str(e)}), 401
        except TokenStorageError:
            return jsonify({"error": "Database error"}), 500
        except Exception:
            log.exception("Unexpected logout error")
            return jsonify({"error": "Server error"}), 500

    @app.post("/logout_all")
    def logout_all():
        """Log out all active sessions for the user owning a refresh token."""
        try:
            data = get_json_or_400()
            refresh_token = data.get("refresh_token")
            if not refresh_token:
                return jsonify({"error": "refresh_token is required"}), 400
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        try:
            user_id = jwt_handler.verify_from_refresh(refresh_token)
        except RefreshTokenInvalid as e:
            return jsonify({"error": str(e)}), 401
        except TokenStorageError:
            return jsonify({"error": "Database error"}), 500
        except Exception:
            log.exception("Unexpected error verifying refresh token")
            return jsonify({"error": "Server error"}), 500

        try:
            jwt_handler.revoke_all_for_user(user_id)
            return jsonify({"message": "All sessions logged out successfully"}), 200
        except TokenStorageError:
            return jsonify({"error": "Database error"}), 500
        except Exception:
            log.exception("Unexpected logout_all error")
            return jsonify({"error": "Server error"}), 500

    @app.post("/login")
    def login():
        """Authenticate a user and return an access token plus refresh token."""
        try:
            data = get_json_or_400()
            user_data = UserSchema(**data)
        except ValidationError:
            return jsonify({"error": "Invalid input"}), 400
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        try:
            user: UserDB | None = (
                db.session.query(UserDB).filter_by(username=user_data.username).first()
            )
        except SQLAlchemyError:
            log.exception("DB error during login lookup")
            return jsonify({"error": "Database error"}), 500
        
        if not user or not user.check_password(user_data.password, pepper_handler):
            return jsonify({"error": "Invalid username or password"}), 401

        refresh_tokens = user.jwt_refresh_tokens or []
        if len(refresh_tokens) >= 5:
            return jsonify(
                {
                    "error": "Too many active sessions. Please refresh or logout other sessions."
                }
            ), 403

        try:
            token, refresh_token = jwt_handler.create_new_tokens(user.id)
        except TokenStorageError:
            # already sanitized inside your handler
            return jsonify({"error": "Database error"}), 500
        except Exception:
            log.exception("Unexpected error creating tokens")
            return jsonify({"error": "Server error"}), 500

        return jsonify(
            {
                "message": "Login successful",
                "token": token,
                "refresh_token": refresh_token,
            }
        ), 200

    @app.post("/register")
    def register():
        """Create a new user account if the username is not taken."""
        try:
            data = get_json_or_400()
            user_data = UserSchema(**data)
        except ValidationError:
            return jsonify({"error": "Invalid input"}), 400
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        try:
            exists = (
                db.session.query(UserDB).filter_by(username=user_data.username).first()
            )
            if exists:
                return jsonify({"error": "Username already exists"}), 400

            new_user = UserDB()
            new_user.username = user_data.username
            new_user.email = user_data.email
            new_user.set_password(user_data.password, pepper_handler)

            db.session.add(new_user)
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            log.exception("DB error during register")
            return jsonify({"error": "Database error"}), 500

        return jsonify({"message": "User registered successfully"}), 201

    @app.post("/refresh")
    def refresh():
        """Exchange a valid refresh token for a new access/refresh pair."""
        try:
            data = get_json_or_400()
            refresh_token = data.get("refresh_token")
            if not refresh_token:
                return jsonify({"error": "refresh_token is required"}), 400
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        try:
            new_token, new_refresh_token = jwt_handler.refresh(refresh_token)
            return jsonify(
                {"token": new_token, "refresh_token": new_refresh_token}
            ), 200
        except RefreshTokenInvalid as e:
            return jsonify({"error": str(e)}), 401
        except TokenStorageError:
            return jsonify({"error": "Database error"}), 500
        except Exception:
            log.exception("Unexpected refresh error")
            return jsonify({"error": "Server error"}), 500

    @app.get("/.well-known/jwks.json")
    @service_protected
    def jwks():
        """Expose the current public signing key set as JWKS for services."""
        try:
            key = key_manager.get_current_signing_key()
            # Standard-ish JWKS shape so clients can do data["keys"]
            return jsonify({"keys": [key.public_jwk]}), 200
        except SQLAlchemyError:
            log.exception("DB error returning JWKS")
            return jsonify({"error": "Database error"}), 500
        except Exception:
            log.exception("Unexpected error returning JWKS")
            return jsonify({"error": "Server error"}), 500

    @app.get("/keys/<kid>")
    @service_protected
    def get_key(kid: str):
        """Return the public JWK for a specific key ID (kid)."""
        try:
            key = key_manager.get_signing_key_by_id(kid)
            return jsonify(key.public_jwk), 200
        except ValueError:
            return jsonify({"error": "kid not found"}), 404
        except SQLAlchemyError:
            log.exception("DB error returning key by kid")
            return jsonify({"error": "Database error"}), 500
        except Exception:
            log.exception("Unexpected error returning key by kid")
            return jsonify({"error": "Server error"}), 500

    return app
