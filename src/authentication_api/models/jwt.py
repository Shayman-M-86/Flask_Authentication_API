import os
import time
from logging import getLogger
from typing import TYPE_CHECKING

import jwt  # PyJWT
from pydantic import BaseModel, Field
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.authentication_api.extensions import db
from src.authentication_api.models.signing_keys import (
    RsaSigningKeys,
    RsaSigningKeysManager,
)

log = getLogger(__name__)

if TYPE_CHECKING:
    from src.authentication_api.models.signing_keys import RsaSigningKeysDB
    from src.authentication_api.models.user import UserDB

def token_expiry() -> int:
    """Default expiry time for access tokens (6 minutes)."""
    return int(time.time()) + 360  # 6 minutes

def refresh_token_expiry() -> int:
    """Default expiry time for refresh tokens (181 days)."""
    return int(time.time()) + 3600 * 24 * 181  # 181 days

# -------------------- domain exceptions --------------------


class JWTHandlerError(RuntimeError):
    """Base error for JWT handler."""


class TokenStorageError(JWTHandlerError):
    """DB failures storing/reading/deleting refresh tokens."""


class RefreshTokenInvalid(JWTHandlerError):
    """Refresh token invalid/expired/not found/signature bad."""


# -------------------- models --------------------


class JwtRefreshPayload(BaseModel):
    """Pydantic payload model for persisted refresh tokens."""

    id: str = Field(default_factory=lambda: os.urandom(32).hex())
    user_id: int
    signature_id: str
    jwt_id: str
    algorithm: str = Field(default="EdDSA")
    created_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: int = Field(default_factory=refresh_token_expiry)


class JwtRefreshDB(db.Model):
    """SQLAlchemy model for storing refresh tokens linked to users and signing keys."""

    __tablename__ = "jwt_refresh"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    signature_id: Mapped[str] = mapped_column(
        ForeignKey("rsa_signing_keys.key_id"), nullable=False
    )
    jwt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(20), nullable=False, default="EdDSA")
    created_at: Mapped[int] = mapped_column(
        Integer, nullable=False, default=lambda: int(time.time())
    )
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False, default=refresh_token_expiry) # 181 days for refresh tokens

    user: Mapped["UserDB"] = relationship("UserDB", back_populates="jwt_refresh_tokens")
    signing_key: Mapped["RsaSigningKeysDB"] = relationship("RsaSigningKeysDB")

    def entry(self, payload: JwtRefreshPayload) -> None:
        """Populate this DB row from a JwtRefreshPayload instance."""
        self.id = payload.id
        self.user_id = payload.user_id
        self.signature_id = payload.signature_id
        self.jwt_id = payload.jwt_id
        self.algorithm = payload.algorithm
        self.created_at = payload.created_at
        self.expires_at = payload.expires_at


class Jwtpayload(BaseModel):
    """Pydantic payload model for access JWTs."""

    user_id: int
    signature_id: str
    id: str = Field(default_factory=lambda: os.urandom(32).hex())
    algorithm: str = Field(default="EdDSA")
    created_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: int = Field(default_factory=token_expiry) # 6 minutes for access tokens


# -------------------- handler --------------------


class JWTHandler:
    """Issue, persist, verify, and refresh JWT access and refresh tokens."""

    def __init__(self, key_manager: RsaSigningKeysManager):
        """Initialize with a signing key manager used to fetch keys."""
        self.key_manager = key_manager

    # ---- create tokens ----

    @staticmethod
    def _create_token(user_id: int, signing_key: RsaSigningKeys) -> tuple[str, str]:
        """Create a signed access JWT and return (token, jwt_id)."""
        payload = Jwtpayload(user_id=user_id, signature_id=signing_key.key_id)
        token = jwt.encode(
            payload.model_dump(),
            signing_key.private_key,
            algorithm=payload.algorithm,
            headers={"kid": signing_key.key_id},
        )
        return token, payload.id

    @staticmethod
    def _create_refresh_token(
        user_id: int, signing_key: RsaSigningKeys, jwt_id: str
    ) -> str:
        """Create, store, and return a signed refresh token for the given user/JWT."""
        payload = JwtRefreshPayload(
            user_id=user_id,
            signature_id=signing_key.key_id,
            jwt_id=jwt_id,
        )

        refresh_token = jwt.encode(
            payload.model_dump(),
            signing_key.private_key,
            algorithm=payload.algorithm,
            headers={"kid": signing_key.key_id},
        )

        try:
            row = JwtRefreshDB()
            row.entry(payload)
            db.session.add(row)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to store refresh token in DB")
            raise TokenStorageError("Failed to store refresh token in database") from e

        return refresh_token

    def create_new_tokens(self, user_id: int) -> tuple[str, str]:
        """Mint a new access token and refresh token pair for a user."""
        signing_key = self.key_manager.get_current_signing_key()
        token, jwt_id = self._create_token(user_id, signing_key)
        refresh_token = self._create_refresh_token(user_id, signing_key, jwt_id)
        return token, refresh_token

    # ---- verify refresh token ----

    @staticmethod
    def _extract_unverified_payload(refresh_token: str) -> dict:
        """Decode a refresh token without verifying its signature to inspect claims."""
        try:
            # unverified payload just to locate DB entry / kid / ids
            return jwt.decode(refresh_token, options={"verify_signature": False})
        except jwt.PyJWTError as e:
            raise RefreshTokenInvalid(f"Malformed refresh token: {e}") from e

    @staticmethod
    def refresh_token_verify(refresh_token: str) -> JwtRefreshDB:
        """Validate DB presence/consistency and expiry of a refresh token."""
        payload = JWTHandler._extract_unverified_payload(refresh_token)
        token_id = payload.get("id")

        if not token_id:
            raise RefreshTokenInvalid("Refresh token missing 'id'")

        try:
            db_entry: JwtRefreshDB | None = (
                db.session.query(JwtRefreshDB).filter_by(id=token_id).first()
            )
        except SQLAlchemyError as e:
            log.exception("DB error while looking up refresh token")
            raise TokenStorageError(
                "Database error while verifying refresh token"
            ) from e

        if not db_entry:
            raise RefreshTokenInvalid("Refresh token not found in database")

        # Basic DB vs payload consistency checks
        if db_entry.signature_id != payload.get("signature_id"):
            raise RefreshTokenInvalid("Refresh token signature_id mismatch")
        if db_entry.jwt_id != payload.get("jwt_id"):
            raise RefreshTokenInvalid("Refresh token jwt_id mismatch")
        if db_entry.expires_at <= int(time.time()):
            raise RefreshTokenInvalid("Refresh token expired")

        return db_entry

    def verify_signature(self, refresh_token: str, db_entry: JwtRefreshDB) -> None:
        """Verify the cryptographic signature of a refresh token using its key."""
        # key manager should raise if not found; treat as invalid token
        try:
            signing_key: RsaSigningKeys = self.key_manager.get_signing_key_by_id(
                db_entry.signature_id
            )
        except Exception as e:
            # keep it strict: if you can't find key, token can't be trusted
            raise RefreshTokenInvalid("Signing key not found") from e

        try:
            jwt.decode(
                refresh_token,
                signing_key.public_key,
                algorithms=[db_entry.algorithm],
                options={
                    "require": ["expires_at", "created_at"]
                },  # optional: enforce if you add them
            )
        except jwt.ExpiredSignatureError as e:
            raise RefreshTokenInvalid(
                "Refresh token signature valid but token expired"
            ) from e
        except jwt.PyJWTError as e:
            raise RefreshTokenInvalid(f"Invalid refresh token signature: {e}") from e

    # ---- refresh flow ----

    def refresh(self, refresh_token: str) -> tuple[str, str]:
        """Validate a refresh token, rotate it, and issue new tokens."""
        db_entry = self.refresh_token_verify(refresh_token)
        self.verify_signature(refresh_token, db_entry)

        # mint new tokens
        try:
            new_tokens = self.create_new_tokens(db_entry.user_id)
        except TokenStorageError:
            # already domain-specific
            raise
        except SQLAlchemyError as e:
            log.exception("DB error while creating new tokens")
            raise TokenStorageError("Database error while creating new tokens") from e

        # revoke old refresh token (single-use)
        try:
            db.session.delete(db_entry)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to delete old refresh token")
            raise TokenStorageError("Failed to delete old refresh token") from e

        return new_tokens

    def revoke_all_for_user(self, user_id: int) -> None:
        """Revoke all refresh tokens for a user, e.g. on password change."""
        try:
            db.session.query(JwtRefreshDB).filter_by(user_id=user_id).delete()
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to revoke refresh tokens for user")
            raise TokenStorageError("Failed to revoke refresh tokens for user") from e

    def revoke_refresh_token_by_refresh_token(self, refresh_token: str) -> None:
        """Revoke a refresh token by its token string, e.g. on logout with token."""
        try:
            payload = self._extract_unverified_payload(refresh_token)
            token_id = payload.get("id")
            if not token_id:
                raise ValueError("Refresh token missing 'id' claim")
            db.session.query(JwtRefreshDB).filter_by(id=token_id).delete()
            db.session.commit()
        except ValueError as e:
            log.warning(f"Attempted to revoke refresh token with invalid payload: {e}")
            # treat as no-op since we can't trust the token
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to revoke refresh token by token")
            raise TokenStorageError("Failed to revoke refresh token") from e

    def revoke_all_for_key(self, signature_id: str) -> None:
        """Revoke all refresh tokens issued with a specific signing key, e.g. on key rotation."""
        try:
            db.session.query(JwtRefreshDB).filter_by(signature_id=signature_id).delete()
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to revoke refresh tokens for signing key")
            raise TokenStorageError(
                "Failed to revoke refresh tokens for signing key"
            ) from e

    def revoke_token_by_id(self, token_id: str) -> None:
        """Revoke a specific refresh token by its ID, e.g. on logout."""
        try:
            db.session.query(JwtRefreshDB).filter_by(id=token_id).delete()
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to revoke refresh token by id")
            raise TokenStorageError("Failed to revoke refresh token") from e

    def revoke_refresh_token_by_limit(self, user_id: int, limit: int) -> None:
        """Revoke a limited number of refresh tokens for a user."""
        try:
            db.session.query(JwtRefreshDB).filter_by(user_id=user_id).order_by(
                JwtRefreshDB.created_at.asc()
            ).limit(limit).delete()
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to revoke refresh tokens by limit")
            raise TokenStorageError("Failed to revoke refresh tokens by limit") from e

    def verify_from_refresh(self, refresh_token: str) -> int:
        """Verify a refresh token and return the associated user ID, e.g. for logout_all."""
        db_entry = self.refresh_token_verify(refresh_token)
        self.verify_signature(refresh_token, db_entry)
        return db_entry.user_id
