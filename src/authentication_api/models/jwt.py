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
from src.authentication_api.models.signing_keys import (SigningKeys,
                                                        SigningKeysManager)

log = getLogger(__name__)

if TYPE_CHECKING:
    from src.authentication_api.models.signing_keys import SigningKeysDB
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

    rid: str = Field(default_factory=lambda: os.urandom(32).hex()) # unique refresh token ID for DB lookup
    sub: int
    kid: str
    tid: str
    alg: str = Field(default="EdDSA")
    iat: int = Field(default_factory=lambda: int(time.time()))
    exp: int = Field(default_factory=refresh_token_expiry)


class JwtRefreshDB(db.Model):
    """SQLAlchemy model for storing refresh tokens linked to users and signing keys."""

    __tablename__ = "jwt_refresh"

    rid: Mapped[str] = mapped_column(String(64), primary_key=True)
    sub: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    kid: Mapped[str] = mapped_column(
        ForeignKey("signing_keys.key_id"), nullable=False
    )
    tid: Mapped[str] = mapped_column(String(64), nullable=False)
    alg: Mapped[str] = mapped_column(String(20), nullable=False, default="EdDSA")
    iat: Mapped[int] = mapped_column(
        Integer, nullable=False, default=lambda: int(time.time())
    )
    exp: Mapped[int] = mapped_column(Integer, nullable=False, default=refresh_token_expiry) # 181 days for refresh tokens

    user: Mapped["UserDB"] = relationship("UserDB", back_populates="jwt_refresh_tokens")
    signing_key: Mapped["SigningKeysDB"] = relationship("SigningKeysDB", foreign_keys=[kid])

    def entry(self, payload: JwtRefreshPayload) -> None:
        """Populate this DB row from a JwtRefreshPayload instance."""
        self.rid = payload.rid # unique refresh token ID for lookup
        self.sub = payload.sub # user ID for association
        self.kid = payload.kid # signing key ID for association
        self.tid = payload.tid # token ID for consistency checks
        self.alg = payload.alg # algorithm for verification
        self.iat = payload.iat # issued at timestamp
        self.exp = payload.exp # expiry timestamp


class Jwtpayload(BaseModel):
    """Pydantic payload model for access JWTs."""

    sub: int
    kid: str
    tid: str = Field(default_factory=lambda: os.urandom(32).hex())
    alg: str = Field(default="EdDSA")
    iat: int = Field(default_factory=lambda: int(time.time()))
    exp: int = Field(default_factory=token_expiry) # 6 minutes for access tokens


# -------------------- handler --------------------


class JWTHandler:
    """Issue, persist, verify, and refresh JWT access and refresh tokens."""

    def __init__(self, key_manager: SigningKeysManager):
        """Initialize with a signing key manager used to fetch keys."""
        self.key_manager = key_manager

    # ---- create tokens ----

    @staticmethod
    def _create_token(sub: int, signing_key: SigningKeys) -> tuple[str, str]:
        """Create a signed access JWT and return (token, tid)."""
        payload = Jwtpayload(sub=sub, kid=signing_key.key_id)
        token = jwt.encode(
            payload.model_dump(),
            signing_key.private_key,
            algorithm=payload.alg,
            headers={"kid": signing_key.key_id},
        )
        return token, payload.tid

    @staticmethod
    def _create_refresh_token(
        sub: int, signing_key: SigningKeys, tid: str
    ) -> str:
        """Create, store, and return a signed refresh token for the given user/JWT."""
        payload = JwtRefreshPayload(
            sub=sub,
            kid=signing_key.key_id,
            tid=tid,
        )

        refresh_token = jwt.encode(
            payload.model_dump(),
            signing_key.private_key,
            algorithm=payload.alg,
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

    def create_new_tokens(self, sub: int) -> tuple[str, str]:
        """Mint a new access token and refresh token pair for a user."""
        signing_key = self.key_manager.get_current_signing_key()
        token, tid = self._create_token(sub, signing_key)
        refresh_token = self._create_refresh_token(sub, signing_key, tid)
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
        token_id = payload.get("rid")

        if not token_id:
            raise RefreshTokenInvalid("Refresh token missing 'rid'")

        try:
            db_entry: JwtRefreshDB | None = (
                db.session.query(JwtRefreshDB).filter_by(rid=token_id).first()
            )
        except SQLAlchemyError as e:
            log.exception("DB error while looking up refresh token")
            raise TokenStorageError(
                "Database error while verifying refresh token"
            ) from e

        if not db_entry:
            raise RefreshTokenInvalid("Refresh token not found in database")

        # Basic DB vs payload consistency checks
        if db_entry.kid != payload.get("kid"):
            raise RefreshTokenInvalid("Refresh token kid mismatch")
        if db_entry.tid != payload.get("tid"):
            raise RefreshTokenInvalid("Refresh token tid mismatch")
        if db_entry.exp <= int(time.time()):
            raise RefreshTokenInvalid("Refresh token expired")

        return db_entry

    def verify_signature(self, refresh_token: str, db_entry: JwtRefreshDB) -> None:
        """Verify the cryptographic signature of a refresh token using its key."""
        # key manager should raise if not found; treat as invalid token
        try:
            signing_key: SigningKeys = self.key_manager.get_signing_key_by_id(
                db_entry.kid
            )
        except Exception as e:
            # keep it strict: if you can't find key, token can't be trusted
            raise RefreshTokenInvalid("Signing key not found") from e

        try:
            jwt.decode(
                refresh_token,
                signing_key.public_key,
                algorithms=[db_entry.alg],
                options={
                    "require": ["exp", "iat"]
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
            new_tokens = self.create_new_tokens(db_entry.sub)
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

    def revoke_all_for_user(self, sub: int) -> None:
        """Revoke all refresh tokens for a user, e.g. on password change."""
        try:
            db.session.query(JwtRefreshDB).filter_by(sub=sub).delete()
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to revoke refresh tokens for user")
            raise TokenStorageError("Failed to revoke refresh tokens for user") from e

    def revoke_refresh_token_by_refresh_token(self, refresh_token: str) -> None:
        """Revoke a refresh token by its token string, e.g. on logout with token."""
        try:
            payload = self._extract_unverified_payload(refresh_token)
            token_id = payload.get("rid")
            if not token_id:
                raise ValueError("Refresh token missing 'rid' claim")
            db.session.query(JwtRefreshDB).filter_by(rid=token_id).delete()
            db.session.commit()
        except ValueError as e:
            log.warning(f"Attempted to revoke refresh token with invalid payload: {e}")
            # treat as no-op since we can't trust the token
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to revoke refresh token by token")
            raise TokenStorageError("Failed to revoke refresh token") from e

    def revoke_all_for_key(self, kid: str) -> None:
        """Revoke all refresh tokens issued with a specific signing key, e.g. on key rotation."""
        try:
            db.session.query(JwtRefreshDB).filter_by(kid=kid).delete()
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
            db.session.query(JwtRefreshDB).filter_by(rid=token_id).delete()
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            log.exception("Failed to revoke refresh token by rid")
            raise TokenStorageError("Failed to revoke refresh token") from e

    def revoke_refresh_token_by_limit(self, sub: int, limit: int) -> None:
        """Revoke a limited number of refresh tokens for a user."""
        try:
            db.session.query(JwtRefreshDB).filter_by(sub=sub).order_by(
                JwtRefreshDB.iat.asc()
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
        return db_entry.sub


