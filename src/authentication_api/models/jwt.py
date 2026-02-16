import os
import time

import jwt  # PyJWT
from pydantic import BaseModel, Field
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.exc import SQLAlchemyError
from typing import TYPE_CHECKING

from src.authentication_api.extensions import db
from src.authentication_api.models.signing_keys import RsaSigningKeysManager, RsaSigningKeys

if TYPE_CHECKING:
    from src.authentication_api.models.user import UserDB
    from src.authentication_api.models.signing_keys import RsaSigningKeysDB


class JwtRefreshPayload(BaseModel):
    id: str = Field(default_factory=lambda: os.urandom(32).hex())
    user_id: int
    signature_id: str
    jwt_id: str
    algorithm: str = Field(default="EdDSA")
    created_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: int = Field(default_factory=lambda: int(time.time()) + 160 * 24 * 3600)

class JwtRefreshDB(db.Model):
    __tablename__ = "jwt_refresh"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    signature_id: Mapped[str] = mapped_column(
        ForeignKey("rsa_signing_keys.key_id"), nullable=False
    )
    jwt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(20), nullable=False, default="EdDSA")
    created_at: Mapped[int] = mapped_column(Integer, nullable=False, default=lambda: int(time.time()))
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False, default=lambda: int(time.time()) + 3600)
    
    user: Mapped["UserDB"] = relationship("UserDB", back_populates="jwt_refresh_tokens")
    signing_key: Mapped["RsaSigningKeysDB"] = relationship("RsaSigningKeysDB")
    
    def entry(self, payload: JwtRefreshPayload) -> None:
        self.id = payload.id
        self.user_id = payload.user_id
        self.signature_id = payload.signature_id
        self.jwt_id = payload.jwt_id
        self.algorithm = payload.algorithm
        self.created_at = payload.created_at
        self.expires_at = payload.expires_at


class Jwtpayload(BaseModel):
    user_id: int
    signature_id: str
    id: str = Field(default_factory=lambda: os.urandom(32).hex())
    algorithm: str = Field(default="EdDSA")
    created_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: int = Field(default_factory=lambda: int(time.time()) + 3600)

class JWTHandler:
    def __init__(self, key_manager: RsaSigningKeysManager):
        self.key_manager = key_manager
        
    @staticmethod
    def _create_refresh_token(user_id: int, signing_key: RsaSigningKeys, jwt_id: str) -> str:
        payload: JwtRefreshPayload = JwtRefreshPayload(user_id=user_id, signature_id=signing_key.key_id, jwt_id=jwt_id)
        refresh_token = jwt.encode(payload.model_dump(), signing_key.private_key, algorithm=payload.algorithm)
        try:
            refresh_token_db = JwtRefreshDB()
            refresh_token_db.entry(payload)
            db.session.add(refresh_token_db)
            db.session.commit()

        except SQLAlchemyError:
            db.session.rollback()
            raise SQLAlchemyError("Failed to store refresh token in the database")
        return refresh_token
    
    @staticmethod
    def _create_token(user_id: int, signing_key: RsaSigningKeys) -> tuple[str, str]:
        payload: Jwtpayload = Jwtpayload(user_id=user_id, signature_id=signing_key.key_id)
        print(f"Creating JWT with payload: {payload.model_dump()}")  # Debugging statement
        token = jwt.encode(payload.model_dump(), signing_key.private_key, algorithm=payload.algorithm, headers={"kid": signing_key.key_id}) 
        return token, payload.id
    
    def create_new_tokens(self, user_id: int) -> tuple[str, str]:
        signing_key = self.key_manager.get_current_signing_key()
        token, jwt_id = self._create_token(user_id, signing_key)
        refresh_token = self._create_refresh_token(user_id, signing_key, jwt_id)
        return token, refresh_token
    
    @staticmethod
    def refresh_token_verify(refresh_token: str) -> JwtRefreshDB:
        payload = jwt.decode(refresh_token, options={"verify_signature": False})
        try:
            db_entry: JwtRefreshDB | None = db.session.query(JwtRefreshDB).filter_by(id=payload.get("id")).first()
            if not db_entry:
                raise jwt.InvalidTokenError("Refresh token not found in database")
        except SQLAlchemyError as e:
            raise jwt.InvalidTokenError(f"Database error: {e}")
        
        if not (
            db_entry.signature_id == payload.get("signature_id")
            and db_entry.jwt_id == payload.get("jwt_id")
            and db_entry.expires_at > int(time.time())
        ):
            raise jwt.InvalidTokenError("Invalid or expired refresh token")
        return db_entry
    
    def verify_signature(self, refresh_token: str, db_entry: JwtRefreshDB):
        signing_key_db: RsaSigningKeys = self.key_manager.get_signing_key_by_id(db_entry.signature_id)
        if not signing_key_db:
            raise jwt.InvalidTokenError("Signing key not found in database")
        try:
            jwt.decode(refresh_token, signing_key_db.public_key, algorithms=[db_entry.algorithm])
        except jwt.PyJWTError as e:
            raise jwt.InvalidTokenError(f"Invalid token signature: {e}")
        

    def refresh(self, refresh_token: str) -> tuple[str, str]:
        db_entry = self.refresh_token_verify(refresh_token)
        try:
            self.verify_signature(refresh_token, db_entry)
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Token verification failed: {e}")
        
        try:
            new_tokens = self.create_new_tokens(db_entry.user_id)
        except SQLAlchemyError as e:
            raise SQLAlchemyError(f"Failed to create new tokens: {e}")
        
        try:
            db.session.delete(db_entry)
            db.session.commit()
            return new_tokens
        except SQLAlchemyError as e:
            db.session.rollback()
            raise SQLAlchemyError(f"Failed to delete old refresh token: {e}")