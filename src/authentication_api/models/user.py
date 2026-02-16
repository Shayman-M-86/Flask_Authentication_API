from typing import Annotated

from flask_login import UserMixin
from pydantic import BaseModel, Field
from sqlalchemy import CheckConstraint, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

from src.authentication_api.extensions import db
from src.authentication_api.models.jwt import JwtRefreshDB

"""User persistence model and input validation schema for the auth API."""


class UserDB(UserMixin, db.Model):
    """SQLAlchemy user table with password hashing and refresh-token relation."""

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime, server_default=func.now())

    _password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    __table_args__ = (
        CheckConstraint(
            "username ~ '^[A-Za-z0-9](?:[A-Za-z0-9_]*[A-Za-z0-9])?$'",
            name="ck_users_username_format",
        ),
        CheckConstraint(
            "length(username) >= 4",
            name="ck_users_username_min_length",
        ),
        CheckConstraint(
            "position('@' in email) > 1",
            name="ck_users_email_has_at",
        ),
    )
    jwt_refresh_tokens: Mapped[list["JwtRefreshDB"]] = relationship(
        "JwtRefreshDB", back_populates="user"
    )

    def __repr__(self) -> str:
        """Return a short textual representation of the user."""
        quote = f"<User {self.username} - {self.email}>"
        return quote

    def set_password(self, password: str) -> None:
        """Hash and store the user's password."""
        self._password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self._password_hash, password)

    def to_dict(self) -> dict:
        """Return a serializable dictionary of basic user fields."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at,
        }


class UserSchema(BaseModel):
    """Pydantic schema for validating username, email, and password input."""

    username: Annotated[
        str,
        Field(..., min_length=4, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9_]*[A-Za-z0-9])?$"),
    ]
    email: Annotated[str, Field(..., pattern=r"^[^@]+@[^@]+\.[^@]+$")]
    password: Annotated[str, Field(..., min_length=8)]
