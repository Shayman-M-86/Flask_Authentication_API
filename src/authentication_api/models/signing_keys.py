import base64
import os
import time
from logging import getLogger
from typing import Any

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Boolean, Integer, LargeBinary, String, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Mapped, mapped_column

from src.authentication_api.extensions import db

log = getLogger(__name__)


# -------------------- domain exceptions --------------------


class SigningKeyError(RuntimeError):
    """Base error for signing-key operations."""


class SigningKeyNotFound(SigningKeyError):
    """No key exists / not found in DB."""


class SigningKeyCryptoError(SigningKeyError):
    """Key serialization/decryption errors."""


class SigningKeyDBError(SigningKeyError):
    """DB query/commit/rollback errors."""


# -------------------- SQLAlchemy model --------------------


class RsaSigningKeysDB(db.Model):
    """SQLAlchemy model storing Ed25519 signing key material and metadata."""

    __tablename__ = "rsa_signing_keys"
    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    private_pem: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_pem: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    alg: Mapped[str] = mapped_column(String(10), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False)
    verify_until: Mapped[int] = mapped_column(Integer, nullable=False)
    signing_deactivate_after: Mapped[int] = mapped_column(Integer, nullable=False)
    public_jwk: Mapped[dict] = mapped_column(JSONB, nullable=False)

    def db_entry(self, rsakeys: "RsaSigningKeys") -> None:
        """Populate this DB record from a RsaSigningKeys value object."""
        self.key_id = rsakeys.key_id
        self.private_pem = rsakeys.private_pem
        self.public_pem = rsakeys.public_pem
        self.alg = rsakeys.alg
        self.is_active = rsakeys.is_active
        self.created_at = rsakeys.created_at
        self.expires_at = rsakeys.expires_at
        self.verify_until = rsakeys.verify_until
        self.signing_deactivate_after = rsakeys.signing_deactivate_after
        self.public_jwk = rsakeys.public_jwk


# -------------------- Pydantic model --------------------


class RsaSigningKeys(BaseModel):
    """In-memory representation of an Ed25519 signing key pair and metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    key_id: str
    private_pem: bytes
    public_pem: bytes
    alg: str
    is_active: bool
    created_at: int
    expires_at: int
    verify_until: int
    signing_deactivate_after: int
    public_jwk: dict[str, Any]

    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey


# -------------------- manager --------------------


class RsaSigningKeysManager:
    """Create, persist, load, and rotate Ed25519 signing keys."""

    def __init__(self, secret_password: str):
        """Initialize the manager with the password used to encrypt private keys."""
        self.secret_password = secret_password

    # ---------- pure helpers ----------



    @staticmethod
    def _encrypt_private_key(
        private_key: ed25519.Ed25519PrivateKey, secret_password: str
    ) -> bytes:
        """Serialize and encrypt a private key using the provided password."""
        return private_key.private_bytes(
            encoding=ser.Encoding.PEM,
            format=ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.BestAvailableEncryption(
                secret_password.encode("utf-8")
            ),
        )

    @staticmethod
    def _encoded_public_key(public_key: ed25519.Ed25519PublicKey) -> bytes:
        """Return the raw-encoded public key bytes."""
        return public_key.public_bytes(
            encoding=ser.Encoding.Raw,
            format=ser.PublicFormat.Raw,
        )

    @staticmethod
    def _b64url(data: bytes) -> str:
        """Base64url-encode bytes without padding and return as text."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    
    @staticmethod
    def _public_key_to_jwk(public_pem: bytes, key_id: str, alg: str, verify_until: int
    ) -> dict[str, Any]:
        """Build a minimal JWK representation for the given public key."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": RsaSigningKeysManager._b64url(public_pem),
            "kid": key_id,
            "use": "sig",
            "alg": alg,
            "ver": verify_until,
        }

    # ---------- crypto ----------

    @staticmethod
    def _decrypt_private_key(
        encrypted_pem: bytes | str, password: str
    ) -> ed25519.Ed25519PrivateKey:
        """Decrypt and deserialize an Ed25519 private key from PEM bytes/text."""
        
        if isinstance(encrypted_pem, str):
            # NOTE: only valid if you stored PEM as TEXT (utf-8)
            encrypted_pem = encrypted_pem.encode("utf-8")

        try:
            key = ser.load_pem_private_key(
                encrypted_pem,
                password=password.encode("utf-8"))
        except ValueError as e:
            raise SigningKeyCryptoError("Failed to decrypt/load private key") from e

        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise SigningKeyCryptoError("Loaded key is not an Ed25519 private key")

        return key

    # ---------- DB ----------

    @staticmethod
    def _load_latest_key() -> RsaSigningKeysDB:
        """Return the most recently created active signing key from the DB."""
        try:
            latest_key = (
                db.session.query(RsaSigningKeysDB)
                .filter(RsaSigningKeysDB.is_active.is_(True))
                .order_by(RsaSigningKeysDB.created_at.desc())
                .first()
            )
        except SQLAlchemyError as e:
            db.session.rollback()
            raise SigningKeyDBError("DB error while loading latest key") from e

        if not latest_key:
            raise SigningKeyNotFound("No active signing keys found in the database.")

        return latest_key

    def _save_to_db(self) -> None:
        """Persist the current signing_keys instance as a new DB record."""
        try:
            existing_key = (
                db.session.query(RsaSigningKeysDB)
                .filter_by(key_id=self.signing_keys.key_id)
                .first()
            )
            if existing_key:
                raise SigningKeyDBError(
                    f"Key with ID {self.signing_keys.key_id} already exists."
                )

            new_key = RsaSigningKeysDB()
            new_key.db_entry(self.signing_keys)
            db.session.add(new_key)
            db.session.commit()

        except SigningKeyDBError:
            db.session.rollback()
            raise
        except SQLAlchemyError as e:
            db.session.rollback()
            raise SigningKeyDBError("DB error while saving key") from e

    # ---------- lifecycle ----------

    def _initial_new_keys(self) -> None:
        """Generate a fresh key pair and populate self.signing_keys without saving."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = self._encrypt_private_key(private_key, self.secret_password)
        public_pem = self._encoded_public_key(public_key)

        alg = "EdDSA"
        key_id = os.urandom(32).hex()
        created_at = int(time.time())

        verify_until = created_at + 182 * 24 * 3600 # 182 days (6 months) - this is the max lifetime for tokens signed with this key
        signing_deactivate_after = created_at + 72 * 3600 # 72 hours
        expires_at = created_at + 365 * 24 * 3600 # 1 year

        public_jwk = self._public_key_to_jwk(public_pem, key_id, alg, verify_until)

        self.signing_keys = RsaSigningKeys(
            key_id=key_id,
            private_key=private_key,
            public_key=public_key,
            private_pem=private_pem,
            public_pem=public_pem,
            alg=alg,
            is_active=True,
            created_at=created_at,
            expires_at=expires_at,
            verify_until=verify_until,
            signing_deactivate_after=signing_deactivate_after,
            public_jwk=public_jwk,
        )


    def _instantiate_from_DB(self) -> None:
        """Load the latest active key from the DB into self.signing_keys."""
        latest_key = self._load_latest_key()
        private_key = self._decrypt_private_key(latest_key.private_pem, self.secret_password)
        public_key = private_key.public_key()

        self.signing_keys = RsaSigningKeys(
            key_id=latest_key.key_id,
            private_key=private_key,
            public_key=public_key,
            private_pem=latest_key.private_pem,
            public_pem=latest_key.public_pem,
            alg=latest_key.alg,
            is_active=latest_key.is_active,
            created_at=latest_key.created_at,
            expires_at=latest_key.expires_at,
            verify_until=latest_key.verify_until,
            signing_deactivate_after=latest_key.signing_deactivate_after,
            public_jwk=latest_key.public_jwk,
        )

    def _generate_new_keys(self) -> None:
        """Create, store, and log a new signing key pair."""
        self._initial_new_keys()
        self._save_to_db()
        log.info("Generated and saved new signing keys (%s).", self.signing_keys.key_id)

    def _deactivate_keys(self) -> None:
        """Mark the current signing key as inactive in memory and in the DB."""
        if not hasattr(self, "signing_keys") or not self.signing_keys.is_active:
            log.warning("No active signing keys found to deactivate.")
            return

        try:
            self.signing_keys.is_active = False
            db.session.execute(
                update(RsaSigningKeysDB)
                .where(RsaSigningKeysDB.key_id == self.signing_keys.key_id)
                .values(is_active=False)
            )
            db.session.commit()
            log.info("Deactivated signing keys (%s).", self.signing_keys.key_id)

        except SQLAlchemyError as e:
            db.session.rollback()
            raise SigningKeyDBError(f"DB error while deactivating keys: {e}") from e

    def check_key_rotation(self) -> None:
        """Rotate keys when the current key has passed its signing lifetime."""
        if self.signing_keys.signing_deactivate_after >= int(time.time()):
            return
        log.info("Key reached rotation time; rotating.")
        self._deactivate_keys()
        self._generate_new_keys()

    def initiate_signature_keys(self) -> None:
        """Ensure signing_keys is loaded, generating new keys if necessary."""
        try:
            self._instantiate_from_DB()
            log.info("Loaded signing keys (%s) from DB.", self.signing_keys.key_id)

        except SigningKeyNotFound as e:
            log.warning("%s Generating new keys.", e)
            self._generate_new_keys()
        except SigningKeyError as e:
            # crypto/db/etc
            log.warning("Failed to load signing keys (%s). Generating new keys.", e)
            self._generate_new_keys()

    def get_current_signing_key(self) -> RsaSigningKeys:
        """Return the in-memory active signing key, loading/rotating as needed."""
        if not hasattr(self, "signing_keys"):
            log.warning("No signing keys in memory. Initiating.")
            self.initiate_signature_keys()
        self.check_key_rotation()
        return self.signing_keys

    def get_signing_key_by_id(self, key_id: str) -> RsaSigningKeys:
        """Fetch and decrypt a specific signing key from the DB by its ID."""
        try:
            record = db.session.query(RsaSigningKeysDB).filter_by(key_id=key_id).first()
        except SQLAlchemyError as e:
            raise SigningKeyDBError(f"DB error while fetching key {key_id}: {e}") from e

        if not record:
            raise SigningKeyNotFound(f"No signing key found with ID {key_id}.")

        private_key = self._decrypt_private_key(
            record.private_pem, self.secret_password
        )
        public_key = private_key.public_key()

        return RsaSigningKeys(
            key_id=record.key_id,
            private_key=private_key,
            public_key=public_key,
            private_pem=record.private_pem,
            public_pem=record.public_pem,
            alg=record.alg,
            is_active=record.is_active,
            created_at=record.created_at,
            expires_at=record.expires_at,
            verify_until=record.verify_until,
            signing_deactivate_after=record.signing_deactivate_after,
            public_jwk=record.public_jwk,
        )
