import base64
import os
import time
from logging import getLogger

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Boolean, Integer, LargeBinary, String, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.authentication_api.extensions import db

log = getLogger(__name__)


class RsaSigningKeysDB(db.Model):
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

    def db_entry(self, Rsakeys: "RsaSigningKeys") -> None:
        self.key_id = Rsakeys.key_id
        self.private_pem = Rsakeys.private_pem
        self.public_pem = Rsakeys.public_pem
        self.alg = Rsakeys.alg
        self.is_active = Rsakeys.is_active
        self.created_at = Rsakeys.created_at
        self.expires_at = Rsakeys.expires_at
        self.verify_until = Rsakeys.verify_until
        self.signing_deactivate_after = Rsakeys.signing_deactivate_after
        self.public_jwk = Rsakeys.public_jwk


class RsaSigningKeys(BaseModel):
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
    public_jwk: dict

    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey


class RsaSigningKeysManager:
    def __init__(self, secret_password: str):
        self.secret_password = secret_password

    def _initial_new_keys(self) -> None:
        private_key = self._private_key_init(self.secret_password)
        public_key = self._public_key_init(private_key)
        private_pem: bytes = self._encrypt_private_key(
            private_key, self.secret_password
        )
        public_pem: bytes = self._encoded_public_key(public_key)
        alg = "EdDSA"
        key_id: str = os.urandom(32).hex()  # Random key ID for tracking
        is_active = True
        created_at = int(time.time())
        verify_until = (
            created_at + 182 * 24 * 3600
        )  # Set verification validity to 182 days
        signing_deactivate_after = (
            created_at + 72 * 3600
        )  # Set deactivation time to 3 days
        expires_at = created_at + 365 * 24 * 3600  # Set expiration to 1 year from now
        public_jwk = self._public_key_to_jwk(public_pem, key_id, alg, verify_until)
        self.signing_keys = RsaSigningKeys(
            key_id=key_id,
            private_key=private_key,
            public_key=public_key,
            private_pem=private_pem,
            public_pem=public_pem,
            alg=alg,
            is_active=is_active,
            created_at=created_at,
            expires_at=expires_at,
            verify_until=verify_until,
            signing_deactivate_after=signing_deactivate_after,
            public_jwk=public_jwk,
        )

    @staticmethod
    def _private_key_init(secret_password: str) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.generate()

    @staticmethod
    def _public_key_init(
        private_key: ed25519.Ed25519PrivateKey,
    ) -> ed25519.Ed25519PublicKey:
        return private_key.public_key()

    @staticmethod
    def _encrypt_private_key(
        private_key: ed25519.Ed25519PrivateKey, secret_password: str
    ) -> bytes:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                secret_password.encode()
            ),
        )

    @staticmethod
    def _encoded_public_key(public_key: ed25519.Ed25519PublicKey) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decrypt_private_key(
        encrypted_pem: bytes | str, password: str
    ) -> ed25519.Ed25519PrivateKey:
        try:
            if isinstance(encrypted_pem, str):
                encrypted_pem = encrypted_pem.encode("utf-8")  # PEM text -> bytes

            key = serialization.load_pem_private_key(
                encrypted_pem,
                password=password.encode("utf-8"),
            )

            if not isinstance(key, ed25519.Ed25519PrivateKey):
                raise ValueError("Loaded key is not an Ed25519 private key")

            return key

        except Exception as e:
            raise ValueError(f"Error decrypting private key: {e}") from e

    @staticmethod
    def _load_latest_key() -> RsaSigningKeysDB:
        try:
            latest_key = (
                db.session.query(RsaSigningKeysDB)
                .filter(RsaSigningKeysDB.is_active.is_(True))
                .order_by(RsaSigningKeysDB.created_at.desc())
                .first()
            )
            if not latest_key:
                log.warning("No active signing keys found in the database.")
                raise ValueError("No active signing keys found in the database.")

            return latest_key
        except Exception as e:
            log.error(f"Error loading latest key from database: {e}")
            raise ValueError(f"Error loading latest key from database: {e}")

    def _public_key_to_jwk(
        self, public_pem: bytes, key_id: str, alg: str, verify_until: int
    ) -> dict:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": self._b64url(public_pem),
            "kid": key_id,
            "use": "sig",
            "alg": alg,
            "ver": verify_until,
        }

    def _save_to_db(self) -> None:
        existing_key = (
            db.session.query(RsaSigningKeysDB)
            .filter_by(key_id=self.signing_keys.key_id)
            .first()
        )
        if existing_key:
            raise ValueError(
                f"Key with ID {self.signing_keys.key_id} already exists in the database."
            )
        try:
            new_key = RsaSigningKeysDB()
            new_key.db_entry(self.signing_keys)
            db.session.add(new_key)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise ValueError(f"Error saving key to database: {e}")

    def _instantiate_from_DB(self):
        try:
            latest_key: RsaSigningKeysDB = self._load_latest_key()
            private_key = self._decrypt_private_key(
                latest_key.private_pem, self.secret_password
            )
            public_key = self._public_key_init(private_key)
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
        except ValueError as e:
            log.error(f"Error instantiating signing keys from database: {e}")
            raise ValueError(f"Error instantiating signing keys from database: {e}")

    def _generate_new_keys(self) -> None:
        self._initial_new_keys()
        try:
            self._save_to_db()
            log.info("Successfully generated and saved new signing keys to database.")
        except ValueError as save_error:
            log.error(f"Failed to save new signing keys to database: {save_error}")
            raise ValueError(
                f"Failed to save new signing keys to database: {save_error}"
            )

    def _deactivate_keys(self) -> None:
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
            log.info(
                f"Successfully deactivated signing keys with ID {self.signing_keys.key_id}."
            )
        except Exception as e:
            db.session.rollback()
            log.error(f"Error deactivating signing keys: {e}")
            raise ValueError(f"Error deactivating signing keys: {e}")

    def check_key_rotation(self) -> None:
        if self.signing_keys.signing_deactivate_after >= int(time.time()):
            return
        log.info(
            "Signing keys have reached deactivation time. Deactivating current keys and generating new ones."
        )
        print("Signing keys have reached deactivation time. Deactivating current keys and generating new ones.")
        self._deactivate_keys()
        self._generate_new_keys()

    def initiate_signature_keys(self):
        try:
            self._instantiate_from_DB()
            log.info("Successfully loaded signing keys from database.")
        except ValueError as e:
            log.warning(
                f"Failed to load signing keys from database: {e}. Generating new keys."
            )
            self._generate_new_keys()

    def get_current_signing_key(self) -> RsaSigningKeys:
        if not hasattr(self, "signing_keys"):
            log.warning("No signing keys found. Initiating signing keys.")
            self.initiate_signature_keys()
        self.check_key_rotation()
        return self.signing_keys

    def get_signing_key_by_id(self, key_id: str) -> RsaSigningKeys:
        try:
            key_record = (
                db.session.query(RsaSigningKeysDB).filter_by(key_id=key_id).first()
            )
            if not key_record:
                log.warning(f"No signing key found with ID {key_id}.")
                raise ValueError(f"No signing key found with ID {key_id}.")
            private_key = self._decrypt_private_key(
                key_record.private_pem, self.secret_password
            )
            public_key = self._public_key_init(private_key)
            return RsaSigningKeys(
                key_id=key_record.key_id,
                private_key=private_key,
                public_key=public_key,
                private_pem=key_record.private_pem,
                public_pem=key_record.public_pem,
                alg=key_record.alg,
                is_active=key_record.is_active,
                created_at=key_record.created_at,
                expires_at=key_record.expires_at,
                verify_until=key_record.verify_until,
                signing_deactivate_after=key_record.signing_deactivate_after,
                public_jwk=key_record.public_jwk,
            )
        except ValueError as e:
            log.error(f"Error retrieving signing key by ID {key_id}: {e}")
            raise ValueError(f"Error retrieving signing key by ID {key_id}: {e}")
