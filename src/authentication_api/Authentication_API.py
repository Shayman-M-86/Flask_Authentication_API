
import os

from flask import Flask, jsonify, request, abort
from pydantic import ValidationError
from dotenv import load_dotenv
from sqlalchemy.exc import SQLAlchemyError
from jwt import InvalidTokenError

from src.authentication_api.extensions import db, migrate
from src.authentication_api.models.user import UserDB, UserSchema
from src.authentication_api.models.signing_keys import RsaSigningKeysManager
from src.authentication_api.models.jwt import JWTHandler

# Load and encode the secret password

# 1) Generate Ed25519 keypair
def extract_password() -> str:
    load_dotenv()  # Load environment variables from .env file
    SECRET_PASSWORD = os.getenv("SECRET_PASSWORD")
    if not isinstance(SECRET_PASSWORD, str):
        raise ValueError(
            "SECRET_PASSWORD environment variable must be set and be a string"
        )
    return SECRET_PASSWORD

# 3) Build claims + sign (EdDSA)

def require_service_password():
    expected = os.getenv("SERVICE_PASSWORD")
    provided = request.headers.get("X-API-Key")

    if not expected or provided != expected:
        abort(401, description="Unauthorized service")

# 4) Verify + decode using the public key


def create_app() -> Flask:
    app = Flask(__name__)
    secret_password = extract_password()
    key_manager = RsaSigningKeysManager(secret_password)
    jwt_handler = JWTHandler(key_manager)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("AUTH_DB")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    migrate.init_app(app, db)
    # login_manager.init_app(app)

    with app.app_context():
        db.create_all()

    # @login_manager.user_loader
    # def load_user(user_id):
    #     return UserDB.query.get(int(user_id))

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json()
        try:
            user_data = UserSchema(**data)
        except ValidationError as e:
            return jsonify({"error": f"{e}"}), 400

        user: UserDB | None = (
            db.session.query(UserDB).filter_by(username=user_data.username).first()
        )
        if not user:
            return jsonify({"error": "Invalid username or password"}), 401
        if user.check_password(user_data.password):
            token, refresh_token = jwt_handler.create_new_tokens(user.id)
            return jsonify({"message": "Login successful", "token": token, "refresh_token": refresh_token}), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401

    @app.route("/register", methods=["POST"])
    def register():
        data = request.get_json()
        print(f"Received registration data: {data}")  # Debugging statement
        try:
            user_data = UserSchema(**data)
        except ValidationError as e:
            return jsonify({"error": f"{e}"}), 400

        if db.session.query(UserDB).filter_by(username=user_data.username).first():
            return jsonify({"error": "Username already exists"}), 400

        new_user = UserDB()
        new_user.username = user_data.username
        new_user.email = user_data.email
        new_user.set_password(user_data.password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201

    @app.route("/refresh", methods=["GET"])
    def refresh():
        data: dict = request.get_json()
        refresh_token = data.get("refresh_token")
        if not refresh_token:
            return jsonify({"error": "Refresh token is required"}), 400
        try:
            new_token, new_refresh_token = jwt_handler.refresh(refresh_token)
            return jsonify({"token": new_token, "refresh_token": new_refresh_token}), 200
        
        except InvalidTokenError as e:
            return jsonify({"error": f"Invalid refresh token: {e}"}), 401
        except SQLAlchemyError as e:
            return jsonify({"error": f"Database error: {e}"}), 500


    @app.route("/.well-known/jwks.json", methods=["GET"])
    def jwks():
        try:
            require_service_password()
            key = key_manager.get_current_signing_key()

            # public_jwk is stored as JSONB dict already
            jwks = {"message": "Login successful" ,"key": key.public_jwk}
            for i in range(4):  # Debugging loop to print the JWKS multiple times
                print()
            print(f"Serving JWKS: {jwks}")  # Debugging statement
            return jsonify(jwks), 200
        except Exception as e:
            return jsonify({"error": f"Database error: {e}"}), 500
        
        
    @app.route("/keys/<kid>", methods=["GET"])
    def get_key(kid: str):
        try:
            require_service_password()
            key = key_manager.get_signing_key_by_id(kid)
            if not key:
                return jsonify({"error": "kid not found"}), 404
            return jsonify(key.public_jwk), 200
        except Exception as e:
            return jsonify({"error": f"Database error: {e}"}), 500
        
    return app
