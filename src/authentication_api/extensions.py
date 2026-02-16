from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager




db: SQLAlchemy = SQLAlchemy()
migrate: Migrate = Migrate()
login_manager: LoginManager = LoginManager()
login_manager.login_view = "login" # pyright: ignore[reportAttributeAccessIssue]