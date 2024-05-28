from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from .config import Config

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
csrf = CSRFProtect()
login = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    csrf.init_app(app)
    login.init_app(app)
    login.login_view = 'main.login'

    with app.app_context():
        from .routes import main_bp
        app.register_blueprint(main_bp)

        db.create_all()

    return app
