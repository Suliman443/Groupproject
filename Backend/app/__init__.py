from flask import Flask
from .extensions import db
# Import models from the models package
from .models import User, Event, Comment
from .routes.auth import auth_bp  # blueprint import for authentication


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    db.init_app(app)

    # Create database tables
    with app.app_context():
        db.create_all()

    # register the blueprint
    app.register_blueprint(auth_bp, url_prefix="/auth")

    @app.route("/")
    def home():
        return "API is up and running"

    return app