from flask import Flask, jsonify
from .extensions import db
# Import models from the models package
from .models import User, Event, Comment, Listing
from .routes.auth import auth_bp  # blueprint import for authentication
from .routes.listings import bp as listings_bp
from .routes.events import bp as events_bp
from .error_handlers import register_error_handlers
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    
    # Initialize extensions
    db.init_app(app)
    CORS(app)  # Enable CORS for all routes
    
    # Register error handlers
    register_error_handlers(app)

    # Create database tables
    with app.app_context():
        db.create_all()

    # register the blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(listings_bp, url_prefix="/api")
    app.register_blueprint(events_bp, url_prefix="/api")

    @app.route("/")
    def home():
        return jsonify({
            "status": "success",
            "message": "API is up and running"
        })

    return app