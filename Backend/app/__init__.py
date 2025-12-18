from flask import Flask, jsonify
from .extensions import db, jwt
# Import models from the models package
from .models import User, Event, Comment, Listing, UserBookmark, UserLike, UserBooking
from .routes.auth import auth_bp  # blueprint import for authentication
from .routes.listings import bp as listings_bp
from .routes.events import bp as events_bp
from .routes.user import user_bp  # blueprint import for user preferences and bookings
from .error_handlers import register_error_handlers
from .security import init_security_middleware, security_manager
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    CORS(app)  # Enable CORS for all routes

    # Initialize security middleware (input sanitization, security headers, rate limiting)
    init_security_middleware(app)
    security_manager.init_app(app)

    # Register error handlers
    register_error_handlers(app)

    # Create database tables
    with app.app_context():
        db.create_all()

    # register the blueprints
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(listings_bp, url_prefix="/api")
    app.register_blueprint(events_bp, url_prefix="/api")
    app.register_blueprint(user_bp, url_prefix="/api/user")

    @app.route("/")
    def home():
        return jsonify({
            "status": "success",
            "message": "API is up and running"
        })

    return app