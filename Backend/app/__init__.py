from flask import Flask
from .extensions import db
from .models import *


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    db.init_app(app)

    @app.route("/")
    def home():
        return "API is up and running"

    return app