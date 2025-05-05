from flask import Flask
from .extensions import db
from . import models
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    db.init_app(app)
    from . import models
    return app