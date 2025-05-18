#!/usr/bin/env python
from flask import Flask
from app.extensions import db
from app.models import User

# Create test app context
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    # Test User model
    print("User model type:", type(User))
    print("User model bases:", User.__bases__)
    print("User has query attribute:", hasattr(User, 'query'))
    print("User attributes:", [attr for attr in dir(User) if not attr.startswith('__')])
    print("Is db.Model in User bases?", db.Model in User.__bases__)

print("Trying to import from app.models.user...")
try:
    from app.models.user import User as UserFromModule
    print("Successfully imported User from app.models.user")
    print("User model type:", type(UserFromModule))
    print("User model bases:", UserFromModule.__bases__)
    print("User has query attribute:", hasattr(UserFromModule, 'query'))
except ImportError as e:
    print("Failed to import User from app.models.user:", e)

print("\nTrying to import from app.models...")
try:
    import app.models
    import sys
    print("app.models path:", app.models.__file__)
    from app.models import User as UserFromFile
    print("Successfully imported User from app.models")
    print("User model type:", type(UserFromFile))
    print("User model bases:", UserFromFile.__bases__)
    print("User has query attribute:", hasattr(UserFromFile, 'query'))
except ImportError as e:
    print("Failed to import User from app.models:", e)

print("\nPython module search paths:")
import sys
for path in sys.path:
    print(path)

# If using Flask-SQLAlchemy, this should be True
print("Is db.Model in User bases?", db.Model in UserFromFile.__bases__) 