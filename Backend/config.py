import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'dev.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'dev-secret-key'
    
    # JWT Configuration
    JWT_SECRET_KEY = 'jwt-secret-string'  # Change this in production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_ALGORITHM = 'HS256'