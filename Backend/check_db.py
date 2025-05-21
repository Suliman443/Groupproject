from app import create_app
from app.models import User

app = create_app()
with app.app_context():
    users = User.query.all()
    for user in users:
        print(f"User: {user.fullname} (Email: {user.email}, Role: {user.role})") 