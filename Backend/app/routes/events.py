from flask import Blueprint

bp = Blueprint("events", __name__)

@bp.route("/", methods=["GET"])
def index():
    return "Hello from Events!"