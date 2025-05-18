from flask import jsonify
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({'error': 'Resource not found'}), 404

    @app.errorhandler(400)
    def bad_request_error(error):
        return jsonify({'error': str(error.description)}), 400

    @app.errorhandler(SQLAlchemyError)
    def database_error(error):
        return jsonify({'error': 'Database error occurred'}), 500

    @app.errorhandler(IntegrityError)
    def integrity_error(error):
        return jsonify({'error': 'Database integrity error'}), 400

    @app.errorhandler(Exception)
    def general_error(error):
        return jsonify({'error': 'An unexpected error occurred'}), 500 