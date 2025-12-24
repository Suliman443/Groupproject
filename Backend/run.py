#!/usr/bin/env python3
"""
Tourism App Backend Server
Entry point for running the Flask application
"""

from app import create_app
import os

# Create Flask application instance
app = create_app()

if __name__ == '__main__':
    # Get port from environment variable or default to 5001
    port = int(os.environ.get('PORT', 5001))
    
    # Get debug mode from environment variable or default to True for development
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    print(f"🚀 Starting Tourism App API server...")
    print(f"📍 Server running on: http://localhost:{port}")
    print(f"🔧 Debug mode: {'ON' if debug_mode else 'OFF'}")
    print(f"📚 API Documentation: See API_TESTING_GUIDE.md")
    print(f"🧪 Postman Collection: Tourism_App_API.postman_collection.json")
    print("=" * 50)
    
    # Run the Flask development server
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug_mode
    )
