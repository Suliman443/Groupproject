from flask import Flask, render_template, send_from_directory, url_for, request, Response, jsonify
import os
import requests
from datetime import datetime

app = Flask(__name__, 
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "Frontend"),
            static_url_path='')

# Backend API URL
BACKEND_API_URL = 'http://localhost:5000'

# Serve HTML pages
@app.route('/')
def index():
    return send_from_directory('Frontend', 'index.html')

@app.route('/events')
def events():
    return send_from_directory('Frontend', 'events.html')

@app.route('/bookmarks')
def bookmarks():
    return send_from_directory('Frontend', 'bookmarks.html')

@app.route('/liked')
def liked():
    return send_from_directory('Frontend', 'liked.html')

@app.route('/account')
def account():
    return send_from_directory('Frontend', 'account.html')

@app.route('/organizer-login')
def organizer_login():
    return send_from_directory('Frontend', 'organizer-login.html')

@app.route('/organizer-dashboard')
def organizer_dashboard():
    return send_from_directory('Frontend', 'organizer-dashboard.html')

# Serve static files
@app.route('/html/<path:filename>')
def html_files(filename):
    return send_from_directory('Frontend/Html', filename)

@app.route('/js/<path:filename>')
def js_files(filename):
    # For API.js, we need to modify the API_BASE_URL to use relative paths
    if filename == 'api.js':
        try:
            with open(os.path.join('Frontend/js', filename), 'r', encoding='utf-8') as f:
                content = f.read()
            # Replace the absolute URL with relative URL for Flask server
            content = content.replace(
                "const API_BASE_URL = 'http://localhost:5000/api';",
                "const API_BASE_URL = '/api';"
            )
            # Update auth refresh endpoint to use absolute path (bypass proxy double /api issue)
            content = content.replace(
                "`${API_BASE_URL}/auth/refresh`",
                "`http://localhost:5000/api/auth/refresh`"
            )
            
            response = Response(content, mimetype='application/javascript')
            return response
        except:
            pass
    
    return send_from_directory('Frontend/js', filename)

@app.route('/css/<path:filename>')
def css_files(filename):
    return send_from_directory('Frontend/css', filename)

@app.route('/images/<path:filename>')
def image_files(filename):
    return send_from_directory('Frontend/images', filename)

# Enhanced API proxy routes to handle all backend endpoints
@app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def api_proxy(path):
    """Proxy all API requests to the backend server"""
    try:
        # Handle preflight OPTIONS requests
        if request.method == 'OPTIONS':
            response = Response()
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
            return response

        # Prepare headers, excluding 'Host' to avoid conflicts
        headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
        
        # Make request to backend
        resp = requests.request(
            method=request.method,
            url=f"{BACKEND_API_URL}/api/{path}",
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=30
        )

        # Prepare response headers, excluding problematic ones
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [(name, value) for (name, value) in resp.raw.headers.items()
                          if name.lower() not in excluded_headers]

        # Create response
        response = Response(resp.content, resp.status_code, response_headers)
        
        # Add CORS headers
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        
        return response
        
    except requests.exceptions.RequestException as e:
        print(f"API proxy error: {e}")
        return jsonify({'error': 'Backend service unavailable'}), 503
    except Exception as e:
        print(f"Unexpected error in API proxy: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint to verify both frontend and backend are working"""
    try:
        # Check if backend is responding
        backend_response = requests.get(f"{BACKEND_API_URL}/", timeout=5)
        backend_status = "healthy" if backend_response.status_code == 200 else "unhealthy"
    except:
        backend_status = "unreachable"
    
    return jsonify({
        'frontend': 'healthy',
        'backend': backend_status,
        'timestamp': str(datetime.now())
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Add support for CORS (Cross-Origin Resource Sharing)
@app.after_request
def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Development configuration
@app.before_request
def log_request_info():
    """Log request information for debugging"""
    if app.debug:
        print(f"Request: {request.method} {request.url}")
        if request.method in ['POST', 'PUT', 'PATCH']:
            print(f"Request data: {request.get_data()}")

if __name__ == '__main__':
    print("🚀 Starting Tourism App Frontend Server...")
    print("📍 Frontend: http://localhost:4322")
    print("🔗 Backend API: http://localhost:5000")
    print("📊 Health Check: http://localhost:4322/health")
    print("\n📝 Available Routes:")
    print("   / - Main page")
    print("   /events - Events page")
    print("   /bookmarks - Bookmarks page")
    print("   /liked - Liked events page")
    print("   /account - Account page")
    print("   /organizer-login - Organizer login")
    print("   /organizer-dashboard - Organizer dashboard")
    print("   /api/* - API proxy to backend")
    print("\n✨ All API calls will be automatically proxied to the backend!")
    
    app.run(debug=True, port=4322, host='0.0.0.0') 