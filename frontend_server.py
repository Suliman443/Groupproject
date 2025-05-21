from flask import Flask, render_template, send_from_directory, url_for, request, Response
import os
import requests

app = Flask(__name__, 
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "Frontend"),
            static_url_path='')

# Backend API URL
BACKEND_API_URL = 'http://localhost:5000'

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

@app.route('/html/<path:filename>')
def html_files(filename):
    return send_from_directory('Frontend/Html', filename)

@app.route('/js/<path:filename>')
def js_files(filename):
    return send_from_directory('Frontend/js', filename)

@app.route('/css/<path:filename>')
def css_files(filename):
    return send_from_directory('Frontend/css', filename)

@app.route('/images/<path:filename>')
def image_files(filename):
    return send_from_directory('Frontend/images', filename)

# API proxy routes
@app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_proxy(path):
    resp = requests.request(
        method=request.method,
        url=f"{BACKEND_API_URL}/api/{path}",
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response

# Auth proxy routes
@app.route('/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def auth_proxy(path):
    resp = requests.request(
        method=request.method,
        url=f"{BACKEND_API_URL}/auth/{path}",
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response

if __name__ == '__main__':
    app.run(debug=True, port=4322) 