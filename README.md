# Group Project Frontend with Flask

This project serves the HTML frontend files using Flask and proxies API requests to the backend server.

## Requirements

- Python 3.x
- Flask
- Requests

## Installation

1. Install the required packages:

```bash
pip install flask requests
```

## Running the Application

### Step 1: Start the Backend Server

```bash
cd Backend
python -m venv .venv
.\.venv\Scripts\activate  # On Windows
source .venv/bin/activate  # On macOS/Linux
pip install -r requirements.txt
python run.py
```

### Step 2: Start the Frontend Server

```bash
python frontend_server.py
```

### Step 3: Access the Website

Open your web browser and navigate to:

- Main page: http://localhost:4322/
- Events page: http://localhost:4322/events
- Bookmarks page: http://localhost:4322/bookmarks
- Liked page: http://localhost:4322/liked
- Account page: http://localhost:4322/account

## Project Structure

- `frontend_server.py`: Flask application serving the frontend files
- `Frontend/`: Directory containing all frontend files (HTML, CSS, JS, images)

## API Endpoints

The frontend server proxies all API requests to the backend server running on port 5000.

- `/api/*`: All API endpoints are forwarded to `http://localhost:5000/api/*`
- `/auth/*`: All auth endpoints are forwarded to `http://localhost:5000/auth/*`

## Features

- Serves static HTML, CSS, JS, and image files
- Proxies API requests to the backend server
- Supports Cross-Origin Resource Sharing (CORS) for API requests
- Responsive design for mobile and desktop devices 