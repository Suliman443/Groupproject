#!/usr/bin/env python3
"""
Test script to verify Flask frontend server integration
"""

import requests
import time
import json

def test_flask_server():
    """Test the Flask frontend server"""
    print("🧪 Testing Flask Frontend Server Integration...")
    
    # Test frontend server health
    try:
        response = requests.get("http://localhost:4322/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ Frontend Server: {health_data['frontend']}")
            print(f"✅ Backend Status: {health_data['backend']}")
        else:
            print("❌ Frontend server health check failed")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to frontend server: {e}")
        print("💡 Make sure to run: python frontend_server.py")
        return False
    
    # Test static file serving
    try:
        response = requests.get("http://localhost:4322/", timeout=5)
        if response.status_code == 200 and "Smart Tourism" in response.text:
            print("✅ Main page loads correctly")
        else:
            print("❌ Main page failed to load")
            return False
    except Exception as e:
        print(f"❌ Error loading main page: {e}")
        return False
    
    # Test API proxy
    try:
        response = requests.get("http://localhost:4322/api/events", timeout=5)
        if response.status_code == 200:
            events = response.json()
            print(f"✅ API proxy working - {len(events)} events found")
        else:
            print("❌ API proxy failed")
            return False
    except Exception as e:
        print(f"❌ API proxy error: {e}")
        return False
    
    # Test JavaScript file serving with modifications
    try:
        response = requests.get("http://localhost:4322/js/api.js", timeout=5)
        if response.status_code == 200:
            content = response.text
            if "const API_BASE_URL = '/api';" in content:
                print("✅ API.js correctly modified for Flask server")
            else:
                print("⚠️ API.js may not be properly configured")
        else:
            print("❌ Failed to serve api.js")
            return False
    except Exception as e:
        print(f"❌ Error serving api.js: {e}")
        return False
    
    print("\n🎉 Flask Frontend Server Integration Test Complete!")
    print("✅ All tests passed! Your tourism app is ready to use.")
    print("\n📍 Access your app at: http://localhost:4322")
    return True

def print_instructions():
    """Print setup instructions"""
    print("\n" + "="*60)
    print("🚀 TOURISM APP - FLASK SERVER SETUP")
    print("="*60)
    print("\n1. Start the Backend Server:")
    print("   cd Backend")
    print("   python run.py")
    print("   (Backend will run on http://localhost:5000)")
    
    print("\n2. Start the Frontend Server:")
    print("   python frontend_server.py")
    print("   (Frontend will run on http://localhost:4322)")
    
    print("\n3. Access your Tourism App:")
    print("   🌐 Open http://localhost:4322 in your browser")
    
    print("\n4. Features Available:")
    print("   ✅ User Registration & Login")
    print("   ✅ Event Browsing & Management")
    print("   ✅ Bookmarking & Liking Events")
    print("   ✅ Event Booking System")
    print("   ✅ User Account Management")
    print("   ✅ Organizer Dashboard")
    
    print("\n🔧 Troubleshooting:")
    print("   - Make sure both servers are running")
    print("   - Check Backend/dev.db exists (created automatically)")
    print("   - Verify no other apps using ports 4322 or 5000")
    print("   - Check browser console for any JavaScript errors")
    
    print("\n📊 Test API Integration:")
    print("   python test_flask_integration.py")

if __name__ == "__main__":
    print_instructions()
    
    print("\n" + "="*60)
    print("🧪 RUNNING INTEGRATION TEST")
    print("="*60)
    
    # Wait a moment for servers to be ready
    print("⏳ Waiting for servers...")
    time.sleep(2)
    
    success = test_flask_server()
    
    if not success:
        print("\n💡 Next Steps:")
        print("1. Make sure backend is running: cd Backend && python run.py")
        print("2. Make sure frontend is running: python frontend_server.py")
        print("3. Try the test again: python test_flask_integration.py") 
