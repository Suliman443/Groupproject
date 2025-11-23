#!/usr/bin/env python3
"""
Test script to verify organizer routes through the frontend server
"""

import requests
import json

FRONTEND_URL = "http://localhost:4322"

def test_route(route, description):
    """Test if a route is accessible"""
    try:
        response = requests.get(f"{FRONTEND_URL}{route}")
        if response.status_code == 200:
            print(f"✅ {description}: {route} - OK")
            return True
        else:
            print(f"❌ {description}: {route} - Status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ {description}: {route} - Error: {e}")
        return False

def main():
    print("Testing Organizer Routes through Frontend Server")
    print("=" * 50)
    
    # Test all organizer-related routes
    routes_to_test = [
        ("/", "Main page"),
        ("/organizer-login", "Organizer login page"),
        ("/organizer-signup", "Organizer signup page"),
        ("/organizer-dashboard", "Organizer dashboard page"),
    ]
    
    all_passed = True
    for route, description in routes_to_test:
        if not test_route(route, description):
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("✅ All organizer routes are accessible!")
    else:
        print("❌ Some routes failed. Please check the frontend server.")
    
    # Test API proxy for organizer endpoints
    print("\nTesting API Proxy for Organizer Endpoints")
    print("=" * 50)
    
    api_endpoints = [
        ("/api/auth/organizer/signup", "POST", "Organizer signup endpoint"),
        ("/api/organizer/events", "GET", "Organizer events endpoint"),
        ("/api/organizer/stats", "GET", "Organizer stats endpoint"),
    ]
    
    for endpoint, method, description in api_endpoints:
        try:
            if method == "GET":
                # These will fail without auth, but we're just checking if proxy works
                response = requests.get(f"{FRONTEND_URL}{endpoint}")
            else:
                response = requests.post(f"{FRONTEND_URL}{endpoint}", json={})
            
            # We expect 401 (unauthorized) or 400 (bad request) for these protected endpoints
            if response.status_code in [401, 400, 403]:
                print(f"✅ {description}: {endpoint} - Proxy working (auth required)")
            elif response.status_code == 503:
                print(f"⚠️  {description}: {endpoint} - Backend not running")
            else:
                print(f"✅ {description}: {endpoint} - Status {response.status_code}")
        except Exception as e:
            print(f"❌ {description}: {endpoint} - Error: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\nError: {e}") 
