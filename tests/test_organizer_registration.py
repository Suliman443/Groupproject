#!/usr/bin/env python3
"""
Test organizer registration through frontend server
"""

import requests
import json
import time

def test_organizer_registration():
    # Test with a unique email
    unique_email = f"testorg_{int(time.time())}@example.com"
    
    data = {
        "fullname": "Test Organizer",
        "email": unique_email,
        "password": "password123"
    }
    
    print("Testing organizer registration...")
    print(f"Email: {unique_email}")
    
    try:
        response = requests.post(
            'http://localhost:4322/api/auth/organizer/signup',
            json=data
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        if response.status_code == 201:
            print("✅ Organizer registration successful!")
        else:
            print("❌ Registration failed")
            
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to frontend server at http://localhost:4322")
        print("   Make sure the frontend server is running.")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_organizer_registration() 
