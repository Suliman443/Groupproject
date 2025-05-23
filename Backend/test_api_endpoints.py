#!/usr/bin/env python3
"""
API Endpoint Testing Script
Comprehensive test to verify all endpoints are working correctly
"""

import requests
import json
import sys
from datetime import datetime, timedelta

BASE_URL = "http://localhost:5000"

class APITester:
    def __init__(self):
        self.access_token = None
        self.event_id = None
        self.listing_id = None
        self.test_user = {
            "email": f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}@example.com",
            "password": "password123",
            "fullname": "Test User"
        }

    def test_signup(self):
        """Test user signup"""
        print("📝 Testing Signup...")
        response = requests.post(f"{BASE_URL}/auth/signup", json=self.test_user)
        
        if response.status_code == 201:
            print("✅ Signup successful")
            return True
        else:
            print(f"❌ Signup failed: {response.status_code} - {response.text}")
            return False

    def test_login(self):
        """Test user login and token generation"""
        print("🔐 Testing Login...")
        login_data = {
            "email": self.test_user["email"],
            "password": self.test_user["password"]
        }
        response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
        
        if response.status_code == 200:
            data = response.json()
            self.access_token = data.get('access_token')
            print("✅ Login successful - Token received")
            return True
        else:
            print(f"❌ Login failed: {response.status_code} - {response.text}")
            return False

    def test_protected_profile(self):
        """Test protected profile endpoint"""
        print("👤 Testing Protected Profile...")
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.get(f"{BASE_URL}/auth/profile", headers=headers)
        
        if response.status_code == 200:
            print("✅ Profile access successful")
            return True
        else:
            print(f"❌ Profile access failed: {response.status_code} - {response.text}")
            return False

    def test_events(self):
        """Test event endpoints"""
        print("🎉 Testing Event Endpoints...")
        
        # Test GET all events
        response = requests.get(f"{BASE_URL}/api/events")
        if response.status_code != 200:
            print(f"❌ Get events failed: {response.status_code}")
            return False
        print("✅ Get all events - OK")
        
        # Test CREATE event (protected)
        headers = {"Authorization": f"Bearer {self.access_token}"}
        event_data = {
            "title": "Test Event",
            "description": "Test event description",
            "location": "Riyadh, Saudi Arabia",
            "latitude": 24.7136,
            "longitude": 46.6753,
            "date": (datetime.now() + timedelta(days=30)).isoformat(),
            "image_url": "https://example.com/test.jpg"
        }
        response = requests.post(f"{BASE_URL}/api/events", json=event_data, headers=headers)
        
        if response.status_code == 201:
            self.event_id = response.json()['id']
            print("✅ Create event - OK")
        else:
            print(f"❌ Create event failed: {response.status_code} - {response.text}")
            return False
        
        # Test GET single event
        response = requests.get(f"{BASE_URL}/api/events/{self.event_id}")
        if response.status_code != 200:
            print(f"❌ Get single event failed: {response.status_code}")
            return False
        print("✅ Get single event - OK")
        
        return True

    def test_event_comments(self):
        """Test event comment endpoints"""
        print("💬 Testing Event Comments...")
        
        # Test GET event comments
        response = requests.get(f"{BASE_URL}/api/events/{self.event_id}/comments")
        if response.status_code != 200:
            print(f"❌ Get event comments failed: {response.status_code}")
            return False
        print("✅ Get event comments - OK")
        
        # Test POST event comment (protected)
        headers = {"Authorization": f"Bearer {self.access_token}"}
        comment_data = {"content": "This is a test comment on the event!"}
        response = requests.post(f"{BASE_URL}/api/events/{self.event_id}/comments", 
                               json=comment_data, headers=headers)
        
        if response.status_code == 201:
            print("✅ Create event comment - OK")
            return True
        else:
            print(f"❌ Create event comment failed: {response.status_code} - {response.text}")
            return False

    def test_listings(self):
        """Test listing endpoints"""
        print("🏨 Testing Listing Endpoints...")
        
        # Test GET all listings
        response = requests.get(f"{BASE_URL}/api/listings")
        if response.status_code != 200:
            print(f"❌ Get listings failed: {response.status_code}")
            return False
        print("✅ Get all listings - OK")
        
        # Test CREATE listing (protected)
        headers = {"Authorization": f"Bearer {self.access_token}"}
        listing_data = {
            "title": "Test Hotel Room",
            "description": "Beautiful test room",
            "price": 150.00,
            "location": "Riyadh, Saudi Arabia",
            "image_url": "https://example.com/room.jpg"
        }
        response = requests.post(f"{BASE_URL}/api/listings", json=listing_data, headers=headers)
        
        if response.status_code == 201:
            self.listing_id = response.json()['id']
            print("✅ Create listing - OK")
        else:
            print(f"❌ Create listing failed: {response.status_code} - {response.text}")
            return False
        
        # Test GET single listing
        response = requests.get(f"{BASE_URL}/api/listings/{self.listing_id}")
        if response.status_code != 200:
            print(f"❌ Get single listing failed: {response.status_code}")
            return False
        print("✅ Get single listing - OK")
        
        return True

    def test_listing_comments(self):
        """Test listing comment endpoints"""
        print("💭 Testing Listing Comments...")
        
        # Test GET listing comments
        response = requests.get(f"{BASE_URL}/api/listings/{self.listing_id}/comments")
        if response.status_code != 200:
            print(f"❌ Get listing comments failed: {response.status_code}")
            return False
        print("✅ Get listing comments - OK")
        
        # Test POST listing comment (protected)
        headers = {"Authorization": f"Bearer {self.access_token}"}
        comment_data = {"content": "This listing looks great!"}
        response = requests.post(f"{BASE_URL}/api/listings/{self.listing_id}/comments", 
                               json=comment_data, headers=headers)
        
        if response.status_code == 201:
            print("✅ Create listing comment - OK")
            return True
        else:
            print(f"❌ Create listing comment failed: {response.status_code} - {response.text}")
            return False

    def test_unauthorized_access(self):
        """Test that protected endpoints reject unauthorized access"""
        print("🔒 Testing Unauthorized Access...")
        
        # Try to create event without token
        event_data = {
            "title": "Unauthorized Event",
            "location": "Test Location",
            "date": (datetime.now() + timedelta(days=1)).isoformat()
        }
        response = requests.post(f"{BASE_URL}/api/events", json=event_data)
        
        if response.status_code == 401:
            print("✅ Unauthorized access properly rejected")
            return True
        else:
            print(f"❌ Unauthorized access not properly rejected: {response.status_code}")
            return False

    def run_all_tests(self):
        """Run all API tests"""
        print("🧪 Starting API Endpoint Tests")
        print("=" * 50)
        
        tests = [
            ("Signup", self.test_signup),
            ("Login", self.test_login),
            ("Protected Profile", self.test_protected_profile),
            ("Events", self.test_events),
            ("Event Comments", self.test_event_comments),
            ("Listings", self.test_listings),
            ("Listing Comments", self.test_listing_comments),
            ("Unauthorized Access", self.test_unauthorized_access)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🔍 Running {test_name} test...")
            try:
                if test_func():
                    passed += 1
                else:
                    print(f"❌ {test_name} test failed")
            except Exception as e:
                print(f"❌ {test_name} test error: {str(e)}")
        
        print("\n" + "=" * 50)
        print(f"🏁 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! API is working correctly.")
            return True
        else:
            print("⚠️  Some tests failed. Check the output above.")
            return False

def main():
    """Main function"""
    print("Tourism App API Endpoint Tester")
    print("Make sure the server is running on http://localhost:5000")
    print()
    
    # Test server connectivity
    try:
        response = requests.get(f"{BASE_URL}/")
        if response.status_code != 200:
            print("❌ Server is not running or not responding correctly")
            sys.exit(1)
        print("✅ Server is running and accessible")
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure it's running on http://localhost:5000")
        sys.exit(1)
    
    # Run tests
    tester = APITester()
    success = tester.run_all_tests()
    
    if success:
        print("\n🎯 All Sprint Tasks Successfully Implemented:")
        print("✅ B-S3-01: Signup endpoint")
        print("✅ B-S3-02: Login endpoint with JWT tokens")
        print("✅ B-S3-03: Token-based authentication middleware")
        print("✅ B-S3-04: getEvents API")
        print("✅ B-S3-05: Event comment API")
        print("✅ B-S3-06: Database relationships finalized")
        print("✅ B-S3-07: API testing (this script + Postman collection)")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main() 