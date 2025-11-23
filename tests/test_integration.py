import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_registration():
    """Test user registration"""
    print("Testing user registration...")
    # Use a unique email based on timestamp
    unique_email = f"test{int(time.time())}@example.com"
    data = {
        "email": unique_email,
        "password": "password123",
        "fullname": "Test User"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/auth/signup", json=data)
        print(f"Registration response: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code in [200, 201], unique_email
    except Exception as e:
        print(f"Error testing registration: {e}")
        return False, None

def test_login(email):
    """Test user login"""
    print("\nTesting user login...")
    data = {
        "email": email,
        "password": "password123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/auth/login", json=data)
        print(f"Login response: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Response: {result}")
            if 'access_token' in result:
                return result['access_token']
        else:
            print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error testing login: {e}")
    
    return None

def test_events():
    """Test events endpoint"""
    print("\nTesting events endpoint...")
    response = requests.get(f"{BASE_URL}/api/events")
    print(f"Events response: {response.status_code}")
    events = response.json()
    print(f"Number of events: {len(events)}")
    return response.status_code == 200

def test_bookmarks(token):
    """Test bookmark functionality"""
    print("\nTesting bookmark functionality...")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test adding bookmark
    data = {"event_id": 1}
    response = requests.post(f"{BASE_URL}/api/user/bookmarks", json=data, headers=headers)
    print(f"Add bookmark response: {response.status_code}")
    if response.status_code not in [200, 201]:
        print(f"Response: {response.json()}")
    
    # Test getting bookmarks
    response = requests.get(f"{BASE_URL}/api/user/bookmarks", headers=headers)
    print(f"Get bookmarks response: {response.status_code}")
    if response.status_code == 200:
        bookmarks = response.json()
        print(f"Number of bookmarks: {len(bookmarks)}")
        return True
    else:
        print(f"Response: {response.json()}")
    
    return False

def test_likes(token):
    """Test like functionality"""
    print("\nTesting like functionality...")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test adding like
    data = {"event_id": 1}
    response = requests.post(f"{BASE_URL}/api/user/likes", json=data, headers=headers)
    print(f"Add like response: {response.status_code}")
    if response.status_code not in [200, 201]:
        print(f"Response: {response.json()}")
    
    # Test getting likes
    response = requests.get(f"{BASE_URL}/api/user/likes", headers=headers)
    print(f"Get likes response: {response.status_code}")
    if response.status_code == 200:
        likes = response.json()
        print(f"Number of likes: {len(likes)}")
        return True
    else:
        print(f"Response: {response.json()}")
    
    return False

def test_bookings(token):
    """Test booking functionality"""
    print("\nTesting booking functionality...")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test creating booking
    data = {
        "event_id": 1,
        "booking_date": "2025-06-01",
        "booking_time": "18:00",
        "quantity": 2
    }
    response = requests.post(f"{BASE_URL}/api/user/bookings", json=data, headers=headers)
    print(f"Create booking response: {response.status_code}")
    if response.status_code not in [200, 201]:
        print(f"Response: {response.json()}")
    
    # Test getting bookings
    response = requests.get(f"{BASE_URL}/api/user/bookings", headers=headers)
    print(f"Get bookings response: {response.status_code}")
    if response.status_code == 200:
        bookings = response.json()
        print(f"Number of bookings: {len(bookings)}")
        return True
    else:
        print(f"Response: {response.json()}")
    
    return False

def main():
    print("Starting API Integration Tests...")
    
    # Test basic endpoints
    if not test_events():
        print("Events test failed!")
        return
    
    # Test authentication
    success, email = test_registration()
    if not success:
        print("Registration test failed!")
        return
    
    token = test_login(email)
    if not token:
        print("Login test failed!")
        return
    
    print(f"\n🎉 Authentication successful! Token: {token[:20]}...")
    
    # Test user features
    print("\n" + "="*50)
    print("Testing User Features")
    print("="*50)
    
    bookmark_success = test_bookmarks(token)
    like_success = test_likes(token)
    booking_success = test_bookings(token)
    
    print("\n" + "="*50)
    print("Test Results Summary")
    print("="*50)
    print(f"✅ Events API: Working")
    print(f"✅ Authentication: Working")
    print(f"{'✅' if bookmark_success else '❌'} Bookmarks: {'Working' if bookmark_success else 'Failed'}")
    print(f"{'✅' if like_success else '❌'} Likes: {'Working' if like_success else 'Failed'}")
    print(f"{'✅' if booking_success else '❌'} Bookings: {'Working' if booking_success else 'Failed'}")
    
    print("\n🎉 All core functionality tested!")

if __name__ == "__main__":
    main() 
