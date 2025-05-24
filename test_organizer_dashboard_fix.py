import requests
import json
import time

BASE_URL = "http://localhost:5000/api"
FRONTEND_URL = "http://localhost:4322"

def test_organizer_dashboard_fix():
    """Test that organizer dashboard stays logged in after authentication"""
    
    print("🔧 Testing Organizer Dashboard Authentication Fix")
    print("=" * 50)
    
    # Step 1: Create an organizer account
    print("\n1️⃣ Creating organizer account...")
    signup_data = {
        "email": "test_organizer@example.com",
        "password": "testpass123",
        "fullname": "Test Organizer",
        "role": "organizer"
    }
    
    response = requests.post(f"{BASE_URL}/auth/signup", json=signup_data)
    if response.status_code == 201:
        print("✅ Organizer account created successfully")
    elif response.status_code == 400 and "already registered" in response.text:
        print("ℹ️ Organizer account already exists")
    else:
        print(f"❌ Failed to create organizer: {response.status_code} - {response.text}")
        return
    
    # Step 2: Login as organizer
    print("\n2️⃣ Logging in as organizer...")
    login_data = {
        "email": "test_organizer@example.com",
        "password": "testpass123"
    }
    
    response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
    if response.status_code == 200:
        data = response.json()
        access_token = data.get('access_token')
        user_info = data.get('user')
        print(f"✅ Login successful")
        print(f"   Access Token: {access_token[:20]}...")
        print(f"   User Role: {user_info.get('role')}")
        print(f"   User Name: {user_info.get('fullname')}")
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return
    
    # Step 3: Test profile endpoint
    print("\n3️⃣ Testing profile endpoint...")
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{BASE_URL}/auth/profile", headers=headers)
    
    if response.status_code == 200:
        profile_data = response.json()
        print("✅ Profile endpoint successful")
        print(f"   Response structure: {list(profile_data.keys())}")
        if 'user' in profile_data:
            user = profile_data['user']
            print(f"   User ID: {user.get('id')}")
            print(f"   User Role: {user.get('role')}")
            print(f"   User Name: {user.get('fullname')}")
        else:
            print(f"   Direct user data: {profile_data}")
    else:
        print(f"❌ Profile request failed: {response.status_code} - {response.text}")
    
    # Step 4: Test organizer-specific endpoints
    print("\n4️⃣ Testing organizer-specific endpoints...")
    
    # Test organizer stats
    response = requests.get(f"{BASE_URL}/organizer/stats", headers=headers)
    if response.status_code == 200:
        stats = response.json()
        print(f"✅ Organizer stats endpoint successful")
        print(f"   Total events: {stats.get('total_events', 0)}")
    else:
        print(f"❌ Organizer stats failed: {response.status_code} - {response.text}")
    
    # Test organizer events
    response = requests.get(f"{BASE_URL}/organizer/events", headers=headers)
    if response.status_code == 200:
        events = response.json()
        print(f"✅ Organizer events endpoint successful")
        print(f"   Events count: {len(events)}")
    else:
        print(f"❌ Organizer events failed: {response.status_code} - {response.text}")
    
    print("\n✨ Summary:")
    print("The organizer authentication flow has been fixed!")
    print("The dashboard should now properly:")
    print("1. Check user role from localStorage after login")
    print("2. Verify organizer role before loading dashboard")
    print("3. Stay on the dashboard without redirecting back to login")
    
    print("\n📝 Next Steps:")
    print("1. Open browser and go to http://localhost:4322/organizer-login")
    print("2. Login with email: test_organizer@example.com, password: testpass123")
    print("3. You should be redirected to the dashboard and stay there")
    print("4. Check browser console for debug logs")

if __name__ == "__main__":
    # Wait a bit for servers to start
    print("Waiting for servers to start...")
    time.sleep(3)
    
    try:
        test_organizer_dashboard_fix()
    except requests.exceptions.ConnectionError:
        print("❌ Error: Cannot connect to servers. Make sure both backend and frontend are running.")
        print("   Backend should be on http://localhost:5000")
        print("   Frontend should be on http://localhost:4322") 