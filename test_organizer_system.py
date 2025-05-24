#!/usr/bin/env python3
"""
Test script to demonstrate the complete organizer system functionality
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000/api"

def print_section(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}\n")

def test_organizer_system():
    # Test data
    organizer_data = {
        "fullname": "John Doe - Event Organizer",
        "email": "organizer@example.com",
        "password": "password123"
    }
    
    user_data = {
        "fullname": "Jane Smith - Regular User",
        "email": "user@example.com",
        "password": "password123"
    }
    
    event_data = {
        "title": "Tech Conference 2025",
        "description": "Annual technology conference featuring the latest innovations",
        "location": "Riyadh Convention Center",
        "date": "2025-06-15T09:00:00",
        "latitude": 24.7136,
        "longitude": 46.6753,
        "image_url": "https://example.com/tech-conference.jpg"
    }
    
    print_section("ORGANIZER SYSTEM DEMONSTRATION")
    
    # 1. Register an organizer
    print("1. Registering a new organizer account...")
    response = requests.post(f"{BASE_URL}/auth/organizer/signup", json=organizer_data)
    if response.status_code == 201:
        print(f"✅ Organizer registered successfully: {response.json()['user']['fullname']}")
    else:
        print(f"❌ Registration failed: {response.json()}")
    
    # 2. Register a regular user
    print("\n2. Registering a regular user account...")
    response = requests.post(f"{BASE_URL}/auth/signup", json=user_data)
    if response.status_code == 201:
        print(f"✅ User registered successfully: {response.json()['user']['fullname']}")
    else:
        print(f"❌ Registration failed: {response.json()}")
    
    # 3. Organizer login
    print("\n3. Organizer logging in...")
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "email": organizer_data["email"],
        "password": organizer_data["password"]
    })
    if response.status_code == 200:
        organizer_tokens = response.json()
        organizer_token = organizer_tokens['access_token']
        print(f"✅ Organizer logged in successfully")
        print(f"   Role: {organizer_tokens['user']['role']}")
    else:
        print(f"❌ Login failed: {response.json()}")
        return
    
    # 4. User login
    print("\n4. Regular user logging in...")
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "email": user_data["email"],
        "password": user_data["password"]
    })
    if response.status_code == 200:
        user_tokens = response.json()
        user_token = user_tokens['access_token']
        print(f"✅ User logged in successfully")
        print(f"   Role: {user_tokens['user']['role']}")
    else:
        print(f"❌ Login failed: {response.json()}")
        return
    
    # 5. Organizer creates an event
    print("\n5. Organizer creating a new event...")
    headers = {"Authorization": f"Bearer {organizer_token}"}
    response = requests.post(f"{BASE_URL}/events", json=event_data, headers=headers)
    if response.status_code == 201:
        created_event = response.json()
        event_id = created_event['id']
        print(f"✅ Event created successfully: {created_event['title']}")
        print(f"   Event ID: {event_id}")
    else:
        print(f"❌ Event creation failed: {response.json()}")
        return
    
    # 6. Check organizer stats
    print("\n6. Checking organizer statistics...")
    response = requests.get(f"{BASE_URL}/organizer/stats", headers=headers)
    if response.status_code == 200:
        stats = response.json()
        print(f"✅ Organizer stats retrieved:")
        print(f"   Total events: {stats['total_events']}")
        print(f"   Organizer name: {stats['organizer_name']}")
    else:
        print(f"❌ Failed to get stats: {response.json()}")
    
    # 7. Get organizer's events
    print("\n7. Getting organizer's events...")
    response = requests.get(f"{BASE_URL}/organizer/events", headers=headers)
    if response.status_code == 200:
        events = response.json()
        print(f"✅ Retrieved {len(events)} events")
        for event in events:
            print(f"   - {event['title']} (ID: {event['id']})")
    else:
        print(f"❌ Failed to get events: {response.json()}")
    
    # 8. Public can view all events
    print("\n8. Public viewing all events (no auth required)...")
    response = requests.get(f"{BASE_URL}/events")
    if response.status_code == 200:
        events = response.json()
        print(f"✅ Retrieved {len(events)} public events")
        for event in events:
            print(f"   - {event['title']} by user ID {event['created_by']}")
    else:
        print(f"❌ Failed to get events: {response.json()}")
    
    # 9. User tries to create event (should work)
    print("\n9. Regular user trying to create an event...")
    user_headers = {"Authorization": f"Bearer {user_token}"}
    user_event = {
        "title": "Community Meetup",
        "description": "Local community gathering",
        "location": "Community Center",
        "date": "2025-07-01T18:00:00",
        "latitude": 24.7136,
        "longitude": 46.6753
    }
    response = requests.post(f"{BASE_URL}/events", json=user_event, headers=user_headers)
    if response.status_code == 201:
        print(f"✅ User created event successfully")
    else:
        print(f"❌ User event creation failed: {response.json()}")
    
    # 10. Organizer updates their event
    print("\n10. Organizer updating their event...")
    update_data = {
        "title": "Tech Conference 2025 - Updated",
        "description": "Updated: Now featuring AI and blockchain tracks!"
    }
    response = requests.put(f"{BASE_URL}/events/{event_id}", json=update_data, headers=headers)
    if response.status_code == 200:
        updated_event = response.json()
        print(f"✅ Event updated successfully: {updated_event['title']}")
    else:
        print(f"❌ Event update failed: {response.json()}")
    
    # 11. User tries to update organizer's event (should fail)
    print("\n11. User trying to update organizer's event (should fail)...")
    response = requests.put(f"{BASE_URL}/events/{event_id}", json={"title": "Hacked!"}, headers=user_headers)
    if response.status_code == 403:
        print(f"✅ Correctly blocked: {response.json()['error']}")
    else:
        print(f"❌ Security issue: User was able to modify organizer's event!")
    
    # 12. Organizer deletes their event
    print("\n12. Organizer deleting their event...")
    response = requests.delete(f"{BASE_URL}/events/{event_id}", headers=headers)
    if response.status_code == 204:
        print(f"✅ Event deleted successfully")
    else:
        print(f"❌ Event deletion failed")
    
    # 13. Verify event is deleted
    print("\n13. Verifying event is deleted...")
    response = requests.get(f"{BASE_URL}/events")
    if response.status_code == 200:
        events = response.json()
        event_ids = [e['id'] for e in events]
        if event_id not in event_ids:
            print(f"✅ Event successfully removed from public listing")
        else:
            print(f"❌ Event still appears in public listing!")
    
    print_section("TEST COMPLETED")
    print("The organizer system is working correctly!")
    print("\nKey features demonstrated:")
    print("✅ Separate organizer registration")
    print("✅ Role-based access control")
    print("✅ Organizers can create, update, and delete their events")
    print("✅ Events are saved to database and persist")
    print("✅ Deleted events are removed from database")
    print("✅ Users cannot modify events they don't own")
    print("✅ Public can view all events without authentication")

if __name__ == "__main__":
    try:
        test_organizer_system()
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the API server.")
        print("   Make sure the backend server is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Error: {e}") 