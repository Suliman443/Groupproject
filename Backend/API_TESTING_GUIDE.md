# Tourism App API Testing Guide

## Overview
This guide provides comprehensive testing instructions for the Tourism App API, including authentication, events, listings, and comments functionality.

## Setup Instructions

### 1. Install Dependencies
```bash
cd Backend
pip install -r requirements.txt
```

### 2. Initialize Database
```bash
python init_db.py
```

### 3. Run the Server
```bash
python run.py
```

## API Endpoints Documentation

### Authentication Endpoints

#### 1. Sign Up
- **Endpoint**: `POST /auth/signup`
- **Description**: Register a new user account
- **Authentication**: None required
- **Request Body**:
```json
{
    "email": "user@example.com",
    "password": "password123",
    "fullname": "John Doe"
}
```
- **Response (201)**:
```json
{
    "message": "User created successfully",
    "user": {
        "email": "user@example.com",
        "fullname": "John Doe"
    }
}
```

#### 2. Login
- **Endpoint**: `POST /auth/login`
- **Description**: Authenticate user and receive JWT tokens
- **Authentication**: None required
- **Request Body**:
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```
- **Response (200)**:
```json
{
    "message": "Login successful",
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "email": "user@example.com",
        "fullname": "John Doe",
        "role": "user"
    }
}
```

#### 3. Get Profile
- **Endpoint**: `GET /auth/profile`
- **Description**: Get current user profile
- **Authentication**: Bearer token required
- **Headers**: `Authorization: Bearer <access_token>`

#### 4. Refresh Token
- **Endpoint**: `POST /auth/refresh`
- **Description**: Get new access token using refresh token
- **Authentication**: Refresh token required

### Event Endpoints

#### 1. Get All Events
- **Endpoint**: `GET /api/events`
- **Description**: Retrieve all events
- **Authentication**: None required

#### 2. Get Single Event
- **Endpoint**: `GET /api/events/{event_id}`
- **Description**: Retrieve a specific event
- **Authentication**: None required

#### 3. Create Event
- **Endpoint**: `POST /api/events`
- **Description**: Create a new event
- **Authentication**: Bearer token required
- **Request Body**:
```json
{
    "title": "Summer Festival",
    "description": "Annual summer festival in the city center",
    "location": "Riyadh, Saudi Arabia",
    "latitude": 24.7136,
    "longitude": 46.6753,
    "date": "2024-07-15T18:00:00",
    "image_url": "https://example.com/festival.jpg"
}
```

#### 4. Update Event
- **Endpoint**: `PUT /api/events/{event_id}`
- **Description**: Update an existing event
- **Authentication**: Bearer token required (owner or admin only)

#### 5. Delete Event
- **Endpoint**: `DELETE /api/events/{event_id}`
- **Description**: Delete an event
- **Authentication**: Bearer token required (owner or admin only)

### Event Comments Endpoints

#### 1. Get Event Comments
- **Endpoint**: `GET /api/events/{event_id}/comments`
- **Description**: Get all comments for a specific event
- **Authentication**: None required

#### 2. Add Event Comment
- **Endpoint**: `POST /api/events/{event_id}/comments`
- **Description**: Add a comment to an event
- **Authentication**: Bearer token required
- **Request Body**:
```json
{
    "content": "This looks like a great event!"
}
```

#### 3. Update Event Comment
- **Endpoint**: `PUT /api/events/{event_id}/comments/{comment_id}`
- **Description**: Update a comment on an event
- **Authentication**: Bearer token required (owner or admin only)

#### 4. Delete Event Comment
- **Endpoint**: `DELETE /api/events/{event_id}/comments/{comment_id}`
- **Description**: Delete a comment from an event
- **Authentication**: Bearer token required (owner or admin only)

### Listing Endpoints

#### 1. Get All Listings
- **Endpoint**: `GET /api/listings`
- **Description**: Retrieve all active listings
- **Authentication**: None required
- **Query Parameters**: `status` (active, sold, deleted)

#### 2. Get Single Listing
- **Endpoint**: `GET /api/listings/{listing_id}`
- **Description**: Retrieve a specific listing
- **Authentication**: None required

#### 3. Create Listing
- **Endpoint**: `POST /api/listings`
- **Description**: Create a new listing
- **Authentication**: Bearer token required
- **Request Body**:
```json
{
    "title": "Beautiful Hotel Room",
    "description": "Spacious room with city view",
    "price": 250.00,
    "location": "Riyadh, Saudi Arabia",
    "image_url": "https://example.com/room.jpg"
}
```

#### 4. Update Listing
- **Endpoint**: `PUT /api/listings/{listing_id}`
- **Description**: Update an existing listing
- **Authentication**: Bearer token required (owner or admin only)

#### 5. Delete Listing
- **Endpoint**: `DELETE /api/listings/{listing_id}`
- **Description**: Soft delete a listing (sets status to 'deleted')
- **Authentication**: Bearer token required (owner or admin only)

### Listing Comments Endpoints

#### 1. Get Listing Comments
- **Endpoint**: `GET /api/listings/{listing_id}/comments`
- **Description**: Get all comments for a specific listing
- **Authentication**: None required

#### 2. Add Listing Comment
- **Endpoint**: `POST /api/listings/{listing_id}/comments`
- **Description**: Add a comment to a listing
- **Authentication**: Bearer token required

#### 3. Update Listing Comment
- **Endpoint**: `PUT /api/listings/{listing_id}/comments/{comment_id}`
- **Description**: Update a comment on a listing
- **Authentication**: Bearer token required (owner or admin only)

#### 4. Delete Listing Comment
- **Endpoint**: `DELETE /api/listings/{listing_id}/comments/{comment_id}`
- **Description**: Delete a comment from a listing
- **Authentication**: Bearer token required (owner or admin only)

## Postman Testing

### Import Collection
1. Import the `Tourism_App_API.postman_collection.json` file into Postman
2. The collection includes:
   - Authentication tests
   - Event CRUD operations
   - Listing CRUD operations
   - Comment functionality
   - Error scenario testing

### Test Execution Order
1. **Authentication Flow**:
   - Run "Signup" to create a test user
   - Run "Login" to get access token (automatically saved to global variables)
   - Run "Get Profile" to verify authentication

2. **Events Testing**:
   - Run "Get All Events" to see current events
   - Run "Create Event" to add a new event (saves event_id)
   - Run "Get Single Event" to verify creation
   - Run "Add Event Comment" to test comment functionality

3. **Listings Testing**:
   - Run "Get All Listings" to see current listings
   - Run "Create Listing" to add a new listing (saves listing_id)
   - Run "Get Single Listing" to verify creation
   - Run "Add Listing Comment" to test comment functionality

4. **Error Testing**:
   - Run "Unauthorized Access" to verify protection
   - Run "Invalid Login" to verify credential validation

### Environment Variables
The collection uses these variables:
- `base_url`: http://localhost:5000
- `access_token`: Automatically set after login
- `event_id`: Automatically set after creating an event
- `listing_id`: Automatically set after creating a listing

## Manual Testing with cURL

### Login and Get Token
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'
```

### Create Event (with token)
```bash
curl -X POST http://localhost:5000/api/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "title": "Test Event",
    "description": "Test Description",
    "location": "Riyadh",
    "date": "2024-12-31T18:00:00"
  }'
```

### Add Event Comment
```bash
curl -X POST http://localhost:5000/api/events/1/comments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{"content": "Great event!"}'
```

## Authentication Details

### JWT Token Structure
- **Access Token**: Valid for 24 hours
- **Refresh Token**: Valid for 30 days
- **Algorithm**: HS256

### Protected Endpoints
All CREATE, UPDATE, DELETE operations require authentication:
- Creating events, listings, comments
- Updating/deleting own content
- Admin operations

### Authorization Levels
- **User**: Can create/edit/delete own content
- **Admin**: Can edit/delete any content

## Error Codes

- **400**: Bad Request (missing/invalid data)
- **401**: Unauthorized (missing/invalid token)
- **403**: Forbidden (insufficient permissions)
- **404**: Not Found (resource doesn't exist)
- **500**: Internal Server Error

## Task Implementation Status

✅ **B-S3-01**: Signup endpoint - COMPLETE
✅ **B-S3-02**: Login endpoint with JWT tokens - COMPLETE  
✅ **B-S3-03**: Token-based authentication middleware - COMPLETE
✅ **B-S3-04**: getEvents API - COMPLETE
✅ **B-S3-05**: Event comment API - COMPLETE
✅ **B-S3-06**: Database relationships finalized - COMPLETE
✅ **B-S3-07**: Postman testing collection - COMPLETE

All sprint tasks have been successfully implemented and are ready for testing! 