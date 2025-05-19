// API base URL - change this to match your backend URL
const API_BASE_URL = 'http://localhost:5000';

// API service for handling backend communication
const api = {
    // Auth endpoints
    async login(email, password) {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });
        return response.json();
    },

    async register(userData) {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData),
        });
        return response.json();
    },

    // Listings endpoints
    async getListings() {
        const response = await fetch(`${API_BASE_URL}/api/listings`);
        return response.json();
    },

    async createListing(listingData) {
        const response = await fetch(`${API_BASE_URL}/api/listings`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
            body: JSON.stringify(listingData),
        });
        return response.json();
    },

    // Events endpoints
    async getEvents() {
        const response = await fetch(`${API_BASE_URL}/api/events`);
        return response.json();
    },

    async createEvent(eventData) {
        const response = await fetch(`${API_BASE_URL}/api/events`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
            body: JSON.stringify(eventData),
        });
        return response.json();
    },

    // Helper function to handle API errors
    handleError(error) {
        console.error('API Error:', error);
        throw error;
    }
}; 