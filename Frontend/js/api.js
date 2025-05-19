// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// API Functions
async function fetchEvents() {
    try {
        const response = await fetch(`${API_BASE_URL}/events`);
        if (!response.ok) throw new Error('Failed to fetch events');
        return await response.json();
    } catch (error) {
        console.error('Error fetching events:', error);
        throw error;
    }
}

async function fetchEventById(eventId) {
    try {
        const response = await fetch(`${API_BASE_URL}/events/${eventId}`);
        if (!response.ok) throw new Error('Failed to fetch event');
        return await response.json();
    } catch (error) {
        console.error('Error fetching event:', error);
        throw error;
    }
}

async function createEvent(eventData) {
    try {
        const response = await fetch(`${API_BASE_URL}/events`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(eventData)
        });
        if (!response.ok) throw new Error('Failed to create event');
        return await response.json();
    } catch (error) {
        console.error('Error creating event:', error);
        throw error;
    }
}

async function updateEvent(eventId, eventData) {
    try {
        const response = await fetch(`${API_BASE_URL}/events/${eventId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(eventData)
        });
        if (!response.ok) throw new Error('Failed to update event');
        return await response.json();
    } catch (error) {
        console.error('Error updating event:', error);
        throw error;
    }
}

async function deleteEvent(eventId) {
    try {
        const response = await fetch(`${API_BASE_URL}/events/${eventId}`, {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Failed to delete event');
        return true;
    } catch (error) {
        console.error('Error deleting event:', error);
        throw error;
    }
}

// UI Functions
function createEventCard(event) {
    return `
        <div class="card" data-event-id="${event.id}">
            <img src="${event.image_url || 'images/default-event.jpg'}" alt="${event.title}">
            <h2>${event.title}</h2>
            <div class="date">${new Date(event.date).toLocaleDateString()}</div>
            <p>${event.description}</p>
            <div class="btns">
                <button onclick="handleBookmark(${event.id})">🔖 Bookmark</button>
                <button onclick="handleLike(${event.id})">❤️ Like</button>
            </div>
        </div>
    `;
}

async function loadEvents() {
    const eventsContainer = document.querySelector('.events');
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'loading';
    loadingDiv.textContent = 'Loading events...';
    eventsContainer.innerHTML = '';
    eventsContainer.appendChild(loadingDiv);

    try {
        const events = await fetchEvents();
        eventsContainer.innerHTML = '';
        events.forEach(event => {
            eventsContainer.innerHTML += createEventCard(event);
        });
    } catch (error) {
        eventsContainer.innerHTML = `
            <div class="error">
                Failed to load events. Please try again later.
            </div>
        `;
    }
}

// Event Handlers
async function handleBookmark(eventId) {
    // TODO: Implement bookmark functionality
    console.log('Bookmark clicked for event:', eventId);
}

async function handleLike(eventId) {
    // TODO: Implement like functionality
    console.log('Like clicked for event:', eventId);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadEvents();
});

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