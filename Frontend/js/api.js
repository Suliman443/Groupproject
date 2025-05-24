// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// Authentication Helper
class AuthManager {
    static getToken() {
        return localStorage.getItem('access_token');
    }

    static setTokens(accessToken, refreshToken) {
        localStorage.setItem('access_token', accessToken);
        localStorage.setItem('refresh_token', refreshToken);
    }

    static removeTokens() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('currentUser');
    }

    static isLoggedIn() {
        return !!this.getToken();
    }

    static async refreshToken() {
        const refreshToken = localStorage.getItem('refresh_token');
        if (!refreshToken) return false;

        try {
            const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${refreshToken}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.setTokens(data.access_token, refreshToken);
                return true;
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
        }
        
        this.removeTokens();
        return false;
    }

    static getAuthHeaders() {
        const token = this.getToken();
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    }
}

// Main API Service
class TourismAPI {
    static async request(endpoint, options = {}) {
        const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
        
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...AuthManager.getAuthHeaders(),
                ...options.headers
            },
            ...options
        };

        try {
            let response = await fetch(url, config);
            
            // Handle token expiration
            if (response.status === 401 && AuthManager.isLoggedIn()) {
                const refreshed = await AuthManager.refreshToken();
                if (refreshed) {
                    config.headers = {
                        ...config.headers,
                        ...AuthManager.getAuthHeaders()
                    };
                    response = await fetch(url, config);
                }
            }

            return response;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    // Authentication Methods
    static async register(userData) {
        const response = await this.request('/auth/signup', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
        return response.json();
    }

    static async login(email, password) {
        const response = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        
        if (response.ok) {
            const data = await response.json();
            AuthManager.setTokens(data.access_token, data.refresh_token);
            
            // Get user profile
            const profile = await this.getUserProfile();
            localStorage.setItem('currentUser', JSON.stringify(profile));
            
            return data;
        }
        
        return response.json();
    }

    static async logout() {
        AuthManager.removeTokens();
        return { success: true };
    }

    static async getUserProfile() {
        const response = await this.request('/auth/profile');
        if (response.ok) {
            const data = await response.json();
            return data.user || data; // Handle different response formats
        }
        throw new Error('Failed to get user profile');
    }

    // Event Methods
    static async getEvents() {
        const response = await this.request('/events');
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to fetch events');
    }

    static async getEventById(eventId) {
        const response = await this.request(`/events/${eventId}`);
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to fetch event');
    }

    static async createEvent(eventData) {
        const response = await this.request('/events', {
            method: 'POST',
            body: JSON.stringify(eventData)
        });
        
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to create event');
    }

    static async updateEvent(eventId, eventData) {
        const response = await this.request(`/events/${eventId}`, {
            method: 'PUT',
            body: JSON.stringify(eventData)
        });
        
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to update event');
    }

    static async deleteEvent(eventId) {
        const response = await this.request(`/events/${eventId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            return { success: true };
        }
        throw new Error('Failed to delete event');
    }

    // Event Comments
    static async getEventComments(eventId) {
        const response = await this.request(`/events/${eventId}/comments`);
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to fetch comments');
    }

    static async addEventComment(eventId, commentData) {
        const response = await this.request(`/events/${eventId}/comments`, {
            method: 'POST',
            body: JSON.stringify(commentData)
        });
        
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to add comment');
    }

    // Listing Methods
    static async getListings() {
        const response = await this.request('/listings');
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to fetch listings');
    }

    static async createListing(listingData) {
        const response = await this.request('/listings', {
            method: 'POST',
            body: JSON.stringify(listingData)
        });
        
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to create listing');
    }

    // User Preferences (Bookmarks and Likes)
    static async getUserBookmarks() {
        const response = await this.request('/user/bookmarks');
        if (response.ok) {
            return response.json();
        }
        return [];
    }

    static async addBookmark(eventId) {
        const response = await this.request('/user/bookmarks', {
            method: 'POST',
            body: JSON.stringify({ event_id: eventId })
        });
        
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to add bookmark');
    }

    static async removeBookmark(eventId) {
        const response = await this.request(`/user/bookmarks/${eventId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            return { success: true };
        }
        throw new Error('Failed to remove bookmark');
    }

    static async getUserLikes() {
        const response = await this.request('/user/likes');
        if (response.ok) {
            return response.json();
        }
        return [];
    }

    static async addLike(eventId) {
        const response = await this.request('/user/likes', {
            method: 'POST',
            body: JSON.stringify({ event_id: eventId })
        });
        
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to add like');
    }

    static async removeLike(eventId) {
        const response = await this.request(`/user/likes/${eventId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            return { success: true };
        }
        throw new Error('Failed to remove like');
    }

    // User Bookings
    static async getUserBookings() {
        const response = await this.request('/user/bookings');
        if (response.ok) {
            return response.json();
        }
        return [];
    }

    static async createBooking(bookingData) {
        const response = await this.request('/user/bookings', {
            method: 'POST',
            body: JSON.stringify(bookingData)
        });
        
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to create booking');
    }

    static async updateBooking(bookingId, bookingData) {
        const response = await this.request(`/user/bookings/${bookingId}`, {
            method: 'PUT',
            body: JSON.stringify(bookingData)
        });
        
        if (response.ok) {
            return response.json();
        }
        throw new Error('Failed to update booking');
    }

    static async deleteBooking(bookingId) {
        const response = await this.request(`/user/bookings/${bookingId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            return { success: true };
        }
        throw new Error('Failed to delete booking');
    }
}

// Legacy API functions for backward compatibility
async function fetchEvents() {
    return TourismAPI.getEvents();
}

async function fetchEventById(eventId) {
    return TourismAPI.getEventById(eventId);
}

async function createEvent(eventData) {
    return TourismAPI.createEvent(eventData);
}

async function updateEvent(eventId, eventData) {
    return TourismAPI.updateEvent(eventId, eventData);
}

async function deleteEvent(eventId) {
    return TourismAPI.deleteEvent(eventId);
}

// UI Helper Functions
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
    const eventsContainer = document.querySelector('.events') || document.getElementById('events-list');
    if (!eventsContainer) return;

    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'loading';
    loadingDiv.textContent = 'Loading events...';
    eventsContainer.innerHTML = '';
    eventsContainer.appendChild(loadingDiv);

    try {
        const events = await TourismAPI.getEvents();
        eventsContainer.innerHTML = '';
        events.forEach(event => {
            eventsContainer.innerHTML += createEventCard(event);
        });
    } catch (error) {
        console.error('Failed to load events:', error);
        eventsContainer.innerHTML = `
            <div class="error">
                Failed to load events. Please try again later.
            </div>
        `;
    }
}

// Event Handlers with API Integration
async function handleBookmark(eventId) {
    if (!AuthManager.isLoggedIn()) {
        showToast('Please login to bookmark events');
        return;
    }

    try {
        // Check if already bookmarked
        const bookmarks = await TourismAPI.getUserBookmarks();
        const isBookmarked = bookmarks.some(b => b.event_id === eventId);

        if (isBookmarked) {
            await TourismAPI.removeBookmark(eventId);
            showToast('Event removed from bookmarks');
        } else {
            await TourismAPI.addBookmark(eventId);
            showToast('Event bookmarked successfully');
        }

        // Update UI if we're on bookmarks page
        if (typeof loadBookmarks === 'function') {
            loadBookmarks();
        }
    } catch (error) {
        console.error('Bookmark action failed:', error);
        showToast('Action failed. Please try again.');
    }
}

async function handleLike(eventId) {
    if (!AuthManager.isLoggedIn()) {
        showToast('Please login to like events');
        return;
    }

    try {
        // Check if already liked
        const likes = await TourismAPI.getUserLikes();
        const isLiked = likes.some(l => l.event_id === eventId);

        if (isLiked) {
            await TourismAPI.removeLike(eventId);
            showToast('Event removed from likes');
        } else {
            await TourismAPI.addLike(eventId);
            showToast('Event liked successfully');
        }

        // Update UI if we're on likes page
        if (typeof loadLikedEvents === 'function') {
            loadLikedEvents();
        }
    } catch (error) {
        console.error('Like action failed:', error);
        showToast('Action failed. Please try again.');
    }
}

// Toast notification function
function showToast(message) {
    console.log('Toast:', message);
    let toast = document.querySelector('.toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.className = 'toast';
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #333;
            color: #fff;
            padding: 1rem;
            border-radius: 4px;
            z-index: 10000;
            opacity: 0;
            transform: translateX(100%);
            transition: all 0.3s ease;
        `;
        document.body.appendChild(toast);
    }
    
    toast.textContent = message;
    toast.style.opacity = '1';
    toast.style.transform = 'translateX(0)';
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
    }, 3000);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Auto-load events if container exists
    if (document.querySelector('.events') || document.getElementById('events-list')) {
        loadEvents();
    }
});

// Export for global use
window.TourismAPI = TourismAPI;
window.AuthManager = AuthManager; 