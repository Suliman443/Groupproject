// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// Event Card Template
function createEventCard(event) {
    return `
        <div class="event-card">
            <img src="${event.image_url || 'images/default-event.jpg'}" alt="${event.title}">
            <h3>${event.title}</h3>
            <div class="date">${new Date(event.date).toLocaleDateString()}</div>
            <div class="description">${event.description || ''}</div>
            <div class="event-actions">
                <button onclick="handleBookmark(${event.id})">🔖 Bookmark</button>
                <button onclick="handleLike(${event.id})">❤️ Like</button>
            </div>
        </div>
    `;
}

// Load Events
async function loadEvents() {
    const eventsContainer = document.getElementById('events-list');
    if (!eventsContainer) return;
    eventsContainer.innerHTML = '<div class="loading">Loading events...</div>';
    try {
        const response = await fetch(`${API_BASE_URL}/events`);
        if (!response.ok) throw new Error('Failed to fetch events');
        const events = await response.json();
        if (events.length === 0) {
            eventsContainer.innerHTML = '<div class="loading">No events found.</div>';
        } else {
            eventsContainer.innerHTML = events.map(event => createEventCard(event)).join('');
        }
    } catch (error) {
        console.error('Error loading events:', error);
        eventsContainer.innerHTML = `
            <div class="error-message">
                Failed to load events. Please try again later.
            </div>
        `;
    }
}

// Event Handlers
function handleBookmark(eventId) {
    // TODO: Implement bookmark functionality
    alert('Bookmark clicked for event: ' + eventId);
}

function handleLike(eventId) {
    // TODO: Implement like functionality
    alert('Like clicked for event: ' + eventId);
}

// Initialize
window.addEventListener('DOMContentLoaded', () => {
    loadEvents();
}); 