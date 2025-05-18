// Sample events data (this would typically come from an API)
const events = [
    {
        id: 1,
        title: 'Summer Music Festival',
        date: '2024-07-15',
        description: 'Join us for an amazing day of live music and entertainment.',
        image: 'images/event1.jpg'
    },
    {
        id: 2,
        title: 'Tech Conference 2024',
        date: '2024-08-20',
        description: 'Learn about the latest technologies and network with professionals.',
        image: 'images/event2.jpg'
    },
    {
        id: 3,
        title: 'Food & Wine Expo',
        date: '2024-09-10',
        description: 'Experience the finest cuisines and wines from around the world.',
        image: 'images/event3.jpg'
    }
];

// Function to create event card HTML
function createEventCard(event) {
    return `
        <div class="event-card" data-event-id="${event.id}">
            <div class="event-image">
                <img src="${event.image}" alt="${event.title}">
            </div>
            <div class="event-details">
                <h3>${event.title}</h3>
                <p class="event-date">${new Date(event.date).toLocaleDateString()}</p>
                <p class="event-description">${event.description}</p>
                <button class="btn-details" onclick="showEventDetails(${event.id})">Learn More</button>
            </div>
        </div>
    `;
}

// Function to display events
function displayEvents() {
    const eventsContainer = document.getElementById('events-container');
    if (eventsContainer) {
        eventsContainer.innerHTML = events.map(event => createEventCard(event)).join('');
    }
}

// Function to show event details (can be expanded based on requirements)
function showEventDetails(eventId) {
    const event = events.find(e => e.id === eventId);
    if (event) {
        alert(`Event Details:\n${event.title}\nDate: ${event.date}\n${event.description}`);
        // This could be replaced with a modal or a more sophisticated UI component
    }
}

// Initialize events when the page loads
document.addEventListener('DOMContentLoaded', () => {
    displayEvents();
}); 