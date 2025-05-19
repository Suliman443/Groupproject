// DOM Elements
const navbar = document.querySelector('.navbar');
const navLinks = document.querySelectorAll('.nav-links a');
const loginBtn = document.getElementById('loginBtn');
const loginModal = document.getElementById('loginModal');
const closeBtn = document.querySelector('.close');
const loginForm = document.getElementById('loginForm');

// Add scroll event listener for navbar
window.addEventListener('scroll', () => {
    if (window.scrollY > 100) {
        navbar.style.backgroundColor = 'rgba(44, 62, 80, 0.9)';
    } else {
        navbar.style.backgroundColor = '#2c3e50';
    }
});

// Smooth scroll for navigation links
navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = link.getAttribute('href');
        const targetSection = document.querySelector(targetId);
        targetSection.scrollIntoView({ behavior: 'smooth' });
    });
});

// Show login modal
loginBtn.addEventListener('click', (e) => {
    e.preventDefault();
    loginModal.style.display = 'block';
});

// Close login modal
closeBtn.addEventListener('click', () => {
    loginModal.style.display = 'none';
});

// Close modal when clicking outside
window.addEventListener('click', (e) => {
    if (e.target === loginModal) {
        loginModal.style.display = 'none';
    }
});

// Handle login form submission
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        const response = await api.login(email, password);
        
        if (response.token) {
            // Store the token
            localStorage.setItem('token', response.token);
            
            // Close the modal
            loginModal.style.display = 'none';
            
            // Update UI to show logged-in state
            loginBtn.textContent = 'Logout';
            loginBtn.href = '#';
            loginBtn.addEventListener('click', handleLogout);
            
            // Show success message
            alert('Login successful!');
        } else {
            alert('Login failed. Please check your credentials.');
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('An error occurred during login. Please try again.');
    }
});

// Handle logout
function handleLogout(e) {
    e.preventDefault();
    localStorage.removeItem('token');
    loginBtn.textContent = 'Login';
    loginBtn.removeEventListener('click', handleLogout);
    loginBtn.addEventListener('click', (e) => {
        e.preventDefault();
        loginModal.style.display = 'block';
    });
}

// Check if user is logged in on page load
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (token) {
        loginBtn.textContent = 'Logout';
        loginBtn.addEventListener('click', handleLogout);
    }
    console.log('Website initialized successfully');
}); 