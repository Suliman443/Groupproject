// DOM Elements
const authModal = document.getElementById('authModal');
const loginForm = document.getElementById('loginForm');
const signupForm = document.getElementById('signupForm');
const loginFormElement = document.getElementById('loginFormElement');
const signupFormElement = document.getElementById('signupFormElement');
const loginBtn = document.getElementById('loginBtn');
const closeBtn = document.querySelector('.close');
const showSignupLink = document.getElementById('showSignup');
const showLoginLink = document.getElementById('showLogin');

// API Endpoints
const API_BASE_URL = 'http://localhost:5000';  // Update this with your backend URL
const LOGIN_ENDPOINT = `${API_BASE_URL}/login`;
const SIGNUP_ENDPOINT = `${API_BASE_URL}/signup`;

// Event Listeners
loginBtn.addEventListener('click', () => {
    authModal.style.display = 'block';
    showLoginForm();
});

closeBtn.addEventListener('click', () => {
    authModal.style.display = 'none';
});

showSignupLink.addEventListener('click', (e) => {
    e.preventDefault();
    showSignupForm();
});

showLoginLink.addEventListener('click', (e) => {
    e.preventDefault();
    showLoginForm();
});

// Close modal when clicking outside
window.addEventListener('click', (e) => {
    if (e.target === authModal) {
        authModal.style.display = 'none';
    }
});

// Form Submission Handlers
loginFormElement.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const response = await fetch(LOGIN_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (response.ok) {
            // Store the token or user data if needed
            localStorage.setItem('user', JSON.stringify(data));
            showMessage(loginForm, 'Login successful!', 'success');
            setTimeout(() => {
                authModal.style.display = 'none';
                window.location.reload(); // Refresh to update UI
            }, 1500);
        } else {
            showMessage(loginForm, data.message || 'Login failed', 'error');
        }
    } catch (error) {
        showMessage(loginForm, 'An error occurred. Please try again.', 'error');
    }
});

signupFormElement.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (password !== confirmPassword) {
        showMessage(signupForm, 'Passwords do not match', 'error');
        return;
    }

    try {
        const response = await fetch(SIGNUP_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (response.ok) {
            showMessage(signupForm, 'Account created successfully! Please login.', 'success');
            setTimeout(() => {
                showLoginForm();
            }, 1500);
        } else {
            showMessage(signupForm, data.message || 'Signup failed', 'error');
        }
    } catch (error) {
        showMessage(signupForm, 'An error occurred. Please try again.', 'error');
    }
});

// Helper Functions
function showLoginForm() {
    loginForm.style.display = 'block';
    signupForm.style.display = 'none';
    clearForms();
}

function showSignupForm() {
    loginForm.style.display = 'none';
    signupForm.style.display = 'block';
    clearForms();
}

function clearForms() {
    loginFormElement.reset();
    signupFormElement.reset();
    // Clear any existing messages
    const messages = document.querySelectorAll('.error-message, .success-message');
    messages.forEach(msg => msg.remove());
}

function showMessage(form, message, type) {
    // Remove any existing messages
    const existingMessage = form.querySelector('.error-message, .success-message');
    if (existingMessage) {
        existingMessage.remove();
    }

    // Create and append new message
    const messageElement = document.createElement('p');
    messageElement.className = `${type}-message`;
    messageElement.textContent = message;
    form.appendChild(messageElement);
}

// Check if user is logged in on page load
function checkAuthStatus() {
    const user = localStorage.getItem('user');
    if (user) {
        // Update UI for logged-in user
        loginBtn.textContent = 'Logout';
        loginBtn.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('user');
            window.location.reload();
        });
    }
}

// Initialize auth status check
checkAuthStatus(); 