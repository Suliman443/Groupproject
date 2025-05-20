// DOM Elements
const navbar = document.querySelector('.navbar');
const navLinks = document.querySelectorAll('#nav-links a');
const hamburger = document.querySelector('.hamburger');

// Add scroll event listener for navbar
window.addEventListener('scroll', () => {
    if (window.scrollY > 100) {
        navbar.style.backgroundColor = 'rgba(44, 62, 80, 0.9)';
    } else {
        navbar.style.backgroundColor = '#2c3e50';
    }
});

// Function to show/hide sections
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.content').forEach(section => {
        section.style.display = 'none';
    });
    
    // Show the selected section
    const selectedSection = document.getElementById(`${sectionId}-section`);
    if (selectedSection) {
        selectedSection.style.display = 'flex';
    }
}

// Toggle mobile menu
function toggleMenu() {
    const navLinks = document.getElementById('nav-links');
    navLinks.classList.toggle('show');
}

// Add click event listeners to navigation links
document.querySelectorAll('#nav-links a').forEach(link => {
    link.addEventListener('click', (e) => {
        const section = link.textContent.toLowerCase();
        if (section === 'home' || section === 'login' || section === 'register' || section === 'map' || section === 'events') {
            e.preventDefault();
            showSection(section);
        }
    });
});

// Handle login form submission
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    showToast('Login functionality will be implemented soon!');
});

// Handle register form submission
document.getElementById('registerForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    showToast('Registration functionality will be implemented soon!');
});

// Toast notification function
function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// Initialize website
document.addEventListener('DOMContentLoaded', () => {
    // Show home section by default
    showSection('home');
    console.log('Website initialized successfully');
}); 