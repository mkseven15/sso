// MkSeven1 SSO Authentication Client
// This handles all frontend authentication logic

// Configuration
const CONFIG = {
    API_BASE_URL: '/api/v1', // gRPC-Gateway endpoint
    GOOGLE_WORKSPACE_REDIRECT: 'https://accounts.google.com/o/saml2/initsso',
    TOKEN_STORAGE_KEY: 'mks_auth_token',
    REFRESH_TOKEN_KEY: 'mks_refresh_token',
    MAX_LOGIN_ATTEMPTS: 5
};

// State management
const state = {
    currentUsername: '',
    loginAttempts: 0,
    isSubmitting: false
};

// DOM Elements
const elements = {
    usernameStep: document.getElementById('username-step'),
    passwordStep: document.getElementById('password-step'),
    forgotUsernameContainer: document.getElementById('forgot-username-container'),
    forgotPasswordContainer: document.getElementById('forgot-password-container'),
    successContainer: document.getElementById('success-container'),
    errorContainer: document.getElementById('error-container'),
    usernameForm: document.getElementById('username-form'),
    passwordForm: document.getElementById('password-form'),
    usernameInput: document.getElementById('username'),
    passwordInput: document.getElementById('password'),
    usernameDisplay: document.getElementById('username-display'),
    loginButton: document.getElementById('login-button'),
    loginText: document.getElementById('login-text'),
    loginSpinner: document.getElementById('login-spinner'),
    togglePassword: document.getElementById('toggle-password')
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    checkExistingSession();
    setupPasswordToggle();
});

// Event Listeners Setup
function initializeEventListeners() {
    // Username form submission
    elements.usernameForm.addEventListener('submit', handleUsernameSubmit);
    
    // Password form submission
    elements.passwordForm.addEventListener('submit', handlePasswordSubmit);
    
    // Navigation links
    document.getElementById('back-to-username').addEventListener('click', (e) => {
        e.preventDefault();
        showStep('username');
    });
    
    document.getElementById('forgot-username-link').addEventListener('click', (e) => {
        e.preventDefault();
        showStep('forgot-username');
    });
    
    document.getElementById('forgot-password-link').addEventListener('click', (e) => {
        e.preventDefault();
        showStep('forgot-password');
    });
    
    document.getElementById('back-from-forgot-username').addEventListener('click', (e) => {
        e.preventDefault();
        showStep('username');
    });
    
    document.getElementById('back-from-forgot-password').addEventListener('click', (e) => {
        e.preventDefault();
        showStep('password');
    });
    
    // Forgot username form
    document.getElementById('forgot-username-form').addEventListener('submit', handleForgotUsername);
    
    // Forgot password form
    document.getElementById('forgot-password-form').addEventListener('submit', handleForgotPassword);
}

// Check for existing valid session
async function checkExistingSession() {
    const token = localStorage.getItem(CONFIG.TOKEN_STORAGE_KEY);
    
    if (token) {
        try {
            const isValid = await validateToken(token);
            if (isValid) {
                // Token is still valid, redirect to workspace
                redirectToWorkspace();
            } else {
                // Try to refresh the token
                await refreshAuthToken();
            }
        } catch (error) {
            // Token validation failed, clear storage
            clearAuthTokens();
        }
    }
}

// Handle username submission
async function handleUsernameSubmit(e) {
    e.preventDefault();
    
    if (state.isSubmitting) return;
    
    const username = elements.usernameInput.value.trim();
    
    if (!username) {
        showError('Please enter a username');
        return;
    }
    
    // Validate username exists (optional pre-check)
    try {
        const exists = await checkUsernameExists(username);
        if (exists) {
            state.currentUsername = username;
            elements.usernameDisplay.textContent = username;
            showStep('password');
            elements.passwordInput.focus();
        } else {
            showError('Username not found');
        }
    } catch (error) {
        // If check fails, proceed anyway (backend will validate)
        state.currentUsername = username;
        elements.usernameDisplay.textContent = username;
        showStep('password');
        elements.passwordInput.focus();
    }
}

// Handle password submission (actual login)
async function handlePasswordSubmit(e) {
    e.preventDefault();
    
    if (state.isSubmitting) return;
    
    const password = elements.passwordInput.value;
    
    if (!password) {
        showError('Please enter a password');
        return;
    }
    
    // Check login attempts
    if (state.loginAttempts >= CONFIG.MAX_LOGIN_ATTEMPTS) {
        showError('Too many failed attempts. Please try again later or reset your password.');
        return;
    }
    
    // Perform login
    await performLogin(state.currentUsername, password);
}

// Perform the actual login via gRPC-Gateway
async function performLogin(username, password) {
    setSubmitting(true);
    clearError();
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.access_token) {
            // Login successful
            handleLoginSuccess(data);
        } else {
            // Login failed
            state.loginAttempts++;
            handleLoginFailure(data.message || 'Invalid username or password');
        }
    } catch (error) {
        console.error('Login error:', error);
        state.loginAttempts++;
        showError('Connection error. Please check your internet connection and try again.');
    } finally {
        setSubmitting(false);
    }
}

// Handle successful login
function handleLoginSuccess(data) {
    // Store tokens
    localStorage.setItem(CONFIG.TOKEN_STORAGE_KEY, data.access_token);
    if (data.refresh_token) {
        localStorage.setItem(CONFIG.REFRESH_TOKEN_KEY, data.refresh_token);
    }
    
    // Reset login attempts
    state.loginAttempts = 0;
    
    // Show success message
    showStep('success');
    
    // Redirect to Google Workspace after short delay
    setTimeout(() => {
        redirectToWorkspace(data.saml_response);
    }, 1500);
}

// Handle failed login
function handleLoginFailure(message) {
    showError(message);
    
    // Clear password field
    elements.passwordInput.value = '';
    elements.passwordInput.focus();
    
    // Show remaining attempts
    const remainingAttempts = CONFIG.MAX_LOGIN_ATTEMPTS - state.loginAttempts;
    if (remainingAttempts > 0 && remainingAttempts <= 3) {
        showError(`${message}. ${remainingAttempts} attempt(s) remaining.`);
    }
}

// Redirect to Google Workspace with SAML assertion
function redirectToWorkspace(samlResponse = null) {
    if (samlResponse) {
        // Create a form to POST the SAML response
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = CONFIG.GOOGLE_WORKSPACE_REDIRECT;
        
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'SAMLResponse';
        input.value = samlResponse;
        
        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
    } else {
        // Fallback redirect
        window.location.href = 'https://workspace.google.com';
    }
}

// Validate token with backend
async function validateToken(token) {
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/auth/validate`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        return response.ok;
    } catch (error) {
        return false;
    }
}

// Refresh authentication token
async function refreshAuthToken() {
    const refreshToken = localStorage.getItem(CONFIG.REFRESH_TOKEN_KEY);
    
    if (!refreshToken) {
        clearAuthTokens();
        return false;
    }
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                refresh_token: refreshToken
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.access_token) {
            localStorage.setItem(CONFIG.TOKEN_STORAGE_KEY, data.access_token);
            return true;
        } else {
            clearAuthTokens();
            return false;
        }
    } catch (error) {
        clearAuthTokens();
        return false;
    }
}

// Check if username exists (optional pre-validation)
async function checkUsernameExists(username) {
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/auth/check-username`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });
        
        const data = await response.json();
        return data.exists === true;
    } catch (error) {
        // If check fails, return true to proceed
        return true;
    }
}

// Handle forgot username
async function handleForgotUsername(e) {
    e.preventDefault();
    
    const email = document.getElementById('recovery-email').value.trim();
    
    if (!email) {
        showError('Please enter your email address');
        return;
    }
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/auth/forgot-username`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email })
        });
        
        if (response.ok) {
            showError('If an account with that email exists, we\'ve sent the username to that address.', 'success');
        } else {
            showError('An error occurred. Please try again later.');
        }
    } catch (error) {
        showError('Connection error. Please try again later.');
    }
}

// Handle forgot password
async function handleForgotPassword(e) {
    e.preventDefault();
    
    const username = document.getElementById('reset-username').value.trim();
    const email = document.getElementById('reset-email').value.trim();
    
    if (!username || !email) {
        showError('Please fill in all fields');
        return;
    }
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/auth/forgot-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email })
        });
        
        if (response.ok) {
            showError('If your information matches our records, we\'ve sent a password reset link to your email.', 'success');
        } else {
            showError('An error occurred. Please try again later.');
        }
    } catch (error) {
        showError('Connection error. Please try again later.');
    }
}

// UI Helper Functions
function showStep(step) {
    // Hide all containers
    elements.usernameStep.style.display = 'none';
    elements.passwordStep.style.display = 'none';
    elements.forgotUsernameContainer.style.display = 'none';
    elements.forgotPasswordContainer.style.display = 'none';
    elements.successContainer.style.display = 'none';
    
    // Show requested step
    switch(step) {
        case 'username':
            elements.usernameStep.style.display = 'block';
            elements.usernameInput.focus();
            break;
        case 'password':
            elements.passwordStep.style.display = 'block';
            break;
        case 'forgot-username':
            elements.forgotUsernameContainer.style.display = 'block';
            break;
        case 'forgot-password':
            elements.forgotPasswordContainer.style.display = 'block';
            break;
        case 'success':
            elements.successContainer.style.display = 'block';
            break;
    }
    
    clearError();
}

function showError(message, type = 'error') {
    elements.errorContainer.textContent = message;
    elements.errorContainer.style.display = 'block';
    
    if (type === 'success') {
        elements.errorContainer.style.backgroundColor = '#d4edda';
        elements.errorContainer.style.borderColor = '#c3e6cb';
        elements.errorContainer.style.color = '#155724';
    } else {
        elements.errorContainer.style.backgroundColor = '#f8d7da';
        elements.errorContainer.style.borderColor = '#f5c6cb';
        elements.errorContainer.style.color = '#721c24';
    }
}

function clearError() {
    elements.errorContainer.style.display = 'none';
    elements.errorContainer.textContent = '';
}

function setSubmitting(isSubmitting) {
    state.isSubmitting = isSubmitting;
    elements.loginButton.disabled = isSubmitting;
    
    if (isSubmitting) {
        elements.loginText.style.display = 'none';
        elements.loginSpinner.style.display = 'inline';
    } else {
        elements.loginText.style.display = 'inline';
        elements.loginSpinner.style.display = 'none';
    }
}

function setupPasswordToggle() {
    elements.togglePassword.addEventListener('click', () => {
        const type = elements.passwordInput.type === 'password' ? 'text' : 'password';
        elements.passwordInput.type = type;
        elements.togglePassword.textContent = type === 'password' ? '👁️' : '👁️‍🗨️';
    });
}

function clearAuthTokens() {
    localStorage.removeItem(CONFIG.TOKEN_STORAGE_KEY);
    localStorage.removeItem(CONFIG.REFRESH_TOKEN_KEY);
}

// Export for testing (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        performLogin,
        validateToken,
        checkUsernameExists
    };
}