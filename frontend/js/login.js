function sanitizeInput(input) {
    return input.replace(/[<>'"]/g, '');
}

function validateInput(input) {
    // Using the same pattern as the HTML form
    return input && input.length >= 3 && input.length <= 50 && /^[a-zA-Z0-9_-]*$/.test(input);
}

async function getCsrfToken() {
    const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
    const data = await res.json();
    return data.csrfToken;
}

document.getElementById('login-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = sanitizeInput(document.getElementById('username').value);
    const password = document.getElementById('password').value;
    const token = document.getElementById('token')?.value || '';
    const errorMessage = document.getElementById('errorMessage');
    
    if (!validateInput(username)) {
        errorMessage.textContent = 'Invalid username format';
        return;
    }
    
    try {
        const csrfToken = await getCsrfToken();
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken // This header name is required by csurf
            },
            credentials: 'same-origin', // <-- Add this line
            body: JSON.stringify({ username, password, token })
        });
        
        const data = await response.json();
        
        if (data.requireTwoFa) {
            // Show 2FA input field
            document.getElementById('password-group').style.display = 'none';
            document.getElementById('twofa-group').style.display = 'block';
            document.getElementById('login-form').dataset.twofa = 'true';
            errorMessage.textContent = '';
            return;
        }
        
        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }
        
        // Redirect to index.html on success instead of 2fa-setup.html
        window.location.href = '/2fa-setup.html';
    } catch (error) {
        errorMessage.textContent = error.message || 'An error occurred during login';
    }
});