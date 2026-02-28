document.addEventListener('DOMContentLoaded', async function() {
    try {
        // First check if 2FA is already enabled for the user
        const statusResponse = await fetch('/api/2fa/status', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const statusData = await statusResponse.json();
        
        // If 2FA is already enabled, show a different view
        if (statusData.enabled) {
            document.getElementById('setup-container').style.display = 'none';
            document.getElementById('already-setup-container').style.display = 'block';
            return;
        }
        
        // Fetch the QR code and secret
        const response = await fetch('/api/2fa/setup', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch 2FA setup data');
        }
        
        const data = await response.json();
        
        // Display QR code and secret
        document.getElementById('qrcode').src = data.qrCode;
        document.getElementById('secret-key').textContent = data.secret;
        
        // Handle verification form submission
        document.getElementById('verify-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const token = document.getElementById('token').value;
            const errorMessage = document.getElementById('errorMessage');
                // Obține CSRF token
                async function getCsrfToken() {
                    const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
                    const data = await res.json();
                    return data.csrfToken;
                }
                const csrfToken = await getCsrfToken();
            
            try {
                    const verifyResponse = await fetch('/api/2fa/verify', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'CSRF-Token': csrfToken // Header necesar pentru csrf
                        },
                        body: JSON.stringify({ token })
                    });
                
                const verifyData = await verifyResponse.json();
                
                if (!verifyResponse.ok) {
                    throw new Error(verifyData.error || 'Verification failed');
                }
                
                // Show success and backup codes
                document.getElementById('setup-container').style.display = 'none';
                document.getElementById('success-container').style.display = 'block';
                document.getElementById('backup-codes').textContent = verifyData.backupCodes.join('\n');
                
                // Scroll to top to ensure the success message is visible
                window.scrollTo(0, 0);
                
                // Add event listener to the "Continue to Dashboard" button
                document.querySelector('#success-container .continue-button').addEventListener('click', function(e) {
                    e.preventDefault();
                    window.location.href = '/index.html';
                });
                
            } catch (error) {
                errorMessage.textContent = error.message;
            }
        });
        
    } catch (error) {
        console.error('2FA setup error:', error);
        document.getElementById('errorMessage').textContent = 'Failed to load 2FA setup: ' + error.message;
    }
});