import fetch from 'node-fetch';

async function testRateLimit() {
    const url = 'https://localhost:3000/auth/login';
    const attempts = 7; // Try 7 attempts (more than the limit of 5)
    
    console.log('Starting rate limit test...\n');
    
    for (let i = 1; i <= attempts; i++) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: 'test',
                    password: 'wrongpassword'
                }),
                // Ignore SSL certificate validation for local testing
                rejectUnauthorized: false
            });
            
            const data = await response.json();
            console.log(`Attempt ${i}: Status ${response.status} - ${data.error || 'Login failed'}`);
            
        } catch (error) {
            console.error(`Attempt ${i} failed:`, error.message);
        }
        
        // Add a small delay between requests
        await new Promise(resolve => setTimeout(resolve, 500));
    }
}

testRateLimit();