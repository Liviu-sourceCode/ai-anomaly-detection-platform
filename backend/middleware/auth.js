import { Router } from 'express';
import bcrypt from 'bcrypt';
import { body, validationResult } from 'express-validator';
import { db } from '../database.js';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import speakeasy from 'speakeasy';

const router = Router();

// Add constant-time comparison function
const timingSafeEqual = (a, b) => {
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
};

// Add rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window per IP
    message: { error: 'Too many login attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false
});

// Middleware to check if user is authenticated
export const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
};

// Login route with rate limiting and timing attack protection
router.post('/login', loginLimiter, [
    body('username').trim().notEmpty(),
    body('password').trim().notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const { username, password, token } = req.body;
        
        // Use parameterized query to prevent SQL injection
        const [users] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        
        if (users.length === 0) {
            // Use constant time comparison even for non-existent users
            await bcrypt.compare(password, '$2b$10$' + crypto.randomBytes(20).toString('hex'));
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if 2FA is enabled for this user
        if (user.twofa_enabled) {
            // If token is not provided, inform client that 2FA is required
            if (!token) {
                return res.status(200).json({ 
                    requireTwoFa: true,
                    message: '2FA verification required'
                });
            }

            // Verify the token
            const verified = speakeasy.totp.verify({
                secret: user.twofa_secret,
                encoding: 'base32',
                token: token,
                window: 1 // Allow 1 time step before/after for clock drift
            });

            if (!verified) {
                // Check if token is a backup code
                let backupCodes = [];
                try {
                    backupCodes = JSON.parse(user.backup_codes || '[]');
                } catch (e) {
                    console.error('Error parsing backup codes:', e);
                }

                // Allow login if token matches any backup code (do NOT remove/mark as used)
                if (!backupCodes.includes(token)) {
                    return res.status(401).json({ error: 'Invalid verification code' });
                }
                // Do not remove the used backup code
            }
        }

        // Create session
        req.session.userId = user.id;
        req.session.username = user.username;
        
        res.json({ success: true });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout route
router.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Add error handling to the login route
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Validate input
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Your existing authentication logic
        const user = await authenticateUser(username, password);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Set session
        req.session.user = {
            id: user.id,
            username: user.username
        };

        res.json({ success: true });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;