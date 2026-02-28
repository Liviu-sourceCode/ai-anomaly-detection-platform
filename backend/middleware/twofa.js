import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import { Router } from 'express';
import { db } from '../database.js';
import rateLimit from 'express-rate-limit';

const router = Router();

// Middleware to ensure user is authenticated
const ensureAuthenticated = (req, res, next) => {
    if (req.session && req.session.userId) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
};

// Rate limiter for 2FA sensitive actions
const twofaLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: { error: 'Too many 2FA attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false
});

// Generate a new secret for 2FA setup
router.get('/setup', ensureAuthenticated, async (req, res) => {
    try {
        // Generate a secret
        const secret = speakeasy.generateSecret({
            name: `Security Dashboard (${req.session.username})`
        });

        // Store the secret temporarily in the session
        req.session.temp_secret = secret.base32;

        // Generate QR code
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

        res.json({
            secret: secret.base32,
            qrCode: qrCodeUrl
        });
    } catch (error) {
        console.error('Error setting up 2FA:', error);
        res.status(500).json({ error: 'Failed to setup 2FA' });
    }
});

// Verify and enable 2FA
router.post('/verify', twofaLimiter, ensureAuthenticated, async (req, res) => {
    try {
        const { token } = req.body;
        const userId = req.session.userId;
        const secret = req.session.temp_secret;
        if (!secret) {
            return res.status(400).json({ error: 'No secret found. Please setup 2FA first.' });
        }
        // Verify the token
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token
        });
        if (!verified) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }
        // Generate backup codes (10 random 8-character codes)
        const backupCodes = Array.from({ length: 10 }, () => 
            Math.random().toString(36).substring(2, 10)
        );
        // Save the secret and enable 2FA
        await db.query(
            'UPDATE users SET twofa_secret = ?, twofa_enabled = TRUE, backup_codes = ? WHERE id = ?',
            [secret, JSON.stringify(backupCodes), userId]
        );
        // Remove the temporary secret from session
        delete req.session.temp_secret;
        res.json({ 
            success: true,
            message: '2FA has been enabled successfully',
            backupCodes: backupCodes
        });
    } catch (error) {
        console.error('Error verifying 2FA:', error);
        res.status(500).json({ error: 'Failed to verify 2FA' });
    }
});

// Disable 2FA
router.post('/disable', twofaLimiter, ensureAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        await db.query(
            'UPDATE users SET twofa_secret = NULL, twofa_enabled = FALSE, backup_codes = NULL WHERE id = ?',
            [userId]
        );

        res.json({ success: true, message: '2FA has been disabled' });
    } catch (error) {
        console.error('Error disabling 2FA:', error);
        res.status(500).json({ error: 'Failed to disable 2FA' });
    }
});

// Add this new route to check if 2FA is already enabled
router.get('/status', ensureAuthenticated, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        // Check if 2FA is already enabled for this user
        const [rows] = await db.query(
            'SELECT twofa_enabled FROM users WHERE id = ?',
            [userId]
        );
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            enabled: rows[0].twofa_enabled === 1
        });
    } catch (error) {
        console.error('Error checking 2FA status:', error);
        res.status(500).json({ error: 'Failed to check 2FA status' });
    }
});

export default router;