// Load environment variables first
import 'dotenv/config';

import express from 'express';
import session from 'express-session';
import csrf from 'csurf';
import SSHClient from './sshClient.js';
import SuricataMonitor from './suricataMonitor.js';
import ApacheMonitor from './apacheMonitor.js';
import WebSocketServer from './webSocket.js';
import { server, session as sessionConfig } from './config.js';
import authRouter, { isAuthenticated } from './middleware/auth.js';
import twofaRoutes from './middleware/twofa.js';
import https from 'https';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { configureSecurityMiddleware } from './middleware/security.js';
import cookieParser from 'cookie-parser';
import fetch from 'node-fetch';
import TelegramBot from 'node-telegram-bot-api';
import PDFDocument from 'pdfkit';
// import rateLimit from 'express-rate-limit'; // <-- Add express-rate-limit import

const __dirname = dirname(fileURLToPath(import.meta.url));

// Define public files at the top level
const publicFiles = [
    '/login.html',
    '/css/login.css',
    '/css/styles.css',
    '/js/login.js',
    '/favicon.ico',
    '/2fa-setup.html',
    '/js/2fa-setup.js'
];

class Application {
    constructor() {
        this.app = express();

        // Add security middleware first
        configureSecurityMiddleware(this.app);

        // Session middleware
        this.app.use(session(sessionConfig));
        this.app.use(express.json());

        
        this.app.use(cookieParser());
       

        // CSRF protection
        const csrfProtection = csrf({
            cookie: {
                httpOnly: true,
                secure: true,
                sameSite: 'strict'
            }
        });

        // CSRF token endpoint
        this.app.get('/api/csrf-token', csrfProtection, (req, res) => {
            res.json({ csrfToken: req.csrfToken() });
        });

        // Apply CSRF protection selectively
        this.app.use((req, res, next) => {
            if (!publicFiles.includes(req.path)) {
                csrfProtection(req, res, next);
            } else {
                next();
            }
        });

        // Configure express.static with proper MIME types
        const staticOptions = {
            setHeaders: (res, path) => {
                if (path.endsWith('.css')) {
                    res.set('Content-Type', 'text/css');
                } else if (path.endsWith('.js')) {
                    res.set('Content-Type', 'application/javascript');
                } else if (path.endsWith('.html')) {
                    res.set('Content-Type', 'text/html; charset=UTF-8');
                } else if (path.endsWith('.ico')) {
                    res.set('Content-Type', 'image/x-icon');
                }
            }
        };

        // Register auth routes BEFORE authentication check
        this.app.use('/auth', authRouter);
        this.app.use('/api/2fa', twofaRoutes);

        // Add Ollama proxy endpoints
        this.setupOllamaProxy();

        // Add ipwho.is proxy endpoint
        this.app.get('/api/ipwhois/:ip', async (req, res) => {
            const ip = req.params.ip;
            try {
                const response = await fetch(`https://ipwho.is/${ip}`);
                const data = await response.json();
                res.json(data);
            } catch (error) {
                res.status(502).json({ error: 'ipwho.is service unavailable' });
            }
        });

        // Add Ollama ping endpoint (optional)
        this.app.get('/api/ollama/ping', async (req, res) => {
            try {
                const response = await fetch('http://localhost:11434/');
                if (response.ok) {
                    res.json({ status: 'ok' });
                } else {
                    res.status(502).json({ status: 'unreachable' });
                }
            } catch (error) {
                res.status(502).json({ status: 'unreachable' });
            }
        });


        this.app.use((req, res, next) => {
    if (req.headers.origin === 'http://localhost:11434') {
        res.header('Access-Control-Allow-Origin', 'http://localhost:11434');
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type');
    }

    res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.header('X-Frame-Options', 'SAMEORIGIN');
    res.header('X-XSS-Protection', '1; mode=block');
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('Referrer-Policy', 'same-origin');
    res.header('Content-Security-Policy',
        "default-src 'self'; " +
        "connect-src 'self' https://ipwho.is wss://localhost:* https://localhost:* http://localhost:11434 " +
        "https://a.basemaps.cartocdn.com https://b.basemaps.cartocdn.com https://c.basemaps.cartocdn.com https://d.basemaps.cartocdn.com; " +
        "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com 'unsafe-inline'; " +
        "style-src 'self' https://cdn.jsdelivr.net https://unpkg.com 'unsafe-inline'; " +
        "img-src 'self' data: https: https://a.basemaps.cartocdn.com https://b.basemaps.cartocdn.com https://c.basemaps.cartocdn.com https://d.basemaps.cartocdn.com; " +
        "font-src 'self';"
    );

    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});
        // Serve public static files without authentication
        this.app.use((req, res, next) => {
            if (publicFiles.includes(req.path)) {
                return express.static(join(__dirname, server.staticDir), staticOptions)(req, res, next);
            }
            next();
        });

        // Authentication middleware
        this.app.use(isAuthenticated);

        // Protected static files
        this.app.use(express.static(join(__dirname, server.staticDir), staticOptions));

        // Request logging
        this.app.use((req, res, next) => {
            const originalEnd = res.end;
            res.end = function (...args) {
                console.log(`Request: ${req.method} ${req.path} - Status: ${res.statusCode}`);
                return originalEnd.apply(this, args);
            };
            next();
        });

        // CSRF Error Handler - Must be after body-parser and csurf middleware
        this.app.use((err, req, res, next) => {
            if (err.code === 'EBADCSRFTOKEN') {
                console.error('CSRF token error:', err.message);
                res.status(403).json({ error: 'Invalid CSRF token' });
            } else {
                next(err); // Pass other errors to the default error handler
            }
        });


        // Initialize components
        this.server = null;
        this.sshClient = new SSHClient();
        this.wss = null;
        this.suricataMonitor = null;
        this.apacheMonitor = null;
        this.isShuttingDown = false;

        // SSL configuration
        this.sslOptions = {
            key: readFileSync(join(__dirname, 'ssl/localhost+2-key.pem')),
            cert: readFileSync(join(__dirname, 'ssl/localhost+2.pem')),
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            ciphers: [
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384'
            ].join(':'),
            honorCipherOrder: true,
            preferServerCipherOrder: true
        };

        // Initialize Telegram bot if credentials are present
        this.telegramBot = null;
        const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
        if (TELEGRAM_BOT_TOKEN) {
            this.telegramBot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false });
        }

        // Setup PDF report endpoint
        this.setupPdfReportEndpoint();

        // Setup export JSON endpoint
        this.setupExportJsonEndpoint();

        // Setup export CSV endpoint
        this.setupExportCsvEndpoint();
    }

    async start() {
        try {
            // HTTPS server
            this.server = https.createServer(this.sslOptions, this.app);

            // Start server
            this.server.listen(server.port, () => {
                console.log(`Secure server running on port ${server.port}`);
            });

            // Initialize WebSocket server
            this.wss = new WebSocketServer(this.server);

            // Connect to SSH
            await this.sshClient.connect();
            console.log('[SSH] SSH connection established');

            // Initialize monitors
            this.suricataMonitor = new SuricataMonitor(this.sshClient);
            this.apacheMonitor = new ApacheMonitor(this.sshClient);
            console.log('[SuricataMonitor] Initialized');

            // Setup WebSocket connections
            this.setupWebSocketHandlers();

            // Graceful shutdown handlers
            process.on('SIGINT', () => this.shutdown());
            process.on('SIGTERM', () => this.shutdown());

            // Handle uncaught exceptions
            process.on('uncaughtException', (error) => {
                console.error('Uncaught Exception:', error);
                this.shutdown(1);
            });

            // Handle unhandled promise rejections
            process.on('unhandledRejection', (reason, promise) => {
                console.error('Unhandled Promise Rejection:', reason);
                this.shutdown(1);
            });
        } catch (error) {
            console.error('Failed to start application:', error);
            process.exit(1);
        }
    }

    async sendTelegramAlert(alert) {
        // Minimal logging - just a single line indicating we're sending an alert
        console.log('[Telegram] Sending alert for signature:', alert.signature || 'Unknown');
        
        const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
        const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
        
        if (!this.telegramBot) {
            if (TELEGRAM_BOT_TOKEN) {
                this.telegramBot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false });
            } else {
                console.error('[Telegram] Cannot initialize bot - token is missing');
                return false;
            }
        }
        
        if (!TELEGRAM_CHAT_ID) {
            console.warn('[Telegram] Chat ID is missing.');
            return false;
        }
        
        const truncate = (str, max = 300) => str && str.length > max ? str.slice(0, max) + '…' : str;
        const signature = truncate(alert.signature || 'Unknown');
        const messageText = truncate(alert.message || '');
        
        // Add more alert details if available
        let message = `🚨 *${this.escapeMarkdown('Level 1 Alert!')}*\n` +
            `*Signature:* ${this.escapeMarkdown(signature)}\n` +
            `*Severity:* ${this.escapeMarkdown(String(alert.severity))}\n`;
            
        if (alert.src_ip) {
            message += `*Source IP:* ${this.escapeMarkdown(alert.src_ip)}\n`;
        }
        
        if (alert.dest_ip) {
            message += `*Destination IP:* ${this.escapeMarkdown(alert.dest_ip)}\n`;
        }
        
        
        try {
            // No need to test the bot every time
            const result = await this.telegramBot.sendMessage(TELEGRAM_CHAT_ID, message, { parse_mode: 'MarkdownV2' });
            return true;
        } catch (error) {
            console.error('[Telegram] Failed to send alert:', error.message);
            return false;
        }
    }

    // Keep only this implementation of setupWebSocketHandlers
    setupWebSocketHandlers() {
        this.wss.wss.on('connection', async (ws) => {
            // Send initial Apache status with metrics
            const apacheStatus = await this.apacheMonitor.checkStatus();
            this.wss.sendToClient(ws, {
                type: 'apache_status',
                ...apacheStatus
            });

            // Start monitoring Suricata logs
            const stream = await this.suricataMonitor.monitorFastLog(async (alert) => {
                // Reduced logging - just log that we received an alert
                console.log('[Suricata] Alert received for:', alert.alert?.signature || 'Unknown signature');
                
                this.wss.sendToClient(ws, {
                    type: 'suricata_event',
                    data: alert
                });
                
                // Fix: Access severity from the correct location in the object structure
                const severity = alert.alert && typeof alert.alert.severity === 'number' 
                    ? alert.alert.severity 
                    : parseInt(alert.alert?.severity);
                
                if (severity === 1) {
                    // Minimal logging for Telegram alerts
                    await this.sendTelegramAlert(alert.alert);
                }
            });

            // Rest of the method remains unchanged
            const statusInterval = setInterval(async () => {
                const status = await this.apacheMonitor.checkStatus();
                this.wss.sendToClient(ws, {
                    type: 'apache_status',
                    ...status
                });
            }, 30000);

            // Clean up on disconnect
            ws.on('close', () => {
                clearInterval(statusInterval);
                if (stream) stream.end();
            });
        });
    }

    // Escape MarkdownV2 special characters (Telegram docs)
    escapeMarkdown(text) {
        if (!text) return '';
        // Escape all special characters for Telegram's MarkdownV2 format
        return text.toString().replace(/[_*\[\]()~`>#+=|{}.!-]/g, '\\$&');
    }

    async shutdown(exitCode = 0) {
        if (this.isShuttingDown) {
            return;
        }

        this.isShuttingDown = true;
        console.log('\n🔄 Starting graceful shutdown...');

        try {
            // Close all WebSocket connections
            if (this.wss) {
                console.log('📡 Closing WebSocket connections...');
                this.wss.isShuttingDown = true;
                await this.wss.close();
                console.log('✅ WebSocket connections closed');
            }

            // Close SSH connection
            if (this.sshClient && this.sshClient.isConnected) {
                console.log('🔑 Closing SSH connection...');
                this.sshClient.isShuttingDown = true;
                await this.sshClient.close(); // <-- corrected from disconnect() to close()
                console.log('✅ SSH connection closed');
            }

            // Close HTTPS server
            if (this.server) {
                console.log('🌐 Closing server...');
                // Remove non-standard socket handling here

                await new Promise((resolve) => {
                    this.server.close(() => {
                        console.log('✅ Server closed successfully');
                        console.log('👋 Goodbye!');
                        resolve();
                    });
                });

                // Only exit after server is fully closed
                process.exit(exitCode);
            } else {
                process.exit(exitCode);
            }
        } catch (error) {
            console.error('❌ Error during shutdown:', error);
            process.exit(1);
        }
    }

    setupOllamaProxy() {
    // Model list endpoint
    this.app.get('/api/ollama/models', async (req, res) => {
        try {
            const ollamaResponse = await fetch('http://localhost:11434/api/tags');
            const data = await ollamaResponse.json();
            res.json(data);
        } catch (error) {
            res.status(502).json({ error: 'Ollama service unavailable' });
        }
    });

    // Chat endpoint
    this.app.post('/api/ollama/chat', async (req, res) => {
    try {
        // Add system prompt if not present
        const systemPrompt = {
            role: "system",
            content: "You are a cybersecurity analyst. Answer all questions and analyze logs, events, and threats as a security expert. Provide actionable insights, threat intelligence, and recommendations for improving security posture. If you are given logs or alerts, explain their significance and possible actions. Alerts will have a severity from 1 (high) to 3 (low). Always provide a concise summary of your analysis and recommendations."
        };

        // Insert system prompt at the start of the messages array if not already present
        let messages = req.body.messages || [];
        if (!messages.find(m => m.role === "system")) {
            messages = [systemPrompt, ...messages];
        }

        const ollamaResponse = await fetch('http://localhost:11434/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...req.body, messages })
        });
        const data = await ollamaResponse.json();
        res.json(data);
    } catch (error) {
        res.status(502).json({ error: 'Ollama service unavailable' });
    }
});
}

    setupPdfReportEndpoint() {
    this.app.post('/api/reports/pdf', async (req, res) => {
        try {
            // Styles configuration
            const styles = {
                colors: {
                    primary: '#4f46e5',
                    background: '#0f172a',
                    surface: '#1e293b',
                    accent: '#334155',
                    text: {
                        primary: '#f8fafc',
                        secondary: '#cbd5e1',
                        muted: '#94a3b8'
                    },
                    severity: {
                        1: '#dc2626', // High - Red
                        2: '#ea580c', // Medium - Orange  
                        3: '#16a34a'  // Low - Green
                    },
                    success: '#10b981',
                    warning: '#f59e0b'
                },
                fonts: {
                    bold: 'Helvetica-Bold',
                    regular: 'Helvetica',
                    italic: 'Helvetica-Oblique',
                    mono: 'Courier'
                },
                layout: {
                    margin: 50,
                    cardSpacing: 16,
                    pageBottomMargin: 80,
                    headerHeight: 90,
                    borderRadius: 12
                }
            };

            // Request validation
            const logs = req.body && Array.isArray(req.body.logs) ? req.body.logs : [];
            if (!logs.length) {
                return res.status(400).json({ error: 'No logs provided for PDF export.' });
            }
            if (logs.length > 500) {
                return res.status(400).json({ error: 'Too many logs (max 500 allowed).' });
            }

            // Deduplicate alerts by signature for AI analysis
            const uniqueLogsBySignature = [];
            const seenSignatures = new Set();
            for (const log of logs) {
                // Use log.signature or log.alert?.signature depending on your data structure
                const signature = log.signature || log.alert?.signature;
                if (signature && !seenSignatures.has(signature)) {
                    uniqueLogsBySignature.push(log);
                    seenSignatures.add(signature);
                }
            }

            // Set response headers
            const timestamp = new Date().toISOString().split('T')[0];
            const filename = `security_report_${timestamp}.pdf`;
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

            // Generate AI summary - wait for full response
            let aiSummary = '';
            console.log('Requesting AI analysis...');
            try {
                const ollamaResponse = await fetch('http://localhost:11434/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        model: 'Cyber-Agent',
                        messages: [
                            {
                                role: 'system',
                                content: `Analyze these ${uniqueLogsBySignature.length} unique security alerts (deduplicated by signature). The alerts are from Suricata Intrusion Detection System.\nProvide:\n1. Brief executive summary\n2. Key threat patterns \n3. Top 3-4 recommendations\nKeep response under 600 words and actionable.`
                            },
                            {
                                role: 'user',
                                content: uniqueLogsBySignature.map(log => (
                                    `Signature: ${log.signature || log.alert?.signature}\nCategory: ${log.category || log.alert?.category}\nSeverity: ${log.severity || log.alert?.severity}\nSource IP: ${log.sourceIp || log.alert?.src_ip}\nDestination IP: ${log.destinationIp || log.alert?.dest_ip}`
                                )).join('\n\n')
                            }
                        ],
                        stream: false
                    })
                });
                
                if (ollamaResponse.ok) {
                    const data = await ollamaResponse.json();
                    aiSummary = data.message?.content || 'AI analysis completed successfully.';
                    console.log('AI analysis completed');
                } else {
                    console.warn('AI service returned error:', ollamaResponse.status);
                    aiSummary = 'AI analysis unavailable - generating report with manual analysis.';
                }
            } catch (error) {
                console.warn('AI service error:', error.message);
                aiSummary = 'AI analysis unavailable - generating report with manual analysis.';
            }

            // Initialize PDF
            const doc = new PDFDocument({ 
                margin: 0, 
                size: 'A4',
                bufferPages: true,
                info: {
                    Title: 'Security Alerts Report',
                    Author: 'Apex Shield Team',
                    Subject: `Security Report - ${logs.length} Alerts`,
                    Keywords: 'security, alerts, cybersecurity, network'
                }
            });
            
            doc.pipe(res);

            let currentY = 0;
            let pageCount = 1;

            // Helper Functions
            const renderBackground = (isFirstPage = false) => {
                // Dark gradient background
                doc.rect(0, 0, doc.page.width, doc.page.height)
                   .fillColor(styles.colors.background)
                   .fill();

                if (isFirstPage) {
                    // Header gradient bar
                    const gradient = doc.linearGradient(0, 0, doc.page.width, 0);
                    gradient.stop(0, styles.colors.primary)
                           .stop(1, '#6366f1');
                    
                    doc.rect(0, 0, doc.page.width, 90)
                       .fill(gradient);

                    // Subtle grid pattern
                    doc.save();
                    doc.opacity(0.03);
                    doc.strokeColor(styles.colors.text.primary);
                    doc.lineWidth(0.5);
                    
                    for (let x = 0; x < doc.page.width; x += 40) {
                        doc.moveTo(x, 0).lineTo(x, doc.page.height).stroke();
                    }
                    for (let y = 0; y < doc.page.height; y += 40) {
                        doc.moveTo(0, y).lineTo(doc.page.width, y).stroke();
                    }
                    doc.restore();

                    return styles.layout.headerHeight;
                } else {
                    // Page indicator
                    doc.font(styles.fonts.regular)
                       .fontSize(10)
                       .fillColor(styles.colors.text.muted)
                       .text(`Page ${pageCount}`, doc.page.width - 80, 25, { 
                           width: 60, align: 'right' 
                       });
                    return 60;
                }
            };

            const renderHeader = (y) => {
                // Move logo up to y=0 for better vertical centering
                doc.image('Apex.png', 0, -5, { width: 110, height: 105 });

                // Main title, moved up to y=20
                doc.font(styles.fonts.bold)
                   .fontSize(28)
                   .fillColor(styles.colors.text.primary)
                   .text('Security Alerts Report', 0, 20, { 
                       align: 'center', 
                       width: doc.page.width 
                   });

                // Subtitle with stats, moved up to y=45
                const criticalCount = logs.filter(log => parseInt(log.severity) === 1).length;
                const highCount = logs.filter(log => parseInt(log.severity) === 2).length;
                const mediumCount = logs.filter(log => parseInt(log.severity) === 3).length;

                doc.font(styles.fonts.regular)
                   .fontSize(12)
                   .fillColor('#f1f5f9')
                   .text(`${logs.length} Total Alerts • ${criticalCount} High • ${highCount} Medium • ${mediumCount} Low`, 0, 50, {
                       align: 'center',
                       width: doc.page.width
                   });

                // Generation time (higher contrast, moved up)
                doc.fontSize(10)
                   .fillColor('#e0e7ef')
                   .text(`Generated: ${new Date().toLocaleString('en-US', {
                       weekday: 'long',
                       year: 'numeric',
                       month: 'long',
                       day: 'numeric',
                       hour: '2-digit',
                       minute: '2-digit'
                   })}`, 0, 75, { align: 'center', width: doc.page.width });

                return y + 20;
            };

            const renderSummaryCard = (y, title, content, bgColor = styles.colors.surface) => {
                // Reduce font size and add more padding to prevent overflow
                const contentFontSize = 10;
                const contentWidth = doc.page.width - (styles.layout.margin * 2) - 40;
                const contentHeight = doc.heightOfString(content, {
                    width: contentWidth,
                    font: styles.fonts.regular,
                    size: contentFontSize,
                    lineGap: 3
                });
                const cardHeight = Math.max(120, contentHeight + 80); // more padding

                // Card shadow effect
                doc.rect(styles.layout.margin + 2, y + 2, 
                        doc.page.width - (styles.layout.margin * 2), cardHeight)
                   .fillColor('#000000')
                   .opacity(0.1)
                   .fill();

                // Main card
                doc.opacity(1)
                   .roundedRect(styles.layout.margin, y, 
                               doc.page.width - (styles.layout.margin * 2), cardHeight, 
                               styles.layout.borderRadius)
                   .fillColor(bgColor)
                   .fill();

                // Accent border
                doc.rect(styles.layout.margin, y, 4, cardHeight)
                   .fillColor(styles.colors.primary)
                   .fill();

                // Title
                doc.font(styles.fonts.bold)
                   .fontSize(16)
                   .fillColor(styles.colors.primary)
                   .text(title, styles.layout.margin + 20, y + 15);

                // Content (smaller font, more width, more bottom padding)
                doc.font(styles.fonts.regular)
                   .fontSize(contentFontSize)
                   .fillColor(styles.colors.text.secondary)
                   .text(content, styles.layout.margin + 20, y + 45, {
                       width: contentWidth,
                       lineGap: 3,
                       align: 'justify',
                       ellipsis: true
                   });

                return y + cardHeight + styles.layout.cardSpacing;
            };

            const renderAlertCard = (log, index, y) => {
                const severity = parseInt(log.severity) || 3;
                const severityColor = styles.colors.severity[severity] || styles.colors.severity[3];
                const cardWidth = doc.page.width - (styles.layout.margin * 2);
                
                // Calculate dynamic height
                const signatureHeight = doc.heightOfString(log.signature || 'Unknown Alert', { 
                    width: cardWidth - 40 
                });
                const cardHeight = Math.max(110, signatureHeight + 85);

                // Card shadow
                doc.rect(styles.layout.margin + 1, y + 1, cardWidth, cardHeight)
                   .fillColor('#000000')
                   .opacity(0.08)
                   .fill();

                // Main card
                doc.opacity(1)
                   .roundedRect(styles.layout.margin, y, cardWidth, cardHeight, 10)
                   .fillColor(styles.colors.surface)
                   .fill();

                // Severity bar
                doc.rect(styles.layout.margin, y, 5, cardHeight)
                   .fillColor(severityColor)
                   .fill();

                // Alert number badge
                const alertNumber = (index + 1).toString();
                doc.circle(styles.layout.margin + 25, y + 20, 12)
                   .fillColor(severityColor)
                   .fill();
                // Adjust font size for 2-digit numbers
                doc.font(styles.fonts.bold)
                   .fontSize(alertNumber.length > 1 ? 8 : 10)
                   .fillColor('#ffffff')
                   .text(alertNumber, styles.layout.margin + 20, y + 16, {
                       width: 10, align: 'center'
                   });

                // Severity badge
                const severityLabels = { 1: 'HIGH', 2: 'MEDIUM', 3: 'LOW' };
                const severityLabel = severityLabels[severity] || 'LOW';
                
                doc.roundedRect(styles.layout.margin + 45, y + 12, 60, 16, 8)
                   .fillColor(severityColor)
                   .fill();
                
                doc.font(styles.fonts.bold)
                   .fontSize(8)
                   .fillColor('#ffffff')
                   .text(severityLabel, styles.layout.margin + 48, y + 16, { 
                       width: 54, align: 'center' 
                   });

                // Alert signature/title
                doc.font(styles.fonts.bold)
                   .fontSize(12)
                   .fillColor(styles.colors.text.primary)
                   .text(log.signature || 'Unknown Alert', styles.layout.margin + 120, y + 15, {
                       width: cardWidth - 140
                   });

                // Details grid
                const detailsY = Math.max(y + 40, doc.y + 8);
                const fields = [
                    { label: 'Category', value: log.category || 'N/A' },
                    { label: 'Source IP', value: log.sourceIp || 'N/A', mono: true },
                    { label: 'Source Location', value: log.sourceLocation || 'Unknown' },
                    { label: 'Destination IP', value: log.destinationIp || 'N/A', mono: true },
                    { label: 'Destination Location', value: log.destinationLocation || 'Unknown' },
                    { label: 'Timestamp', value: formatTimestamp(log.timestamp) }
                ];

                const columnWidth = (cardWidth - 60) / 2;
                let fieldY = detailsY;
                let column = 0;

                fields.forEach((field, idx) => {
                    if (idx > 0 && idx % 2 === 0) {
                        fieldY += 18;
                        column = 0;
                    }

                    const fieldX = styles.layout.margin + 20 + (column * (columnWidth + 10));

                    // Field background
                    doc.rect(fieldX - 2, fieldY - 2, columnWidth + 4, 16)
                       .fillColor(styles.colors.accent)
                       .opacity(0.3)
                       .fill();

                    // Label
                    doc.opacity(1)
                       .font(styles.fonts.regular)
                       .fontSize(9)
                       .fillColor(styles.colors.text.muted)
                       .text(`${field.label}:`, fieldX, fieldY);

                    // Value
                    const valueX = fieldX + 90;
                    doc.font(field.mono ? styles.fonts.mono : styles.fonts.regular)
                       .fontSize(9)
                       .fillColor(styles.colors.text.primary)
                       .text(field.value, valueX, fieldY, {
                           width: columnWidth - 90,
                           ellipsis: true
                       });

                    column++;
                });

                return y + cardHeight;
            };

            const formatTimestamp = (timestamp) => {
                if (!timestamp) return 'N/A';
                // If the timestamp is already a human-readable string (e.g., contains ',' or is not ISO), use as-is
                if (typeof timestamp === 'string' && (timestamp.includes(',') || timestamp.match(/\d{1,2}\/\d{1,2}\/\d{4}/))) {
                    return timestamp;
                }
                try {
                    return new Date(timestamp).toLocaleString('en-US', {
                        month: 'short',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                    });
                } catch {
                    return timestamp.toString().substring(0, 19);
                }
            };

            const checkPageBreak = (currentY, requiredHeight) => {
                if (currentY + requiredHeight + styles.layout.pageBottomMargin >= doc.page.height) {
                    doc.addPage();
                    pageCount++;
                    return renderBackground(false);
                }
                return currentY;
            };

            const addFooter = (pageNum, totalPages) => {
                // Footer line
                doc.lineWidth(1)
                   .strokeColor(styles.colors.primary)
                   .opacity(0.6)
                   .moveTo(styles.layout.margin, doc.page.height - 50)
                   .lineTo(doc.page.width - styles.layout.margin, doc.page.height - 50)
                   .stroke();

                // Footer content
                doc.opacity(1)
                   .font(styles.fonts.regular)
                   .fontSize(9)
                   .fillColor(styles.colors.text.muted)
                   .text('Apex Shield Team - Confidential Report', 
                          styles.layout.margin, doc.page.height - 35)
                   .text(`${pageNum}/${totalPages}`, 
                          doc.page.width - 80, doc.page.height - 35, 
                          { width: 60, align: 'right' });
            };

            // Generate PDF Content
            currentY = renderBackground(true);
            currentY = renderHeader(currentY);

            // AI Summary section
            if (aiSummary) {
                currentY = checkPageBreak(currentY, 120);
                currentY = renderSummaryCard(currentY, 'AI Security Analysis', aiSummary);
            }

            // Force new page for Security Alerts section
            doc.addPage();
            pageCount++;
            currentY = renderBackground(false);

            // Section divider
            currentY = checkPageBreak(currentY, 40);
            currentY += 10; // add spacing before divider
            doc.lineWidth(2)
               .strokeColor(styles.colors.primary)
               .moveTo(styles.layout.margin, currentY)
               .lineTo(doc.page.width - styles.layout.margin, currentY)
               .stroke();
            currentY += 20; // add spacing after divider

            // Alerts header
            doc.font(styles.fonts.bold)
               .fontSize(18)
               .fillColor(styles.colors.primary)
               .text(`Security Alerts (${logs.length} total)`, styles.layout.margin, currentY);
            currentY += 35; // more spacing after header

            // Render alerts
            logs.forEach((log, index) => {
                const estimatedHeight = 120;
                currentY = checkPageBreak(currentY, estimatedHeight);
                currentY = renderAlertCard(log, index, currentY);
                currentY += styles.layout.cardSpacing;
            });

            // Add footers to all pages
            const range = doc.bufferedPageRange();
            for (let i = range.start; i < range.start + range.count; i++) {
                doc.switchToPage(i);
                addFooter(i + 1, pageCount);
            }

            doc.end();

        } catch (error) {
            console.error('PDF generation error:', error);
            if (!res.headersSent) {
                res.status(500).json({ 
                    error: 'Failed to generate PDF report',
                    details: error.message 
                });
            }
        }
    });
}

    setupExportJsonEndpoint() {
    this.app.get('/api/alerts/export-json', async (req, res) => {
        try {
            const command = `tail -n 5000 /var/log/suricata/eve.json | grep '"event_type":"alert"'`;
            const stdout = await this.sshClient.execCommand(command);

            if (!stdout || !stdout.trim()) {
                console.error('[Export JSON] No stdout from SSH command');
                return res.status(500).json({ error: 'No output from SSH command.' });
            }

            const lines = stdout
                .split('\n')
                .map(line => line.trim())
                .filter(line => line.startsWith('{') && line.endsWith('}'));

            const alerts = [];

            for (const line of lines) {
                try {
                    const json = JSON.parse(line);
                    if (json.event_type === 'alert') {
                        alerts.push(json);
                    }
                } catch (parseErr) {
                    
                }
            }

            if (alerts.length === 0) {
                return res.status(204).json({ message: 'No alerts found in eve.json.' });
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `suricata_alerts_${timestamp}.json`;

            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.send(JSON.stringify(alerts, null, 2));
        } catch (error) {
            console.error('[Export JSON] Unexpected error:', error);
            res.status(500).json({ error: 'Internal server error.' });
        }
    });
}


    setupExportCsvEndpoint() {
        this.app.get('/api/alerts/export-csv', async (req, res) => {
            try {
                const command = `tail -n 5000 /var/log/suricata/eve.json | grep '"event_type":"alert"'`;
                const stdout = await this.sshClient.execCommand(command);

                if (!stdout || !stdout.trim()) {
                    console.error('[Export CSV] No stdout from SSH command');
                    return res.status(500).json({ error: 'No output from SSH command.' });
                }

                const lines = stdout
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line.startsWith('{') && line.endsWith('}'));

                const alerts = [];

                for (const line of lines) {
                    try {
                        const json = JSON.parse(line);
                        if (json.event_type === 'alert') {
                            alerts.push(json);
                        }
                    } catch (parseErr) {
                        // Line was not valid JSON — skip silently or log
                    }
                }

                if (alerts.length === 0) {
                    return res.status(204).json({ message: 'No alerts found in eve.json.' });
                }

                // Define CSV fields
                const fields = [
                    'timestamp',
                    'src_ip',
                    'src_port',
                    'dest_ip',
                    'dest_port',
                    'proto', // Added protocol field
                    'alert.signature',
                    'alert.category',
                    'alert.severity',
                    'http.hostname',
                    'http.url',
                    'http.status'
                ];

                // Helper to get nested value
                const get = (obj, path) => path.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : ''), obj);

                // Build CSV header
                const csvRows = [fields.join(',')];

                // Build CSV rows
                for (const alert of alerts) {
                    const row = fields.map(f => {
                        let val = get(alert, f);
                        if (typeof val === 'string') {
                            // Escape quotes and commas
                            val = '"' + val.replace(/"/g, '""') + '"';
                        }
                        return val;
                    });
                    csvRows.push(row.join(','));
                }

                const csvContent = csvRows.join('\r\n');
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const filename = `suricata_alerts_${timestamp}.csv`;

                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
                res.send(csvContent);
            } catch (error) {
                console.error('[Export CSV] Unexpected error:', error);
                res.status(500).json({ error: 'Internal server error.' });
            }
        });
    }


    // Helper method to get severity text
    getSeverityText(severity) {
        switch (parseInt(severity)) {
            case 1: return 'High';
            case 2: return 'Medium';
            case 3: return 'Low';
            default: return 'Unknown';
        }
    }
}

// Start the application
new Application().start().catch(error => {
    console.error('Application error:', error);
    process.exit(1);
});