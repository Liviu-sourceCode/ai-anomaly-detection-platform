import WebSocket from 'ws';
import { WebSocketServer as WSServer } from 'ws';
import crypto from 'crypto';

// Utility function for retrying operations
function retryOperation(operation, maxRetries, delay, retryCount = 0) {
    try {
        operation();
    } catch (error) {
        console.error('Error during operation:', error);
        if (retryCount < maxRetries) {
            setTimeout(() => {
                retryOperation(operation, maxRetries, delay, retryCount + 1);
            }, delay * (retryCount + 1));
        }
    }
}

export default class WebSocketServer {
    constructor(server) {
        this.wss = new WSServer({ 
            server,
            clientTracking: true,
            verifyClient: (info) => {
                const secure = info.req.headers['x-forwarded-proto'] === 'https' || info.req.socket.encrypted;
                if (!secure) {
                    console.warn('Rejected insecure WebSocket connection attempt');
                    return false;
                }
                return true;
            }
        });

        this.clients = new Set();
        this.isShuttingDown = false;
        this.maxRetries = 3;
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        this.wss.on('connection', (ws) => {
            if (this.isShuttingDown) {
                ws.terminate();
                return;
            }

            this.clients.add(ws);
            console.log('Client connected');

            // Send initial unencrypted message
            ws.send(JSON.stringify({ type: 'connected' }));

            ws.isAlive = true;
            ws.on('pong', () => {
                ws.isAlive = true;
            });

            ws.on('close', () => {
                this.clients.delete(ws);
                if (!this.isShuttingDown) {
                    console.log('Client disconnected');
                }
            });

            ws.on('error', (error) => {
                console.error('WebSocket client error:', error);
                this.clients.delete(ws);
            });
        });

        // Set up connection health checks
        this.heartbeatInterval = setInterval(() => {
            if (this.isShuttingDown) return;
            
            this.clients.forEach(ws => {
                if (ws.isAlive === false) {
                    console.log('Terminating inactive client');
                    this.clients.delete(ws);
                    return ws.terminate();
                }
                
                ws.isAlive = false;
                ws.ping();
            });
        }, 30000);

        this.wss.on('error', (error) => {
            console.error('WebSocket server error:', error);
        });
    }

    broadcast(message, retryCount = 0) {
        const jsonMessage = typeof message === 'string' ? message : JSON.stringify(message);
        const failedDeliveries = [];

        this.clients.forEach(client => {
            try {
                if (client.readyState === 1) {
                    client.send(jsonMessage);
                } else {
                    failedDeliveries.push(client);
                }
            } catch (error) {
                console.error('Error broadcasting to client:', error);
                failedDeliveries.push(client);
            }
        });

        if (failedDeliveries.length > 0 && retryCount < this.maxRetries) {
            retryOperation(() => this.broadcast(message, retryCount + 1), this.maxRetries, 1000);
        }
    }

    sendToClient(ws, message, retryCount = 0) {
        retryOperation(() => {
            if (ws.readyState === 1) {
                ws.send(JSON.stringify(message));
            }
        }, this.maxRetries, 1000, retryCount);
    }

    async close() {
        return new Promise((resolve) => {
            this.isShuttingDown = true;
            clearInterval(this.heartbeatInterval);
            
            const closePromises = [];
            this.clients.forEach(client => {
                closePromises.push(new Promise((clientResolve) => {
                    try {
                        client.once('close', () => clientResolve());
                        client.terminate();
                    } catch (err) {
                        console.error('Error terminating WebSocket client:', err);
                        clientResolve();
                    }
                }));
            });

            Promise.race([
                Promise.all(closePromises),
                new Promise(r => setTimeout(r, 3000))
            ]).then(() => {
                this.clients.clear();
                this.wss.close(() => {
                    console.log('WebSocket server closed');
                    resolve();
                });
            });
        });
    }

    getActiveConnections() {
        return this.clients.size;
    }
}