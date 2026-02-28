import { Client } from 'ssh2';
import { ssh } from './config.js';

class SSHClient {
    constructor() {
        this.connection = new Client();
        this.streams = new Set();
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectTimeout = 5000;
        this.isShuttingDown = false;
        this.channelOpenFailures = 0;
        this.maxChannelFailures = 3;
        this.lastChannelFailureTime = 0;
        this.channelCooldownPeriod = 30000; // 30 seconds cooldown
    }

    async connect() {
        return new Promise((resolve, reject) => {
            const connectWithRetry = () => {
                this.connection = new Client();

                this.connection.on('ready', () => {
                    console.log('SSH Connection established');
                    this.isConnected = true;
                    this.reconnectAttempts = 0;
                    resolve(this.connection);
                });

                this.connection.on('error', (err) => {
                    console.error('SSH connection error:', err);
                    this.handleConnectionError(err, reject);
                });

                this.connection.on('end', () => {
                    console.log('SSH connection ended');
                    this.isConnected = false;
                    if (!this.isShuttingDown) {
                        this.handleConnectionError(new Error('Connection ended'), reject);
                    }
                });

                try {
                    this.connection.connect(ssh);
                } catch (err) {
                    this.handleConnectionError(err, reject);
                }
            };

            connectWithRetry();
        });
    }

    handleConnectionError(error, reject) {
        this.isConnected = false;
        if (!this.isShuttingDown && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
            setTimeout(() => this.connect(), this.reconnectTimeout);
        } else {
            reject(new Error(`Failed to connect after ${this.maxReconnectAttempts} attempts: ${error.message}`));
        }
    }

    async execCommand(command) {
        return new Promise((resolve, reject) => {
            if (!this.isConnected) {
                return reject(new Error('SSH connection not established'));
            }

            // Check if we're in a cooldown period after multiple channel failures
            const now = Date.now();
            if (this.channelOpenFailures >= this.maxChannelFailures && 
                (now - this.lastChannelFailureTime) < this.channelCooldownPeriod) {
                return reject(new Error('Too many channel failures, waiting for cooldown period'));
            }

            this.connection.exec(command, (err, stream) => {
                if (err) {
                    // Check specifically for channel open failures
                    if (err.message && err.message.includes('Channel open failure')) {
                        this.channelOpenFailures++;
                        this.lastChannelFailureTime = now;
                        
                        console.warn(`Channel open failure detected (${this.channelOpenFailures}/${this.maxChannelFailures})`);
                        
                        // If we've hit too many failures, force a reconnection
                        if (this.channelOpenFailures >= this.maxChannelFailures) {
                            console.warn('Too many channel failures, forcing reconnection...');
                            this.isConnected = false;
                            this.reconnectAttempts = 0;
                            
                            // Attempt to reconnect
                            this.connect().then(() => {
                                console.log('Reconnected after channel failures');
                                this.channelOpenFailures = 0;
                            }).catch(reconnectErr => {
                                console.error('Failed to reconnect after channel failures:', reconnectErr);
                            });
                        }
                    }
                    return reject(err);
                }

                // Reset channel failure counter on success
                this.channelOpenFailures = 0;

                let output = '';
                let errorOutput = '';

                stream.on('data', (data) => {
                    output += data.toString();
                });

                stream.stderr.on('data', (data) => {
                    errorOutput += data.toString();
                });

                stream.on('close', (code) => {
                    this.streams.delete(stream);
                    if (code !== 0) {
                        reject(new Error(`Command failed with code ${code}: ${errorOutput}`));
                    } else {
                        resolve(output);
                    }
                });

                stream.on('error', (err) => {
                    this.streams.delete(stream);
                    reject(err);
                });

                this.streams.add(stream);
            });
        });
    }

    // Apply similar changes to tailFile method
    async tailFile(filePath, callback) {
        return new Promise((resolve, reject) => {
            if (!this.isConnected) {
                return reject(new Error('SSH connection not established'));
            }

            // Check if we're in a cooldown period after multiple channel failures
            const now = Date.now();
            if (this.channelOpenFailures >= this.maxChannelFailures && 
                (now - this.lastChannelFailureTime) < this.channelCooldownPeriod) {
                return reject(new Error('Too many channel failures, waiting for cooldown period'));
            }

            const command = `tail -f ${filePath}`;
            this.connection.exec(command, (err, stream) => {
                if (err) {
                    // Check specifically for channel open failures
                    if (err.message && err.message.includes('Channel open failure')) {
                        this.channelOpenFailures++;
                        this.lastChannelFailureTime = now;
                        
                        console.warn(`Channel open failure detected (${this.channelOpenFailures}/${this.maxChannelFailures})`);
                        
                        // If we've hit too many failures, force a reconnection
                        if (this.channelOpenFailures >= this.maxChannelFailures) {
                            console.warn('Too many channel failures, forcing reconnection...');
                            this.isConnected = false;
                            this.reconnectAttempts = 0;
                            
                            // Attempt to reconnect
                            this.connect().then(() => {
                                console.log('Reconnected after channel failures');
                                this.channelOpenFailures = 0;
                            }).catch(reconnectErr => {
                                console.error('Failed to reconnect after channel failures:', reconnectErr);
                            });
                        }
                    }
                    return reject(err);
                }

                // Reset channel failure counter on success
                this.channelOpenFailures = 0;

                let buffer = '';
                stream.on('data', (data) => {
                    buffer += data.toString();
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || '';

                    lines.forEach(line => {
                        if (line.trim()) {
                            callback(line);
                        }
                    });
                });

                stream.on('close', () => {
                    console.log('Tail stream closed');
                    this.streams.delete(stream);
                });

                stream.stderr.on('data', (data) => {
                    console.error('Tail error:', data.toString());
                });

                stream.on('error', (err) => {
                    console.error('Stream error:', err);
                    this.streams.delete(stream);
                });

                this.streams.add(stream);
                resolve(stream);
            });
        });
    }

    async close() {
        return new Promise((resolve) => {
            this.isShuttingDown = true;
            
            // Clean up all streams first
            this.streams.forEach(stream => {
                try {
                    stream.end();
                    stream.destroy();
                } catch (err) {
                    console.error('Error closing SSH stream:', err);
                }
            });
            
            this.streams.clear();
            
            if (this.connection) {
                if (this.isConnected) {
                    this.connection.end();
                    this.connection.on('end', () => {
                        this.isConnected = false;
                        console.log('SSH connection closed successfully');
                        resolve();
                    });
                    
                    // Force close after 3 seconds if normal close fails
                    setTimeout(() => {
                        if (this.isConnected) {
                            this.connection.destroy();
                            this.isConnected = false;
                            console.log('SSH connection force closed');
                            resolve();
                        }
                    }, 3000);
                } else {
                    resolve();
                }
            } else {
                resolve();
            }
        });
    }
}

export default SSHClient;