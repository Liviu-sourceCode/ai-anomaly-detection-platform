import { suricata } from './config.js';
import { db } from './database.js';
import geoip from 'geoip-lite';

class SuricataMonitor {
    constructor(sshClient) {
        this.sshClient = sshClient;
        this.activeStreams = new Set();
    }

    isPrivateIP(ip) {
        return /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/.test(ip);
    }

    getIPLocation(ip) {
        if (!ip || this.isPrivateIP(ip)) {
            return { 
                country: 'Local Network',
                city: 'Private IP',
                region: 'N/A',
                ll: [0, 0]
            };
        }

        const geo = geoip.lookup(ip);
        return geo || {
            country: 'Unknown',
            city: 'Unknown',
            region: 'Unknown',
            ll: [0, 0]
        };
    }

    parseFastLogLine(line) {
        if (!line || typeof line !== 'string') {
            return null;
        }

        try {
            const alert = {
                event_type: 'alert',
                timestamp: new Date().toISOString(),
                alert: {
                    signature: line.split('[**]')[1]?.trim() || 'Unknown Alert',
                    category: (line.match(/\[Classification: (.*?)\]/) || [])[1] || 'Unknown',
                    severity: parseInt((line.match(/\[Priority: (\d+)\]/) || [])[1]) || 0,
                    src_ip: (line.match(/(\d+\.\d+\.\d+\.\d+)/) || [])[0] || null,
                    dest_ip: (line.match(/(\d+\.\d+\.\d+\.\d+)(?!.*\d+\.\d+\.\d+\.\d+)/) || [])[0] || null
                },
                raw: line
            };
            // Add geolocation data
            if (alert.alert.src_ip) {
                alert.alert.src_location = this.getIPLocation(alert.alert.src_ip);
            }
            if (alert.alert.dest_ip) {
                alert.alert.dest_location = this.getIPLocation(alert.alert.dest_ip);
            }

            // Validate parsed data
            if (!alert.alert.signature || alert.alert.signature === 'Unknown Alert') {
                console.warn('Warning: Could not parse alert signature from line:', line);
            }
            return alert;
        } catch (error) {
            console.error('Error parsing log line:', error, '\nLine:', line);
            return null;
        }
    }

    async saveLogToDb(alert) {
        try {
            // Convert ISO string to MySQL DATETIME format (YYYY-MM-DD HH:MM:SS)
            const date = new Date(alert.timestamp);
            const mysqlTimestamp = date.toISOString().slice(0, 19).replace('T', ' ');

            await db.query(
                `INSERT INTO suricata_logs (timestamp, signature, category, severity, src_ip, dest_ip)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    mysqlTimestamp,
                    alert.alert.signature,
                    alert.alert.category,
                    alert.alert.severity,
                    alert.alert.src_ip,
                    alert.alert.dest_ip
                ]
            );
        } catch (error) {
            console.error('Failed to save Suricata log to DB:', error);
        }
    }

    async monitorFastLog(callback) {
        try {
            const stream = await this.sshClient.tailFile(suricata.logPath, async (line) => {
                try {
                    const alert = this.parseFastLogLine(line);
                    if (alert) {
                        await this.saveLogToDb(alert); // Save to DB before callback
                        callback(alert);
                    }
                } catch (error) {
                    console.error('Error processing log line:', error);
                }
            });
    
            this.activeStreams.add(stream);
    
            // Handle stream closure
            stream.on('close', () => {
                this.activeStreams.delete(stream);
                console.log('Suricata monitoring stream closed');
            });
    
            return stream;
        } catch (error) {
            console.error('Failed to start Suricata monitoring:', error);
            throw error;
        }
    }

    stopMonitoring() {
        this.activeStreams.forEach(stream => {
            try {
                stream.end();
            } catch (error) {
                console.error('Error stopping monitoring stream:', error);
            }
        });
        this.activeStreams.clear();
    }
}

export default SuricataMonitor;
