import { apache } from './config.js';

class ApacheMonitor {
    constructor(sshClient) {
        this.sshClient = sshClient;
        this.lastStatus = null;
        this.statusCheckInterval = 15000; // 15 seconds
    }

    async checkStatus() {
        try {
            const [statusOutput, metricsOutput] = await Promise.all([
                this.sshClient.execCommand(apache.statusCommand),
                this.getServerMetrics()
            ]);
            
            const newStatus = statusOutput.includes('active (running)') ? 'running' : 'stopped';
            
            if (this.lastStatus && this.lastStatus !== newStatus) {
                console.log(`Apache status changed from ${this.lastStatus} to ${newStatus}`);
            }
            
            this.lastStatus = newStatus;
            return {
                status: newStatus,
                metrics: metricsOutput
            };
        } catch (error) {
            console.error('Error checking Apache status:', error);
            this.lastStatus = 'error';
            return {
                status: 'error',
                metrics: null
            };
        }
    }

    async getServerMetrics() {
        try {
            const [cpu, memory, uptime, disk, loadAvg] = await Promise.all([
                this.sshClient.execCommand("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"),
                this.sshClient.execCommand("free -m | grep Mem | awk '{print $3,$2}'"),
                this.sshClient.execCommand("uptime -p"),
                this.sshClient.execCommand("df -h / | tail -1 | awk '{print $5}'"),
                this.sshClient.execCommand("cat /proc/loadavg | awk '{print $1,$2,$3}'")
            ]);

            const [usedMem, totalMem] = memory.trim().split(' ').map(Number);
            const memoryUsage = ((usedMem / totalMem) * 100).toFixed(1);
            const [load1, load5, load15] = loadAvg.trim().split(' ').map(Number);

            return {
                cpu: parseFloat(cpu).toFixed(1),
                memory: memoryUsage,
                uptime: uptime.replace('up ', ''),
                disk: disk.replace('%', ''),
                loadAverage: {
                    '1min': load1.toFixed(2),
                    '5min': load5.toFixed(2),
                    '15min': load15.toFixed(2)
                }
            };
        } catch (error) {
            console.error('Error getting server metrics:', error);
            return null;
        }
    }

    startMonitoring(callback) {
        if (this._monitoringInterval) {
            clearInterval(this._monitoringInterval);
        }

        // Initial check
        this.checkStatus().then(result => callback(result));

        // Set up periodic checks
        this._monitoringInterval = setInterval(async () => {
            const result = await this.checkStatus();
            callback(result);
        }, this.statusCheckInterval);

        return this._monitoringInterval;
    }

    stopMonitoring() {
        if (this._monitoringInterval) {
            clearInterval(this._monitoringInterval);
            this._monitoringInterval = null;
        }
    }
}

export default ApacheMonitor;