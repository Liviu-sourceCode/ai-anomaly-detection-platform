// Security Dashboard Application

class SecurityDashboard {
    constructor() {
        this.securityChart = null;
        this.currentCount = 0;
        this.alertCount = { high: 0, medium: 0, low: 0 };
        this.attackStats = new Map();
        this.severityStats = new Map();
        this.sourceIPStats = new Map();
        this.logPaused = false;
        this.pendingLogs = [];
        this.ws = null;
        this.geoChart = null;
        this.severityChart = null;
        this.categoryChart = null;

        this.metricCharts = {
            cpu: null,
            memory: null,
            disk: null,
            load: null,
            uptime: null
        };

        this.severityCounts = {
            high: 0,
            medium: 0,
            low: 0
        };


        this.metricHistory = {
            cpu: Array(20).fill(0),
            memory: Array(20).fill(0),
            disk: Array(20).fill(0),
            load: {
                '1min': Array(20).fill(0),
                '5min': Array(20).fill(0),
                '15min': Array(20).fill(0)
            }
        };

        this.logViewMode = 'json';
        this.logs = []; // Store logs for table rendering
        this.init();
    }

    async init() {
        try {
            // Get CSRF token
            const response = await fetch('/api/csrf-token', { credentials: 'same-origin' });
        const { csrfToken } = await response.json();
        this.csrfToken = csrfToken;

            // Initialize existing components
            this.initializeCsrf()
            this.initializeChart();
            this.initializeCharts();
            this.initializeMetricCharts();
            this.connectWebSocket();
            this.setupChatUI();
            this.setupChatWindowControls();
            this.setupEventListeners();
            this.setupClearButton();
            this.setupLogViewToggle();
        } catch (error) {
            console.error('Initialization error:', error);
        }
    }

    async makeRequest(url, options = {}) {
        // Get CSRF token from meta tag
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        
        // Merge default headers with provided options
        const defaultOptions = {
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            }
        };

        // Merge options, preserving any custom headers
        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...(options.headers || {})
            }
        };

        return fetch(url, mergedOptions);
    }

    async initializeCsrf() {
        try {
            const response = await fetch('/api/csrf-token');
            const data = await response.json();
            document.querySelector('meta[name="csrf-token"]').setAttribute('content', data.csrfToken);
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
        }
    }

    initializeMetricCharts() {
        // Predefine chart dimensions to prevent layout shifts
        const chartCanvasConfig = [
            { id: 'cpuChart', width: 120, height: 30 },
            { id: 'memoryChart', width: 120, height: 30 },
            { id: 'diskChart', width: 120, height: 30 },
            { id: 'loadChart', width: 120, height: 30 }
        ];

        // Set dimensions before chart initialization
        chartCanvasConfig.forEach(({ id, width, height }) => {
            const canvas = document.getElementById(id);
            if (canvas) {
                canvas.width = width;
                canvas.height = height;
                canvas.style.width = width + 'px';
                canvas.style.height = height + 'px';
            }
        });

        // Base chart configuration for small metric charts
        const chartConfig = (label, color) => ({
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [{
                    label: label,
                    data: Array(20).fill(0),
                    borderColor: color,
                    backgroundColor: color.replace(')', ', 0.1)'),
                    borderWidth: 1.5,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                },
                scales: {
                    x: { display: false },
                    y: { 
                        display: false,
                        min: 0,
                        max: 100
                    }
                },
                animation: false,
                layout: {
                    padding: 0
                },
                elements: {
                    line: {
                        tension: 0.4,
                        borderWidth: 1.5
                    }
                }
            }
        });

        // Initialize CPU Chart
        const cpuCtx = document.getElementById('cpuChart').getContext('2d');
        this.metricCharts.cpu = new Chart(cpuCtx, chartConfig('CPU', 'rgba(239, 68, 68, 1)'));

        // Initialize Memory Chart
        const memCtx = document.getElementById('memoryChart').getContext('2d');
        this.metricCharts.memory = new Chart(memCtx, chartConfig('Memory', 'rgba(59, 130, 246, 1)'));

        // Initialize Disk Chart
        const diskCtx = document.getElementById('diskChart').getContext('2d');
        this.metricCharts.disk = new Chart(diskCtx, chartConfig('Disk', 'rgba(16, 185, 129, 1)'));

        // Initialize Load Average Chart with multi-line configuration
        const loadCtx = document.getElementById('loadChart').getContext('2d');
        this.metricCharts.load = new Chart(loadCtx, {
            type: 'line',
            data: {
                labels: Array(20).fill(''),
                datasets: [
                    {
                        label: '1min',
                        data: Array(20).fill(0),
                        borderColor: 'rgba(245, 158, 11, 1)',
                        borderWidth: 1.5,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: '5min',
                        data: Array(20).fill(0),
                        borderColor: 'rgba(99, 102, 241, 1)',
                        borderWidth: 1.5,
                        tension: 0.4,
                        pointRadius: 0
                    },
                    {
                        label: '15min',
                        data: Array(20).fill(0),
                        borderColor: 'rgba(167, 139, 250, 1)',
                        borderWidth: 1.5,
                        tension: 0.4,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                },
                scales: {
                    x: { display: false },
                    y: { 
                        display: false,
                        suggestedMin: 0,
                        suggestedMax: 4
                    }
                },
                animation: false,
                layout: {
                    padding: 0
                }
            }
        });
    }

    setupLogViewToggle() {
        const toggleBtn = document.getElementById('toggleLogView');
        const logsContainer = document.getElementById('logsContainer');
        const logsTableContainer = document.getElementById('logsTableContainer');
        toggleBtn.addEventListener('click', () => {
            if (this.logViewMode === 'json') {
                this.logViewMode = 'table';
                toggleBtn.textContent = 'Switch to JSON View';
                logsContainer.style.display = 'none';
                logsTableContainer.style.display = '';
                this.renderLogsTable();
            } else {
                this.logViewMode = 'json';
                toggleBtn.textContent = 'Switch to Table View';
                logsContainer.style.display = '';
                logsTableContainer.style.display = 'none';
            }
        });
    }

    initializeChart() {
        const canvas = document.getElementById('trafficChart');
        const ctx = canvas.getContext('2d', { willReadFrequently: true });

        this.securityChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Array(30).fill(''),
                datasets: [
                    {
                        label: 'Traffic Volume',
                        type: 'line',
                        data: Array(30).fill(0),
                        borderColor: '#4f46e5',
                        backgroundColor: 'rgba(79, 70, 229, 0.2)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        yAxisID: 'y',
                    },
                    {
                        label: 'High Severity Alerts',
                        type: 'bar',
                        data: Array(30).fill(0),
                        backgroundColor: '#ef4444',
                        yAxisID: 'y1',
                    },
                    {
                        label: 'Medium Severity Alerts',
                        type: 'bar',
                        data: Array(30).fill(0),
                        backgroundColor: '#f59e0b',
                        yAxisID: 'y1',
                    },
                    {
                        label: 'Low Severity Alerts',
                        type: 'bar',
                        data: Array(30).fill(0),
                        backgroundColor: '#10b981',
                        yAxisID: 'y1',
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#e0e0e0',
                            font: {
                                family: "'Segoe UI', sans-serif",
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: '#2d2d2d',
                        borderColor: '#404040',
                        borderWidth: 1,
                        titleColor: '#e0e0e0',
                        bodyColor: '#e0e0e0',
                        padding: 10,
                        cornerRadius: 4,
                        callbacks: {
                            label: function(context) {
                                const label = context.dataset.label || '';
                                const value = context.parsed.y;
                                return `${label}: ${value}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: 'rgba(64, 64, 64, 0.5)',
                            drawOnChartArea: true
                        },
                        ticks: {
                            color: '#a0a0a0',
                            font: {
                                size: 11
                            }
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(64, 64, 64, 0.5)',
                            drawOnChartArea: true
                        },
                        ticks: {
                            color: '#a0a0a0',
                            font: {
                                size: 11
                            },
                            padding: 8
                        },
                        title: {
                            display: true,
                            text: 'Traffic Volume',
                            color: '#e0e0e0',
                            font: {
                                size: 12,
                                weight: 'bold'
                            }
                        }
                    },
                    y1: {
                        beginAtZero: true,
                        position: 'right',
                        grid: {
                            drawOnChartArea: false,
                        },
                        ticks: {
                            color: '#a0a0a0',
                            font: {
                                size: 11
                            },
                            padding: 8
                        },
                        title: {
                            display: true,
                            text: 'Alert Count',
                            color: '#e0e0e0',
                            font: {
                                size: 12,
                                weight: 'bold'
                            }
                        }
                    }
                },
                elements: {
                    point: {
                        radius: 3,
                        hoverRadius: 5,
                        backgroundColor: 'rgba(255, 255, 255, 0.8)'
                    },
                    line: {
                        tension: 0.4
                    }
                }
            }
        });
    }


    initializeCharts() {
        // Initialize geo chart
        this.geoChart = new GeoChart('geo-map');
        
        // Initialize severity chart
        this.severityChart = new SeverityPieChart('severity-chart');
        
        // Initialize category chart
        this.categoryChart = new CategoryBarChart('category-chart');
    }

    connectWebSocket() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('Connected to server');
            if (this._reconnectTimeout) {
                clearTimeout(this._reconnectTimeout);
                this._reconnectTimeout = null;
                this._reconnectAttempts = 0;
            }
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                if (message.type === 'connected') {
                    console.log('Successfully connected to server');
                    return;
                }
                this.handleMessage(message);
            } catch (error) {
                console.error('Error processing message:', error);
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            if (error.code === 1008) {
                console.error('Authentication failed, redirecting to login');
                window.location.href = '/login.html';
                return;
            }
        };

        this.ws.onclose = (event) => {
            console.log('Disconnected from server');
            
            if (event.code === 1000) {
                return;
            }

            const backoffTime = Math.min(1000 * Math.pow(2, this._reconnectAttempts || 0), 30000);
            this._reconnectAttempts = (this._reconnectAttempts || 0) + 1;
            
            this._reconnectTimeout = setTimeout(() => {
                console.log(`Attempting to reconnect (attempt ${this._reconnectAttempts})`);
                this.connectWebSocket();
            }, backoffTime);
        };
    }

    async decryptMessage(encryptedData) {
        try {
            const subtle = window.crypto.subtle;
            const key = await subtle.importKey(
                'raw',
                this.hexToUint8Array(this.encryptionKey),
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            const decrypted = await subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: this.hexToUint8Array(encryptedData.iv),
                    tagLength: 128,
                    additionalData: this.hexToUint8Array(encryptedData.authTag)
                },
                key,
                this.hexToUint8Array(encryptedData.encrypted)
            );

            return JSON.parse(new TextDecoder().decode(decrypted));
        } catch (error) {
            console.error('Decryption error:', error);
            throw error;
        }
    }

    hexToUint8Array(hex) {
        return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    }

    handleMessage(message) {
        switch(message.type) {
            case 'apache_status':
                this.updateApacheStatus(message.status);
                if (message.metrics) {
                    this.updateMetricValue('cpuMetric', `${message.metrics.cpu}%`);
                    this.updateMetricValue('memoryMetric', `${message.metrics.memory}%`);
                    this.updateMetricValue('diskMetric', `${message.metrics.disk}%`);
                    this.updateMetricValue('load1Metric', message.metrics.loadAverage['1min']);
                    this.updateMetricValue('load5Metric', message.metrics.loadAverage['5min']);
                    this.updateMetricValue('load15Metric', message.metrics.loadAverage['15min']);
                    this.updateMetricValue('uptimeMetric', message.metrics.uptime);
                    this.updateMetricCharts(message.metrics);
                }
                break;
            case 'suricata_event':
                this.addLogEntry(message.data);
                break;
            case 'error':
                console.error('Server error:', message.message);
                break;
        }
    }

    updateChart(trafficCount, alertData) {
        const currentTime = new Date().toLocaleTimeString();

        this.securityChart.data.datasets[0].data.push(trafficCount);
        this.securityChart.data.datasets[0].data.shift();

        this.securityChart.data.datasets[1].data.push(alertData.high || 0);
        this.securityChart.data.datasets[2].data.push(alertData.medium || 0);
        this.securityChart.data.datasets[3].data.push(alertData.low || 0);

        this.securityChart.data.datasets[1].data.shift();
        this.securityChart.data.datasets[2].data.shift();
        this.securityChart.data.datasets[3].data.shift();

        this.securityChart.data.labels.push(currentTime);
        this.securityChart.data.labels.shift();

        this.securityChart.update('none');
    }

    processAlert(alert) {
        // Update geo chart if source and destination IPs are available
        if (alert.alert && alert.alert.src_ip && alert.alert.dest_ip) {
            this.geoChart.addAttackPoint(
                alert.alert.src_ip,
                alert.alert.dest_ip,
                alert.alert.severity
            );
        }
        
        // Update severity counts and chart
        if (alert.alert && alert.alert.severity) {
            const severity = parseInt(alert.alert.severity);
            if (severity === 1) {
                this.severityCounts.high++;
            } else if (severity === 2) {
                this.severityCounts.medium++;
            } else {
                this.severityCounts.low++;
            }
            
            this.severityChart.update(
                this.severityCounts.high,
                this.severityCounts.medium,
                this.severityCounts.low
            );
        }
        
        // Update category chart
        if (alert.alert && alert.alert.category) {
            this.categoryChart.addCategory(alert.alert.category);
        }
    }

    updateMetricCharts(metrics) {
        if (!metrics) return;

        // Update CPU history and chart
        this.metricHistory.cpu.push(parseFloat(metrics.cpu));
        this.metricHistory.cpu.shift();
        this.metricCharts.cpu.data.datasets[0].data = this.metricHistory.cpu;
        this.metricCharts.cpu.update('none');

        // Update Memory history and chart
        this.metricHistory.memory.push(parseFloat(metrics.memory));
        this.metricHistory.memory.shift();
        this.metricCharts.memory.data.datasets[0].data = this.metricHistory.memory;
        this.metricCharts.memory.update('none');

        // Update Disk history and chart
        this.metricHistory.disk.push(parseFloat(metrics.disk));
        this.metricHistory.disk.shift();
        this.metricCharts.disk.data.datasets[0].data = this.metricHistory.disk;
        this.metricCharts.disk.update('none');

        // Update Load Average history and chart
        this.metricHistory.load['1min'].push(parseFloat(metrics.loadAverage['1min']));
        this.metricHistory.load['5min'].push(parseFloat(metrics.loadAverage['5min']));
        this.metricHistory.load['15min'].push(parseFloat(metrics.loadAverage['15min']));
        
        this.metricHistory.load['1min'].shift();
        this.metricHistory.load['5min'].shift();
        this.metricHistory.load['15min'].shift();

        this.metricCharts.load.data.datasets[0].data = this.metricHistory.load['1min'];
        this.metricCharts.load.data.datasets[1].data = this.metricHistory.load['5min'];
        this.metricCharts.load.data.datasets[2].data = this.metricHistory.load['15min'];
        this.metricCharts.load.update('none');
    }

    getHighestValueKey(map) {
        let maxKey = null;
        let maxValue = 0;

        for (const [key, value] of map.entries()) {
            if (value > maxValue) {
                maxValue = value;
                maxKey = key;
            }
        }

        return { key: maxKey, value: maxValue };
    }

    getSeverityLabel(severity) {
        switch (parseInt(severity)) {
            case 1: return "HIGH";
            case 2: return "MEDIUM";
            case 3: return "LOW";
            default: return "UNKNOWN";
        }
    }

    updateSecurityMetrics(event) {
        if (event.event_type === 'alert' && event.alert) {
            // Track attack signatures
            const signature = event.alert.signature || 'Unknown Attack';
            this.attackStats.set(signature, (this.attackStats.get(signature) || 0) + 1);

            // Track severity
            const severity = event.alert.severity || 0;
            this.severityStats.set(severity, (this.severityStats.get(severity) || 0) + 1);

            // Track source IP if available
            if (event.alert.src_ip) {
                this.sourceIPStats.set(event.alert.src_ip, (this.sourceIPStats.get(event.alert.src_ip) || 0) + 1);
            }

            this.updateMetricsDisplay();
        }
    }

    updateMetricsDisplay() {
        // Update Most Common Attack
        const topAttack = this.getHighestValueKey(this.attackStats);
        if (topAttack.key) {
            // Remove leading [id:gid:sid:rev] if present
            let attackName = topAttack.key.replace(/^\[[^\]]*\]\s*/, '');
            // No truncation, let CSS handle wrapping
            document.getElementById('commonAttack').textContent = attackName;
            document.getElementById('attackCount').textContent =
                `${topAttack.value} occurrence${topAttack.value !== 1 ? 's' : ''}`;
        }

        // Update Highest Severity
        const topSeverity = this.getHighestValueKey(this.severityStats);
        if (topSeverity.key !== null) {
            const severityElement = document.getElementById('highestSeverity');
            const severityLevel = this.getSeverityLabel(topSeverity.key);
            severityElement.textContent = severityLevel;
            severityElement.className = `stat-value severity-${severityLevel.toLowerCase()}`;
            document.getElementById('severityCount').textContent =
                `${topSeverity.value} alert${topSeverity.value !== 1 ? 's' : ''}`;
        }

        // Update Top Source IP
        const topSourceIP = this.getHighestValueKey(this.sourceIPStats);
        if (topSourceIP.key) {
            document.getElementById('topSourceIP').textContent = topSourceIP.key;
            document.getElementById('sourceIPCount').textContent =
                `${topSourceIP.value} event${topSourceIP.value !== 1 ? 's' : ''}`;
        }
    }

    updateApacheStatus(status) {
        const statusElement = document.getElementById('apacheStatus');
        statusElement.textContent = status;
        
        // Remove any existing status classes
        statusElement.classList.remove('status-running', 'status-stopped', 'status-error');
        
        // Add appropriate status class
        switch(status.toLowerCase()) {
            case 'running':
                statusElement.classList.add('status-running');
                break;
            case 'stopped':
                statusElement.classList.add('status-stopped');
                break;
            default:
                statusElement.classList.add('status-error');
                break;
        }
    }

    updateMetricValue(metricId, value, thresholds = { warning: 70, critical: 90 }) {
        const element = document.getElementById(metricId);
        if (!element) return;

        // Remove existing classes
        element.classList.remove('metric-warning', 'metric-critical');
        
        // Add appropriate class based on thresholds
        const numValue = parseFloat(value);
        if (numValue >= thresholds.critical) {
            element.classList.add('metric-critical');
        } else if (numValue >= thresholds.warning) {
            element.classList.add('metric-warning');
        }
        
        element.textContent = value;
    }

    addLogEntry(event) {
        if (this.logPaused) {
            this.pendingLogs.push(event);
            return;
        }

        this.logs.unshift(event);
        if (this.logs.length > 100) this.logs.pop();

        if (event.event_type === 'alert' && event.alert) {
            // Process the alert for the new charts
            this.processAlert(event);
            const severity = event.alert.severity || 0;
            if (severity === 1) this.alertCount.high = (this.alertCount.high || 0) + 1;
            else if (severity === 2) this.alertCount.medium = (this.alertCount.medium || 0) + 1;
            else if (severity === 3) this.alertCount.low = (this.alertCount.low || 0) + 1;
        }

        const logsContainer = document.getElementById('logsContainer');
        const logElement = document.createElement('div');
        logElement.className = `log-entry ${event.event_type === 'alert' ? 'alert-entry' : ''}`;

        let detailsToShow = event;
        if (event.alert) {
            const srcLocation = event.alert.src_location || {};
            const destLocation = event.alert.dest_location || {};
            // Format location: 'City, Country' if both, else just 'Country' if city missing
            const formatLocation = (loc) => {
                if (!loc) return 'Unknown';
                if (loc.country === 'Local Network') return 'Local Network';
                if (loc.city && loc.country) return `${loc.city}, ${loc.country}`;
                if (loc.country) return loc.country;
                return 'Unknown';
            };
            detailsToShow = {
                signature: event.alert.signature,
                category: event.alert.category,
                severity: event.alert.severity,
                source: {
                    ip: event.alert.src_ip || 'Unknown',
                    location: formatLocation(srcLocation)
                },
                destination: {
                    ip: event.alert.dest_ip || 'Unknown',
                    location: formatLocation(destLocation)
                }
            };
        }

        logElement.innerHTML = `
            <div class="log-type ${event.event_type === 'alert' ? 'alert-type' : ''}">${event.event_type.toUpperCase()}</div>
            <div class="log-time">${new Date(event.timestamp).toLocaleString()}</div>
            <div class="log-details">
                <pre>${JSON.stringify(detailsToShow, null, 2)}</pre>
            </div>
        `;

        if (event.event_type === 'alert') {
            const analyzeButton = document.createElement('button');
            analyzeButton.className = 'analyze-event-button';
            analyzeButton.textContent = 'Analyze with AI';
            // Insert button after JSON content
            const preElement = logElement.querySelector('pre');
            preElement.insertAdjacentElement('afterend', analyzeButton);
            analyzeButton.addEventListener('click', () => {
                const question = `Analyze this security event: ${JSON.stringify(detailsToShow, null, 2)}`;
                document.getElementById('aiChatInput').value = question;
                // Always open chat if minimized
                const chatContainer = document.getElementById('aiChatContainer');
                const stickyOpenBtn = document.getElementById('aiChatStickyOpen');
                if (chatContainer.style.display === 'none' || stickyOpenBtn.style.display === 'flex') {
                    chatContainer.classList.remove('collapsed');
                    chatContainer.style.display = '';
                    stickyOpenBtn.style.display = 'none';
                }
                document.getElementById('aiChatInput').focus();
            });
        }

        logsContainer.insertBefore(logElement, logsContainer.firstChild);

        if (logsContainer.children.length > 100) {
            logsContainer.removeChild(logsContainer.lastChild);
        }

        if (this.logViewMode === 'table') {
            this.renderLogsTable();
        }

        this.currentCount++;
        this.updateSecurityMetrics(event);
    }

    renderLogsTable() {
        const logsTableContainer = document.getElementById('logsTableContainer');
        // Define columns to show
        const columns = [
            { label: 'Time', key: 'timestamp' },
            { label: 'Type', key: 'event_type' },
            { label: 'Signature', key: 'alert.signature' },
            { label: 'Category', key: 'alert.category' },
            { label: 'Severity', key: 'alert.severity' },
            { label: 'Source IP', key: 'alert.src_ip' },
            { label: 'Destination IP', key: 'alert.dest_ip' }
        ];

        let html = '<table class="logs-table"><thead><tr>';
        columns.forEach(col => html += `<th>${col.label}</th>`);
        html += '</tr></thead><tbody>';

        this.logs.forEach(event => {
            html += '<tr>';
            columns.forEach(col => {
                let value = event;
                col.key.split('.').forEach(k => value = value && value[k]);
                if (col.key === 'timestamp') {
                    value = value ? new Date(value).toLocaleString() : '';
                }
                html += `<td>${value !== undefined ? value : ''}</td>`;
            });
            html += '</tr>';
        });

        html += '</tbody></table>';
        logsTableContainer.innerHTML = html;
    }

    clearLogs() {
        const logsContainer = document.getElementById('logsContainer');
        const logsTableContainer = document.getElementById('logsTableContainer');
        
        // Clear both containers
        logsContainer.innerHTML = '';
        logsTableContainer.innerHTML = '';
        
        // Reset logs array and related state
        this.logs = [];
        this.pendingLogs = [];
        this.logPaused = false;

        // Clear the charts
        this.clearCharts();
        
        // Update pause button state
        const pauseButton = document.getElementById('pauseLogs');
        if (pauseButton) {
            pauseButton.textContent = 'Pause';
        }
    }

    // Add a method to clear the charts
    clearCharts() {
        if (this.geoChart) this.geoChart.clear();
        if (this.categoryChart) this.categoryChart.reset();
        this.severityCounts = { high: 0, medium: 0, low: 0 };
        if (this.severityChart) this.severityChart.update(0, 0, 0);
    }

    setupClearButton() {
        const logsControls = document.querySelector('.log-controls');
        const clearButton = document.createElement('button');
        clearButton.id = 'clearLogs';
        clearButton.innerHTML = '🗑️ Clear Logs';
        clearButton.className = 'clear-button';
        clearButton.title = 'Clear all logs';
        logsControls.appendChild(clearButton);

        clearButton.addEventListener('click', () => {
            this.clearLogs();
        });
    }

    setupChatUI() {
        // Polyfill for Element.prototype.closest() for older browsers
        if (!Element.prototype.closest) {
            Element.prototype.closest = function(s) {
                let el = this;
                do {
                    if (el.matches(s)) return el;
                    el = el.parentElement || el.parentNode;
                } while (el && el.nodeType === 1);
                return null;
            };
        }

        this.currentModel = '';
        this.chatHistory = [];

        // Toggle chat visibility (no longer needed, replaced by minimize/close)
        // Remove old aiChatToggle button logic
        // Model selection
        const modelSelect = document.getElementById('aiModelSelect');
        modelSelect.addEventListener('change', (e) => {
            this.currentModel = e.target.value;
            this.chatHistory = [];
        });
        // Refresh models button
        document.getElementById('aiRefreshModels').addEventListener('click', () => this.updateModelList());
        // Send message handling
        const chatInput = document.getElementById('aiChatInput');
        const sendButton = document.getElementById('aiChatSend');
        const sendMessage = () => {
            const message = chatInput.value.trim();
            if (message && this.currentModel) {
                this.sendChatMessage();
            }
        };
        sendButton.addEventListener('click', sendMessage);
        chatInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.altKey) {
                e.preventDefault();
                sendMessage();
            }
        });
        // Initialize model list
        this.updateModelList();
    }

    /**
     * Chat window controls: minimize, close, drag, and thinking dots
     */
    setupChatWindowControls() {
        const chatContainer = document.getElementById('aiChatContainer');
        const chatHeader = document.getElementById('aiChatHeader');
        const chatBody = document.getElementById('aiChatBody');
        const toggleBtn = document.getElementById('aiChatToggle');
        const maximizeBtn = document.getElementById('aiChatMaximize');
        const thinkingDots = document.getElementById('aiThinking');
        const stickyOpenBtn = document.getElementById('aiChatStickyOpen');

        // Remove any default resize from CSS
        chatContainer.style.resize = 'none';
        chatContainer.style.overflow = 'auto';

        // State: open, minimized, maximized
        let chatState = 'open'; // 'open', 'minimized', 'maximized'
        let normalWidth = 350;
        let normalHeight = 600;
        let maximized = false;
        // Set initial size
        chatContainer.style.width = normalWidth + 'px';
        chatContainer.style.height = normalHeight + 'px';

        function updateChatState(newState) {
            chatState = newState;
            if (chatState === 'open') {
                chatContainer.classList.remove('collapsed');
                chatContainer.style.display = '';
                stickyOpenBtn.style.display = 'none';
                toggleBtn.textContent = '−';
                toggleBtn.title = 'Minimize';
            } else if (chatState === 'minimized') {
                chatContainer.classList.add('collapsed');
                chatContainer.style.display = 'none';
                stickyOpenBtn.style.display = 'flex';
            }
        }
        // Initial state
        updateChatState('open');

        // Toggle button logic: open <-> minimized
        toggleBtn.addEventListener('click', () => {
            if (chatState === 'open' || chatState === 'maximized') {
                updateChatState('minimized');
            } else {
                updateChatState('open');
            }
        });
        // Maximize button logic
        maximizeBtn.addEventListener('click', () => {
            maximized = !maximized;
            if (maximized) {
                chatContainer.style.width = (normalWidth * 2) + 'px';
                chatContainer.style.height = (normalHeight * 2) + 'px';
                maximizeBtn.textContent = '❐';
                maximizeBtn.title = 'Restore';
            } else {
                chatContainer.style.width = normalWidth + 'px';
                chatContainer.style.height = normalHeight + 'px';
                maximizeBtn.textContent = '□';
                maximizeBtn.title = 'Maximize';
            }
        });
        // Sticky open button logic
        stickyOpenBtn.addEventListener('click', () => {
            updateChatState('open');
        });
        // Restore on header double-click
        chatHeader.addEventListener('dblclick', () => {
            updateChatState('open');
        });

        // Drag-to-move
        let isDragging = false, dragOffsetX = 0, dragOffsetY = 0;
        chatHeader.addEventListener('mousedown', (e) => {
            if (e.target === toggleBtn || e.target === maximizeBtn) return;
            isDragging = true;
            const rect = chatContainer.getBoundingClientRect();
            dragOffsetX = e.clientX - rect.left;
            dragOffsetY = e.clientY - rect.top;
            chatContainer.style.transition = 'none';
            document.body.style.userSelect = 'none';
        });
        document.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            chatContainer.style.left = (e.clientX - dragOffsetX) + 'px';
            chatContainer.style.top = (e.clientY - dragOffsetY) + 'px';
            chatContainer.style.right = 'auto';
            chatContainer.style.bottom = 'auto';
            chatContainer.style.position = 'fixed';
        });
        document.addEventListener('mouseup', () => {
            if (isDragging) {
                isDragging = false;
                chatContainer.style.transition = '';
                document.body.style.userSelect = '';
            }
        });

        // Show/hide thinking dots (call these in your chat logic)
        this.showThinking = () => { thinkingDots.style.display = 'flex'; };
        this.hideThinking = () => { thinkingDots.style.display = 'none'; };

        // Patch sendChatMessage to show/hide thinking dots
        const origSendChatMessage = this.sendChatMessage.bind(this);
        this.sendChatMessage = async (...args) => {
            this.showThinking();
            try {
                await origSendChatMessage(...args);
            } finally {
                this.hideThinking();
            }
        };
    }

    async updateModelList() {
        const select = document.getElementById('aiModelSelect');
        select.innerHTML = '<option value="">Loading models...</option>';
        
        const models = await this.getAvailableModels();
        
        if (models.length === 0) {
            select.innerHTML = '<option value="">No models found</option>';
            return;
        }
        
        select.innerHTML = models.map(model => 
            `<option value="${model.name}">${model.name}</option>`
        ).join('');
        
        // Try to select Cyber-Agent if available
        const securityAgentOption = models.find(m => m.name.includes('Cyber-Agent'));
        if (securityAgentOption) {
            select.value = securityAgentOption.name;
            this.currentModel = securityAgentOption.name;
        }
    }

    async getAvailableModels() {
        try {
            // First check if Ollama service is running through proxy
            const pingResponse = await this.makeRequest('/api/ollama/ping', {
                method: 'HEAD',
                timeout: 3000
            });
            
            if (!pingResponse.ok) {
                throw new Error('Ollama service not reachable');
            }

            const response = await this.makeRequest('/api/ollama/models', {
                signal: AbortSignal.timeout(5000)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            return data.models || [];
        } catch (error) {
            console.error('Error fetching models:', error);
            this.showModelError(error.message);
            return [];
        }
    }

    async sendChatMessage() {
        const input = document.getElementById('aiChatInput');
        const message = input.value.trim();
        if (!message || !this.currentModel) return;
        
        this.addChatMessage(message, 'user');
        input.value = '';
        
        const messages = [
            ...this.chatHistory,
            { role: 'user', content: message }
        ];
        
        try {
            const response = await this.makeRequest('/api/ollama/chat', {
                method: 'POST',
                body: JSON.stringify({
                    model: this.currentModel,
                    messages: messages,
                    stream: false
                })
            });
            
            if (!response.ok) throw new Error('AI request failed');
            
            const data = await response.json();
            const aiResponse = data.message?.content || "I couldn't generate a response.";
            
            this.addChatMessage(aiResponse, 'ai');
            
            this.chatHistory = [
                ...messages,
                { role: 'assistant', content: aiResponse }
            ].slice(-10);
            
        } catch (error) {
            console.error('Error communicating with AI:', error);
            this.addChatMessage("Sorry, I encountered an error. Please try again.", 'ai');
        }
    }

    addChatMessage(message, sender) {
        const messagesContainer = document.getElementById('aiChatMessages');
        const messageElement = document.createElement('div');
        messageElement.className = `ai-message ai-message-${sender}`;
        messageElement.textContent = message;
        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    setupEventListeners() {
        // Pause/resume logs
        document.getElementById('pauseLogs').addEventListener('click', () => {
            this.logPaused = !this.logPaused;
            const button = document.getElementById('pauseLogs');
            button.textContent = this.logPaused ? 'Resume' : 'Pause';
            
            if (!this.logPaused && this.pendingLogs.length > 0) {
                this.pendingLogs.forEach(log => this.addLogEntry(log));
                this.pendingLogs = [];
            }
        });

        // Severity filter
        document.getElementById('severityFilter').addEventListener('change', (e) => {
            const severity = e.target.value;
            
            if (this.logViewMode === 'json') {
                // Handle JSON view filtering
                const logs = document.querySelectorAll('.log-entry');
                logs.forEach(log => {
                    if (severity === 'all') {
                        log.style.display = '';
                    } else {
                        const logSeverity = log.querySelector('.log-details')?.textContent?.includes(`"severity": ${this.getSeverityValue(severity)}`);
                        log.style.display = logSeverity ? '' : 'none';
                    }
                });
            } else {
                // Handle table view filtering
                const tableRows = document.querySelectorAll('.logs-table tbody tr');
                tableRows.forEach(row => {
                    if (severity === 'all') {
                        row.style.display = '';
                    } else {
                        // Severity is in the 5th column (index 4) in the table
                        const severityCell = row.cells[4];
                        const logSeverity = severityCell?.textContent === this.getSeverityValue(severity).toString();
                        row.style.display = logSeverity ? '' : 'none';
                    }
                });
            }
        });

        const exportButton = document.getElementById('exportCSV');
        if (exportButton) {
            exportButton.addEventListener('click', async () => {
                try {
                    const response = await fetch('/api/alerts/export-csv');
                    if (!response.ok) throw new Error('Failed to export alerts as CSV');
                    const blob = await response.blob();
                    // Extract filename from Content-Disposition header
                    const disposition = response.headers.get('Content-Disposition');
                    let filename = 'suricata_alerts.csv';
                    if (disposition && disposition.indexOf('filename=') !== -1) {
                        filename = disposition.split('filename=')[1].replace(/\"/g, '');
                    }
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    window.URL.revokeObjectURL(url);
                } catch (err) {
                    alert('Error exporting alerts as CSV: ' + err.message);
                }
            });
        } else {
            console.error('Export CSV button not found');
        }

        // PDF export functionality
        const exportPDFButton = document.getElementById('exportPDF');
        if (exportPDFButton) {
            exportPDFButton.addEventListener('click', async () => {
                // Save original button text
                const originalText = exportPDFButton.textContent;
                exportPDFButton.disabled = true;
                exportPDFButton.textContent = 'Generating...';
                exportPDFButton.classList.add('loading');
                try {
                    // Collect all visible log entries (same as CSV export)
                    const logEntries = Array.from(document.querySelectorAll('.log-entry'))
                        .filter(entry => entry.style.display !== 'none');
                    if (logEntries.length === 0) {
                        alert('No logs to export');
                        exportPDFButton.disabled = false;
                        exportPDFButton.textContent = originalText;
                        exportPDFButton.classList.remove('loading');
                        return;
                    }
                    // Prepare logs for backend (match server.js expectations)
                    const logs = logEntries.map(entry => {
                        const type = entry.querySelector('.log-type')?.textContent?.trim() || '';
                        const timestamp = entry.querySelector('.log-time')?.textContent?.trim() || '';
                        const jsonText = entry.querySelector('pre')?.textContent || '{}';
                        try {
                            const details = JSON.parse(jsonText);
                            // Format location for PDF export as well
                            const formatLocation = (loc) => {
                                if (!loc) return 'Unknown';
                                if (loc === 'Local Network') return 'Local Network';
                                if (typeof loc === 'string') return loc;
                                if (loc.city && loc.country) return `${loc.city}, ${loc.country}`;
                                if (loc.country) return loc.country;
                                return 'Unknown';
                            };
                            if (type === 'ALERT') {
                                return {
                                    signature: details.signature || '',
                                    severity: details.severity || '',
                                    category: details.category || '',
                                    sourceIp: details.source?.ip || '',
                                    sourceLocation: formatLocation(details.source?.location),
                                    destinationIp: details.destination?.ip || '',
                                    destinationLocation: formatLocation(details.destination?.location),
                                    timestamp: timestamp
                                };
                            }
                        } catch (e) {
                            // skip invalid
                        }
                        return null;
                    }).filter(Boolean);

                    const response = await fetch('/api/reports/pdf', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                        },
                        body: JSON.stringify({ logs })
                    });
                    if (!response.ok) throw new Error('Failed to generate PDF');
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'network_alerts_report.pdf';
                    document.body.appendChild(a);
                    a.click();
                    setTimeout(() => {
                        document.body.removeChild(a);
                        window.URL.revokeObjectURL(url);
                    }, 100);
                } catch (err) {
                    alert('Error generating PDF: ' + err.message);
                } finally {
                    exportPDFButton.disabled = false;
                    exportPDFButton.textContent = originalText;
                    exportPDFButton.classList.remove('loading');
                }
            });
        }

        document.getElementById('export-json-btn').addEventListener('click', async () => {
            try {
                const response = await fetch('/api/alerts/export-json');
                if (!response.ok) throw new Error('Failed to export alerts as JSON');
                const blob = await response.blob();
                // Extract filename from Content-Disposition header
                const disposition = response.headers.get('Content-Disposition');
                let filename = 'suricata_alerts.json';
                if (disposition && disposition.indexOf('filename=') !== -1) {
                    filename = disposition.split('filename=')[1].replace(/\"/g, '');
                }
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            } catch (err) {
                alert('Error exporting alerts as JSON: ' + err.message);
            }
        });

        // Update chart at fixed interval
        setInterval(() => {
            const eventsCount = this.currentCount;
            const alertData = {
                high: this.alertCount.high || 0,
                medium: this.alertCount.medium || 0,
                low: this.alertCount.low || 0
            };

            this.currentCount = 0;
            this.alertCount = { high: 0, medium: 0, low: 0 };

            this.updateChart(eventsCount, alertData);
        }, 1500);
    }

    getSeverityValue(severity) {
        switch(severity) {
            case 'high': return 1;
            case 'medium': return 2;
            case 'low': return 3;
            default: return 0;
        }
    }

    showModelError(errorMessage) {
        const errorContainer = document.getElementById('modelErrorContainer');
        if (errorContainer) {
            errorContainer.textContent = errorMessage;
            errorContainer.style.display = 'block';
        }
    }
}

// Initialize the dashboard when the page loads
window.onload = () => {
    new SecurityDashboard();
};
