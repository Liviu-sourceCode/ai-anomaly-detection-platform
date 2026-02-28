class GeoChart {
    constructor(containerId) {
        this.containerId = containerId;
        this.ipCache = new Map(); // Cache for IP coordinates
        this.initialize();
    }

    initialize() {
        try {
            if (!document.getElementById(this.containerId)) {
                console.error(`Map container #${this.containerId} not found`);
                return;
            }
            
            this.map = L.map(this.containerId).setView([20, 0], 2);
            
            // DARK MODE - CartoDB Dark Matter
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(this.map);
        
            this.attackLayer = L.featureGroup().addTo(this.map);
            
            // Add export button
            this.addExportButton();
            
            // Force a resize after initialization to handle any display issues
            setTimeout(() => {
                this.map.invalidateSize();
            }, 100);
        } catch (error) {
            console.error('Error initializing map:', error);
        }
    }
    
    
    addExportButton() {
        // Create a custom control for the export button
        const ExportControl = L.Control.extend({
            options: {
                position: 'topright'
            },
            
            onAdd: () => {
                const container = L.DomUtil.create('div', 'leaflet-bar leaflet-control');
                const button = L.DomUtil.create('a', 'export-button', container);
                
                button.href = '#';
                button.title = 'Export Map as PNG';
                button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/><path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/></svg>';
                button.style.backgroundColor = '#333';
                button.style.color = 'white';
                button.style.width = '30px';
                button.style.height = '30px';
                button.style.lineHeight = '30px';
                button.style.textAlign = 'center';
                
                // Click handler for the export button
                L.DomEvent.on(button, 'click', (e) => {
                    L.DomEvent.preventDefault(e);
                    this.exportMapAsPNG();
                });
                
                return container;
            }
        });
        
        // Add the control to the map
        this.map.addControl(new ExportControl());
    }
    
    // Method to export the map as PNG
    exportMapAsPNG() {
        try {
            // Try to use dom-to-image library which works better with SVG elements
            if (typeof domtoimage === 'undefined') {
                // If dom-to-image is not loaded, dynamically load it
                const script = document.createElement('script');
                script.src = 'https://cdnjs.cloudflare.com/ajax/libs/dom-to-image/2.6.0/dom-to-image.min.js';
                script.onload = () => this.captureMapWithDomToImage();
                document.head.appendChild(script);
            } else {
                this.captureMapWithDomToImage();
            }
        } catch (error) {
            console.error('Error exporting map:', error);
            alert('Failed to export map. Please try again.');
        }
    }
    
    // New method to capture map with dom-to-image
    captureMapWithDomToImage() {
        const mapContainer = document.getElementById(this.containerId);
        
        // Show a loading indicator
        const loadingDiv = document.createElement('div');
        loadingDiv.id = 'map-export-loading';
        loadingDiv.style.position = 'absolute';
        loadingDiv.style.top = '50%';
        loadingDiv.style.left = '50%';
        loadingDiv.style.transform = 'translate(-50%, -50%)';
        loadingDiv.style.background = 'rgba(0,0,0,0.7)';
        loadingDiv.style.color = 'white';
        loadingDiv.style.padding = '10px 20px';
        loadingDiv.style.borderRadius = '5px';
        loadingDiv.style.zIndex = '1000';
        loadingDiv.textContent = 'Preparing to capture map...';
        mapContainer.appendChild(loadingDiv);
        
        // Store original styles
        const originalStyle = {
            width: mapContainer.style.width,
            height: mapContainer.style.height,
            overflow: mapContainer.style.overflow,
            position: mapContainer.style.position
        };
        
        // Force map to redraw all layers
        this.map.invalidateSize();
        
        // Wait a moment to ensure all map elements are rendered
        setTimeout(() => {
            // Hide the loading indicator before capture
            loadingDiv.style.display = 'none';
            
            // Get the actual map container (not the wrapper)
            const mapPane = mapContainer.querySelector('.leaflet-map-pane') || 
                           mapContainer.querySelector('.leaflet-pane');
            
            // Get the bounds of the visible content
            const bounds = this.attackLayer.getBounds();
            this.map.fitBounds(bounds, { padding: [20, 20] });
            
            // Use dom-to-image to capture the map
            domtoimage.toPng(mapContainer, {
                bgcolor: null, // Transparent background
                style: {
                    'transform': 'scale(1)',
                    'transform-origin': 'top left'
                },
                filter: (node) => {
                    // Filter out loading indicator and any other unwanted elements
                    return node.id !== 'map-export-loading' && 
                           !node.classList?.contains('leaflet-control-container');
                },
                width: mapContainer.offsetWidth,
                height: mapContainer.offsetHeight
            })
            .then((dataUrl) => {
                // Create an image to get the dimensions
                const img = new Image();
                img.onload = () => {
                    // Create a canvas to crop the image
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    
                    // Find the actual map content bounds by analyzing the image
                    const imageData = this.getImageBounds(img);
                    
                    // Set canvas size to the content bounds
                    canvas.width = imageData.width;
                    canvas.height = imageData.height;
                    
                    // Draw only the content part of the image
                    ctx.drawImage(
                        img, 
                        imageData.left, imageData.top, imageData.width, imageData.height,
                        0, 0, imageData.width, imageData.height
                    );
                    
                    // Convert canvas to PNG
                    const croppedDataUrl = canvas.toDataURL('image/png');
                    
                    // Create download link
                    const link = document.createElement('a');
                    link.download = `security-map-${new Date().toISOString().slice(0,10)}.png`;
                    link.href = croppedDataUrl;
                    
                    // Trigger download
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    
                    // Remove loading indicator
                    mapContainer.removeChild(loadingDiv);
                    
                    // Restore original styles
                    mapContainer.style.width = originalStyle.width;
                    mapContainer.style.height = originalStyle.height;
                    mapContainer.style.overflow = originalStyle.overflow;
                    mapContainer.style.position = originalStyle.position;
                };
                img.src = dataUrl;
            })
            .catch(function(error) {
                console.error('Error capturing map with dom-to-image:', error);
                mapContainer.removeChild(loadingDiv);
                alert('Failed to capture map. Please try again.');
                
                // Restore original styles
                mapContainer.style.width = originalStyle.width;
                mapContainer.style.height = originalStyle.height;
                mapContainer.style.overflow = originalStyle.overflow;
                mapContainer.style.position = originalStyle.position;
            });
        }, 1000); // Longer delay to ensure map is fully rendered
    }
    
    // Helper method to find the actual content bounds in the image
    getImageBounds(img) {
        // Create a canvas to analyze the image
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        
        // Get image data
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const data = imageData.data;
        
        // Find the bounds of non-black pixels
        let minX = canvas.width;
        let minY = canvas.height;
        let maxX = 0;
        let maxY = 0;
        
        // Scan the image data to find content bounds
        for (let y = 0; y < canvas.height; y++) {
            for (let x = 0; x < canvas.width; x++) {
                const idx = (y * canvas.width + x) * 4;
                // Check if pixel is not black or transparent
                // R, G, B values all > 5 to allow for some anti-aliasing
                const isContent = data[idx] > 5 || data[idx + 1] > 5 || data[idx + 2] > 5 || data[idx + 3] > 5;
                
                if (isContent) {
                    minX = Math.min(minX, x);
                    minY = Math.min(minY, y);
                    maxX = Math.max(maxX, x);
                    maxY = Math.max(maxY, y);
                }
            }
        }
        
        // Add a small padding
        const padding = 10;
        minX = Math.max(0, minX - padding);
        minY = Math.max(0, minY - padding);
        maxX = Math.min(canvas.width, maxX + padding);
        maxY = Math.min(canvas.height, maxY + padding);
        
        return {
            left: minX,
            top: minY,
            width: maxX - minX,
            height: maxY - minY
        };
    }

    async addAttackPoint(sourceIP, destIP, severity) {
        if (!sourceIP || !destIP) return;

        try {
            const sourceCoords = await this.getIPCoordinates(sourceIP);
            const destCoords = await this.getIPCoordinates(destIP);

            // If either coordinate is missing, skip plotting and do not log warnings/errors
            if (!sourceCoords || !destCoords) {
                return;
            }

            let color;
            switch (parseInt(severity)) {
                case 1: color = '#ff0000'; break;      // Red - High
                case 2: color = '#ffa500'; break;      // Orange - Medium
                case 3: color = '#56FF91'; break;      // Green - Low
            }

            const sourceMarker = L.circleMarker([sourceCoords.lat, sourceCoords.lon], {
                radius: 5,
                fillColor: color,
                color: '#000',
                weight: 1,
                opacity: 1,
                fillOpacity: 0.8
            }).addTo(this.attackLayer);

            const destMarker = L.circleMarker([destCoords.lat, destCoords.lon], {
                radius: 5,
                fillColor: color,  // Changed from '#ff0000' to use severity-based color
                color: '#000',
                weight: 1,
                opacity: 1,
                fillOpacity: 0.8
            }).addTo(this.attackLayer);

            // Create a curved line instead of straight line
            const latlngs = this.createCurvedLine(
                [sourceCoords.lat, sourceCoords.lon],
                [destCoords.lat, destCoords.lon]
            );

            // Create the visible attack line
            const attackLine = L.polyline(latlngs, {
                color: color,
                weight: 2,
                opacity: 0.7,
                dashArray: '5, 5'
            }).addTo(this.attackLayer);
            
            // Create an invisible wider line on top for easier hovering
            const hoverLine = L.polyline(latlngs, {
                color: color,
                weight: 10,  // Much wider for easier hovering
                opacity: 0,  // Completely transparent
            }).addTo(this.attackLayer);
            
            // Add tooltip to the hover line
            hoverLine.bindTooltip(`Attack: ${sourceIP} → ${destIP}<br>Severity: ${this.getSeverityText(severity)}<br>Source: ${sourceCoords.city || ''} ${sourceCoords.country || ''}<br>Destination: ${destCoords.city || ''} ${destCoords.country || ''}`);

            sourceMarker.bindTooltip(`Source IP: ${sourceIP} (${sourceCoords.city || ''} ${sourceCoords.country || ''})`);
            destMarker.bindTooltip(`Destination IP: ${destIP} (${destCoords.city || ''} ${destCoords.country || ''})`);

            this.map.fitBounds(this.attackLayer.getBounds(), { padding: [50, 50] });

        } catch (error) {
            // Suppress errors for missing geolocation
        }
    }

    async getIPCoordinates(ipAddress) {
        // Private IP fallback
        if (
            ipAddress.startsWith('10.') ||
            ipAddress.startsWith('192.168.') ||
            ipAddress.startsWith('127.') ||
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ipAddress)
        ) {
            const coords = {
                lat: 45.9432,
                lon: 24.9668,
                city: '',
                country: 'Romania'
            };
            this.ipCache.set(ipAddress, coords);
            return coords;
        }

        if (this.ipCache.has(ipAddress)) {
            return this.ipCache.get(ipAddress);
        }

        try {
            // Use backend proxy to avoid CORS issues
            const response = await fetch(`/api/ipwhois/${ipAddress}`);
            const data = await response.json();
            if (data && data.success) {
                const coords = {
                    lat: parseFloat(data.latitude),
                    lon: parseFloat(data.longitude),
                    city: data.city,
                    country: data.country
                };
                this.ipCache.set(ipAddress, coords);
                return coords;
            }
            return null;
        } catch (error) {
            console.error(`Error geocoding IP ${ipAddress}:`, error);
            return null;
        }
    }

    clear() {
        this.attackLayer.clearLayers();
    }

    // Add this new method to create curved lines
    createCurvedLine(source, dest) {
        // Get the straight-line distance
        const dx = dest[1] - source[1];
        const dy = dest[0] - source[0];
        const distance = Math.sqrt(dx * dx + dy * dy);
        
        // Calculate a random offset for the midpoint (higher for longer distances)
        const offsetFactor = Math.min(0.2, Math.max(0.05, distance * 0.01));
        const randomOffset = (Math.random() * 2 - 1) * offsetFactor;
        
        // Calculate midpoint with offset
        const midLat = (source[0] + dest[0]) / 2;
        const midLon = (source[1] + dest[1]) / 2;
        
        // Apply perpendicular offset to create curve
        const offsetLat = midLat + randomOffset * (dest[1] - source[1]);
        const offsetLon = midLon - randomOffset * (dest[0] - source[0]);
        
        // Create a path with multiple points for a smooth curve
        const path = [];
        const steps = 10;
        
        for (let i = 0; i <= steps; i++) {
            const t = i / steps;
            
            // Quadratic Bezier curve formula
            const lat = (1-t)*(1-t)*source[0] + 2*(1-t)*t*offsetLat + t*t*dest[0];
            const lon = (1-t)*(1-t)*source[1] + 2*(1-t)*t*offsetLon + t*t*dest[1];
            
            path.push([lat, lon]);
        }
        
        return path;
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

window.GeoChart = GeoChart;
