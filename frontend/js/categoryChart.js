class CategoryBarChart {
    constructor(canvasId) {
        this.canvasId = canvasId;
        this.chart = null;
        this.categories = {};
        this.initialize();
    }
    
    initialize() {
        const ctx = document.getElementById(this.canvasId).getContext('2d');
        this.chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attack Categories',
                    data: [],
                    backgroundColor: '#4F46E5',
                    borderColor: '#4338CA',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Top Attack Categories',
                        color: '#FFFFFF',
                        font: {
                            size: 16
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#E5E7EB'
                        }
                    },
                    y: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            color: '#E5E7EB'
                        }
                    }
                }
            }
        });
    }
    
    addCategory(category) {
        if (!category) return;
        
        this.categories[category] = (this.categories[category] || 0) + 1;
        this.updateChart();
    }
    
    updateChart() {
        // Sort categories by count and take top 10
        const sortedCategories = Object.entries(this.categories)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);
        
        this.chart.data.labels = sortedCategories.map(item => item[0]);
        this.chart.data.datasets[0].data = sortedCategories.map(item => item[1]);
        this.chart.update();
    }
    
    reset() {
        this.categories = {};
        this.chart.data.labels = [];
        this.chart.data.datasets[0].data = [];
        this.chart.update();
    }
}

// Export for use in app.js
window.CategoryBarChart = CategoryBarChart;