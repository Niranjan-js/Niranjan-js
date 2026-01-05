let severityChart;
let vectorChart;

const COLORS = {
    CRITICAL: '#ef4444',
    HIGH: '#f59e0b',
    MEDIUM: '#3b82f6',
    LOW: '#10b981',
    OTHER: '#94a3b8'
};

function initSeverityChart(data = {}) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    if (severityChart) severityChart.destroy();

    const labels = Object.keys(data).length ? Object.keys(data) : ['NORMAL'];
    const values = Object.values(data).length ? Object.values(data) : [1];
    const bgColors = labels.map(l => COLORS[l] || COLORS.OTHER);

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: bgColors,
                borderWidth: 0,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '75%',
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', usePointStyle: true, padding: 20 } }
            }
        }
    });
}

function initVectorChart(data = {}) {
    const ctx = document.getElementById('vectorChart').getContext('2d');
    if (vectorChart) vectorChart.destroy();

    const labels = Object.keys(data);
    const values = Object.values(data);

    vectorChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.length ? labels : ['Pending'],
            datasets: [{
                label: 'Threat Count',
                data: values.length ? values : [0],
                backgroundColor: 'rgba(56, 189, 248, 0.4)',
                borderColor: '#38bdf8',
                borderWidth: 2,
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

async function fetchSummary() {
    try {
        const response = await fetch('/dashboard/summary');
        const data = await response.json();

        document.getElementById('total').innerText = data.total_threats;
        document.getElementById('rawCount').innerText = data.raw_count;
        document.getElementById('critical').innerText = data.critical;

        initSeverityChart(data.by_severity);
        initVectorChart(data.by_type);
        renderDecisions(data.decisions);
    } catch (err) {
        console.error("Sync error:", err);
    }
}

function renderDecisions(decisions) {
    const container = document.getElementById('aiDecisions');
    if (!decisions || decisions.length === 0) return;

    // Check if we have new decisions to avoid flickering
    const currentCount = container.querySelectorAll('.decision-item').length;
    if (currentCount === decisions.length) return;

    container.innerHTML = '';
    // Limit to latest 50 to match backend or UI constraints
    decisions.slice(-50).reverse().forEach((d, index) => {
        const div = document.createElement('div');
        div.className = 'decision-item';
        if (index === 0 && decisions.length > currentCount) {
            div.classList.add('new-entry');
        }
        div.innerHTML = `
            <div class="decision-header">
                <span style="font-weight: 700; color: #fff;">${d.decision}</span>
                <span class="decision-tag tag-${d.severity.toLowerCase()}">${d.severity}</span>
            </div>
            <p style="color: var(--text-secondary); font-size: 13px;">${d.reason}</p>
            <div class="action-list">
                ${d.actions.map(a => `<span class="action-chip">${a}</span>`).join('')}
            </div>
        `;
        container.appendChild(div);
    });
}

async function analyzeLogs() {
    const logText = document.getElementById('logInput').value;
    if (!logText.trim()) return;

    const btn = document.getElementById('analyzeBtn');
    btn.disabled = true;
    btn.innerText = "Processing...";

    try {
        const response = await fetch('/analyze/logs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ logs: logText.split('\n').filter(l => l.trim()) })
        });
        await response.json();
        await fetchSummary();
        document.getElementById('logInput').value = '';
    } catch (err) {
        console.error("Manual analysis failed:", err);
    } finally {
        btn.disabled = false;
        btn.innerText = "Execute Analysis";
    }
}

document.getElementById('analyzeBtn').addEventListener('click', analyzeLogs);
document.getElementById('refreshBtn').addEventListener('click', fetchSummary);

// Auto-sync every 3 seconds
setInterval(fetchSummary, 3000);

window.onload = () => {
    initSeverityChart();
    initVectorChart();
    fetchSummary();
};