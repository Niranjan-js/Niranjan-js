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
        document.getElementById('remediated').innerText = data.remediated;
        document.getElementById('critical').innerText = data.critical;

        // Update Pulse
        const pulseBar = document.getElementById('pulseBar');
        const pulseValue = document.getElementById('pulseValue');
        if (pulseBar && pulseValue) {
            pulseValue.innerText = `${data.pulse}%`;
            pulseBar.style.width = `${data.pulse}%`;

            // Change color based on pulse
            if (data.pulse < 40) {
                pulseBar.style.background = 'var(--danger)';
                pulseBar.style.boxShadow = '0 0 10px var(--danger)';
            } else if (data.pulse < 70) {
                pulseBar.style.background = 'var(--warning)';
                pulseBar.style.boxShadow = '0 0 10px var(--warning)';
            } else {
                pulseBar.style.background = 'var(--success)';
                pulseBar.style.boxShadow = '0 0 10px var(--success)';
            }
        }

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
        const threatId = d.id || `threat-${index}`;

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
            <div style="margin-top: 15px; display: flex; justify-content: flex-end;">
                <button class="remediate-btn" onclick="remediateThreat('${threatId}')">Remediate</button>
            </div>
        `;
        container.appendChild(div);
    });
}

async function remediateThreat(threatId) {
    try {
        const response = await fetch('/dashboard/remediate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threat_id: threatId })
        });
        const result = await response.json();
        if (result.status === 'success') {
            await fetchSummary();
        }
    } catch (err) {
        console.error("Remediation failed:", err);
    }
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

// Tab Switching Logic
document.getElementById('textTab').addEventListener('click', () => {
    document.getElementById('textTab').classList.add('active');
    document.getElementById('fileTab').classList.remove('active');
    document.getElementById('textInputArea').style.display = 'block';
    document.getElementById('fileUploadArea').style.display = 'none';
});

document.getElementById('fileTab').addEventListener('click', () => {
    document.getElementById('fileTab').classList.add('active');
    document.getElementById('textTab').classList.remove('active');
    document.getElementById('fileUploadArea').style.display = 'block';
    document.getElementById('textInputArea').style.display = 'none';
});

// File Upload Logic
const logFile = document.getElementById('logFile');
const uploadBtn = document.getElementById('uploadBtn');
const fileInfo = document.getElementById('fileInfo');

logFile.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        fileInfo.innerText = `Selected: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
    }
});

async function uploadFile() {
    const file = logFile.files[0];
    if (!file) return;

    uploadBtn.disabled = true;
    uploadBtn.innerText = "Analyzing File...";

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/analyze/upload', {
            method: 'POST',
            body: formData
        });
        await response.json();
        await fetchSummary();
        fileInfo.innerText = "Analysis complete!";
        logFile.value = '';
    } catch (err) {
        console.error("File upload failed:", err);
        fileInfo.innerText = "Error analyzing file.";
    } finally {
        uploadBtn.disabled = false;
        uploadBtn.innerText = "Analyze File";
    }
}

uploadBtn.addEventListener('click', uploadFile);

document.getElementById('analyzeBtn').addEventListener('click', analyzeLogs);
document.getElementById('refreshBtn').addEventListener('click', fetchSummary);

// Update status every 5 seconds
async function checkStatus() {
    try {
        const res = await fetch('/');
        if (res.ok) {
            document.getElementById('connectionStatus').innerHTML = '<span class="status-dot online"></span> SYSTEM ONLINE';
        }
    } catch {
        document.getElementById('connectionStatus').innerHTML = '<span class="status-dot" style="background:var(--danger); box-shadow:0 0 8px var(--danger);"></span> OFFLINE';
    }
}

// Auto-sync
setInterval(fetchSummary, 3000);
setInterval(checkStatus, 5000);

window.onload = () => {
    initSeverityChart();
    initVectorChart();
    fetchSummary();
    checkStatus();
};