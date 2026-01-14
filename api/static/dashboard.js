let severityChart, historyChart;
let scene, camera, renderer, globe;
let graphSvg, simulation;
let websocket = null;
let reconnectAttempts = 0;
let maxReconnectAttempts = 5;
let threatMarkers = [];

const COLORS = {
    CRITICAL: '#ef4444',
    HIGH: '#f59e0b',
    MEDIUM: '#19f1ff',
    LOW: '#22c55e',
    OTHER: '#94a3b8'
};

// --- Module Navigation ---
function initNavigation() {
    const navItems = document.querySelectorAll('#mainNav li');
    const modules = document.querySelectorAll('.module-section');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetModule = item.getAttribute('data-module');

            // Update UI
            navItems.forEach(ni => ni.classList.remove('active'));
            item.classList.add('active');

            modules.forEach(m => m.classList.remove('active'));
            const targetElem = document.getElementById(`${targetModule}Module`);
            if (targetElem) targetElem.classList.add('active');

            // Update Headers
            document.getElementById('moduleTitle').innerText = item.innerText.trim();
            document.getElementById('moduleSubtitle').innerText = `Live Intelligence: ${item.innerText.trim()} Hub`;

            // Special Init
            if (targetModule === 'map') init3DMap();
            if (targetModule === 'investigation') initGraph();
        });
    });
}

// --- 3D Network Map (Three.js) ---
function init3DMap() {
    const container = document.getElementById('threeJsContainer');
    if (!container || container.children.length > 0) return;

    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(75, container.clientWidth / container.clientHeight, 0.1, 1000);
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);

    // Create Globe
    const geometry = new THREE.SphereGeometry(5, 32, 32);
    const material = new THREE.MeshPhongMaterial({
        color: 0x1e293b,
        wireframe: true,
        transparent: true,
        opacity: 0.3
    });
    globe = new THREE.Mesh(geometry, material);
    scene.add(globe);

    // Add Nodes (Glowing Spheres)
    const points = [];
    for (let i = 0; i < 20; i++) {
        const phi = Math.acos(-1 + (2 * i) / 20);
        const theta = Math.sqrt(20 * Math.PI) * phi;
        const p = new THREE.Vector3().setFromSphericalCoords(5, phi, theta);

        const nodeGeo = new THREE.SphereGeometry(0.15, 8, 8);
        const nodeMat = new THREE.MeshBasicMaterial({ color: 0x19f1ff });
        const node = new THREE.Mesh(nodeGeo, nodeMat);
        node.position.copy(p);
        globe.add(node);
        points.push(p);
    }

    // Add Connections
    const lineMat = new THREE.LineBasicMaterial({ color: 0x19f1ff, transparent: true, opacity: 0.2 });
    for (let i = 0; i < points.length; i++) {
        const lineGeo = new THREE.BufferGeometry().setFromPoints([points[i], points[(i + 1) % points.length]]);
        const line = new THREE.Line(lineGeo, lineMat);
        globe.add(line);
    }

    const light = new THREE.PointLight(0xffffff, 1);
    light.position.set(10, 10, 10);
    scene.add(light);
    scene.add(new THREE.AmbientLight(0x404040));

    camera.position.z = 10;

    function animate() {
        requestAnimationFrame(animate);
        globe.rotation.y += 0.005;
        globe.rotation.x += 0.002;

        // Animate threat markers
        threatMarkers.forEach(marker => {
            marker.scale.x = marker.scale.y = marker.scale.z = 1 + Math.sin(Date.now() * 0.005) * 0.3;
        });

        renderer.render(scene, camera);
    }
    animate();
}

// Add threat marker to 3D map
function addThreatMarker(lat, lon, severity) {
    if (!globe) return;

    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lon + 180) * (Math.PI / 180);
    const position = new THREE.Vector3().setFromSphericalCoords(5.2, phi, theta);

    const color = severity === 'CRITICAL' ? 0xef4444 : severity === 'HIGH' ? 0xf59e0b : 0x19f1ff;
    const markerGeo = new THREE.SphereGeometry(0.2, 8, 8);
    const markerMat = new THREE.MeshBasicMaterial({ color: color });
    const marker = new THREE.Mesh(markerGeo, markerMat);
    marker.position.copy(position);

    globe.add(marker);
    threatMarkers.push(marker);

    // Remove after 10 seconds
    setTimeout(() => {
        globe.remove(marker);
        const index = threatMarkers.indexOf(marker);
        if (index > -1) threatMarkers.splice(index, 1);
    }, 10000);
}

// --- Investigation Graph (D3.js) ---
function initGraph() {
    const container = document.getElementById('investigationGraph');
    if (!container || container.children.length > 0) return;

    const width = container.clientWidth;
    const height = container.clientHeight;

    graphSvg = d3.select("#investigationGraph")
        .append("svg")
        .attr("width", width)
        .attr("height", height);

    const data = {
        nodes: [
            { id: "SOC", group: 1, label: "Core" },
            { id: "192.168.1.50", group: 2, label: "IP-1" },
            { id: "10.0.0.5", group: 2, label: "IP-2" },
            { id: "Threat-X", group: 3, label: "Attack" }
        ],
        links: [
            { source: "SOC", target: "192.168.1.50" },
            { source: "SOC", target: "10.0.0.5" },
            { source: "192.168.1.50", target: "Threat-X" }
        ]
    };

    simulation = d3.forceSimulation(data.nodes)
        .force("link", d3.forceLink(data.links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(width / 2, height / 2));

    const link = graphSvg.append("g")
        .selectAll("line")
        .data(data.links)
        .join("line")
        .attr("stroke", "rgba(255,255,255,0.1)")
        .attr("stroke-width", 2);

    const node = graphSvg.append("g")
        .selectAll("circle")
        .data(data.nodes)
        .join("circle")
        .attr("r", 10)
        .attr("fill", d => d.group === 1 ? COLORS.MEDIUM : (d.group === 2 ? COLORS.LOW : COLORS.CRITICAL))
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));

    node.append("title").text(d => d.id);

    simulation.on("tick", () => {
        link.attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        node.attr("cx", d => d.x).attr("cy", d => d.y);
    });

    function dragstarted(event) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
    }
    function dragged(event) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
    }
    function dragended(event) {
        if (!event.active) simulation.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
    }
}

// --- Data Synchronization ---
async function fetchSummary() {
    try {
        const response = await fetch('/dashboard/summary');
        const data = await response.json();

        // Update Overview
        updateOverview(data);

        // Update Matrix
        updateMatrix(data.correlated_attacks || []);

        // Update Charts
        initSeverityChart(data.by_severity);
        initHistoryChart(data.history);

        // Update Funnel
        updateFunnel(data);

        // Update MITRE
        updateMitre(data.mitre_tactics || {});

        // Update AI Feeds
        renderDecisions(data.decisions || []);
        updateLatestThreats(data.decisions || []);

        // Cloud & Pulse
        if (document.getElementById('pulseValue')) document.getElementById('pulseValue').innerText = `${data.pulse}%`;
        if (document.getElementById('pulseBar')) document.getElementById('pulseBar').style.width = `${data.pulse}%`;

    } catch (err) {
        console.error("Dashboard Sync Error:", err);
    }
}

function updateOverview(data) {
    const ents = data.entities || {};
    if (document.getElementById('resCount')) document.getElementById('resCount').innerText = ents.Resources || 0;
    if (document.getElementById('identCount')) document.getElementById('identCount').innerText = ents.Identities || 0;
    if (document.getElementById('machCount')) document.getElementById('machCount').innerText = ents.Machine || 0;
    if (document.getElementById('roleCount')) document.getElementById('roleCount').innerText = ents.Roles || 0;
}

function updateMatrix(attacks) {
    const body = document.getElementById('matrixBody');
    if (!body) return;
    body.innerHTML = '';

    attacks.forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-family: monospace; color: var(--accent-primary)">${Math.random().toString(16).substr(2, 6).toUpperCase()}</td>
            <td>${a.source_ip}</td>
            <td>${a.attack}</td>
            <td><span class="badge" style="background:rgba(25,241,255,0.1); color:var(--accent-primary)">AGENT_01</span></td>
            <td><span class="status-dot online"></span> ACTIVE</td>
            <td><button class="badge" onclick="remediate('${a.source_ip}')" style="background:var(--success); border:none; cursor:pointer">REMEDIATE</button></td>
        `;
        body.appendChild(tr);
    });
}

// --- Existing Visual Helpers (Restored & Refined) ---

function initSeverityChart(data = {}) {
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (severityChart) severityChart.destroy();

    const labels = Object.keys(data).length ? Object.keys(data) : ['SECURE'];
    const values = Object.values(data).length ? Object.values(data) : [1];

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: labels.map(l => COLORS[l] || COLORS.OTHER),
                borderWidth: 0
            }]
        },
        options: { responsive: true, cutout: '80%', plugins: { legend: { display: false } } }
    });
}

function initHistoryChart(history = {}) {
    const canvas = document.getElementById('historyChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (historyChart) historyChart.destroy();

    historyChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: history.times || [],
            datasets: [{
                label: 'Attacks',
                data: history.threat_counts || [],
                borderColor: COLORS.MEDIUM,
                fill: true,
                backgroundColor: 'rgba(25, 241, 255, 0.1)',
                tension: 0.4
            }]
        },
        options: { responsive: true, scales: { x: { display: false }, y: { display: false } }, plugins: { legend: { display: false } } }
    });
}

function updateFunnel(data) {
    const raw = Math.max(data.raw_count * 10, 50000);
    const findings = data.raw_count || 0;
    const correlated = data.total_threats || 0;
    const incidents = Math.floor(correlated * 0.4);

    document.getElementById('rawEventsCount').innerText = raw.toLocaleString();
    document.getElementById('findingsCount').innerText = findings;
    document.getElementById('correlatedCount').innerText = correlated;
    document.getElementById('incidentsCount').innerText = Math.max(incidents, (correlated > 0 ? 1 : 0));
}

function updateMitre(tactics) {
    const container = document.getElementById('mitreTable');
    if (!container) return;
    container.innerHTML = '';
    Object.entries(tactics).sort((a, b) => b[1] - a[1]).slice(0, 5).forEach(([t, c]) => {
        const div = document.createElement('div');
        div.className = 'mitre-item';
        div.innerHTML = `<span>${t}</span><span class="badge" style="background:var(--bg-input)">${c}</span>`;
        container.appendChild(div);
    });
}

function renderDecisions(decisions) {
    const container = document.getElementById('aiDecisions');
    if (!container) return;
    container.innerHTML = '';
    decisions.slice(-5).reverse().forEach(d => {
        const div = document.createElement('div');
        div.className = 'glass-card';
        div.style.marginBottom = '15px';
        div.style.padding = '15px';
        div.innerHTML = `<h5>${d.decision}</h5><p style="font-size:12px; color:var(--text-muted)">${d.reason}</p>`;
        container.appendChild(div);
    });
}

function updateLatestThreats(decisions) {
    const list = document.getElementById('latestThreatsList');
    if (!list) return;
    list.innerHTML = '';
    decisions.slice(-3).forEach(d => {
        const div = document.createElement('div');
        div.className = 'mitre-item';
        div.innerHTML = `<span>${d.decision}</span><span class="badge" style="background:${COLORS[d.severity]}">${d.severity}</span>`;
        list.appendChild(div);
    });
}

// --- Event Listeners ---
document.getElementById('textTab')?.addEventListener('click', () => switchTab('textTab', 'textInputArea'));
document.getElementById('emailTab')?.addEventListener('click', () => switchTab('emailTab', 'emailInputArea'));
document.getElementById('ipTab')?.addEventListener('click', () => switchTab('ipTab', 'ipInputArea'));

function switchTab(btn, area) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(a => a.style.display = 'none');
    document.getElementById(btn).classList.add('active');
    document.getElementById(area).style.display = 'block';
}

document.getElementById('analyzeBtn')?.addEventListener('click', () => performAnalysis('/analyze/logs', { logs: document.getElementById('logInput').value.split('\n') }));
document.getElementById('analyzeEmailBtn')?.addEventListener('click', () => performAnalysis('/analyze/email', { content: document.getElementById('emailInput').value }));
document.getElementById('analyzeIpBtn')?.addEventListener('click', () => performAnalysis('/analyze/ip', { scan_data: document.getElementById('ipInput').value }));

async function performAnalysis(url, body) {
    const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    await resp.json();
    fetchSummary();
}

// ===== WebSocket Connection =====
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    websocket = new WebSocket(wsUrl);

    websocket.onopen = () => {
        console.log('[WebSocket] Connected to real-time threat feed');
        notifications.show('Connected to real-time threat intelligence', 'success', 3000);
        reconnectAttempts = 0;

        // Update connection status
        const statusEl = document.getElementById('connectionStatus');
        if (statusEl) {
            statusEl.innerHTML = '<span class="status-dot online"></span> REAL-TIME ACTIVE';
        }
    };

    websocket.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
        } catch (e) {
            console.error('[WebSocket] Error parsing message:', e);
        }
    };

    websocket.onerror = (error) => {
        console.error('[WebSocket] Error:', error);
    };

    websocket.onclose = () => {
        console.log('[WebSocket] Connection closed');
        const statusEl = document.getElementById('connectionStatus');
        if (statusEl) {
            statusEl.innerHTML = '<span class="status-dot offline"></span> RECONNECTING...';
        }

        // Attempt to reconnect
        if (reconnectAttempts < maxReconnectAttempts) {
            reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
            console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${reconnectAttempts})`);
            setTimeout(connectWebSocket, delay);
        } else {
            notifications.show('Real-time connection lost. Falling back to polling.', 'warning');
            // Fallback to polling
            setInterval(fetchSummary, 5000);
        }
    };
}

function handleWebSocketMessage(message) {
    console.log('[WebSocket] Received:', message.type);

    switch (message.type) {
        case 'connection':
            console.log('[WebSocket] Connection established');
            break;

        case 'threat_update':
            handleThreatUpdate(message.data);
            break;

        case 'alert':
            handleAlert(message);
            break;

        case 'remediation':
            handleRemediation(message.data);
            break;

        default:
            console.log('[WebSocket] Unknown message type:', message.type);
    }
}

function handleThreatUpdate(data) {
    // Refresh dashboard data
    fetchSummary();

    // Show notification for new threats
    if (data.new_threats && data.new_threats.length > 0) {
        const threat = data.new_threats[0];
        const severity = threat.severity || 'MEDIUM';

        // Add threat marker to 3D map
        const randomLat = Math.random() * 180 - 90;
        const randomLon = Math.random() * 360 - 180;
        addThreatMarker(randomLat, randomLon, severity);

        // Show notification
        const notifType = severity === 'CRITICAL' ? 'critical' : severity === 'HIGH' ? 'warning' : 'info';
        notifications.show(
            `${threat.attack || 'Threat'} detected from ${threat.source_ip || 'unknown source'}`,
            notifType,
            5000
        );
    }
}

function handleAlert(message) {
    const severity = message.severity || 'INFO';
    const type = severity === 'CRITICAL' ? 'critical' : severity === 'HIGH' ? 'warning' : 'info';
    notifications.show(message.message, type, 8000);
}

function handleRemediation(data) {
    notifications.show(`Threat remediated: ${data.threat_id || 'Unknown'}`, 'success', 4000);
    fetchSummary();
}

// Add CSS for status indicators
const statusStyle = document.createElement('style');
statusStyle.textContent = `
    .status-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 8px;
    }
    .status-dot.online {
        background: #22c55e;
        box-shadow: 0 0 10px #22c55e;
        animation: pulse 2s infinite;
    }
    .status-dot.offline {
        background: #ef4444;
    }
    .status-badge {
        display: flex;
        align-items: center;
        padding: 8px 16px;
        background: rgba(30, 41, 59, 0.7);
        border-radius: 8px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.5px;
    }
`;
document.head.appendChild(statusStyle);

window.onload = () => {
    initNavigation();
    fetchSummary();
    connectWebSocket(); // Use WebSocket instead of polling
};