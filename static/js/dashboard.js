/**
 * NetGuard Dashboard - Smart Firewall & IDS
 * Real-time network monitoring with Chart.js visualizations,
 * firewall decision tracking, and attack detection display.
 */

// ============================================================
// Configuration
// ============================================================
const CONFIG = {
    API_BASE: '',
    WS_URL: window.location.origin,
    MAX_TABLE_ROWS: 100,
    MAX_CHART_POINTS: 30,
    REFRESH_INTERVAL: 2000,
    ANIMATION_DURATION: 500,
};

// ============================================================
// State
// ============================================================
const state = {
    captureRunning: false,
    packets: [],
    alerts: [],
    flows: [],
    firewallData: null,
    normalTraffic: null,
    stats: null,
    alertFilter: 'all',
    alertMethodFilter: 'all',
    packetSearch: '',
    charts: {},
    trafficHistory: [],
    protocolData: {},
    socket: null,
};

// ============================================================
// Initialization
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    initializeWebSocket();
    initializeCharts();
    initializeTabs();
    initializeEventListeners();
    startPeriodicRefresh();
    updateClock();
    setInterval(updateClock, 1000);
});

// ============================================================
// WebSocket (Socket.IO loaded from <head> script tag)
// ============================================================
function initializeWebSocket() {
    // Socket.IO is loaded in <head> of index.html — no dynamic script injection
    if (typeof io === 'undefined') {
        console.error('[NetGuard] Socket.IO not loaded! Check index.html <head>.');
        updateConnectionStatus(false);
        return;
    }

    state.socket = io(CONFIG.WS_URL, {
        transports: ['websocket', 'polling'],
    });

    state.socket.on('connect', () => {
        console.log('[NetGuard] WebSocket connected');
        updateConnectionStatus(true);
    });

    state.socket.on('disconnect', () => {
        console.log('[NetGuard] WebSocket disconnected');
        updateConnectionStatus(false);
    });

    state.socket.on('new_packet', (packet) => {
        handleNewPacket(packet);
    });

    state.socket.on('new_alert', (alert) => {
        handleNewAlert(alert);
    });

    state.socket.on('stats_update', (stats) => {
        handleStatsUpdate(stats);
    });

    state.socket.on('firewall_decision', (decision) => {
        handleFirewallDecision(decision);
    });

    state.socket.on('status', (data) => {
        state.captureRunning = data.capture_running;
        updateCaptureButton();
    });
}

// ============================================================
// Charts
// ============================================================
function initializeCharts() {
    // Traffic Timeline Chart
    const trafficCtx = document.getElementById('trafficChart');
    if (trafficCtx) {
        state.charts.traffic = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets/s',
                    data: [],
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHitRadius: 10,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#6366f1',
                }, {
                    label: 'KB/s',
                    data: [],
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.08)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHitRadius: 10,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#06b6d4',
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: CONFIG.ANIMATION_DURATION },
                interaction: { intersect: false, mode: 'index' },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        align: 'end',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Inter', size: 11, weight: '500' },
                            boxWidth: 12,
                            padding: 15,
                            usePointStyle: true,
                            pointStyle: 'circle',
                        },
                    },
                    tooltip: {
                        backgroundColor: 'rgba(17, 24, 39, 0.95)',
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        borderColor: 'rgba(99, 102, 241, 0.3)',
                        borderWidth: 1,
                        cornerRadius: 8,
                        padding: 12,
                        titleFont: { family: 'Inter', weight: '600' },
                        bodyFont: { family: 'JetBrains Mono', size: 12 },
                    },
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(99, 102, 241, 0.06)', drawBorder: false },
                        ticks: { color: '#64748b', font: { size: 10 }, maxTicksLimit: 8 },
                    },
                    y: {
                        grid: { color: 'rgba(99, 102, 241, 0.06)', drawBorder: false },
                        ticks: { color: '#64748b', font: { size: 10 } },
                        beginAtZero: true,
                    },
                },
            },
        });
    }

    // Protocol Distribution Chart
    const protocolCtx = document.getElementById('protocolChart');
    if (protocolCtx) {
        state.charts.protocol = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#6366f1', '#06b6d4', '#f59e0b', '#10b981',
                        '#8b5cf6', '#ec4899', '#ef4444', '#14b8a6',
                        '#f97316', '#64748b',
                    ],
                    borderWidth: 0,
                    hoverOffset: 8,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: CONFIG.ANIMATION_DURATION },
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Inter', size: 11 },
                            padding: 12,
                            usePointStyle: true,
                            pointStyle: 'circle',
                        },
                    },
                    tooltip: {
                        backgroundColor: 'rgba(17, 24, 39, 0.95)',
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        borderColor: 'rgba(99, 102, 241, 0.3)',
                        borderWidth: 1,
                        cornerRadius: 8,
                        padding: 12,
                        callbacks: {
                            label: (ctx) => {
                                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                                const pct = ((ctx.raw / total) * 100).toFixed(1);
                                return ` ${ctx.label}: ${ctx.raw.toLocaleString()} (${pct}%)`;
                            },
                        },
                    },
                },
            },
        });
    }

    // Alert Severity Chart
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        state.charts.severity = new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.6)',
                        'rgba(245, 158, 11, 0.6)',
                        'rgba(139, 92, 246, 0.6)',
                        'rgba(6, 182, 212, 0.6)',
                    ],
                    borderColor: [
                        '#ef4444', '#f59e0b', '#8b5cf6', '#06b6d4',
                    ],
                    borderWidth: 1,
                    borderRadius: 6,
                    borderSkipped: false,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: CONFIG.ANIMATION_DURATION },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(17, 24, 39, 0.95)',
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        borderColor: 'rgba(99, 102, 241, 0.3)',
                        borderWidth: 1,
                        cornerRadius: 8,
                    },
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#64748b', font: { size: 11 } },
                    },
                    y: {
                        grid: { color: 'rgba(99, 102, 241, 0.06)', drawBorder: false },
                        ticks: { color: '#64748b', font: { size: 10 }, stepSize: 1 },
                        beginAtZero: true,
                    },
                },
            },
        });
    }

    // Attack Type Distribution
    const attackCtx = document.getElementById('attackTypeChart');
    if (attackCtx) {
        state.charts.attackType = new Chart(attackCtx, {
            type: 'polarArea',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.5)',
                        'rgba(245, 158, 11, 0.5)',
                        'rgba(139, 92, 246, 0.5)',
                        'rgba(6, 182, 212, 0.5)',
                        'rgba(16, 185, 129, 0.5)',
                        'rgba(236, 72, 153, 0.5)',
                        'rgba(249, 115, 22, 0.5)',
                    ],
                    borderWidth: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: CONFIG.ANIMATION_DURATION },
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Inter', size: 11 },
                            padding: 10,
                            usePointStyle: true,
                        },
                    },
                },
                scales: {
                    r: {
                        grid: { color: 'rgba(99, 102, 241, 0.08)' },
                        ticks: { display: false },
                    },
                },
            },
        });
    }

    // Normal Traffic Protocol Chart
    const normalCtx = document.getElementById('normalProtocolChart');
    if (normalCtx) {
        state.charts.normalProtocol = new Chart(normalCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#10b981', '#06b6d4', '#8b5cf6', '#6366f1',
                        '#14b8a6', '#34d399', '#a78bfa', '#64748b',
                    ],
                    borderWidth: 0,
                    hoverOffset: 8,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: CONFIG.ANIMATION_DURATION },
                cutout: '60%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Inter', size: 11 },
                            padding: 10,
                            usePointStyle: true,
                            pointStyle: 'circle',
                        },
                    },
                    tooltip: {
                        backgroundColor: 'rgba(17, 24, 39, 0.95)',
                        titleColor: '#f1f5f9',
                        bodyColor: '#94a3b8',
                        borderColor: 'rgba(16, 185, 129, 0.3)',
                        borderWidth: 1,
                        cornerRadius: 8,
                        callbacks: {
                            label: (ctx) => {
                                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                                const pct = ((ctx.raw / total) * 100).toFixed(1);
                                return ` ${ctx.label}: ${ctx.raw.toLocaleString()} (${pct}%)`;
                            },
                        },
                    },
                },
            },
        });
    }
}

// ============================================================
// Tabs
// ============================================================
function initializeTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.tab;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${target}`).classList.add('active');
        });
    });
}

// ============================================================
// Event Listeners
// ============================================================
function initializeEventListeners() {
    // Capture toggle
    const captureBtn = document.getElementById('captureToggle');
    if (captureBtn) {
        captureBtn.addEventListener('click', toggleCapture);
    }

    // Packet search
    const searchInput = document.getElementById('packetSearch');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            state.packetSearch = e.target.value.toLowerCase();
            renderPacketTable();
        });
    }

    // Severity filters
    document.querySelectorAll('.filter-chip:not(.method-filter)').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.filter-chip:not(.method-filter)').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            state.alertFilter = chip.dataset.filter;
            renderAlerts();
        });
    });

    // Method filters
    document.querySelectorAll('.filter-chip.method-filter').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.filter-chip.method-filter').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            state.alertMethodFilter = chip.dataset.method;
            renderAlerts();
        });
    });

    // ML retrain
    const retrainBtn = document.getElementById('retrainBtn');
    if (retrainBtn) {
        retrainBtn.addEventListener('click', () => {
            fetch('/api/ml/retrain', { method: 'POST' });
            retrainBtn.textContent = 'Retraining...';
            setTimeout(() => { retrainBtn.textContent = '🔄 Retrain Model'; }, 3000);
        });
    }
}

// ============================================================
// Data Handlers
// ============================================================
function handleNewPacket(packet) {
    state.packets.unshift(packet);
    if (state.packets.length > CONFIG.MAX_TABLE_ROWS) {
        state.packets.pop();
    }
    renderPacketTable();
}

function handleNewAlert(alert) {
    const existingIdx = state.alerts.findIndex(a => a.alert_id === alert.alert_id);
    if (existingIdx >= 0) {
        state.alerts[existingIdx] = alert;
    } else {
        state.alerts.unshift(alert);
        if (state.alerts.length > 200) {
            state.alerts.pop();
        }
    }
    renderAlerts();
    renderOverviewAlerts();
    updateAlertBadge();
    showAlertNotification(alert);
}

function handleStatsUpdate(data) {
    state.stats = data;
    updateStatsCards(data);
    updateTrafficChart(data.capture);
    updateProtocolChart(data.capture);
    updateDetectionCharts(data.detection);
    updateMLStatus(data.detection?.ml);
    updateFirewallStats(data.detection?.firewall);
    updateNormalTrafficStats(data.detection?.normal_traffic);
}

function handleFirewallDecision(decision) {
    // Flash notification for BLOCK decisions
    if (decision.action === 'BLOCK') {
        showFirewallNotification(decision);
    }
    // Update firewall badge
    updateFirewallBadge();
}

// ============================================================
// Stats Cards
// ============================================================
function updateStatsCards(data) {
    const capture = data.capture || {};
    const detection = data.detection || {};

    setElementText('stat-total-packets', formatNumber(capture.total_packets || 0));
    setElementText('stat-pps', (capture.packets_per_second || 0) + ' pps');
    setElementText('stat-total-bytes', formatBytes(capture.total_bytes || 0));
    setElementText('stat-bps', formatBytes(capture.bytes_per_second || 0) + '/s');
    setElementText('stat-encrypted', formatNumber(capture.encrypted_packets || 0));
    setElementText('stat-uptime', formatDuration(capture.uptime || 0));

    // Alert stats — use all_alerts instead of hybrid-only
    const allAlertStats = detection.all_alerts || {};
    const totalAlerts = allAlertStats.total || 0;
    setElementText('stat-alerts', totalAlerts);

    // Show breakdown by method
    const byMethod = allAlertStats.by_method || {};
    setElementText('stat-alerts-breakdown',
        `Rule: ${byMethod['rule-based'] || 0} | ML: ${byMethod['machine-learning'] || 0} | Hybrid: ${byMethod['hybrid'] || 0}`
    );

    const alertCard = document.getElementById('alert-stat-card');
    if (alertCard) {
        if (totalAlerts > 0) {
            alertCard.classList.add('danger');
        } else {
            alertCard.classList.remove('danger');
        }
    }

    // Normal/clean traffic stats
    const normalTraffic = detection.normal_traffic || {};
    setElementText('stat-clean-packets', formatNumber(normalTraffic.total_clean_packets || 0));
    setElementText('stat-clean-ips', `${normalTraffic.unique_safe_ips || 0} safe IPs`);

    setElementText('stat-active-flows', detection.flows?.active || 0);

    // Firewall stats
    const firewall = detection.firewall || {};
    setElementText('stat-blocked-ips', firewall.blocked_ips_count || 0);
    setElementText('stat-flagged-ips', `${firewall.flagged_ips_count || 0} flagged`);
    setElementText('stat-total-decisions', formatNumber(firewall.total_decisions || 0));
    setElementText('stat-decision-breakdown',
        `BLOCK: ${firewall.blocked || 0} | FLAG: ${firewall.flagged || 0} | ALLOW: ${firewall.allowed || 0}`
    );

    const fwCard = document.getElementById('firewall-stat-card');
    if (fwCard) {
        if ((firewall.blocked_ips_count || 0) > 0) {
            fwCard.classList.add('danger');
        } else {
            fwCard.classList.remove('danger');
        }
    }
}

// ============================================================
// Chart Updates
// ============================================================
function updateTrafficChart(capture) {
    if (!state.charts.traffic || !capture) return;

    const now = new Date();
    const timeLabel = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

    const chart = state.charts.traffic;
    chart.data.labels.push(timeLabel);
    chart.data.datasets[0].data.push(capture.packets_per_second || 0);
    chart.data.datasets[1].data.push(Math.round((capture.bytes_per_second || 0) / 1024));

    if (chart.data.labels.length > CONFIG.MAX_CHART_POINTS) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
        chart.data.datasets[1].data.shift();
    }

    chart.update('none');
}

function updateProtocolChart(capture) {
    if (!state.charts.protocol || !capture?.protocol_counts) return;

    const counts = capture.protocol_counts;
    const labels = Object.keys(counts);
    const data = Object.values(counts);

    state.charts.protocol.data.labels = labels;
    state.charts.protocol.data.datasets[0].data = data;
    state.charts.protocol.update('none');
}

function updateDetectionCharts(detection) {
    if (!detection) return;

    // Severity chart — use all_alerts stats, not just hybrid
    if (state.charts.severity && detection.all_alerts?.by_severity) {
        const sev = detection.all_alerts.by_severity;
        state.charts.severity.data.datasets[0].data = [
            sev.critical || 0,
            sev.high || 0,
            sev.medium || 0,
            sev.low || 0,
        ];
        state.charts.severity.update('none');
    }

    // Attack type chart — use all_alerts stats
    if (state.charts.attackType && detection.all_alerts?.by_type) {
        const types = detection.all_alerts.by_type;
        state.charts.attackType.data.labels = Object.keys(types);
        state.charts.attackType.data.datasets[0].data = Object.values(types);
        state.charts.attackType.update('none');
    }
}

// ============================================================
// Normal Traffic
// ============================================================
function updateNormalTrafficStats(normalTraffic) {
    if (!normalTraffic) return;

    setElementText('normal-total-packets', formatNumber(normalTraffic.total_clean_packets || 0));
    setElementText('normal-total-bytes', formatBytes(normalTraffic.total_clean_bytes || 0));
    setElementText('normal-unique-ips', normalTraffic.unique_safe_ips || 0);

    // Calculate clean ratio
    const totalCapture = state.stats?.capture?.total_packets || 1;
    const cleanPackets = normalTraffic.total_clean_packets || 0;
    const ratio = totalCapture > 0 ? ((cleanPackets / totalCapture) * 100).toFixed(1) : '100';
    setElementText('normal-ratio', `${ratio}%`);
}

function fetchNormalTraffic() {
    fetch('/api/normal-traffic')
        .then(r => r.json())
        .then(data => {
            state.normalTraffic = data;
            renderNormalTrafficDetails(data);
        })
        .catch(() => {});
}

function renderNormalTrafficDetails(data) {
    if (!data) return;

    // Update protocol chart
    if (state.charts.normalProtocol && data.protocol_counts) {
        const counts = data.protocol_counts;
        const labels = Object.keys(counts);
        const values = Object.values(counts);

        state.charts.normalProtocol.data.labels = labels;
        state.charts.normalProtocol.data.datasets[0].data = values;
        state.charts.normalProtocol.update('none');
    }

    // Update stats
    setElementText('normal-total-packets', formatNumber(data.total_clean_packets || 0));
    setElementText('normal-total-bytes', formatBytes(data.total_clean_bytes || 0));
    setElementText('normal-unique-ips', data.unique_safe_ips || 0);

    // Calculate clean ratio
    const totalCapture = state.stats?.capture?.total_packets || 1;
    const cleanPackets = data.total_clean_packets || 0;
    const ratio = totalCapture > 0 ? ((cleanPackets / totalCapture) * 100).toFixed(1) : '100';
    setElementText('normal-ratio', `${ratio}%`);

    // Render top safe IPs
    const container = document.getElementById('safeIpsList');
    if (container) {
        const topIps = data.top_safe_ips || [];
        if (topIps.length === 0) {
            container.innerHTML = `
                <div class="empty-state" style="padding: 2rem;">
                    <div class="icon">⏳</div>
                    <p>Collecting normal traffic data...</p>
                </div>
            `;
            return;
        }

        container.innerHTML = topIps.map((entry, idx) => `
            <div class="firewall-entry" style="border-left: 3px solid var(--accent-success); background: rgba(16, 185, 129, 0.05);">
                <div class="fw-ip">
                    <span style="color: var(--accent-success); font-weight: 600;">#${idx + 1}</span>
                    ✅ <code>${entry.ip}</code>
                </div>
                <div class="fw-details">
                    <span class="fw-reason">${formatNumber(entry.packets)} packets · ${formatBytes(entry.bytes)}</span>
                    <span class="fw-time">Last seen: ${entry.last_seen ? new Date(entry.last_seen * 1000).toLocaleTimeString() : '-'}</span>
                </div>
            </div>
        `).join('');
    }
}

// ============================================================
// ML Status
// ============================================================
function updateMLStatus(ml) {
    if (!ml) return;

    let statusText = '⏳ Collecting Data...';
    if (ml.training_in_progress) {
        statusText = '🔄 Training in Progress...';
    } else if (ml.trained) {
        const modelType = ml.model_type === 'xgboost' ? 'XGBoost' : 'Isolation Forest';
        statusText = `✅ ${modelType} Active (×${ml.times_trained || 1})`;
    }

    setElementText('ml-status-text', statusText);
    setElementText('ml-samples', `${ml.samples_collected} / ${ml.min_samples_needed}`);
    setElementText('ml-anomalies', ml.anomalies_detected || 0);

    // Show XGBoost or IF accuracy
    if (ml.xgb_accuracy) {
        setElementText('ml-accuracy', `${(ml.xgb_accuracy * 100).toFixed(1)}% (XGBoost)`);
    } else if (ml.model_accuracy) {
        setElementText('ml-accuracy', `${(ml.model_accuracy * 100).toFixed(1)}%`);
    } else {
        setElementText('ml-accuracy', 'N/A');
    }

    const progressFill = document.getElementById('ml-progress-fill');
    if (progressFill) {
        const pct = ml.trained ? 100 : Math.min(100, (ml.samples_collected / ml.min_samples_needed) * 100);
        progressFill.style.width = `${pct}%`;
    }

    // Update the rule status in Detection Engine tab
    const ruleStatus = document.getElementById('ml-rule-status');
    if (ruleStatus) {
        if (ml.training_in_progress) {
            ruleStatus.style.color = 'var(--accent-warning)';
            ruleStatus.textContent = '🔄 Training...';
        } else if (ml.trained) {
            ruleStatus.style.color = 'var(--accent-success)';
            ruleStatus.textContent = '● Active';
        } else {
            ruleStatus.style.color = 'var(--accent-warning)';
            ruleStatus.textContent = '⏳ Learning';
        }
    }

    // Update XGBoost status
    const xgbStatus = document.getElementById('xgb-rule-status');
    if (xgbStatus) {
        if (ml.model_type === 'xgboost' && ml.trained) {
            xgbStatus.style.color = 'var(--accent-success)';
            xgbStatus.textContent = '● Active';
        } else {
            xgbStatus.style.color = 'var(--accent-warning)';
            xgbStatus.textContent = '⏳ Not Loaded';
        }
    }
}

// ============================================================
// Firewall Status
// ============================================================
function updateFirewallStats(firewall) {
    if (!firewall) return;

    setElementText('fw-total-blocked', firewall.blocked || 0);
    setElementText('fw-total-flagged', firewall.flagged || 0);
    setElementText('fw-total-allowed', firewall.allowed || 0);
    setElementText('fw-active-blocks', firewall.blocked_ips_count || 0);
}

function renderBlockedIps(blockedIps) {
    const container = document.getElementById('blockedIpsList');
    if (!container) return;

    if (!blockedIps || blockedIps.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding: 2rem;">
                <div class="icon">✅</div>
                <p>No IPs currently blocked.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = blockedIps.map(entry => `
        <div class="firewall-entry blocked">
            <div class="fw-ip">🚫 <code>${entry.ip}</code></div>
            <div class="fw-details">
                <span class="fw-reason">${entry.reason}</span>
                <span class="fw-time">Blocked at: ${entry.blocked_at} | ${entry.remaining}s remaining</span>
            </div>
            <button class="btn btn-sm btn-outline" onclick="unblockIp('${entry.ip}')">Unblock</button>
        </div>
    `).join('');
}

function renderFlaggedIps(flaggedIps) {
    const container = document.getElementById('flaggedIpsList');
    if (!container) return;

    if (!flaggedIps || flaggedIps.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding: 2rem;">
                <div class="icon">🟢</div>
                <p>No IPs currently flagged.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = flaggedIps.map(entry => `
        <div class="firewall-entry flagged">
            <div class="fw-ip">⚠️ <code>${entry.ip}</code></div>
            <div class="fw-details">
                <span class="fw-reason">${entry.reason}</span>
                <span class="fw-time">Count: ${entry.count} | First seen: ${entry.first_seen}</span>
            </div>
            <button class="btn btn-sm btn-danger" onclick="blockIp('${entry.ip}')">Block</button>
        </div>
    `).join('');
}

function renderDecisionTable(decisions) {
    const tbody = document.getElementById('decisionTableBody');
    if (!tbody) return;

    const fragment = document.createDocumentFragment();

    (decisions || []).slice(0, 50).forEach(d => {
        const row = document.createElement('tr');
        const actionClass = d.action === 'BLOCK' ? 'action-block' :
                           d.action === 'FLAG' ? 'action-flag' : 'action-allow';
        row.innerHTML = `
            <td>${d.time_str || '-'}</td>
            <td><span class="action-badge ${actionClass}">${d.action}</span></td>
            <td>${d.source_ip || '-'}</td>
            <td>${d.target_ip || '-'}</td>
            <td>${d.attack_type || '-'}</td>
            <td><span class="severity-badge severity-${d.severity}">${(d.severity || 'low').toUpperCase()}</span></td>
            <td>${(d.confidence * 100).toFixed(0)}%</td>
            <td>${d.rule_matched ? '✅' : '❌'}</td>
            <td>${d.ml_matched ? '✅' : '❌'}</td>
        `;
        fragment.appendChild(row);
    });

    tbody.innerHTML = '';
    tbody.appendChild(fragment);
}

function blockIp(ip) {
    fetch(`/api/firewall/block/${ip}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({reason: 'Manually blocked from dashboard'})
    })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                fetchFirewallStatus();
            }
        });
}

function unblockIp(ip) {
    fetch(`/api/firewall/unblock/${ip}`, { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                fetchFirewallStatus();
            }
        });
}

function updateFirewallBadge() {
    const badge = document.getElementById('firewallBadge');
    if (badge && state.firewallData) {
        const count = (state.firewallData.blocked_ips || []).length;
        badge.textContent = count;
        badge.style.display = count > 0 ? 'inline' : 'none';
    }
}

function showFirewallNotification(decision) {
    const originalTitle = document.title;
    document.title = `🔥 BLOCKED: ${decision.source_ip} - NetGuard`;
    setTimeout(() => { document.title = originalTitle; }, 5000);
}

// ============================================================
// Packet Table
// ============================================================
function renderPacketTable() {
    const tbody = document.getElementById('packetTableBody');
    if (!tbody) return;

    let packets = state.packets;
    if (state.packetSearch) {
        packets = packets.filter(p =>
            (p.src_ip || '').toLowerCase().includes(state.packetSearch) ||
            (p.dst_ip || '').toLowerCase().includes(state.packetSearch) ||
            (p.protocol || '').toLowerCase().includes(state.packetSearch) ||
            String(p.src_port).includes(state.packetSearch) ||
            String(p.dst_port).includes(state.packetSearch)
        );
    }

    const fragment = document.createDocumentFragment();
    const displayPackets = packets.slice(0, CONFIG.MAX_TABLE_ROWS);

    displayPackets.forEach(pkt => {
        const row = document.createElement('tr');
        const timeStr = new Date(pkt.timestamp * 1000).toLocaleTimeString('en-US', {
            hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 1,
        });

        row.innerHTML = `
            <td>${timeStr}</td>
            <td>${pkt.src_ip || '-'}</td>
            <td>${pkt.src_port || '-'}</td>
            <td>${pkt.dst_ip || '-'}</td>
            <td>${pkt.dst_port || '-'}</td>
            <td><span class="protocol-badge protocol-${pkt.protocol}">${pkt.protocol}</span></td>
            <td>${pkt.length || 0}</td>
            <td>${pkt.flags || '-'}</td>
            <td>${pkt.is_encrypted ? '<span class="encrypted-icon">🔒</span>' : '-'}</td>
        `;
        fragment.appendChild(row);
    });

    tbody.innerHTML = '';
    tbody.appendChild(fragment);
}

// ============================================================
// Alerts
// ============================================================
function renderAlerts() {
    const container = document.getElementById('alertsList');
    if (!container) return;

    let alerts = state.alerts;

    // Severity filter
    if (state.alertFilter !== 'all') {
        alerts = alerts.filter(a => a.severity === state.alertFilter);
    }

    // Method filter
    if (state.alertMethodFilter !== 'all') {
        alerts = alerts.filter(a => {
            const method = a.detection_method || 'rule-based';
            if (state.alertMethodFilter === 'machine-learning') {
                return method.startsWith('machine-learning');
            }
            return method === state.alertMethodFilter;
        });
    }

    if (alerts.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="icon">🛡️</div>
                <p>No alerts match the current filters. Network appears clean.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = alerts.map(alert => renderAlertCard(alert)).join('');
}

/**
 * Render the Overview tab's "Recent Alerts" preview (top 5 most recent).
 */
function renderOverviewAlerts() {
    const container = document.getElementById('overviewAlerts');
    if (!container) return;

    if (state.alerts.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding: 2rem;">
                <div class="icon">🛡️</div>
                <p>Monitoring... No threats detected yet.</p>
            </div>
        `;
        return;
    }

    // Show top 5 most recent alerts
    const recentAlerts = state.alerts.slice(0, 5);
    container.innerHTML = recentAlerts.map(alert => renderAlertCard(alert)).join('');
}

/**
 * Render a single alert card (shared between Alerts tab and Overview preview).
 */
function renderAlertCard(alert) {
    const methodClass = getMethodClass(alert.detection_method);
    const methodLabel = getMethodLabel(alert.detection_method);
    return `
        <div class="alert-card severity-${alert.severity} animate-in ${alert.severity === 'critical' ? 'glow-danger' : ''}"
             onclick="toggleAlertExpand(this)" id="alert-${alert.alert_id}">
            <div class="alert-header">
                <div class="alert-type">
                    ${getAlertIcon(alert.alert_type)}
                    ${alert.alert_type}
                </div>
                <div class="alert-meta">
                    <span class="detection-method-badge ${methodClass}">${methodLabel}</span>
                    <span class="severity-badge severity-${alert.severity}">${alert.severity}</span>
                    <span>${alert.time_str}</span>
                </div>
            </div>
            <div class="alert-description">${alert.description}</div>
            <div class="alert-ips">
                <span>📤 ${alert.source_ip || 'N/A'}</span>
                ${alert.target_ip ? `<span>→</span><span>📥 ${alert.target_ip}</span>` : ''}
            </div>
            <div class="confidence-bar">
                <div class="confidence-fill ${alert.confidence > 0.7 ? 'high' : alert.confidence > 0.4 ? 'medium' : 'low'}"
                     style="width: ${Math.round(alert.confidence * 100)}%"></div>
            </div>
            <div class="alert-evidence">
                <div class="evidence-title">🔍 Evidence & Explanation</div>
                <ul class="evidence-list">
                    ${(alert.evidence || []).map(e => `<li>${e}</li>`).join('')}
                </ul>
                <div style="margin-top: 0.75rem; text-align: right;">
                    <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); acknowledgeAlert(${alert.alert_id})">
                        ✓ Acknowledge
                    </button>
                </div>
            </div>
        </div>
    `;
}

/**
 * Map detection_method string to CSS class.
 */
function getMethodClass(method) {
    if (!method) return 'method-rule-based';
    if (method === 'hybrid') return 'method-hybrid';
    if (method.startsWith('machine-learning')) return 'method-machine-learning';
    return 'method-rule-based';
}

/**
 * Map detection_method to a human-friendly label.
 */
function getMethodLabel(method) {
    if (!method) return '📋 Rule-Based';
    if (method === 'hybrid') return '⚡ Hybrid';
    if (method === 'machine-learning-xgboost') return '🤖 XGBoost';
    if (method.startsWith('machine-learning')) return '🤖 ML';
    return '📋 Rule-Based';
}

function toggleAlertExpand(el) {
    el.classList.toggle('expanded');
}

function acknowledgeAlert(alertId) {
    fetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
    const el = document.getElementById(`alert-${alertId}`);
    if (el) {
        el.style.opacity = '0.5';
        el.style.transform = 'scale(0.98)';
    }
}

function getAlertIcon(type) {
    const icons = {
        'DDoS': '🌊',
        'Port Scan': '🔍',
        'SYN Flood': '🌊',
        'SQL Injection': '💉',
        'Brute Force': '🔨',
        'DNS Tunneling': '🚇',
        'DNS Tunneling (Frequency)': '🚇',
        'ICMP Flood': '❄️',
        'ARP Spoofing': '🎭',
        'Encrypted Traffic Anomaly': '🔐',
        'ML Anomaly': '🤖',
    };
    // Check for XGBoost prefixed types
    for (const [key, icon] of Object.entries(icons)) {
        if (type.includes(key)) return icon;
    }
    return icons[type] || '⚠️';
}

function updateAlertBadge() {
    const badge = document.getElementById('alertBadge');
    if (badge) {
        badge.textContent = state.alerts.length;
        badge.style.display = state.alerts.length > 0 ? 'inline' : 'none';
    }
}

function showAlertNotification(alert) {
    // Flash the page title
    const originalTitle = document.title;
    document.title = `⚠️ ${alert.alert_type} - NetGuard`;
    setTimeout(() => { document.title = originalTitle; }, 3000);
}

// ============================================================
// Capture Control
// ============================================================
function toggleCapture() {
    if (state.captureRunning) {
        fetch('/api/capture/stop', { method: 'POST' })
            .then(() => {
                state.captureRunning = false;
                updateCaptureButton();
            });
    } else {
        fetch('/api/capture/start', { method: 'POST' })
            .then(() => {
                state.captureRunning = true;
                updateCaptureButton();
            });
    }
}

function updateCaptureButton() {
    const btn = document.getElementById('captureToggle');
    if (!btn) return;

    if (state.captureRunning) {
        btn.className = 'btn btn-danger';
        btn.innerHTML = '⏹ Stop Capture';
    } else {
        btn.className = 'btn btn-primary';
        btn.innerHTML = '▶ Start Capture';
    }
}

// ============================================================
// Periodic Refresh
// ============================================================
function startPeriodicRefresh() {
    // Initial data load
    fetchAlerts();
    fetchPackets();
    fetchFlows();
    fetchFirewallStatus();
    fetchNormalTraffic();

    // Periodic refresh for data not pushed via websocket
    setInterval(fetchAlerts, 5000);
    setInterval(fetchFlows, 5000);
    setInterval(fetchFirewallStatus, 3000);
    setInterval(fetchNormalTraffic, 5000);
}

function fetchAlerts() {
    fetch('/api/alerts?count=100')
        .then(r => r.json())
        .then(data => {
            state.alerts = data;
            renderAlerts();
            renderOverviewAlerts();
            updateAlertBadge();
        })
        .catch(() => {});
}

function fetchPackets() {
    fetch('/api/packets?count=50')
        .then(r => r.json())
        .then(data => {
            state.packets = data;
            renderPacketTable();
        })
        .catch(() => {});
}

function fetchFlows() {
    fetch('/api/flows')
        .then(r => r.json())
        .then(data => {
            state.flows = data;
            renderFlowsTable();
        })
        .catch(() => {});
}

function fetchFirewallStatus() {
    fetch('/api/firewall/status')
        .then(r => r.json())
        .then(data => {
            state.firewallData = data;
            renderBlockedIps(data.blocked_ips);
            renderFlaggedIps(data.flagged_ips);
            renderDecisionTable(data.recent_decisions);
            updateFirewallBadge();
        })
        .catch(() => {});
}

// ============================================================
// Flows Table
// ============================================================
function renderFlowsTable() {
    const tbody = document.getElementById('flowsTableBody');
    if (!tbody) return;

    const fragment = document.createDocumentFragment();

    state.flows.slice(0, 50).forEach(flow => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${flow.src || '-'}</td>
            <td>${flow.dst || '-'}</td>
            <td><span class="protocol-badge protocol-${flow.protocol}">${flow.protocol}</span></td>
            <td>${flow.packets || 0}</td>
            <td>${formatBytes(flow.bytes || 0)}</td>
            <td>${flow.duration || 0}s</td>
            <td>${flow.pps || 0}</td>
            <td>${flow.encrypted ? '<span class="encrypted-icon">🔒</span>' : '-'}</td>
        `;
        fragment.appendChild(row);
    });

    tbody.innerHTML = '';
    tbody.appendChild(fragment);
}

// ============================================================
// Utility Functions
// ============================================================
function setElementText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function formatNumber(n) {
    if (typeof n !== 'number' || isNaN(n)) return '0';
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toString();
}

function formatBytes(bytes) {
    if (typeof bytes !== 'number' || isNaN(bytes) || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    if (typeof seconds !== 'number' || isNaN(seconds)) return '0s';
    if (seconds < 60) return `${Math.floor(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function updateClock() {
    const el = document.getElementById('navClock');
    if (el) {
        const now = new Date();
        el.textContent = now.toLocaleTimeString('en-US', { hour12: false });
    }
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connectionStatus');
    if (statusEl) {
        if (connected) {
            statusEl.className = 'nav-status';
            statusEl.innerHTML = '<span class="status-dot"></span> Live';
        } else {
            statusEl.className = 'nav-status offline';
            statusEl.innerHTML = '<span class="status-dot"></span> Offline';
        }
    }
}
