// Global variables for Chart references
let protocolChart = null;
let threatChart = null;

// DOM Elements
const elements = {
    profileSelect: document.getElementById('profile-select'),
    btnRunSimulation: document.getElementById('btn-run-simulation'),
    dropZone: document.getElementById('pcap-drop-zone'),
    fileInput: document.getElementById('pcap-file-input'),
    progressContainer: document.getElementById('upload-progress-container'),
    progressBar: document.getElementById('upload-progress'),
    
    // Stats elements
    statTotalPackets: document.getElementById('stat-total-packets'),
    statTotalAlerts: document.getElementById('stat-total-alerts'),
    statPortScans: document.getElementById('stat-port-scans'),
    statSynFloods: document.getElementById('stat-syn-floods'),
    
    // Logs and tables
    terminalConsole: document.getElementById('terminal-console'),
    btnClearLogs: document.getElementById('btn-clear-logs'),
    alertsTableBody: document.getElementById('alerts-table-body'),
    
    systemStatusIndicator: document.getElementById('system-status-indicator'),
    systemStatusText: document.getElementById('system-status-text')
};

// Initialize the Application
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    setupEventListeners();
    checkHealth();
});

// Setup event listeners
function setupEventListeners() {
    // Clear logs button
    elements.btnClearLogs.addEventListener('click', () => {
        elements.terminalConsole.innerHTML = '';
        logToTerminal('System', 'Console cleared.', 'system-msg');
    });

    // Run Simulation Button
    elements.btnRunSimulation.addEventListener('click', runSimulation);

    // Dropzone Events
    elements.dropZone.addEventListener('click', () => elements.fileInput.click());
    
    elements.fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    elements.dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        elements.dropZone.classList.add('dragover');
    });

    elements.dropZone.addEventListener('dragleave', () => {
        elements.dropZone.classList.remove('dragover');
    });

    elements.dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        elements.dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
}

// Health Check API
async function checkHealth() {
    try {
        const response = await fetch('/api/health');
        if (response.ok) {
            elements.systemStatusIndicator.className = 'status-indicator online';
            elements.systemStatusText.innerText = 'System Active';
        } else {
            throw new Error();
        }
    } catch {
        elements.systemStatusIndicator.className = 'status-indicator offline';
        elements.systemStatusText.innerText = 'Service Unreachable';
        logToTerminal('System', '[WARN] Backend web service is unreachable. Check local server terminal.', 'alert-msg');
    }
}

// Write line to log terminal console
function logToTerminal(sender, message, styleClass = '') {
    const timestamp = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = `terminal-line ${styleClass}`;
    line.innerHTML = `[${timestamp}] [${sender}] ${escapeHTML(message)}`;
    elements.terminalConsole.appendChild(line);
    elements.terminalConsole.scrollTop = elements.terminalConsole.scrollHeight;
}

// Escape HTML utility
function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
}

// Run Simulation
async function runSimulation() {
    setLoadingState(true);
    logToTerminal('System', `Requesting threat simulation replay under ${elements.profileSelect.value} profile...`, 'system-msg');
    
    try {
        const response = await fetch(`/api/replay-test?profile=${elements.profileSelect.value}`);
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Simulation error.');
        }
        
        const data = await response.json();
        logToTerminal('System', 'Simulation complete. Displaying threat detection analysis.', 'system-msg');
        displayResults(data);
    } catch (error) {
        logToTerminal('System', `Simulation failed: ${error.message}`, 'alert-msg');
    } finally {
        setLoadingState(false);
    }
}

// Upload and analyze PCAP
async function handleFileUpload(file) {
    if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
        logToTerminal('System', '[ERROR] Invalid file format. Only .pcap or .pcapng files are supported.', 'alert-msg');
        return;
    }

    setLoadingState(true);
    logToTerminal('System', `Uploading ${file.name} (Size: ${(file.size / 1024 / 1024).toFixed(2)} MB)...`, 'system-msg');
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        // Simple progress simulation
        elements.progressContainer.classList.remove('hidden');
        elements.progressBar.style.width = '30%';
        
        const profile = elements.profileSelect.value;
        const response = await fetch(`/api/analyze?profile=${profile}`, {
            method: 'POST',
            body: formData
        });
        
        elements.progressBar.style.width = '90%';

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Analysis error.');
        }

        elements.progressBar.style.width = '100%';
        const data = await response.json();
        logToTerminal('System', `Analysis of ${file.name} completed successfully.`, 'system-msg');
        displayResults(data);
    } catch (error) {
        logToTerminal('System', `Analysis failed: ${error.message}`, 'alert-msg');
    } finally {
        setTimeout(() => {
            elements.progressContainer.classList.add('hidden');
            elements.progressBar.style.width = '0%';
        }, 1000);
        setLoadingState(false);
    }
}

// Controls loading UI state
function setLoadingState(isLoading) {
    if (isLoading) {
        elements.btnRunSimulation.disabled = true;
        elements.dropZone.style.pointerEvents = 'none';
        elements.dropZone.style.opacity = '0.6';
    } else {
        elements.btnRunSimulation.disabled = false;
        elements.dropZone.style.pointerEvents = 'auto';
        elements.dropZone.style.opacity = '1';
    }
}

// Display results and populate graphs
function displayResults(data) {
    // 1. Animate counters
    animateValue(elements.statTotalPackets, data.packets_processed);
    animateValue(elements.statTotalAlerts, data.alerts_count);

    // Sum details for threat categories
    let portScans = 0;
    let synFloods = 0;
    let arpSpoofing = 0;

    data.alerts.forEach(alert => {
        const type = alert.alert_type.toLowerCase();
        if (type.includes('port scan') || type.includes('portscan')) portScans++;
        else if (type.includes('syn flood') || type.includes('synflood')) synFloods++;
        else if (type.includes('arp')) arpSpoofing++;
    });

    animateValue(elements.statPortScans, portScans);
    animateValue(elements.statSynFloods, synFloods);

    // 2. Log Alert events to the terminal console
    if (data.alerts.length === 0) {
        logToTerminal('NIDS Engine', 'Analysis finished. No suspicious activity or threats detected.', 'system-msg');
    } else {
        data.alerts.forEach(alert => {
            logToTerminal('ALERT', `[${alert.alert_type.toUpperCase()}] Source: ${alert.src_ip} -> Destination: ${alert.dst_ip} | Details: ${alert.details}`, 'alert-msg');
        });
    }

    // 3. Update Chart datasets
    updateCharts(data.protocol_stats, {
        "Port Scan": portScans,
        "SYN Flood": synFloods,
        "ARP Spoofing": arpSpoofing
    });

    // 4. Render Table data
    renderAlertTable(data.alerts);
}

// Count Animation Utility
function animateValue(obj, endValue) {
    let startValue = 0;
    const duration = 800; // ms
    const startTime = performance.now();

    function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const value = Math.floor(progress * (endValue - startValue) + startValue);
        obj.innerText = value.toLocaleString();
        if (progress < 1) {
            requestAnimationFrame(step);
        } else {
            obj.innerText = endValue.toLocaleString();
        }
    }
    requestAnimationFrame(step);
}

// Populate Alert table rows
function renderAlertTable(alerts) {
    elements.alertsTableBody.innerHTML = '';
    
    if (alerts.length === 0) {
        elements.alertsTableBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="6">No alerts loaded. Analyze a PCAP capture file or click "Run Threat Simulation".</td>
            </tr>
        `;
        return;
    }

    alerts.forEach(alert => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${escapeHTML(alert.timestamp)}</td>
            <td><span class="badge badge-high">High</span></td>
            <td><strong>${escapeHTML(alert.alert_type)}</strong></td>
            <td><code>${escapeHTML(alert.src_ip)}</code></td>
            <td><code>${escapeHTML(alert.dst_ip)}</code></td>
            <td>${escapeHTML(alert.details)}</td>
        `;
        
        elements.alertsTableBody.appendChild(row);
    });
}

// Charts Initialization
function initCharts() {
    const ctxProtocol = document.getElementById('protocol-chart').getContext('2d');
    const ctxThreat = document.getElementById('threat-chart').getContext('2d');

    // Chart.js default fonts custom settings
    Chart.defaults.color = '#90a0b0';
    Chart.defaults.font.family = "'Inter', sans-serif";

    protocolChart = new Chart(ctxProtocol, {
        type: 'bar',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'OTHER'],
            datasets: [{
                label: 'Packet Counts',
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(0, 191, 255, 0.65)',
                    'rgba(0, 255, 136, 0.65)',
                    'rgba(255, 160, 0, 0.65)',
                    'rgba(238, 130, 238, 0.65)',
                    'rgba(144, 160, 176, 0.65)'
                ],
                borderColor: [
                    '#00bfff',
                    '#00ff88',
                    '#ffa000',
                    '#ee82ee',
                    '#90a0b0'
                ],
                borderWidth: 1.5,
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { precision: 0 }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });

    threatChart = new Chart(ctxThreat, {
        type: 'doughnut',
        data: {
            labels: ['Port Scan', 'SYN Flood', 'ARP Spoofing'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(255, 160, 0, 0.7)',
                    'rgba(255, 51, 68, 0.7)',
                    'rgba(0, 255, 136, 0.7)'
                ],
                borderColor: '#141821',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { boxWidth: 12, padding: 15 }
                }
            },
            cutout: '65%'
        }
    });
}

// Update charts with actual analysis data
function updateCharts(protocolStats, threatStats) {
    if (protocolChart) {
        protocolChart.data.datasets[0].data = [
            protocolStats.TCP || 0,
            protocolStats.UDP || 0,
            protocolStats.ICMP || 0,
            protocolStats.ARP || 0,
            protocolStats.OTHER || 0
        ];
        protocolChart.update();
    }

    if (threatChart) {
        threatChart.data.datasets[0].data = [
            threatStats["Port Scan"] || 0,
            threatStats["SYN Flood"] || 0,
            threatStats["ARP Spoofing"] || 0
        ];
        threatChart.update();
    }
}
