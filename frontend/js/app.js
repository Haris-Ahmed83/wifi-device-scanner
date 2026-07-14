let currentTab = 'devices';
let deviceList = [];
let topologyNetwork = null;
let historyChart = null;
let historyData = { labels: [], counts: [] };

function getDeviceIcon(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('router') || t.includes('gateway') || t.includes('network')) return '\uD83C\uDFE1';
  if (t.includes('phone') || t.includes('mobile') || t.includes('smartphone')) return '\uD83D\uDCF1';
  if (t.includes('laptop') || t.includes('desktop') || t.includes('windows')) return '\uD83D\uDCBB';
  if (t.includes('camera')) return '\uD83D\uDCF7';
  if (t.includes('tv') || t.includes('media') || t.includes('apple')) return '\uD83D\uDCFA';
  if (t.includes('printer')) return '\uD83D\uDDA8';
  return '\u2753';
}

function getGroup(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('router') || t.includes('gateway') || t.includes('network')) return 'router';
  if (t.includes('server') || t.includes('linux')) return 'server';
  if (t.includes('camera') || t.includes('iot')) return 'iot';
  return 'unknown';
}

function formatPorts(ports) {
  if (!ports || ports.length === 0) return 'None';
  return ports.slice(0, 6).map(p => `${p.port} (${p.service || '?'})`).join(', ') +
    (ports.length > 6 ? ` +${ports.length - 6} more` : '');
}

function confidenceBadge(conf) {
  const c = (conf || 'low').toLowerCase();
  const colors = { high: '#22c55e', medium: '#eab308', low: '#ef4444' };
  return `<span class="conf-badge conf-${c}" style="color:${colors[c] || '#888'}">${conf}</span>`;
}

async function loadDevices() {
  try {
    deviceList = await fetchDevices();
    renderDevices();
    renderTopology();
    updateStats();
  } catch (e) {
    console.warn('loadDevices:', e);
  }
}

function renderDevices() {
  const grid = document.getElementById('device-grid');
  if (!deviceList || deviceList.length === 0) {
    grid.innerHTML = '<div class="loading">No devices found. Click Scan Now to start.</div>';
    return;
  }
  grid.innerHTML = deviceList.map((d, i) => {
    const icon = getDeviceIcon(d.device_type);
    const hostname = d.hostname || d.ip || '?';
    const ports = formatPorts(d.open_ports);
    const details = (d.details || []).join(' | ');
    return `
      <div class="device-card" onclick="toggleDevice(${i})">
        <div class="card-header">
          <span class="card-icon">${icon}</span>
          <span class="card-hostname">${hostname}</span>
          ${confidenceBadge(d.confidence)}
        </div>
        <div class="card-meta">
          <span class="card-ip">${d.ip || '?'}</span>
          <span class="card-type">${d.device_type || 'Unknown'}</span>
        </div>
        <div class="card-details" id="detail-${i}" style="display:none">
          <div class="detail-row"><span class="detail-label">MAC</span><code>${d.mac || '?'}</code></div>
          <div class="detail-row"><span class="detail-label">Vendor</span>${d.vendor || 'Unknown'}</div>
          <div class="detail-row"><span class="detail-label">OS</span>${d.os || 'Unknown'} ${d.ttl ? '(TTL: ' + d.ttl + ')' : ''}</div>
          <div class="detail-row"><span class="detail-label">Ports</span>${ports}</div>
          <div class="detail-row"><span class="detail-label">Hostname</span>${d.hostname || 'N/A'}</div>
          ${details ? '<div class="detail-row detail-extra">' + details + '</div>' : ''}
        </div>
      </div>
    `;
  }).join('');
}

function toggleDevice(idx) {
  const el = document.getElementById(`detail-${idx}`);
  if (el) {
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
  }
}

function updateStats() {
  const total = document.getElementById('stat-total');
  const types = document.getElementById('stat-types');
  if (total) total.textContent = deviceList.length;
  if (!types) return;

  const counts = {};
  deviceList.forEach(d => {
    const t = d.device_type || 'Unknown';
    counts[t] = (counts[t] || 0) + 1;
  });
  types.innerHTML = Object.entries(counts).map(([k, v]) =>
    `<div class="stat"><span class="stat-num">${v}</span><span class="stat-label">${k}</span></div>`
  ).join('');
}

function renderTopology() {
  const container = document.getElementById('topology-container');
  if (!container) return;
  if (deviceList.length === 0) {
    container.innerHTML = '<div class="loading">No devices to show</div>';
    return;
  }

  const routerNode = { id: 'router', label: 'Router', group: 'router', size: 35, shape: 'star' };
  const nodes = [routerNode];
  const edges = [];

  deviceList.forEach(d => {
    const nodeId = d.mac || d.ip;
    const hostname = d.hostname || d.ip;
    const group = getGroup(d.device_type);
    nodes.push({
      id: nodeId,
      label: hostname,
      title: `${d.ip}<br>${d.vendor || ''}<br>Ports: ${(d.open_ports || []).map(p => p.port).join(', ')}`,
      group: group,
      size: 20,
      shape: group === 'router' ? 'star' : (group === 'server' ? 'square' : (group === 'iot' ? 'triangle' : 'dot')),
    });
    edges.push({ from: nodeId, to: 'router', color: { color: '#475569' }, width: 2 });
  });

  if (topologyNetwork) {
    topologyNetwork.setData({ nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) });
    return;
  }

  const options = {
    physics: {
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {
        gravitationalConstant: -40,
        centralGravity: 0.01,
        springLength: 150,
        springConstant: 0.08,
      },
      stabilization: { iterations: 100 },
    },
    edges: { smooth: { type: 'continuous' } },
    nodes: {
      font: { color: '#e2e8f0', size: 13 },
      borderWidth: 2,
    },
    groups: {
      router: { color: { background: '#ef4444', border: '#dc2626' } },
      server: { color: { background: '#3b82f6', border: '#2563eb' } },
      iot: { color: { background: '#22c55e', border: '#16a34a' } },
      unknown: { color: { background: '#6b7280', border: '#4b5563' } },
    },
    interaction: { hover: true, navigationButtons: true, keyboard: true },
    backgroundColor: '#0f172a',
  };

  topologyNetwork = new vis.Network(container, { nodes, edges }, options);
}

function initHistoryChart() {
  const canvas = document.getElementById('history-chart');
  if (!canvas || historyChart) return;

  const ctx = canvas.getContext('2d');
  historyChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: historyData.labels,
      datasets: [{
        label: 'Devices Over Time',
        data: historyData.counts,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        fill: true,
        tension: 0.3,
        pointRadius: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#94a3b8', maxTicksLimit: 10 },
          grid: { color: '#1e293b' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#94a3b8', stepSize: 1 },
          grid: { color: '#1e293b' },
        },
      },
      plugins: {
        legend: { labels: { color: '#e2e8f0' } },
      },
    },
  });
}

function addHistoryPoint(count) {
  const now = new Date();
  const time = now.toLocaleTimeString();
  historyData.labels.push(time);
  historyData.counts.push(count);
  if (historyData.labels.length > 50) {
    historyData.labels.shift();
    historyData.counts.shift();
  }
  if (historyChart) {
    historyChart.update('none');
  }
}

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.toggle('active', t.id === `tab-${tab}`));
  if (tab === 'topology') setTimeout(() => renderTopology(), 100);
  if (tab === 'history') setTimeout(() => initHistoryChart(), 100);
}

async function init() {
  try {
    const info = await fetchNetworkInfo();
    if (info) {
      const hostEl = document.getElementById('nav-hostname');
      const ipEl = document.getElementById('nav-ip');
      if (hostEl) hostEl.textContent = info.hostname || '';
      if (ipEl) ipEl.textContent = info.local_ip || '';
    }
  } catch (e) {
    // network info not critical
  }

  await loadDevices();
  initHistoryChart();
  if (deviceList.length > 0) addHistoryPoint(deviceList.length);

  wsClient.on('device_discovered', (msg) => {
    const dev = msg.device;
    const idx = deviceList.findIndex(d => d.mac === dev.mac);
    if (idx >= 0) {
      deviceList[idx] = dev;
    } else {
      deviceList.push(dev);
    }
    if (currentTab === 'devices') renderDevices();
    renderTopology();
    updateStats();
  });

  wsClient.on('scan_complete', (msg) => {
    const count = msg.summary?.devices_found || 0;
    addHistoryPoint(count);
    const timeEl = document.getElementById('nav-scan-time');
    if (timeEl) timeEl.textContent = `Last scan: ${new Date().toLocaleTimeString()}`;
    if (currentTab === 'devices') renderDevices();
    updateStats();
  });

  setInterval(() => loadDevices(), 30000);
}

document.addEventListener('DOMContentLoaded', init);
