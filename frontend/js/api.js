const API_BASE = '/api/v1';

async function apiGet(path) {
  const r = await fetch(`${API_BASE}${path}`);
  if (!r.ok) throw new Error(`API ${r.status}: ${r.statusText}`);
  return r.json();
}

async function apiPost(path) {
  const r = await fetch(`${API_BASE}${path}`, { method: 'POST' });
  if (!r.ok) throw new Error(`API ${r.status}: ${r.statusText}`);
  return r.json();
}

async function fetchDevices() {
  return apiGet('/devices');
}

async function fetchStats() {
  return apiGet('/devices/summary/stats');
}

async function fetchNetworkInfo() {
  return apiGet('/network/info');
}

async function triggerScan() {
  const btn = document.getElementById('btn-scan');
  btn.disabled = true;
  btn.textContent = '\u23F3 Scanning...';
  await apiGet('/scan');
  btn.disabled = false;
  btn.textContent = '\uD83D\uDD0D Scan Now';
}
