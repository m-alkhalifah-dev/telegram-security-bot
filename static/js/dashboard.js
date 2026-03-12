/**
 * SecBot Dashboard — auto-refresh, charts, live stats
 */

const MAX_POINTS  = 30;   // history points on charts
const REFRESH_MS  = 30000; // 30 seconds

// Shared chart data history
const cpuHistory  = [];
const ramHistory  = [];
const rxHistory   = [];
const txHistory   = [];
const labels      = [];

let cpuRamChart   = null;
let bwChart       = null;
let bwChart2      = null;   // network page chart

// ── Clock ──────────────────────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  function tick() {
    el.textContent = new Date().toUTCString().replace('GMT', 'UTC');
  }
  tick();
  setInterval(tick, 1000);
}

// ── Sidebar toggle ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  const btn     = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  if (btn && sidebar) {
    btn.addEventListener('click', () => sidebar.classList.toggle('collapsed'));
  }
});

// ── Overview page ──────────────────────────────────────────────────────────
function initOverview() {
  cpuRamChart = buildLineChart('cpuRamChart', [
    { label: 'CPU %',  data: cpuHistory,  color: '#f0c040' },
    { label: 'RAM %',  data: ramHistory,  color: '#40c0f0' },
  ]);
  bwChart = buildLineChart('bandwidthChart', [
    { label: 'RX kbps', data: rxHistory, color: '#40f0a0' },
    { label: 'TX kbps', data: txHistory, color: '#f07040' },
  ]);

  fetchStats();
  fetchBandwidth();
  fetchProcesses();

  setInterval(() => { fetchStats(); fetchBandwidth(); fetchProcesses(); }, REFRESH_MS);
}

// ── Network page ───────────────────────────────────────────────────────────
function initNetworkPage() {
  bwChart2 = buildLineChart('bandwidthChart2', [
    { label: 'RX kbps', data: rxHistory, color: '#40f0a0' },
    { label: 'TX kbps', data: txHistory, color: '#f07040' },
  ]);
  fetchBandwidth();
  fetchDevices();
  setInterval(fetchBandwidth, 5000);
  setInterval(fetchDevices, REFRESH_MS);  // auto-refresh every 30s
}

function fetchDevices() {
  fetch('/api/devices')
    .then(r => r.json())
    .then(d => {
      renderDevicesTable(d.devices || []);
      const countEl = document.getElementById('device-count');
      if (countEl) countEl.textContent = (d.count || 0) + ' devices';
      const updEl = document.getElementById('last-updated');
      if (updEl) updEl.textContent = 'Updated ' + new Date().toLocaleTimeString();
    })
    .catch(() => {});
}

function runScan() {
  const btn = document.getElementById('scan-btn');
  const status = document.getElementById('scan-status');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>Scanning…'; }
  if (status) status.classList.remove('d-none');

  fetch('/api/scan', { method: 'POST' })
    .then(r => r.json())
    .then(d => {
      if (d.error) {
        if (status) { status.classList.remove('d-none'); status.classList.replace('alert-warning', 'alert-danger'); status.innerHTML = '<i class="bi bi-x-circle me-1"></i>' + escHtml(d.error); }
      } else {
        renderDevicesTable(d.devices || []);
        const countEl = document.getElementById('device-count');
        if (countEl) countEl.textContent = (d.count || 0) + ' devices';
        if (status) status.classList.add('d-none');
        const updEl = document.getElementById('last-updated');
        if (updEl) updEl.textContent = 'Scanned ' + new Date().toLocaleTimeString();
      }
    })
    .catch(() => {
      if (status) { status.classList.replace('alert-warning', 'alert-danger'); status.innerHTML = '<i class="bi bi-x-circle me-1"></i>Scan request failed'; }
    })
    .finally(() => {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-radar me-1"></i>Run Scan'; }
    });
}

function renderDevicesTable(devices) {
  const tbody = document.getElementById('devices-tbody');
  if (!tbody) return;
  if (!devices.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4 text-muted">No devices found.</td></tr>';
    return;
  }
  let html = '';
  devices.forEach(d => {
    const statusBadge = d.status === 'known'
      ? '<span class="badge bg-success">Known</span>'
      : '<span class="badge bg-warning text-dark">Unknown</span>';
    html += `<tr>
      <td>${statusBadge}</td>
      <td><code class="text-success">${escHtml(d.mac || '—')}</code></td>
      <td><code>${escHtml(d.ip || '—')}</code></td>
      <td class="text-light">${escHtml(d.hostname || d.vendor || '—')}</td>
      <td class="text-muted small">${escHtml(d.first_seen || '—')}</td>
      <td class="text-muted small">${escHtml(d.last_seen || '—')}</td>
    </tr>`;
  });
  tbody.innerHTML = html;
}

function refreshNetwork() {
  fetchDevices();
}

// ── API fetchers ───────────────────────────────────────────────────────────
function fetchStats() {
  fetch('/api/stats')
    .then(r => r.json())
    .then(d => {
      setText('cpu-val',      d.cpu_percent + '%');
      setText('ram-val',      d.ram_percent + '%');
      setText('temp-val',     d.temp_c + '°C');
      setText('disk-val',     d.disk_percent + '%');
      setText('uptime-val',   d.uptime);
      setText('ram-total-val', d.ram_total_gb + ' GB');
      setText('disk-total-val', d.disk_total_gb + ' GB');

      setBar('cpu-bar',  d.cpu_percent);
      setBar('ram-bar',  d.ram_percent);
      setBar('temp-bar', Math.min(d.temp_c / 85 * 100, 100));
      setBar('disk-bar', d.disk_percent);

      pushChartData(d.cpu_percent, d.ram_percent);
    })
    .catch(() => {});
}

function fetchBandwidth() {
  fetch('/api/bandwidth')
    .then(r => r.json())
    .then(d => {
      setText('net-rx', d.rx_kbps + ' kbps');
      setText('net-tx', d.tx_kbps + ' kbps');
      pushBwData(d.rx_kbps, d.tx_kbps);
    })
    .catch(() => {});
}

function fetchProcesses() {
  fetch('/api/processes')
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById('processes-table');
      if (!el) return;
      if (!d.processes || d.processes.length === 0) {
        el.innerHTML = '<div class="text-muted small">No data</div>';
        return;
      }
      let html = '<table class="table table-dark table-sm mb-0">' +
        '<thead><tr class="text-success">' +
        '<th>PID</th><th>Name</th><th>CPU%</th><th>MEM%</th></tr></thead><tbody>';
      d.processes.forEach(p => {
        html += `<tr>
          <td class="text-muted">${p.pid}</td>
          <td class="text-light">${escHtml(p.name)}</td>
          <td class="text-warning">${p.cpu}</td>
          <td class="text-info">${p.mem}</td>
        </tr>`;
      });
      html += '</tbody></table>';
      el.innerHTML = html;
    })
    .catch(() => {});
}

// ── Chart helpers ──────────────────────────────────────────────────────────
function buildLineChart(canvasId, datasets) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  const ctx = canvas.getContext('2d');
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: datasets.map(ds => ({
        label:       ds.label,
        data:        ds.data,
        borderColor: ds.color,
        backgroundColor: ds.color + '18',
        borderWidth: 1.5,
        pointRadius: 0,
        fill: true,
        tension: 0.4,
      }))
    },
    options: {
      animation: false,
      responsive: true,
      plugins: { legend: { labels: { color: '#7a9a7a', font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: '#4a6a4a', maxTicksLimit: 6 }, grid: { color: 'rgba(0,255,136,0.05)' } },
        y: { ticks: { color: '#4a6a4a' }, grid: { color: 'rgba(0,255,136,0.05)' }, min: 0 }
      }
    }
  });
}

function pushChartData(cpu, ram) {
  const now = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  labels.push(now);
  cpuHistory.push(cpu);
  ramHistory.push(ram);
  if (labels.length > MAX_POINTS) {
    labels.shift(); cpuHistory.shift(); ramHistory.shift();
  }
  if (cpuRamChart) cpuRamChart.update('none');
}

function pushBwData(rx, tx) {
  rxHistory.push(rx);
  txHistory.push(tx);
  if (rxHistory.length > MAX_POINTS) { rxHistory.shift(); txHistory.shift(); }
  if (bwChart)  bwChart.update('none');
  if (bwChart2) bwChart2.update('none');
}

// ── DOM utils ─────────────────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setBar(id, pct) {
  const el = document.getElementById(id);
  if (el) el.style.width = Math.min(pct, 100) + '%';
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
