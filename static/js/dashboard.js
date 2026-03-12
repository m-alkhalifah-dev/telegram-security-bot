/**
 * SecBot Dashboard v3.0 — JavaScript
 * Handles charts, API polling, real-time updates, toast notifications.
 */

'use strict';

// ── Globals ───────────────────────────────────────────────────────────────────

let cpuRamChart = null;
let bandwidthChart = null;
let bwChart = null;
let gaugeCharts = {};
let cpuHistory = [];
let ramHistory = [];
let bwRxHistory = [];
let bwTxHistory = [];
const MAX_HISTORY = 30;

// ── Clock ─────────────────────────────────────────────────────────────────────

function updateClock() {
  const el = document.getElementById('clock');
  if (el) {
    el.textContent = new Date().toUTCString().slice(17, 25) + ' UTC';
  }
}

setInterval(updateClock, 1000);
updateClock();

// ── Sidebar toggle ────────────────────────────────────────────────────────────

function isMobile() {
  return window.innerWidth <= 768;
}

function closeSidebar() {
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  if (!sidebar) return;
  if (isMobile()) {
    sidebar.classList.remove('open');
  } else {
    sidebar.classList.add('collapsed');
  }
  if (backdrop) backdrop.classList.remove('show');
}

function openSidebar() {
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  if (!sidebar) return;
  if (isMobile()) {
    sidebar.classList.add('open');
    if (backdrop) backdrop.classList.add('show');
  } else {
    sidebar.classList.remove('collapsed');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const toggleBtn = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      if (isMobile()) {
        const isOpen = sidebar.classList.contains('open');
        isOpen ? closeSidebar() : openSidebar();
      } else {
        const isCollapsed = sidebar.classList.contains('collapsed');
        isCollapsed ? openSidebar() : closeSidebar();
      }
    });
  }

  // Close sidebar when clicking backdrop
  if (backdrop) {
    backdrop.addEventListener('click', closeSidebar);
  }

  // Close sidebar on mobile when clicking a nav link
  if (sidebar) {
    sidebar.querySelectorAll('.sidebar-link').forEach(link => {
      link.addEventListener('click', () => {
        if (isMobile()) closeSidebar();
      });
    });
  }

  // On resize: clean up classes so desktop always shows sidebar
  window.addEventListener('resize', () => {
    if (!isMobile()) {
      if (sidebar) sidebar.classList.remove('open');
      if (backdrop) backdrop.classList.remove('show');
    }
  });

  // Load hostname into navbar
  fetch('/api/status')
    .then(r => r.ok ? r.json() : null)
    .then(d => {
      if (!d) return;
      const el = document.getElementById('hostname-display');
      if (el) el.textContent = d.hostname || 'SecBot';
    })
    .catch(() => {});
});

// ── Toast notifications ───────────────────────────────────────────────────────

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const colors = { success: '#00cc66', danger: '#ff4444', warning: '#ffaa00', info: '#4488ff' };
  const icons = { success: 'check-circle', danger: 'exclamation-triangle', warning: 'exclamation-circle', info: 'info-circle' };

  const toastEl = document.createElement('div');
  toastEl.className = 'toast show align-items-center';
  toastEl.style.borderLeft = `3px solid ${colors[type] || colors.info}`;
  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">
        <i class="bi bi-${icons[type] || 'info-circle'} me-2" style="color:${colors[type]}"></i>${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="this.closest('.toast').remove()"></button>
    </div>
  `;
  container.appendChild(toastEl);
  setTimeout(() => toastEl.remove(), 4000);
}

// ── Gauge charts (doughnut) ───────────────────────────────────────────────────

function initGauges() {
  const gauges = [
    { id: 'cpuGauge', color: '#f0a500' },
    { id: 'ramGauge', color: '#0dcaf0' },
    { id: 'tempGauge', color: '#ff4444' },
    { id: 'diskGauge', color: '#00cc66' },
  ];

  gauges.forEach(g => {
    const canvas = document.getElementById(g.id);
    if (!canvas) return;
    gaugeCharts[g.id] = new Chart(canvas, {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [0, 100],
          backgroundColor: [g.color, 'rgba(255,255,255,0.04)'],
          borderWidth: 0,
          cutout: '72%',
        }]
      },
      options: {
        responsive: false,
        animation: { animateRotate: true, duration: 500 },
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      }
    });
  });
}

function updateGauge(id, value) {
  const chart = gaugeCharts[id];
  if (!chart) return;
  chart.data.datasets[0].data = [value, Math.max(0, 100 - value)];
  chart.update('none');
}

// ── CPU/RAM line chart ────────────────────────────────────────────────────────

function initCpuRamChart() {
  const canvas = document.getElementById('cpuRamChart');
  if (!canvas) return;

  cpuRamChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'CPU %',
          data: [],
          borderColor: '#f0a500',
          backgroundColor: 'rgba(240,165,0,0.08)',
          tension: 0.4, fill: true, pointRadius: 0,
          borderWidth: 1.5,
        },
        {
          label: 'RAM %',
          data: [],
          borderColor: '#0dcaf0',
          backgroundColor: 'rgba(13,202,240,0.08)',
          tension: 0.4, fill: true, pointRadius: 0,
          borderWidth: 1.5,
        }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      animation: { duration: 300 },
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#4a6080', font: { size: 9 }, maxTicksLimit: 8 },
          grid: { color: 'rgba(255,255,255,0.03)' },
        },
        y: {
          min: 0, max: 100,
          ticks: { color: '#4a6080', font: { size: 9 }, callback: v => v + '%' },
          grid: { color: 'rgba(255,255,255,0.05)' },
        }
      }
    }
  });
}

// ── Bandwidth chart (overview page) ──────────────────────────────────────────

function initBandwidthLineChart() {
  const canvas = document.getElementById('bandwidthChart');
  if (!canvas) return;

  bandwidthChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'RX (kbps)',
          data: [],
          borderColor: '#0dcaf0',
          backgroundColor: 'rgba(13,202,240,0.06)',
          tension: 0.4, fill: true, pointRadius: 0, borderWidth: 1.5,
        },
        {
          label: 'TX (kbps)',
          data: [],
          borderColor: '#f0a500',
          backgroundColor: 'rgba(240,165,0,0.06)',
          tension: 0.4, fill: true, pointRadius: 0, borderWidth: 1.5,
        }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      animation: { duration: 200 },
      plugins: { legend: {
        display: true,
        labels: { color: '#6b7e9e', font: { size: 9 } }
      }},
      scales: {
        x: {
          ticks: { color: '#4a6080', font: { size: 9 }, maxTicksLimit: 6 },
          grid: { color: 'rgba(255,255,255,0.03)' }
        },
        y: {
          ticks: { color: '#4a6080', font: { size: 9 } },
          grid: { color: 'rgba(255,255,255,0.05)' }
        }
      }
    }
  });
}

// ── Bandwidth chart (network page) ────────────────────────────────────────────

function initBandwidthChart() {
  const canvas = document.getElementById('bwChart');
  if (!canvas) return;

  bwChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Download (kbps)',
          data: [],
          borderColor: '#0dcaf0',
          backgroundColor: 'rgba(13,202,240,0.06)',
          tension: 0.4, fill: true, pointRadius: 0, borderWidth: 1.5,
        },
        {
          label: 'Upload (kbps)',
          data: [],
          borderColor: '#f0a500',
          backgroundColor: 'rgba(240,165,0,0.06)',
          tension: 0.4, fill: true, pointRadius: 0, borderWidth: 1.5,
        }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      animation: { duration: 200 },
      plugins: { legend: {
        display: true,
        labels: { color: '#6b7e9e', font: { size: 9 } }
      }},
      scales: {
        x: {
          ticks: { color: '#4a6080', font: { size: 9 }, maxTicksLimit: 6 },
          grid: { color: 'rgba(255,255,255,0.03)' }
        },
        y: {
          ticks: { color: '#4a6080', font: { size: 9 } },
          grid: { color: 'rgba(255,255,255,0.05)' }
        }
      }
    }
  });
}

function pushChart(chart, label, ...values) {
  if (!chart) return;
  chart.data.labels.push(label);
  values.forEach((v, i) => chart.data.datasets[i].data.push(v));
  if (chart.data.labels.length > MAX_HISTORY) {
    chart.data.labels.shift();
    chart.data.datasets.forEach(d => d.data.shift());
  }
  chart.update('none');
}

// ── Load historical stats for CPU/RAM chart ───────────────────────────────────

async function loadHistoricalStats() {
  if (!cpuRamChart) return;
  try {
    const resp = await fetch('/api/status/history?hours=24');
    const data = await resp.json();
    const history = data.history || [];
    if (history.length < 2) return;
    cpuRamChart.data.labels = history.map(h => h.timestamp ? h.timestamp.slice(11, 16) : '');
    cpuRamChart.data.datasets[0].data = history.map(h => h.cpu || 0);
    cpuRamChart.data.datasets[1].data = history.map(h => h.ram || 0);
    cpuRamChart.update('none');
  } catch(e) {}
}

// ── Fetch system stats ────────────────────────────────────────────────────────

async function fetchStats() {
  try {
    const resp = await fetch('/api/status');
    if (!resp.ok) return;   // session expired → redirect handled by browser
    const d = await resp.json();

    const now = new Date().toLocaleTimeString('en', { hour12: false });

    // Safely parse numeric values
    const cpu  = parseFloat(d.cpu_percent)  || 0;
    const ram  = parseFloat(d.ram_percent)  || 0;
    const temp = parseFloat(d.temp_c)       || 0;
    const disk = parseFloat(d.disk_percent) || 0;

    _setText('cpu-val',  cpu.toFixed(0)  + '%');
    _setText('ram-val',  ram.toFixed(0)  + '%');
    _setText('temp-val', temp.toFixed(1) + '°C');
    _setText('disk-val', disk.toFixed(0) + '%');

    // Doughnut gauges
    updateGauge('cpuGauge',  cpu);
    updateGauge('ramGauge',  ram);
    updateGauge('tempGauge', Math.min(temp, 100));
    updateGauge('diskGauge', disk);

    // Progress bars
    _setWidth('cpu-bar',  cpu);
    _setWidth('ram-bar',  ram);
    _setWidth('temp-bar', Math.min(temp, 100));
    _setWidth('disk-bar', disk);

    // System info card
    _setText('uptime-val',     d.uptime    || '—');
    _setText('ram-total-val',  d.ram_total_gb  != null ? d.ram_total_gb  + ' GB' : '—');
    _setText('disk-total-val', d.disk_total_gb != null ? d.disk_total_gb + ' GB' : '—');
    _setText('info-hostname',  d.hostname  || '—');

    // Push live readings to CPU/RAM chart
    if (cpuRamChart) {
      pushChart(cpuRamChart, now, cpu, ram);
    }
  } catch(e) {
    console.warn('fetchStats error:', e);
  }
}

// ── Fetch bandwidth ───────────────────────────────────────────────────────────

async function fetchBandwidth() {
  try {
    const resp = await fetch('/api/bandwidth');
    const d = await resp.json();
    const now = new Date().toLocaleTimeString('en', { hour12: false });

    _setText('rx-val', (d.rx_kbps || 0) + ' kbps');
    _setText('tx-val', (d.tx_kbps || 0) + ' kbps');

    const rx = d.rx_kbps || 0;
    const tx = d.tx_kbps || 0;

    if (bandwidthChart) pushChart(bandwidthChart, now, rx, tx);
    if (bwChart) pushChart(bwChart, now, rx, tx);
  } catch(e) {}
}

// ── Fetch processes ───────────────────────────────────────────────────────────

async function fetchProcesses() {
  try {
    const resp = await fetch('/api/processes');
    const d = await resp.json();
    const el = document.getElementById('processes-table');
    if (!el) return;

    const rows = (d.processes || []).slice(0, 8).map(p => `
      <div class="d-flex justify-content-between align-items-center py-1 border-bottom" style="border-color:rgba(255,255,255,0.04)!important">
        <span class="font-mono small text-light" style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${p.name}</span>
        <div class="d-flex gap-3 small">
          <span class="text-warning">${p.cpu.toFixed(1)}%</span>
          <span class="text-info">${p.mem.toFixed(1)}%</span>
        </div>
      </div>
    `).join('');

    el.innerHTML = rows || '<p class="text-muted small">No process data</p>';
  } catch(e) {}
}

// ── Network scan button ───────────────────────────────────────────────────────

async function runNetworkScan() {
  const spinner = document.getElementById('scan-spinner');
  const btn = document.getElementById('scan-btn');
  if (spinner) spinner.classList.remove('d-none');
  if (btn) btn.disabled = true;
  showToast('Network scan running... this may take 15-30s', 'info');

  try {
    const resp = await fetch('/api/scan/network', { method: 'POST' });
    const d = await resp.json();
    if (d.error) {
      showToast('Scan failed: ' + d.error, 'danger');
    } else {
      const found = d.found || d.count || 0;
      showToast(`Scan complete — ${found} device(s) found`, 'success');

      // Update summary counters
      const devices = d.devices || [];
      const knownList   = devices.filter(x => x.status === 'known');
      const unknownList = devices.filter(x => x.status === 'unknown');
      _setText('net-total',   devices.length);
      _setText('net-known',   knownList.length);
      _setText('net-unknown', unknownList.length);

      // Rebuild device table if it exists on this page
      const tbody = document.getElementById('devices-tbody');
      if (tbody && devices.length > 0) {
        tbody.innerHTML = devices.map(dev => `
          <tr class="device-row ${dev.status === 'known' ? 'row-known' : 'row-unknown'}"
              data-status="${dev.status || ''}"
              data-ip="${dev.ip || ''}"
              data-mac="${dev.mac || ''}"
              data-vendor="${dev.vendor || ''}">
            <td class="font-mono">${dev.ip || '—'}</td>
            <td class="font-mono text-muted small">${dev.mac || '—'}</td>
            <td class="small">${dev.vendor || '—'}</td>
            <td class="small text-info">${dev.friendly_name || dev.hostname || '—'}</td>
            <td>
              ${dev.status === 'known'
                ? '<span class="badge bg-success-subtle text-success">Known</span>'
                : '<span class="badge bg-warning-subtle text-warning">Unknown</span>'}
            </td>
            <td class="small text-muted">${dev.first_seen || '—'}</td>
            <td class="small text-muted">${dev.last_seen || '—'}</td>
            <td>
              <button class="btn btn-xs btn-outline-info"
                onclick="showDeviceDetails('${dev.mac||''}','${dev.ip||''}','${(dev.vendor||'').replace(/'/g,"\\'")}','${(dev.friendly_name||dev.hostname||'').replace(/'/g,"\\'")}','${dev.status||''}','${dev.first_seen||''}','${dev.last_seen||''}')"
                title="Details">
                <i class="bi bi-eye"></i>
              </button>
            </td>
          </tr>
        `).join('');
      }
    }
  } catch(e) {
    showToast('Scan request failed: ' + e.message, 'danger');
    console.error('runNetworkScan error:', e);
  }

  if (spinner) spinner.classList.add('d-none');
  if (btn) btn.disabled = false;
}

// ── Refresh stats button ──────────────────────────────────────────────────────

function refreshStats() {
  fetchStats();
  fetchBandwidth();
  fetchProcesses();
  showToast('Stats refreshed', 'success');
}

// ── Bandwidth polling (network page, every 5s) ────────────────────────────────

let bwInterval = null;
function startBandwidthPolling() {
  fetchBandwidth();
  bwInterval = setInterval(fetchBandwidth, 5000);
}

// ── Overview page initializer ─────────────────────────────────────────────────

function initOverview() {
  initCpuRamChart();
  initBandwidthLineChart();
  loadHistoricalStats();
  fetchStats();
  fetchBandwidth();
  fetchProcesses();
  // Poll every 10s for stats, every 5s for bandwidth
  setInterval(fetchStats, 10000);
  setInterval(fetchBandwidth, 5000);
  setInterval(fetchProcesses, 30000);
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function _setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function _setWidth(id, pct) {
  const el = document.getElementById(id);
  if (el) el.style.width = Math.min(100, Math.max(0, pct)).toFixed(1) + '%';
}
