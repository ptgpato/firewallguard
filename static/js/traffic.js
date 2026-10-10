let trafficChart = null;
const maxDataPoints = 12;

document.addEventListener('DOMContentLoaded', () => {
  initTrafficChart();
  fetchLiveTrafficData();

  setInterval(fetchLiveTrafficData, 3000);
});

function initTrafficChart() {
  const ctx = document.getElementById('liveBandwidthChart');
  if (!ctx) return;

  const initialLabels = [];
  const initialInbound = [];
  const initialOutbound = [];
  const now = new Date();

  for (let i = maxDataPoints - 1; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 3000);
    initialLabels.push(time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    initialInbound.push(0);
    initialOutbound.push(0);
  }

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: initialLabels,
      datasets: [
        {
          label: 'Inbound (KB/s)',
          data: initialInbound,
          borderColor: '#55b7c9',
          backgroundColor: 'rgba(85, 183, 201, 0.08)',
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          pointBackgroundColor: '#55b7c9'
        },
        {
          label: 'Outbound (KB/s)',
          data: initialOutbound,
          borderColor: '#a895d8',
          backgroundColor: 'rgba(168, 149, 216, 0.07)',
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          pointBackgroundColor: '#a895d8'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 500 },
      plugins: {
        legend: {
          labels: { color: '#9aa8b8', font: { family: 'Inter', size: 12 } }
        },
        tooltip: {
          mode: 'index',
          intersect: false,
          backgroundColor: '#151c25',
          titleColor: '#edf2f7',
          bodyColor: '#d5dde6',
          borderColor: '#354252',
          borderWidth: 1
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(154, 168, 184, 0.1)' },
          ticks: { color: '#6f7d8d', font: { size: 11 } }
        },
        y: {
          grid: { color: 'rgba(154, 168, 184, 0.1)' },
          ticks: { color: '#6f7d8d', font: { size: 11 } },
          beginAtZero: true
        }
      }
    }
  });
}

async function fetchLiveTrafficData() {
  try {
    const res = await fetch('/api/traffic/live');
    if (!res.ok) return;
    const data = await res.json();

    // Update KPI indicators
    const inKbps = document.getElementById('liveInboundRate');
    const outKbps = document.getElementById('liveOutboundRate');
    const activeSockets = document.getElementById('liveActiveSockets');

    if (inKbps) inKbps.textContent = `${data.throughput.inbound_kbps} KB/s`;
    if (outKbps) outKbps.textContent = `${data.throughput.outbound_kbps} KB/s`;
    if (activeSockets) activeSockets.textContent = data.throughput.active_sockets;

    // Update Chart
    if (trafficChart) {
      const timeLabel = data.throughput.timestamp;
      trafficChart.data.labels.push(timeLabel);
      trafficChart.data.datasets[0].data.push(data.throughput.inbound_kbps);
      trafficChart.data.datasets[1].data.push(data.throughput.outbound_kbps);

      if (trafficChart.data.labels.length > maxDataPoints) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
        trafficChart.data.datasets[1].data.shift();
      }
      trafficChart.update();
    }

    // Update Socket Table
    renderLiveConnectionTable(data.connections);
  } catch (err) {
    console.error('Failed to fetch live traffic stream:', err);
  }
}

function renderLiveConnectionTable(connections) {
  const tbody = document.getElementById('trafficTableBody');
  if (!tbody) return;

  const canQuickBlock = tbody.dataset.canQuickBlock === 'true';
  tbody.innerHTML = '';
  connections.forEach(conn => {
    const isAllow = conn.action === 'Allow';
    const actionBadge = isAllow 
      ? `<span class="badge-allow"><i class="bi bi-shield-check me-1"></i>Allow</span>` 
      : `<span class="badge-block"><i class="bi bi-shield-x me-1"></i>Block</span>`;
    
    const directionBadge = conn.direction === 'Inbound'
      ? `<span class="badge-direction-in"><i class="bi bi-arrow-down-left me-1"></i>In</span>`
      : `<span class="badge-direction-out"><i class="bi bi-arrow-up-right me-1"></i>Out</span>`;

    const stateClass = conn.state === 'ESTABLISHED' ? 'text-success' : conn.state === 'LISTEN' ? 'text-cyan' : 'text-amber';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <div class="fw-semibold text-light">${conn.process}</div>
        <small class="text-muted font-mono">PID: ${conn.pid} | ${conn.description}</small>
      </td>
      <td><span class="badge-protocol">${conn.protocol}</span></td>
      <td>${directionBadge}</td>
      <td><span class="ip-badge">${conn.local_endpoint}</span></td>
      <td><span class="ip-badge text-warning">${conn.remote_endpoint}</span></td>
      <td><span class="fw-medium font-mono ${stateClass}">${conn.state}</span></td>
      <td><span class="text-secondary font-mono">${conn.bytes_transferred}</span></td>
      <td>${actionBadge}</td>
      ${canQuickBlock ? `
        <td>
          <button class="btn btn-sm btn-outline-danger" title="Quick Block this IP" onclick="quickBlockIp('${conn.remote_ip}', '${conn.remote_port}')">
            <i class="bi bi-shield-slash"></i> Block IP
          </button>
        </td>
      ` : ''}
    `;
    tbody.appendChild(tr);
  });
}

function quickBlockIp(remoteIp, remotePort) {
  if (confirm(`Do you want to create an immediate Firewall Block Rule for IP ${remoteIp}?`)) {
    sessionStorage.setItem('quick_block_ip', remoteIp);
    sessionStorage.setItem('quick_block_port', remotePort);
    window.location.href = '/rules?action=quick_block&ip=' + encodeURIComponent(remoteIp);
  }
}
