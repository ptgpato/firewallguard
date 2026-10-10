document.addEventListener('DOMContentLoaded', () => {
  const logSearch = document.getElementById('logSearch');
  const logAction = document.getElementById('logAction');
  const logDirection = document.getElementById('logDirection');
  const logProtocol = document.getElementById('logProtocol');

  const filterInputs = [logSearch, logAction, logDirection, logProtocol];
  filterInputs.forEach(input => {
    if (input) {
      input.addEventListener('change', fetchFilteredLogs);
      if (input.tagName === 'INPUT') {
        input.addEventListener('input', debounce(fetchFilteredLogs, 300));
      }
    }
  });
});

function debounce(func, wait) {
  let timeout;
  return function(...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}

async function fetchFilteredLogs() {
  const search = document.getElementById('logSearch')?.value.trim() || '';
  const action = document.getElementById('logAction')?.value || 'All';
  const direction = document.getElementById('logDirection')?.value || 'All';
  const protocol = document.getElementById('logProtocol')?.value || 'All';

  const params = new URLSearchParams();
  if (search) params.append('search', search);
  if (action !== 'All') params.append('action', action);
  if (direction !== 'All') params.append('direction', direction);
  if (protocol !== 'All') params.append('protocol', protocol);

  try {
    const res = await fetch(`/api/logs?${params.toString()}`);
    if (!res.ok) return;
    const data = await res.json();
    renderLogsTable(data.logs);
  } catch (err) {
    console.error('Failed to query logs:', err);
  }
}

function renderLogsTable(logs) {
  const tbody = document.getElementById('logsTableBody');
  const countEl = document.getElementById('logResultCount');
  if (!tbody) return;

  if (countEl) countEl.textContent = `Showing ${logs.length} logged events`;

  tbody.innerHTML = '';
  if (logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-muted"><i class="bi bi-inbox me-2"></i>No matching security logs found.</td></tr>`;
    return;
  }

  logs.forEach(log => {
    const isAllow = log.action === 'Allow';
    const actionBadge = isAllow 
      ? `<span class="badge-allow"><i class="bi bi-shield-check me-1"></i>Allowed</span>` 
      : `<span class="badge-block"><i class="bi bi-shield-x me-1"></i>Blocked</span>`;
    
    const directionBadge = log.direction === 'Inbound'
      ? `<span class="badge-direction-in"><i class="bi bi-arrow-down-left me-1"></i>Inbound</span>`
      : `<span class="badge-direction-out"><i class="bi bi-arrow-up-right me-1"></i>Outbound</span>`;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="font-mono text-muted small">${log.timestamp}</td>
      <td>${actionBadge}</td>
      <td>${directionBadge}</td>
      <td><span class="badge-protocol">${log.protocol}</span></td>
      <td><span class="ip-badge">${log.source_ip}</span><span class="port-badge ms-1">:${log.source_port}</span></td>
      <td><span class="ip-badge text-warning">${log.dest_ip}</span><span class="port-badge ms-1">:${log.dest_port}</span></td>
      <td class="fw-semibold text-light">${log.rule_name || '<span class="text-muted">Default Drop</span>'}</td>
      <td class="text-secondary small">${log.reason || 'Standard filter inspection'}</td>
    `;
    tbody.appendChild(tr);
  });
}

function exportLogs(format) {
  window.location.href = `/api/export/logs?format=${format}`;
  showToast('Export Initiated', `Downloading security logs in ${format.toUpperCase()} format...`, 'info');
}

function printLogReport() {
  window.print();
}
