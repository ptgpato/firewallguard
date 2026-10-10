// =========================================================
// FirewallGuard - Rules Management JavaScript
// =========================================================

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('ruleForm');
  const modalEl = document.getElementById('ruleModal');
  const ruleModal = modalEl ? new bootstrap.Modal(modalEl) : null;

  // Form input elements for live preview & validation
  const nameInput = document.getElementById('ruleName');
  const descInput = document.getElementById('ruleDesc');
  const directionSelect = document.getElementById('ruleDirection');
  const actionSelect = document.getElementById('ruleAction');
  const protocolSelect = document.getElementById('ruleProtocol');
  const srcIpInput = document.getElementById('ruleSrcIp');
  const dstIpInput = document.getElementById('ruleDstIp');
  const srcPortInput = document.getElementById('ruleSrcPort');
  const dstPortInput = document.getElementById('ruleDstPort');
  const profileSelect = document.getElementById('ruleProfile');
  const psPreviewBox = document.getElementById('psPreviewText');
  const netshPreviewBox = document.getElementById('netshPreviewText');

  // Listeners to update command preview and validate input
  const previewInputs = [nameInput, descInput, directionSelect, actionSelect, protocolSelect, srcIpInput, dstIpInput, srcPortInput, dstPortInput, profileSelect];
  previewInputs.forEach(input => {
    if (input) {
      input.addEventListener('input', updateCommandPreview);
      input.addEventListener('change', updateCommandPreview);
    }
  });

  if (protocolSelect) {
    protocolSelect.addEventListener('change', () => {
      const isIcmp = protocolSelect.value === 'ICMP';
      if (srcPortInput && dstPortInput) {
        if (isIcmp) {
          srcPortInput.value = 'N/A';
          dstPortInput.value = 'N/A';
          srcPortInput.disabled = true;
          dstPortInput.disabled = true;
        } else {
          if (srcPortInput.value === 'N/A') srcPortInput.value = 'Any';
          if (dstPortInput.value === 'N/A') dstPortInput.value = 'Any';
          srcPortInput.disabled = false;
          dstPortInput.disabled = false;
        }
      }
      updateCommandPreview();
    });
  }

  function updateCommandPreview() {
    if (!psPreviewBox) return;

    const name = (nameInput?.value || 'New-Custom-Rule').trim().replace(/\s+/g, '-');
    const direction = directionSelect?.value || 'Inbound';
    const action = actionSelect?.value || 'Allow';
    const protocol = protocolSelect?.value || 'TCP';
    const srcIp = (srcIpInput?.value || 'Any').trim();
    const dstIp = (dstIpInput?.value || 'Any').trim();
    const srcPort = (srcPortInput?.value || 'Any').trim();
    const dstPort = (dstPortInput?.value || 'Any').trim();
    const profile = profileSelect?.value || 'Any';

    const isOutbound = direction.toLowerCase() === 'outbound';

    // Inbound:  Source = Remote (-RemoteAddress, -RemotePort), Dest = Local (-LocalAddress, -LocalPort)
    // Outbound: Source = Local  (-LocalAddress, -LocalPort),   Dest = Remote Website (-RemoteAddress, -RemotePort)
    const localPort = isOutbound ? srcPort : dstPort;
    const remotePort = isOutbound ? dstPort : srcPort;
    const localIp = isOutbound ? srcIp : dstIp;
    const remoteIp = isOutbound ? dstIp : srcIp;

    // Update dynamic helper text on form
    const srcHelp = document.getElementById('srcHelpText');
    const dstHelp = document.getElementById('dstHelpText');
    if (srcHelp) {
      srcHelp.textContent = isOutbound 
        ? "Local interface sending the packet (use 'Any' for all)" 
        : "Remote client sending incoming packet (use 'Any' for all)";
    }
    if (dstHelp) {
      dstHelp.textContent = isOutbound 
        ? "Target website/server IP (e.g. YouTube 142.250.190.46, Facebook)" 
        : "Local interface receiving the packet";
    }

    let ps = `New-NetFirewallRule -DisplayName "${name}" -Direction ${direction} -Action ${action} -Enabled True`;
    if (protocol !== 'Any') ps += ` -Protocol ${protocol}`;
    if (localPort !== 'Any' && localPort !== 'N/A' && protocol !== 'ICMP') ps += ` -LocalPort ${localPort}`;
    if (remotePort !== 'Any' && remotePort !== 'N/A' && protocol !== 'ICMP') ps += ` -RemotePort ${remotePort}`;
    if (localIp !== 'Any') ps += ` -LocalAddress ${localIp}`;
    if (remoteIp !== 'Any') ps += ` -RemoteAddress ${remoteIp}`;
    if (profile !== 'Any') ps += ` -Profile ${profile}`;

    psPreviewBox.textContent = ps;

    if (netshPreviewBox) {
      let netsh = `netsh advfirewall firewall add rule name="${name}" dir=${isOutbound ? 'out' : 'in'} action=${action.toLowerCase()} enable=yes`;
      if (protocol !== 'Any') netsh += ` protocol=${protocol.toLowerCase()}`;
      if (localPort !== 'Any' && localPort !== 'N/A' && protocol !== 'ICMP') netsh += ` localport=${localPort}`;
      if (remotePort !== 'Any' && remotePort !== 'N/A' && protocol !== 'ICMP') netsh += ` remoteport=${remotePort}`;
      if (localIp !== 'Any') netsh += ` localip=${localIp}`;
      if (remoteIp !== 'Any') netsh += ` remoteip=${remoteIp}`;
      if (profile !== 'Any') netsh += ` profile=${profile.toLowerCase()}`;
      netshPreviewBox.textContent = netsh;
    }
  }

  // Initial call
  updateCommandPreview();

  // Save Rule Form Submit
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const ruleId = document.getElementById('ruleId')?.value;
      const payload = {
        name: nameInput.value.trim(),
        description: descInput.value.trim(),
        direction: directionSelect.value,
        action: actionSelect.value,
        protocol: protocolSelect.value,
        source_ip: srcIpInput.value.trim() || 'Any',
        dest_ip: dstIpInput.value.trim() || 'Any',
        source_port: srcPortInput.value.trim() || 'Any',
        dest_port: dstPortInput.value.trim() || 'Any',
        profile: profileSelect.value
      };

      // Validation
      if (!payload.name) {
        showToast('Validation Error', 'Rule name is required.', 'danger');
        return;
      }

      try {
        const url = ruleId ? `/api/rules/${ruleId}` : '/api/rules';
        const method = ruleId ? 'PUT' : 'POST';

        const res = await fetch(url, {
          method: method,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (res.ok && data.success) {
          showToast('Success', data.message, 'success');
          if (ruleModal) ruleModal.hide();
          setTimeout(() => { window.location.reload(); }, 600);
        } else {
          showToast('Error', data.error || 'Failed to save rule.', 'danger');
        }
      } catch (err) {
        showToast('Network Error', 'Unable to communicate with firewall backend.', 'danger');
      }
    });
  }

  // Apply All Rules to Windows Defender Firewall Button
  const btnApplyAll = document.getElementById('btnApplyAll');
  if (btnApplyAll) {
    btnApplyAll.addEventListener('click', async () => {
      btnApplyAll.disabled = true;
      btnApplyAll.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Applying to Windows Defender...';
      try {
        const res = await fetch('/api/rules/apply-all', { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast('Firewall Engine Synchronized', data.message, 'success');
        } else {
          showToast('Apply Failed', data.error || 'Could not sync rules.', 'danger');
        }
      } catch (err) {
        showToast('Error', 'Failed to reach firewall service.', 'danger');
      } finally {
        btnApplyAll.disabled = false;
        btnApplyAll.innerHTML = '<i class="bi bi-shield-check me-1"></i> Apply Rules to Windows Firewall';
      }
    });
  }

  // Filter Table Handlers
  const filterDirection = document.getElementById('filterDirection');
  const filterAction = document.getElementById('filterAction');
  const filterProtocol = document.getElementById('filterProtocol');
  const filterSearch = document.getElementById('filterSearch');

  [filterDirection, filterAction, filterProtocol, filterSearch].forEach(el => {
    if (el) {
      el.addEventListener('change', filterRulesTable);
      if (el.tagName === 'INPUT') el.addEventListener('keyup', filterRulesTable);
    }
  });

  function filterRulesTable() {
    const dir = filterDirection?.value.toLowerCase() || 'all';
    const act = filterAction?.value.toLowerCase() || 'all';
    const proto = filterProtocol?.value.toLowerCase() || 'all';
    const search = filterSearch?.value.toLowerCase().trim() || '';

    const rows = document.querySelectorAll('#rulesTableBody tr');
    rows.forEach(row => {
      const rDir = row.getAttribute('data-direction')?.toLowerCase() || '';
      const rAct = row.getAttribute('data-action')?.toLowerCase() || '';
      const rProto = row.getAttribute('data-protocol')?.toLowerCase() || '';
      const rText = row.innerText.toLowerCase();

      const matchDir = dir === 'all' || rDir === dir;
      const matchAct = act === 'all' || rAct === act;
      const matchProto = proto === 'all' || rProto === proto;
      const matchSearch = !search || rText.includes(search);

      if (matchDir && matchAct && matchProto && matchSearch) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
    });
  }
});

// Toggle rule Enable/Disable via API
async function toggleRule(ruleId, ruleName, checkbox) {
  try {
    const res = await fetch(`/api/rules/${ruleId}/toggle`, { method: 'PUT' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Firewall Rule Updated', data.message, data.enabled ? 'success' : 'info');
      const badge = document.getElementById(`status-badge-${ruleId}`);
      if (badge) {
        badge.className = data.enabled ? 'badge bg-success-subtle text-success border border-success' : 'badge bg-secondary text-light';
        badge.textContent = data.enabled ? 'Active' : 'Disabled';
      }
    } else {
      checkbox.checked = !checkbox.checked;
      showToast('Action Denied', data.error || 'Failed to toggle rule state.', 'danger');
    }
  } catch (err) {
    checkbox.checked = !checkbox.checked;
    showToast('Error', 'Connection to server failed.', 'danger');
  }
}

// Delete Rule Function
async function deleteRule(ruleId, ruleName) {
  if (!confirm(`Are you sure you want to delete the firewall rule "${ruleName}"?\nThis will remove the rule from Windows Defender Firewall.`)) {
    return;
  }

  try {
    const res = await fetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Rule Deleted', data.message, 'success');
      const row = document.getElementById(`rule-row-${ruleId}`);
      if (row) row.remove();
    } else {
      showToast('Error', data.error || 'Could not delete rule.', 'danger');
    }
  } catch (err) {
    showToast('Error', 'Failed to communicate with firewall API.', 'danger');
  }
}

// Open Edit Rule Modal
function openEditRuleModal(rule) {
  document.getElementById('ruleModalTitle').textContent = 'Edit Firewall Rule';
  document.getElementById('ruleId').value = rule.id;
  document.getElementById('ruleName').value = rule.name;
  document.getElementById('ruleDesc').value = rule.description || '';
  document.getElementById('ruleDirection').value = rule.direction;
  document.getElementById('ruleAction').value = rule.action;
  document.getElementById('ruleProtocol').value = rule.protocol;
  document.getElementById('ruleSrcIp').value = rule.source_ip;
  document.getElementById('ruleDstIp').value = rule.dest_ip;
  document.getElementById('ruleSrcPort').value = rule.source_port;
  document.getElementById('ruleDstPort').value = rule.dest_port;
  document.getElementById('ruleProfile').value = rule.profile;

  const modalEl = document.getElementById('ruleModal');
  const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
  modal.show();

  // trigger update preview
  const event = new Event('input');
  document.getElementById('ruleName').dispatchEvent(event);
}

// Reset form for New Rule
function openCreateRuleModal() {
  document.getElementById('ruleModalTitle').textContent = 'Create New Firewall Rule';
  document.getElementById('ruleId').value = '';
  document.getElementById('ruleForm').reset();
  document.getElementById('ruleSrcIp').value = 'Any';
  document.getElementById('ruleDstIp').value = 'Any';
  document.getElementById('ruleSrcPort').value = 'Any';
  document.getElementById('ruleDstPort').value = 'Any';

  const modalEl = document.getElementById('ruleModal');
  const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
  modal.show();

  const event = new Event('input');
  document.getElementById('ruleName').dispatchEvent(event);
}

// View Command Detail Modal
function viewRuleCommand(name, powershellCmd, netshCmd) {
  document.getElementById('cmdModalRuleName').textContent = name;
  document.getElementById('cmdModalPS').textContent = powershellCmd;
  document.getElementById('cmdModalNetsh').textContent = netshCmd;

  const modalEl = document.getElementById('commandDetailModal');
  const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
  modal.show();
}
