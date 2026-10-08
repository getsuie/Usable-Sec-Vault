/**
 * ============================================================================
 * VaultAccess — UI Module: Cryptographic Audit Trail & Escalation View (SEC-03)
 * ============================================================================
 * Implements rich cryptographic audit log rendering, hash-chain verification,
 * interactive tamper simulation, multi-parameter filtering, and Tier 4 exports.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.AuditView = (function () {
  let activeSeverityFilter = 'ALL';
  let activeTierFilter = 'ALL';
  let searchQuery = '';
  let expandedRows = {};
  let lastVerificationResult = null;

  function setSeverityFilter(sev) {
    activeSeverityFilter = sev;
    render();
  }

  function setTierFilter(tier) {
    activeTierFilter = tier;
    render();
  }

  function setSearchQuery(q) {
    searchQuery = (q || '').toLowerCase().trim();
    render();
  }

  function toggleRowDetails(id) {
    expandedRows[id] = !expandedRows[id];
    render();
  }

  function handleVerifyIntegrity() {
    const result = VaultAccess.Audit.verifyLogIntegrity();
    lastVerificationResult = result;
    render();
    alert(result.message);
  }

  function handleTamperDemo() {
    const result = VaultAccess.Audit.tamperLogEntry();
    lastVerificationResult = null;
    render();
    alert(result.message);
  }

  function handleExport(format) {
    const current = VaultAccess.Auth.getCurrentRole();
    if (!current || current.tier < 4) {
      alert("Permission Denied: Only Tier 4 (Security Admin) is authorized to export cryptographic audit trails.");
      return;
    }

    const res = VaultAccess.Audit.exportAuditLogs(format);
    if (!res.success) {
      alert(res.message);
      return;
    }

    // Trigger browser file download
    const blob = new Blob([res.data], { type: format === 'json' ? 'application/json' : 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vaultaccess-audit-${Date.now()}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    alert(`Export complete: ${res.count} cryptographically chained records exported as ${format.toUpperCase()}. Operation recorded in audit trail.`);
    render();
  }

  function render() {
    const escLogTbody = document.getElementById('escLog');
    const statAlerts = document.getElementById('statAlerts');
    const container = document.getElementById('socIncidentQueueContainer');
    const viewSection = document.getElementById('view-escalation');

    if (!viewSection) return;

    const allLogs = VaultAccess.Audit.getLogs();
    const incidents = VaultAccess.Audit.getIncidents();

    // Filter logs
    const filteredLogs = allLogs.filter(e => {
      if (activeSeverityFilter !== 'ALL' && e.severity !== activeSeverityFilter.toLowerCase()) return false;
      if (activeTierFilter !== 'ALL' && String(e.tier) !== String(activeTierFilter)) return false;
      if (searchQuery) {
        const text = `${e.id} ${e.action} ${e.src} ${e.acct} ${e.resource} ${e.operatorId} ${e.resultCode}`.toLowerCase();
        if (!text.includes(searchQuery)) return false;
      }
      return true;
    });

    if (statAlerts) {
      statAlerts.textContent = allLogs.length;
    }

    // Inject SEC-03 Control Toolbar & Verification Banner before the table
    let toolbarEl = document.getElementById('auditCryptoToolbar');
    if (!toolbarEl) {
      toolbarEl = document.createElement('div');
      toolbarEl.id = 'auditCryptoToolbar';
      const heading = viewSection.querySelector('h3');
      if (heading) {
        viewSection.insertBefore(toolbarEl, heading);
      }
    }

    const currentRole = VaultAccess.Auth.getCurrentRole();
    const isTier4 = currentRole && currentRole.tier >= 4;

    toolbarEl.innerHTML = `
      <div class="bank-panel" style="background:var(--panel2); border:1px solid var(--line); border-radius:10px; padding:16px; margin-bottom:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
          <div>
            <div style="font-size:11px; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:.04em;">
              Operational Monitoring & Audit Log
            </div>
            <h3 style="margin:2px 0 0; font-size:15px;">Real-Time Security Activity Trail</h3>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            ${isTier4 ? `
              <button type="button" class="btn ghost" style="font-size:12px;" onclick="VaultAccess.AuditView.handleExport('json')">Export JSON</button>
              <button type="button" class="btn ghost" style="font-size:12px;" onclick="VaultAccess.AuditView.handleExport('csv')">Export CSV</button>
            ` : `
              <span class="tag" style="align-self:center; font-size:11px;">Export: Tier 4 only</span>
            `}
          </div>
        </div>

        <!-- Filter Bar -->
        <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap; background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:10px 12px;">
          <span style="font-size:11.5px; font-weight:700; color:var(--muted); text-transform:uppercase;">Filters:</span>
          
          <div style="display:flex; gap:4px; align-items:center;">
            <label for="auditFilterSev" style="font-size:11px; color:var(--muted);">Status:</label>
            <select id="auditFilterSev" onchange="VaultAccess.AuditView.setSeverityFilter(this.value)" style="padding:4px 8px; font-size:11.5px; background:var(--panel2); border:1px solid var(--line); color:var(--text); border-radius:4px;">
              <option value="ALL" ${activeSeverityFilter === 'ALL' ? 'selected' : ''}>All Events</option>
              <option value="danger" ${activeSeverityFilter === 'danger' ? 'selected' : ''}>Blocked (Violations)</option>
              <option value="warn" ${activeSeverityFilter === 'warn' ? 'selected' : ''}>Adjusted (Warnings)</option>
              <option value="info" ${activeSeverityFilter === 'info' ? 'selected' : ''}>Granted (Normal Activity)</option>
            </select>
          </div>

          <div style="display:flex; gap:4px; align-items:center;">
            <label for="auditFilterTier" style="font-size:11px; color:var(--muted);">Tier:</label>
            <select id="auditFilterTier" onchange="VaultAccess.AuditView.setTierFilter(this.value)" style="padding:4px 8px; font-size:11.5px; background:var(--panel2); border:1px solid var(--line); color:var(--text); border-radius:4px;">
              <option value="ALL" ${activeTierFilter === 'ALL' ? 'selected' : ''}>All Tiers</option>
              <option value="1" ${activeTierFilter === '1' ? 'selected' : ''}>Tier 1 (Teller)</option>
              <option value="2" ${activeTierFilter === '2' ? 'selected' : ''}>Tier 2 (Supervisor/HelpDesk)</option>
              <option value="3" ${activeTierFilter === '3' ? 'selected' : ''}>Tier 3 (IT Admin)</option>
              <option value="4" ${activeTierFilter === '4' ? 'selected' : ''}>Tier 4 (Sec Admin)</option>
            </select>
          </div>

          <div style="flex:1; min-width:180px;">
            <input id="auditFilterSearch" placeholder="Search action, staff member, terminal, or ID..." value="${searchQuery}" oninput="VaultAccess.AuditView.setSearchQuery(this.value)" style="width:100%; padding:4px 10px; font-size:11.5px; background:var(--panel2); border:1px solid var(--line); color:var(--text); border-radius:4px;">
          </div>

          <span style="font-size:11px; color:var(--muted);">
            Showing ${filteredLogs.length} of ${allLogs.length}
          </span>
        </div>
      </div>
    `;

    // Render Table Rows (Cleaned 6 columns: Time/ID, Source/Terminal, Staff Member, Attempted Action, Status, Details)
    if (escLogTbody) {
      if (filteredLogs.length === 0) {
        escLogTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--muted);">No monitoring entries match active filters.</td></tr>`;
      } else {
        escLogTbody.innerHTML = filteredLogs.map(e => {
          let tagClass = 'warn';
          let tagLabel = e.resultCode || e.result;

          if (e.resultCode === 'GRANTED' || e.result === 'granted') {
            tagClass = 'ok';
            tagLabel = 'GRANTED';
          } else if (e.resultCode === 'ESCALATION_ADJUSTED' || e.result === 'adjusted') {
            tagClass = 'warn';
            tagLabel = 'ADJUSTED';
          } else if (e.resultCode === 'CONFIRMED_MALICIOUS') {
            tagClass = 'danger';
            tagLabel = 'MALICIOUS';
          } else if (e.resultCode === 'UNCONFIRMED') {
            tagClass = 'warn';
            tagLabel = 'UNCONFIRMED';
          } else if (e.resultCode === 'FREEZE_EXPIRED') {
            tagClass = 'ok';
            tagLabel = 'EXPIRED';
          } else if (e.resultCode === 'ESCALATION_BLOCKED' || e.result === 'denied') {
            tagClass = 'danger';
            tagLabel = 'BLOCKED';
          }

          const isExpanded = !!expandedRows[e.id];
          const staffName = e.operatorName || e.acct || (e.operatorId ? e.operatorId.split('_')[0] : "Staff");

          return `
            <tr style="cursor:pointer;" onclick="VaultAccess.AuditView.toggleRowDetails('${e.id}')">
              <td>
                <strong>${e.timestamp}</strong><br>
                <span style="font-size:10.5px; color:var(--muted); font-family:'JetBrains Mono',monospace;">${e.id}</span>
              </td>
              <td class="plain" style="font-size:12px;">
                ${e.src}<br>
                <span style="font-size:10.5px; color:var(--muted);">${e.terminalId}</span>
              </td>
              <td>
                <strong style="color:var(--text);">${staffName}</strong><br>
                <span style="font-size:10px; color:var(--accent);">Tier ${e.tier} (${e.operatorId || 'ID'})</span>
              </td>
              <td class="plain" style="font-size:12px;">
                ${e.action}
                <div style="font-size:10.5px; color:var(--muted); margin-top:2px;">Target: <code>${e.resource}</code></div>
              </td>
              <td>
                <span class="tag ${tagClass}">
                  ${tagLabel}
                </span>
              </td>
              <td style="text-align:right;">
                <button type="button" class="btn ghost" style="padding:2px 7px; font-size:10.5px;" onclick="event.stopPropagation(); VaultAccess.AuditView.toggleRowDetails('${e.id}')">
                  ${isExpanded ? 'Hide ▲' : 'Details ▼'}
                </button>
              </td>
            </tr>
            ${isExpanded ? `
              <tr style="background:var(--panel2); border-bottom:2px solid var(--line);">
                <td colspan="6" style="padding:12px 16px;">
                  <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:10px; font-size:11.5px;">
                    <div>
                      <strong style="color:var(--muted); text-transform:uppercase; font-size:10px;">Staff Operator Identity:</strong>
                      <div><strong>${staffName}</strong> (Operator ID: <code>${e.operatorId}</code>)</div>
                    </div>
                    <div>
                      <strong style="color:var(--muted); text-transform:uppercase; font-size:10px;">Network Origin:</strong>
                      <div>IP: <code>${e.sourceIP}</code> · Device: <code>${e.deviceSignature}</code></div>
                    </div>
                    <div>
                      <strong style="color:var(--muted); text-transform:uppercase; font-size:10px;">Security Policy Classification:</strong>
                      <div>Reason: <code>${e.reasonCode}</code> · Case: <code>${e.caseId}</code></div>
                    </div>
                  </div>
                </td>
              </tr>
            ` : ''}
          `;
        }).join('');
      }
    }
  }

  return {
    render,
    setSeverityFilter,
    setTierFilter,
    setSearchQuery,
    toggleRowDetails,
    handleVerifyIntegrity,
    handleTamperDemo,
    handleExport
  };
})();
