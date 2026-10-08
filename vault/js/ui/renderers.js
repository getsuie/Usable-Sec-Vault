/**
 * ============================================================================
 * VaultAccess — UI Module: View Controllers & DOM Renderers
 * ============================================================================
 * Renders role-specific banking workstations, live ledgers (PHP),
 * automated security lock overlays, interactive hack inspection consoles,
 * privilege tiers, and incident audit trails.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.UI = (function () {
  const VIEW_KEYS = ['dash', 'bankwork', 'helpdesk', 'tiers', 'escalation'];
  let activeCustomer = null;
  let activeTab = 'withdraw';

  /**
   * Displays an accessible in-app popup modal instead of browser native alert().
   * @param {string} message - Message text
   * @param {string} [title="System Notification"] - Title header
   * @param {'info'|'warn'|'danger'|'ok'} [type="info"] - Theme variant
   * @param {Function} [onClose] - Callback when dismissed
   */
  function showModalNotification(message, title = "System Notification", type = "info", onClose = null) {
    const existing = document.getElementById('systemModalPopup');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'systemModalPopup';
    overlay.className = 'system-popup-overlay';
    overlay.setAttribute('role', 'alertdialog');
    overlay.setAttribute('aria-modal', 'true');

    overlay.innerHTML = `
      <div class="system-popup-card type-${type}">
        <h3 class="system-popup-title">${title}</h3>
        <div class="system-popup-msg">${message}</div>
        <div class="system-popup-actions">
          <button type="button" class="btn" id="systemModalCloseBtn" style="padding:7px 18px; font-size:12.5px;">OK</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const closeBtn = overlay.querySelector('#systemModalCloseBtn');
    const dismiss = () => {
      overlay.remove();
      if (typeof onClose === 'function') onClose();
    };

    if (closeBtn) {
      closeBtn.focus();
      closeBtn.addEventListener('click', dismiss);
    }

    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) dismiss();
    });

    const keyListener = (e) => {
      if (e.key === 'Escape' || e.key === 'Enter') {
        window.removeEventListener('keydown', keyListener);
        dismiss();
      }
    };
    window.addEventListener('keydown', keyListener);
  }

  /**
   * Switches active workspace view.
   * @param {string} viewKey - ID key ('dash', 'bankwork', 'helpdesk', 'tiers', 'escalation')
   */
  function showView(viewKey) {
    const current = VaultAccess.Auth.getCurrentRole();

    // Security Team Restriction: only secadmin can open tiers or escalation
    if ((viewKey === 'tiers' || viewKey === 'escalation') && (!current || current.id !== 'secadmin')) {
      // Log this unauthorized access attempt to the Escalation Monitor
      const session = VaultAccess.Auth.getSession();
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: "Navigation Panel — UI Tampering",
        acct: session ? session.user : "unknown",
        action: `UNAUTHORIZED ACCESS ATTEMPT: ${current ? current.label : 'Unknown'} (Tier ${current ? current.tier : '?'}) tried to open ${viewKey === 'tiers' ? 'AD Privilege Tiers' : 'Escalation Monitor'} (Security Admin only)`,
        result: "denied",
        resultCode: "ESCALATION_BLOCKED",
        severity: "danger"
      });
      renderEscalationLog();
      alert("Access Denied: Only Security Team (Tier 4) may access AD Privilege Tiers and Escalation Monitor.");
      return;
    }

    document.querySelectorAll('.navbtn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === viewKey);
    });

    VIEW_KEYS.forEach(k => {
      const el = document.getElementById('view-' + k);
      if (el) {
        el.style.display = (k === viewKey) ? 'block' : 'none';
      }
    });

    if (viewKey === 'bankwork') {
      renderBankWorkstation();
    } else if (viewKey === 'helpdesk') {
      VaultAccess.HelpDesk.render();
    }
  }

  /**
   * Updates user identity labels in sidebar and dashboard header.
   * Enforces role-based visibility across roles and tiers.
   */
  function updateRoleDisplay() {
    const current = VaultAccess.Auth.getCurrentRole();
    const session = VaultAccess.Auth.getSession();

    if (!current || !session) return;

    const whoName = document.getElementById('whoName');
    const whoRole = document.getElementById('whoRole');
    const statTier = document.getElementById('statTier');

    if (whoName) whoName.textContent = session.name;
    if (whoRole) whoRole.textContent = current.label;
    if (statTier) statTier.textContent = current.tierSub ? "T" + current.tierSub : "T" + current.tier;

    const isSecAdmin = (current.id === 'secadmin');
    const isHelpDesk = (current.id === 'helpdesk');
    const isSupervisor = (current.id === 'supervisor');

    // Role-specific navigation visibility
    document.querySelectorAll('.navbtn[data-view="helpdesk"]').forEach(btn => {
      btn.style.display = (isHelpDesk || isSupervisor || isSecAdmin) ? 'flex' : 'none';
    });

    document.querySelectorAll('.navbtn[data-view="bankwork"]').forEach(btn => {
      btn.style.display = isHelpDesk ? 'none' : 'flex';
    });

    document.querySelectorAll('.navbtn[data-view="tiers"], .navbtn[data-view="escalation"]').forEach(btn => {
      btn.style.display = isSecAdmin ? 'flex' : 'none';
    });

    // Check terminal freeze state on role switch
    checkTerminalFreezeState();
    if (isSecAdmin) {
      renderTiers();
    }
  }

  /**
   * Renders the AD Privilege Tiers breakdown.
   */
  function renderTiers() {
    const current = VaultAccess.Auth.getCurrentRole();
    const list = document.getElementById('tierList');
    if (!list) return;

    const currentTier = current ? current.tier : 0;

    list.innerHTML = VaultAccess.Config.TIER_DATA.map(t => {
      const isCurrent = t.min === currentTier;
      const locked = t.min > currentTier;

      return `
        <div class="tier ${locked ? 'locked' : ''}">
          <div>
            <div class="name">${t.name}</div>
            ${isCurrent ? '<span class="tag ok">your tier</span>' : ''}
            ${locked ? '<span class="tag danger">above your access</span>' : ''}
          </div>
          <div class="perms">${t.desc}<br>${t.perms}</div>
          <div style="font-size:12px; font-weight:700; color:var(--muted);">${locked ? '[LOCKED]' : '[AVAILABLE]'}</div>
        </div>
      `;
    }).join('');
  }

  /**
   * Renders the security audit log table and active alert counter.
   * Enforces non-color-only indicators (icons + text labels) and renders
   * the Lucid Staff Flow: Assessing Intent Triage Queue.
   */
  function renderEscalationLog() {
    if (VaultAccess.AuditView && VaultAccess.AuditView.render) {
      VaultAccess.AuditView.render();
    }

    const statAlerts = document.getElementById('statAlerts');
    if (statAlerts) {
      statAlerts.textContent = VaultAccess.Audit.getAlertCount();
    }

    const incidentContainer = document.getElementById('socIncidentQueueContainer');
    const incidents = VaultAccess.Audit ? VaultAccess.Audit.getIncidents() : [];

    // Render Lucid Staff Flow: Assessing Intent Incident Desk
    if (incidentContainer) {
      const pendingCount = incidents.filter(i => i.status === 'ASSESSING_INTENT').length;

      incidentContainer.innerHTML = `
        <div class="bank-panel" style="background:var(--panel2); border:1px solid var(--line); border-radius:10px; padding:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
            <div>
              <div style="font-size:11px; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:.04em;">
                Lucid Staff Flow: Privilege Escalation Assessment (Steps 3 & 4)
              </div>
              <h3 style="margin:2px 0 0; font-size:15px;">SOC Incident Triage Desk</h3>
            </div>
            <div>
              <span class="tag ${pendingCount > 0 ? 'warn' : 'ok'}">
                ${pendingCount} Pending Assessment${pendingCount === 1 ? '' : 's'}
              </span>
            </div>
          </div>

          <p style="font-size:12px; color:var(--muted); margin:0 0 12px; line-height:1.5;">
            When an operator attempts an action strictly above their tier, remote access is blocked (<code>ESCALATION_BLOCKED</code>) and queued here under <strong>ASSESSING_INTENT</strong>. The Security Admin investigates and issues a binding resolution:
            <strong>CONFIRMED_MALICIOUS</strong> (suspends account, records identity/resource/timestamp) or <strong>UNCONFIRMED</strong> (revokes elevated session, flags account).
          </p>

          <div style="overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; font-size:12px; text-align:left;">
              <thead>
                <tr style="border-bottom:1px solid var(--line); color:var(--muted);">
                  <th style="padding:6px 8px;">Case / Time</th>
                  <th style="padding:6px 8px;">Operator</th>
                  <th style="padding:6px 8px;">Attempted Resource</th>
                  <th style="padding:6px 8px;">Status</th>
                  <th style="padding:6px 8px;">Forensic Details</th>
                  <th style="padding:6px 8px; text-align:right;">SOC Decision</th>
                </tr>
              </thead>
              <tbody>
                ${incidents.map(inc => {
                  const isPending = inc.status === 'ASSESSING_INTENT';
                  const isMalicious = inc.status === 'CONFIRMED_MALICIOUS';
                  const statusTag = isPending
                    ? `<span class="tag warn">ASSESSING_INTENT</span>`
                    : (isMalicious ? `<span class="tag danger">CONFIRMED_MALICIOUS</span>` : `<span class="tag ok">UNCONFIRMED</span>`);

                  return `
                    <tr style="border-bottom:1px solid var(--line);">
                      <td style="padding:8px;">
                        <strong>${inc.id}</strong><br>
                        <span style="font-size:11px; color:var(--muted);">${inc.timestamp}</span>
                      </td>
                      <td style="padding:8px;">
                        <strong>${inc.username}</strong><br>
                        <span style="font-size:11px; color:var(--muted);">${inc.operatorId} (${inc.role})</span>
                      </td>
                      <td style="padding:8px;">
                        <strong>${inc.resource}</strong><br>
                        <span style="font-size:11px; color:var(--muted);">Tier ${inc.actualTier} -> Tier ${inc.requestedTier}</span>
                      </td>
                      <td style="padding:8px;">
                        ${statusTag}
                      </td>
                      <td style="padding:8px; font-size:11.5px; color:var(--text); max-width:240px;">
                        ${inc.details}
                        ${inc.decisionNotes ? `<div style="font-size:10.5px; color:var(--muted); margin-top:2px;"><em>${inc.decisionNotes}</em></div>` : ''}
                      </td>
                      <td style="padding:8px; text-align:right;">
                        ${isPending ? `
                          <div style="display:flex; gap:6px; justify-content:flex-end;">
                            <button type="button" class="btn" style="background:var(--danger); font-size:11px; padding:3px 8px;"
                                    title="Confirm malicious intent: suspends operator account immediately"
                                    onclick="VaultAccess.UI.handleResolveIncident('${inc.id}', 'CONFIRMED_MALICIOUS')">
                              Confirm Malicious
                            </button>
                            <button type="button" class="btn ghost" style="font-size:11px; padding:3px 8px;"
                                    title="Unconfirmed intent: revokes elevated token and flags account"
                                    onclick="VaultAccess.UI.handleResolveIncident('${inc.id}', 'UNCONFIRMED')">
                              Unconfirmed
                            </button>
                          </div>
                        ` : `
                          <span style="font-size:11px; color:var(--muted);">
                            Resolved by ${inc.resolvedBy || 'sec_soc01'}<br>at ${inc.resolvedAt || 'earlier'}
                          </span>
                        `}
                      </td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }
  }

  // --------------------------------------------------------------------------
  // Bank Workstation Dynamic Renderer (Role-Specific)
  // --------------------------------------------------------------------------

  function renderBankWorkstation() {
    const container = document.getElementById('bankWorkContainer');
    if (!container) return;

    const currentRole = VaultAccess.Auth.getCurrentRole();
    if (!currentRole) return;

    if (currentRole.id === 'teller') {
      renderTellerWorkstation(container);
    } else if (currentRole.id === 'supervisor') {
      renderSupervisorWorkstation(container);
    } else if (currentRole.id === 'itadmin') {
      renderITAdminWorkstation(container);
    } else if (currentRole.id === 'secadmin') {
      renderSecAdminWorkstation(container);
    }
  }

  /**
   * 1. TELLER WORKSTATION (Tier 1)
   */
  function renderTellerWorkstation(container) {
    if (!activeCustomer) {
      activeCustomer = VaultAccess.Banking.lookupCustomer('1003-8821'); // Default to E. Villanueva
    }

    container.innerHTML = `
      <div style="margin-bottom:14px; background:var(--panel2); border:1px solid var(--line); border-radius:10px; padding:12px 16px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Assigned Terminal:</span>
          <strong style="margin-left:6px; color:var(--text);">Branch Terminal #14 (TERM-BR14)</strong>
          <span style="margin-left:14px; font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Operator:</span>
          <strong style="margin-left:6px; color:var(--accent);">teller_402 (A. Santos)</strong>
        </div>
        <div>
          <span class="tag ok">Max Withdrawal: ₱60,500</span>
        </div>
      </div>

      <div class="bank-grid">
        <!-- Panel 1: Customer Lookup Screen -->
        <div class="bank-panel">
          <h3>Customer Lookup Screen <span class="tag ok">Read-Only</span></h3>
          <div class="panel-sub">Search accounts, verify customer identity, and inspect live ledger balances.</div>
          
          <div class="searchrow" style="margin-bottom:10px;">
            <label for="tellerCustomerSearch" class="sr-only">Search Account or Name</label>
            <input id="tellerCustomerSearch" placeholder="Account # or Name (e.g. 1003-8821, Reyes)" value="${activeCustomer ? activeCustomer.name : ''}">
            <button type="button" class="btn" id="tellerSearchBtn">Search</button>
          </div>

          <div style="display:flex; gap:6px; margin-bottom:12px; font-size:11.5px;">
            <span style="color:var(--muted);">Samples:</span>
            <button type="button" class="btn ghost" style="padding:2px 7px; font-size:11px;" onclick="VaultAccess.UI.loadCustomerSample('1003-8821')">E. Villanueva (Good)</button>
            <button type="button" class="btn ghost" style="padding:2px 7px; font-size:11px;" onclick="VaultAccess.UI.loadCustomerSample('1001-4471')">J. Reyes (Protected)</button>
          </div>

          <div id="tellerCustomerCard">
            ${renderCustomerCard(activeCustomer)}
          </div>

          <!-- Customer Identity Verification Checklist (Phase 8) -->
          <div style="margin-top:14px; background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px;">
            <div style="font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase; margin-bottom:8px;">
              Mandatory In-Person ID Verification Checklist (T1)
            </div>
            <label style="display:flex; align-items:center; gap:8px; font-size:12px; margin-bottom:6px; cursor:pointer;">
              <input type="checkbox" id="chkNameMatch" onchange="VaultAccess.Workstations.updateIDChecklist('nameMatched', this.checked)">
              <span>Customer photo matches physical presenter</span>
            </label>
            <label style="display:flex; align-items:center; gap:8px; font-size:12px; margin-bottom:6px; cursor:pointer;">
              <input type="checkbox" id="chkIDType" onchange="VaultAccess.Workstations.updateIDChecklist('idTypeVerified', this.checked)">
              <span>Primary government ID validated (PhilSys / Passport / Driver's)</span>
            </label>
            <label style="display:flex; align-items:center; gap:8px; font-size:12px; cursor:pointer;">
              <input type="checkbox" id="chkSignature" onchange="VaultAccess.Workstations.updateIDChecklist('signatureVerified', this.checked)">
              <span>Signature card matches withdrawal slip</span>
            </label>
          </div>

          <!-- Quick Teller Operational Actions -->
          <div style="margin-top:12px; display:flex; gap:8px;">
            <button type="button" class="btn ghost" style="border-color:var(--warn); color:var(--warn); font-size:11.5px; flex:1;" onclick="VaultAccess.Workstations.handleFlagSuspicious('${activeCustomer ? activeCustomer.acctNumber : ''}')">
              Flag Suspicious Customer / Activity
            </button>
          </div>
        </div>

        <!-- Panel 2: Transaction Input & Cash Drawer Reconciliation Screen -->
        <div class="bank-panel">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <h3>Transaction Input & Drawer Desk</h3>
            <span class="tag ok" style="font-size:11px;">Drawer: ₱${VaultAccess.Workstations.getDrawerBalance().toLocaleString('en-US', {minimumFractionDigits:2})}</span>
          </div>
          <div class="panel-sub">Process cash transactions, track supervisor requests, and reconcile shift float.</div>

          <div class="tab-nav">
            <button type="button" class="tab-btn ${activeTab==='withdraw'?'active':''}" onclick="VaultAccess.UI.switchBankTab('withdraw')">Withdrawal (Attack Demo)</button>
            <button type="button" class="tab-btn ${activeTab==='deposit'?'active':''}" onclick="VaultAccess.UI.switchBankTab('deposit')">Deposit</button>
            <button type="button" class="tab-btn" onclick="VaultAccess.Workstations.handleReconcileCashDrawer()">Reconcile Drawer</button>
          </div>

          <div id="bankTabContent">
            ${renderBankTabContent()}
          </div>
        </div>
      </div>
    `;

    // Attach search event
    const searchBtn = document.getElementById('tellerSearchBtn');
    const searchInput = document.getElementById('tellerCustomerSearch');
    if (searchBtn && searchInput) {
      searchBtn.addEventListener('click', () => {
        const found = VaultAccess.Banking.lookupCustomer(searchInput.value);
        if (found) {
          activeCustomer = found;
          document.getElementById('tellerCustomerCard').innerHTML = renderCustomerCard(found);
          document.getElementById('bankTabContent').innerHTML = renderBankTabContent();
        } else {
          alert('Customer account not found.');
        }
      });
    }
  }

  function renderCustomerCard(acct) {
    if (!acct) return '<div class="customer-card" style="color:var(--muted);">No customer selected.</div>';
    const isLocked = acct.status === "Account Locked";
    const statusTag = isLocked ? "danger" : (acct.status.includes("Protected") ? "warn" : "ok");

    return `
      <div class="customer-card">
        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
          <div>
            <h4 style="margin:0 0 2px; font-size:15px; color:var(--text);">${acct.name}</h4>
            <div style="font-size:12px; color:var(--muted);">Acct: <strong style="color:var(--text);">${acct.acctNumber}</strong> · ${acct.branch}</div>
          </div>
          <span class="tag ${statusTag}">${acct.status}</span>
        </div>

        <div style="margin-top:12px;">
          <div style="font-size:11px; text-transform:uppercase; color:var(--muted);">Available Ledger Balance:</div>
          <div class="balance-display">₱${acct.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}</div>
        </div>

        <div style="font-size:11.5px; border-top:1px solid var(--line); padding-top:10px; margin-top:10px;">
          <div style="color:var(--muted); margin-bottom:6px; font-weight:600;">Recent Ledger History:</div>
          ${acct.recentTransactions.slice(0, 2).map(tx => `
            <div style="display:flex; justify-content:space-between; color:var(--muted); font-size:11.5px; margin-bottom:3px;">
              <span>${tx.date} · ${tx.desc}</span>
              <strong style="color:${tx.amount > 0 ? 'var(--ok)' : 'var(--text)'};">
                ${tx.amount > 0 ? '+' : ''}₱${Math.abs(tx.amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}
              </strong>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  function renderBankTabContent() {
    if (!activeCustomer) return '<div style="color:var(--muted);">Select a customer to transact.</div>';

    if (activeTab === 'withdraw') {
      const activeOverride = VaultAccess.Banking.findActiveOverride(activeCustomer.acctNumber);

      return `
        ${activeOverride && activeOverride.status === 'APPROVED' ? `
          <div style="background:rgba(55,194,129,.12); border:1px solid var(--ok); border-radius:8px; padding:12px; margin-bottom:14px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <strong style="color:var(--ok); font-size:13px;">HIGH-VALUE OVERRIDE APPROVED: ${activeOverride.id}</strong>
              <span class="tag ok">APPROVED</span>
            </div>
            <div style="font-size:12px; color:var(--text); margin-top:5px;">
              Approved by: <strong>${activeOverride.approvedBy}</strong> · Authorized Amount: <strong>₱${activeOverride.amount.toLocaleString('en-US', {minimumFractionDigits:2})}</strong>
            </div>
            <div style="font-size:11.5px; color:var(--muted); margin-top:2px;">
              Authorized action: ₱${activeOverride.amount.toLocaleString()} withdrawal · Scope: Single transaction (Teller remains Tier 1)
            </div>
            <div style="margin-top:10px;">
              <button type="button" class="btn" style="background:var(--ok); width:100%; font-weight:700;" onclick="VaultAccess.UI.handleCompleteAuthorizedWithdrawal('${activeOverride.id}')">
                Complete Authorized ₱${activeOverride.amount.toLocaleString()} Withdrawal
              </button>
            </div>
          </div>
        ` : ''}

        ${activeOverride && activeOverride.status === 'PENDING' ? `
          <div style="background:rgba(235,165,63,.1); border:1px solid var(--warn); border-radius:8px; padding:12px; margin-bottom:14px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <strong style="color:var(--warn); font-size:13px;">OVERRIDE REQUEST PENDING: ${activeOverride.id}</strong>
              <span class="tag warn">PENDING</span>
            </div>
            <div style="font-size:12px; color:var(--text); margin-top:5px;">
              Requested amount: <strong>₱${activeOverride.amount.toLocaleString('en-US', {minimumFractionDigits:2})}</strong> (Threshold: ₱60,500)
            </div>
            <div style="font-size:11.5px; color:var(--muted); margin-top:2px;">
              Awaiting Branch Supervisor review in the Supervisor Station queue.
            </div>
          </div>
        ` : ''}

        ${activeOverride && activeOverride.status === 'REJECTED' ? `
          <div style="background:rgba(240,86,111,.1); border:1px solid var(--danger); border-radius:8px; padding:12px; margin-bottom:14px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <strong style="color:var(--danger); font-size:13px;">OVERRIDE REJECTED: ${activeOverride.id}</strong>
              <span class="tag danger">REJECTED</span>
            </div>
            <div style="font-size:12px; color:var(--text); margin-top:5px;">
              Rejected by: <strong>${activeOverride.rejectedBy || 'Branch Supervisor'}</strong>
            </div>
            <div style="font-size:11.5px; color:var(--muted); margin-top:2px;">
              Transaction of ₱${activeOverride.amount.toLocaleString()} blocked by supervisor exception handling.
            </div>
          </div>
        ` : ''}

        <form onsubmit="event.preventDefault(); VaultAccess.UI.handleTellerWithdrawal();">
          <div class="form-group">
            <label for="withdrawCustName">Selected Customer Profile</label>
            <input id="withdrawCustName" value="${activeCustomer.name} (${activeCustomer.acctNumber})" readonly style="font-weight:600; color:var(--text); background:var(--panel2);">
          </div>

          <div class="form-group">
            <label for="withdrawAmount">Withdrawal Amount (PHP)</label>
            <div class="currency-input">
              <span class="currency-symbol">₱</span>
              <input id="withdrawAmount" type="number" min="100" step="50" placeholder="Max ₱60,500 without override" required>
            </div>
          </div>

          <div style="font-size:11.5px; color:var(--muted); margin-bottom:12px; line-height:1.4;">
            PRIVILEGE TIER: <strong>TELLER (TIER 1)</strong> · MAX WITHDRAWAL: <strong>₱60,500.00</strong><br>
            Amounts exceeding ₱60,500 require Tier 2 (Branch Supervisor) privilege escalation approval.
          </div>

          <div style="display:flex; gap:8px;">
            <button type="submit" class="btn" style="flex:1;">Process Withdrawal</button>
            <button type="button" class="btn ghost" style="font-size:11.5px;" onclick="document.getElementById('withdrawAmount').value=85000;">Test ₱85k Limit</button>
          </div>
        </form>

        <div style="margin-top:16px; padding-top:14px; border-top:1px solid var(--line);">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <span style="font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase; letter-spacing:.04em;">Scenario 3: Privilege Manipulation / DevTools</span>
          </div>
          <button type="button" class="btn ghost" style="width:100%; font-size:12px;" onclick="VaultAccess.UI.openHackerInspectorModal()">
            Simulate Privilege Manipulation (Role Injection Test)
          </button>
        </div>
      `;
    }

    if (activeTab === 'deposit') {
      return `
        <div style="background:rgba(235,165,63,.08); border:1px solid var(--warn); border-radius:8px; padding:10px 12px; font-size:12px; color:var(--text); margin-bottom:14px;">
          <strong style="color:var(--warn);">Presentation Demo Guide:</strong><br>
          • A customer hands over cash to deposit into their bank account.<br>
          • The teller must type the <strong>destination account number</strong> manually.<br>
          • <strong>Step 1 (Attack Demo):</strong> The teller types a wrong/fake account number to redirect the deposit (e.g. <code>9999-0000</code>).<br>
          • <strong>Step 2 (Security Lock):</strong> The system detects the mismatch and automatically freezes the terminal!
        </div>

        <form onsubmit="event.preventDefault(); VaultAccess.UI.handleTellerDeposit();">
          <div class="form-group">
            <label for="depositAcct">Customer Name (depositing cash)</label>
            <input id="depositAcct" value="${activeCustomer.name}" readonly style="font-weight:600; color:var(--text); background:var(--panel2);">
          </div>

          <div class="form-group">
            <label for="depositAcctNum">Destination Account Number (Type Manually)</label>
            <input id="depositAcctNum" placeholder="Manually enter account number (e.g. 1003-8821)" value="" autocomplete="off">
          </div>

          <div style="display:flex; gap:6px; margin-bottom:12px; font-size:11px; flex-wrap:wrap;">
            <span style="color:var(--muted);">Presets:</span>
            <button type="button" class="btn ghost" style="padding:2px 7px; font-size:11px;" onclick="document.getElementById('depositAcctNum').value='${activeCustomer.acctNumber}'">Valid Acct (${activeCustomer.acctNumber})</button>
            <button type="button" class="btn ghost" style="padding:2px 7px; font-size:11px; border-color:var(--danger); color:var(--danger);" onclick="document.getElementById('depositAcctNum').value='9999-0000'">Simulate Mismatch: 9999-0000 (Attack Demo)</button>
          </div>

          <div class="form-group">
            <label for="depositAmount">Deposit Amount (PHP)</label>
            <div class="currency-input">
              <span class="currency-symbol">₱</span>
              <input id="depositAmount" type="number" min="100" step="50" placeholder="e.g. 5000" required>
            </div>
          </div>

          <div style="display:flex; gap:8px;">
            <button type="submit" class="btn" style="flex:1; background:var(--danger); font-weight:700;">Process Cash Deposit & Verify Security</button>
          </div>
        </form>
      `;
    }
  }

  /**
   * 2. SUPERVISOR WORKSTATION (Tier 2)
   */
  function renderSupervisorWorkstation(container) {
    const overrides = VaultAccess.Banking.getSupervisorOverrides();

    container.innerHTML = `
      <div style="margin-bottom:14px; background:var(--panel2); border:1px solid var(--line); border-radius:10px; padding:12px 16px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Supervisor Station:</span>
          <strong style="margin-left:6px; color:var(--text);">Supervisor Station #01 (TERM-BR-SUPV1)</strong>
          <span style="margin-left:14px; font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Supervisor:</span>
          <strong style="margin-left:6px; color:var(--accent);">supv_108 (R. Dizon)</strong>
        </div>
        <div>
          <span class="tag ok">High-Value Approval Authority</span>
        </div>
      </div>

      <div class="bank-panel">
        <h3>High-Value Withdrawal Overrides Queue (${overrides.length})</h3>
        <div class="panel-sub">Authorizes teller transactions exceeding the standard ₱60,500 daily branch threshold.</div>

        <div id="overridesList">
          ${overrides.map(o => {
            const isPending = o.status === 'PENDING' || o.status === 'PENDING_APPROVAL';
            const isApproved = o.status === 'APPROVED';
            const isConsumed = o.status === 'CONSUMED';
            const isRejected = o.status === 'REJECTED';
            const tagClass = (isApproved || isConsumed) ? 'ok' : (isRejected ? 'danger' : 'warn');

            return `
            <div class="override-item">
              <div class="title-row">
                <div>
                  <strong style="color:var(--text); font-size:14px;">${o.id}</strong> · 
                  <span style="color:var(--muted); font-size:12px;">Requested by ${o.tellerId} (${o.terminal})</span>
                </div>
                <span class="tag ${tagClass}">${o.status}</span>
              </div>
              <div style="margin:8px 0; font-size:13px;">
                Customer: <strong>${o.customer}</strong> (${o.acct}) — 
                Amount: <strong style="color:var(--danger); font-size:14px;">₱${o.amount.toLocaleString('en-US', {minimumFractionDigits:2})}</strong>
                <span style="color:var(--muted); font-size:11.5px;">(Limit: ₱${o.threshold.toLocaleString()})</span>
              </div>
              <div style="font-size:12px; color:var(--muted); margin-bottom:10px;">${o.justification}</div>
              
              ${isPending ? `
                <div style="margin-top:10px; background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:10px;">
                  <div style="font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase; margin-bottom:6px;">Dual Authorization Reason (Maker-Checker Policy)</div>
                  <div style="display:flex; gap:8px; margin-bottom:8px; flex-wrap:wrap;">
                    <select id="ovrReasonCode_${o.id}" style="flex:1; min-width:200px; padding:6px 10px; font-size:12px; background:var(--panel); border:1px solid var(--line); color:var(--text); border-radius:6px;">
                      <option value="DUAL_ID_CONFIRMED">Dual Government ID & Signature Card Verified</option>
                      <option value="ESTABLISHED_VIP_CLIENT">Established Commercial / VIP Account</option>
                      <option value="BRANCH_MANAGER_COUNTERSIGN">Branch Manager Verbal Approval</option>
                      <option value="SUSPICIOUS_HIGH_RISK">High-Risk Presentation / Suspicious</option>
                    </select>
                    <input id="ovrNotes_${o.id}" style="flex:2; min-width:220px; padding:6px 10px; font-size:12px; background:var(--panel); border:1px solid var(--line); color:var(--text); border-radius:6px;" placeholder="Verification details..." value="Passport and PhilSys ID validated on premises">
                  </div>
                  <div style="display:flex; gap:8px;">
                    <button type="submit" class="btn" onclick="VaultAccess.UI.handleApproveOverride('${o.id}')">Approve Override</button>
                    <button type="button" class="btn ghost" style="border-color:var(--danger); color:var(--danger);" onclick="VaultAccess.UI.handleRejectOverride('${o.id}')">Reject Override</button>
                  </div>
                </div>
              ` : ''}

              ${isApproved ? `
                <div style="font-size:12px; color:var(--ok); font-weight:600;">
                  Approved by ${o.approvedBy || 'supv_108 (R. Dizon)'} · Scope: Single transaction · Awaiting Teller completion.
                </div>
              ` : ''}

              ${isConsumed ? `
                <div style="font-size:12px; color:var(--ok);">
                  Override CONSUMED on ${o.consumedAt || 'today'} by ${o.consumedBy || 'teller_402'}. Single transaction finalized. Teller remains Tier 1.
                </div>
              ` : ''}

              ${isRejected ? `
                <div style="font-size:12px; color:var(--danger);">
                  Override REJECTED by ${o.rejectedBy || 'supv_108 (R. Dizon)'}. High-value transaction blocked.
                </div>
              ` : ''}
            </div>
            `;
          }).join('')}
        </div>
      </div>

      <!-- Staff-Assisted Recovery Desk for Customers Stuck at Level 3 / Locked (Phase 8) -->
      <div class="bank-panel" style="margin-top:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <h3>Staff-Assisted Customer Recovery Desk</h3>
            <div class="panel-sub">Authorize in-person identity verification to unlock accounts halted during high-risk challenge failure.</div>
          </div>
          <button type="button" class="btn ghost" style="border-color:var(--warn); color:var(--warn); font-size:11.5px;" onclick="VaultAccess.Workstations.handleRequestSecurityReview()">
            Request SOC Security Review
          </button>
        </div>

        <div style="background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:14px; margin-top:12px;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px;">
            <div>
              <strong style="color:var(--text); font-size:14px;">M. Cruz (1002-9902)</strong>
              <span class="tag danger" style="margin-left:8px;">Account Locked</span>
              <div style="font-size:12px; color:var(--muted); margin-top:4px;">
                Incident: Final identity challenge expired · Password sign-in disabled · Account frozen pending in-person verification
              </div>
            </div>
            <button type="button" class="btn" style="background:var(--ok); font-size:12px;" onclick="VaultAccess.Workstations.handleStaffAssistedRecovery('1002-9902')">
              Conduct In-Person Recovery (Verify PhilSys ID)
            </button>
          </div>
        </div>
      </div>

      <!-- Branch Teller Limits & Activity Overview (Phase 8) -->
      <div class="bank-panel" style="margin-top:16px;">
        <h3>Branch Operations & Cash Limit Overview</h3>
        <div class="panel-sub">Real-time status of branch counter terminals, teller transaction limits, and daily caps.</div>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-top:12px;">
          <div style="background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px;">
            <div style="font-size:11px; text-transform:uppercase; color:var(--muted);">Teller Counter Limit</div>
            <div style="font-size:18px; font-weight:700; color:var(--accent); margin-top:4px;">₱60,500.00</div>
            <div style="font-size:11px; color:var(--muted); margin-top:2px;">Threshold for mandatory supervisor override</div>
          </div>
          <div style="background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px;">
            <div style="font-size:11px; text-transform:uppercase; color:var(--muted);">Branch Shift Cash Flow</div>
            <div style="font-size:18px; font-weight:700; color:var(--text); margin-top:4px;">₱1,280,000.00</div>
            <div style="font-size:11px; color:var(--ok); margin-top:2px;">All 14 branch drawers within limits</div>
          </div>
          <div style="background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px;">
            <div style="font-size:11px; text-transform:uppercase; color:var(--muted);">Assigned Tellers Online</div>
            <div style="font-size:18px; font-weight:700; color:var(--ok); margin-top:4px;">1 Active (TERM-BR14)</div>
            <div style="font-size:11px; color:var(--muted); margin-top:2px;">Operator: teller_402 (A. Santos)</div>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * 3. IT ADMIN WORKSTATION (Tier 3)
   */
  function renderITAdminWorkstation(container) {
    const nodes = VaultAccess.Banking.getInfrastructureNodes();

    container.innerHTML = `
      <div style="margin-bottom:14px; background:var(--panel2); border:1px solid var(--line); border-radius:10px; padding:12px 16px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Connection:</span>
          <strong style="margin-left:6px; color:var(--text);">Remote Admin VPN [Encrypted]</strong>
          <span style="margin-left:14px; font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Operator:</span>
          <strong style="margin-left:6px; color:var(--accent);">sys_it88 (K. Lim)</strong>
        </div>
        <div>
          <span class="tag warn">Separation of Duties (SoD) Active</span>
        </div>
      </div>

      ${(() => {
        const activity = VaultAccess.Workstations.getITSessionActivity();

        return `
          <!-- Server Node Telemetry & Maintenance Controls -->
          <div class="bank-panel" style="margin-bottom:16px;">
            <h3>Core Banking Infrastructure & Server Node Telemetry</h3>
            <div class="panel-sub">Monitors cluster health, transaction gateways, and hardware security modules.</div>

            <div class="infra-grid">
              ${nodes.map(n => `
                <div class="infra-card">
                  <div class="node-name">${n.name}</div>
                  <div class="node-ip">${n.id} · ${n.ip}</div>
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <span class="tag ok">${n.status}</span>
                    <span style="font-size:11px; color:var(--muted); font-family:'JetBrains Mono',monospace;">CPU ${n.cpu} · ${n.latency}</span>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>

          <!-- Separation of Duties Block Desk -->
          <div class="bank-panel" style="margin-bottom:16px;">
            <h3 style="color:var(--danger);">Separation of Duties Verification Desk (SoD Policy - G2)</h3>
            <div class="panel-sub">Demonstrates that system administrators cannot query customer financial PII or ledger balances.</div>
            <p style="font-size:13px; color:var(--text); margin-bottom:12px;">
              Under enterprise security policy, IT administrators maintain infrastructure uptime but are strictly barred from querying customer account records or financial balances.
            </p>
            <button type="button" class="btn" style="background:var(--danger);" onclick="VaultAccess.UI.handleITAdminPIIAttempt()">
              Query Customer Balances &amp; PII (Demonstrate SoD Block)
            </button>
            <div id="itAdminPIIBanner" class="banner" style="margin-top:14px;"></div>
          </div>

          <!-- Session Activity Log -->
          <div class="bank-panel">
            <h3>My Session Activity (IT Admin Audit Log)</h3>
            <div class="panel-sub">Verifiable telemetry for current administrative session.</div>
            <div style="font-size:11.5px; font-family:'JetBrains Mono',monospace; max-height:200px; overflow-y:auto; margin-top:8px;">
              ${activity.length === 0
                ? `<div style="color:var(--muted); padding:16px 0; text-align:center; font-size:12px;">No activity yet this session. Actions you take will appear here.</div>`
                : activity.map(act => `
                  <div style="padding:4px 0; border-bottom:1px solid var(--line); display:flex; justify-content:space-between;">
                    <span><strong style="color:var(--muted);">${act.time}</strong> ${act.action}</span>
                    <span class="tag ${act.status === 'SUCCESS' ? 'ok' : (act.status === 'ELEVATED' ? 'warn' : '')}" style="font-size:10px;">${act.status}</span>
                  </div>
                `).join('')}
            </div>
          </div>
        `;
      })()}
    `;
  }


  /**
   * 4. SECURITY ADMIN WORKSTATION (Tier 4)
   */
  function renderSecAdminWorkstation(container) {
    const lockState = VaultAccess.Banking.getTerminalLockState();

    container.innerHTML = `
      <div style="margin-bottom:14px; background:var(--panel2); border:1px solid var(--line); border-radius:10px; padding:12px 16px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Command Node:</span>
          <strong style="margin-left:6px; color:var(--text);">SOC Command Gateway [Encrypted]</strong>
          <span style="margin-left:14px; font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Security Officer:</span>
          <strong style="margin-left:6px; color:var(--accent);">sec_soc01 (L. Garcia)</strong>
        </div>
        <div>
          <span class="tag danger">Tier 4 Override Authority</span>
        </div>
      </div>

      <div class="bank-panel" style="margin-bottom:18px;">
        <h3>Branch Terminal Lockout Remediation Desk</h3>
        <div class="panel-sub">Authorizes forensic review and clears automated fraud freezes across branch terminals.</div>

        <div style="background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <div>
              <strong style="font-size:14px; color:var(--text);">Branch Terminal #14 (TERM-BR14)</strong>
              <div style="font-size:12px; color:var(--muted);">Assigned Operator: teller_402 (A. Santos)</div>
            </div>
            <span class="tag ${lockState.isLocked ? 'danger' : 'ok'}">${lockState.isLocked ? 'FROZEN / LOCKED' : 'NORMAL / OPERATIONAL'}</span>
          </div>

          ${lockState.isLocked ? `
            <div style="background:rgba(240,86,111,.08); border:1px solid var(--danger); border-radius:8px; padding:12px; margin:12px 0;">
              <strong style="color:var(--danger); font-size:12.5px;">Active Lockout Flag:</strong>
              <p style="margin:4px 0 0; font-size:12px; color:var(--text);">${lockState.reason}</p>
              <div style="font-size:11.5px; color:var(--muted); margin-top:6px;">
                Locked At: <strong>${lockState.lockedAt}</strong> · Ref: <strong style="color:var(--warn);">${lockState.refCode || 'N/A'}</strong> · Escalation Attempts Logged: <strong>${lockState.escalationAttemptCount}</strong>
              </div>
            </div>

            <div style="background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px; margin-bottom:12px;">
              <div style="font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase; margin-bottom:6px;">Maker-Checker Resolution Requirements (G4)</div>
              <div style="display:flex; gap:8px; margin-bottom:8px; flex-wrap:wrap;">
                <div style="width:140px;">
                  <label for="secUnlockIncidentId" style="font-size:10.5px; color:var(--muted); display:block; margin-bottom:2px;">Incident Ref ID</label>
                  <input id="secUnlockIncidentId" style="width:100%; padding:6px 8px; font-size:12px; background:var(--panel2); border:1px solid var(--line); color:var(--text); border-radius:6px;" value="INC-4011" placeholder="INC-####">
                </div>
                <div style="flex:1; min-width:240px;">
                  <label for="secUnlockJustification" style="font-size:10.5px; color:var(--muted); display:block; margin-bottom:2px;">Forensic Justification (Min 15 chars)</label>
                  <input id="secUnlockJustification" style="width:100%; padding:6px 8px; font-size:12px; background:var(--panel2); border:1px solid var(--line); color:var(--text); border-radius:6px;" value="Lobby rush typo verified; customer identity confirmed in person." placeholder="Enter mandatory justification...">
                </div>
              </div>
              <button type="button" class="btn" style="background:var(--ok);" onclick="VaultAccess.UI.handleSecAdminUnlockTerminal()">
                Authorize Security Review & Unlock Terminal
              </button>
            </div>
          ` : `
            <div style="font-size:12.5px; color:var(--ok); margin-top:10px;">
              [NORMAL] Terminal is operating normally with no active fraud flags.
            </div>
          `}
        </div>
      </div>

      <div class="bank-panel" style="margin-bottom:18px;">
        <h3 style="color:var(--danger);">Separation of Duties Verification (Zero Money Movement Policy - G2)</h3>
        <div class="panel-sub">Security Admins hold full forensic and administrative authority, but cannot initiate deposits, withdrawals, or transfers.</div>
        <p style="font-size:12.5px; color:var(--text); margin-bottom:12px; line-height:1.5;">
          Under enterprise banking policy, all administrative tiers are strictly prohibited from moving money. Attempting a financial transaction as Security Admin triggers an immediate <strong>403 Forbidden</strong> and writes an audit breach event.
        </p>
        <button type="button" class="btn" style="background:var(--danger);" onclick="VaultAccess.UI.handleSecAdminTransactionAttempt()">
          Try a Financial Transaction as Security Admin (Demonstrate SoD Block)
        </button>
        <div id="secAdminSoDBanner" class="banner" style="margin-top:12px;"></div>
      </div>

      <div class="bank-panel">
        <h3>URL Path Tampering & Account Freeze Control Desk</h3>
        <div class="panel-sub">Monitor unauthorized direct URL path escalations (e.g. /secadmin) and remotely freeze or unfreeze compromised operator accounts with 24h auto-expiry.</div>

        <div style="background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:16px;">
          <h4 style="font-size:13px; margin:0 0 10px; color:var(--text);">Detected URL Path Escalations & Account Status</h4>
          ${(() => {
            const incidents = VaultAccess.Auth.getURLTamperIncidents();
            const freezes = VaultAccess.Auth.getAccountFreezes();
            const users = VaultAccess.Config.USERS;

            return `
              <div style="overflow-x:auto;">
                <table style="width:100%; border-collapse:collapse; font-size:12px; text-align:left;">
                  <thead>
                    <tr style="border-bottom:1px solid var(--line); color:var(--muted);">
                      <th style="padding:8px;">User / Operator</th>
                      <th style="padding:8px;">Assigned Role</th>
                      <th style="padding:8px;">Account Status & Expiry</th>
                      <th style="padding:8px;">Suspicious Activity / Escalations</th>
                      <th style="padding:8px; text-align:right;">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${(() => {
                      // Filter to unique primary accounts
                      const primaryUsernames = Object.keys(users).filter(k => users[k].user === k);
                      
                      // Calculate active headcount per role
                      const headcountByRole = {};
                      primaryUsernames.forEach(k => {
                        const r = users[k].role;
                        headcountByRole[r] = (headcountByRole[r] || 0) + 1;
                      });

                      return primaryUsernames.map(username => {
                        const u = users[username];
                        const isFrozen = !!freezes[username];
                        const userIncidents = incidents.filter(inc => inc.username === username);
                        const isSoleMember = (headcountByRole[u.role] || 0) <= 1;

                        return `
                          <tr style="border-bottom:1px solid var(--line);">
                            <td style="padding:10px 8px;">
                              <strong>${u.name}</strong><br>
                              <span style="font-size:11px; color:var(--muted);">${u.user} (${u.operatorId})</span>
                            </td>
                            <td style="padding:10px 8px;">
                              <span class="tag">${VaultAccess.Config.ROLES[u.role].label}</span>
                              ${isSoleMember ? `<div style="font-size:10px; color:var(--warn); margin-top:2px;">Sole operator in role</div>` : ''}
                            </td>
                            <td style="padding:10px 8px;">
                              ${isFrozen
                                ? `<span class="tag danger" style="font-weight:700;">[FROZEN / SUSPENDED]</span><br>
                                   <span style="font-size:10.5px; color:#ff9eaf;">${freezes[username].reason}</span><br>
                                   <span style="font-size:10.5px; color:var(--muted);">Auto-Expires: <strong>${freezes[username].expiresAt || '24h'}</strong></span>`
                                : `<span class="tag ok">ACTIVE / NORMAL</span>`
                              }
                            </td>
                            <td style="padding:10px 8px;">
                              ${userIncidents.length > 0
                                ? `<span style="color:var(--danger); font-weight:600;">[ALERT] ${userIncidents.length} URL breach attempt(s)</span><br><span style="font-size:11px; color:var(--muted);">${userIncidents[0].details}</span>`
                                : `<span style="color:var(--muted);">No direct breaches detected</span>`
                              }
                            </td>
                            <td style="padding:10px 8px; text-align:right;">
                              ${isFrozen ? `
                                <div style="display:flex; gap:4px; justify-content:flex-end;">
                                  <button type="button" class="btn" style="background:var(--ok); font-size:11px; padding:4px 8px;" onclick="VaultAccess.UI.handleUnfreezeAccount('${username}')">
                                    Unfreeze
                                  </button>
                                  <button type="button" class="btn ghost" style="font-size:10.5px; padding:4px 8px;" title="Fast-forward 24h to demonstrate auto-lift" onclick="VaultAccess.UI.handleFastForwardFreeze('${username}')">
                                    Simulate Expiry (Demo)
                                  </button>
                                </div>
                              ` : `
                                <button type="button" class="btn" 
                                  style="background:var(--danger); font-size:11px; padding:4px 10px; ${isSoleMember ? 'opacity:0.45; cursor:not-allowed;' : ''}" 
                                  ${isSoleMember ? 'disabled title="Cannot freeze: Only 1 person assigned to this role. Operational continuity requires at least one active operator."' : `onclick="VaultAccess.UI.handleFreezeAccount('${username}')"`}>
                                  Freeze Account
                                </button>
                              `}
                            </td>
                          </tr>
                        `;
                      }).join('');
                    })()}
                  </tbody>
                </table>
              </div>
            `;
          })()}
        </div>
      </div>

      <!-- Active Directory Tier Assignment Policy Editor (Phase 8 - Maker-Checker) -->
      <div class="bank-panel" style="margin-top:16px;">
        <h3>Active Directory Tier Assignment Policy Editor</h3>
        <div class="panel-sub">Manage enterprise personnel tier boundaries. Policy changes require mandatory justification and create chained audit records.</div>

        <div style="background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:16px; margin-top:12px; overflow-x:auto;">
          <table style="width:100%; border-collapse:collapse; font-size:12px; text-align:left;">
            <thead>
              <tr style="border-bottom:1px solid var(--line); color:var(--muted);">
                <th style="padding:8px;">Operator ID</th>
                <th style="padding:8px;">Staff Member</th>
                <th style="padding:8px;">Assigned Role</th>
                <th style="padding:8px;">Current Tier</th>
                <th style="padding:8px; text-align:right;">Modify Policy</th>
              </tr>
            </thead>
            <tbody>
              ${(() => {
                const assignments = VaultAccess.Workstations.getADTierAssignments();
                
                // Calculate headcount per role across assignments
                const roleCounts = {};
                Object.keys(assignments).forEach(id => {
                  const r = assignments[id].role;
                  roleCounts[r] = (roleCounts[r] || 0) + 1;
                });

                return Object.keys(assignments).map(opId => {
                  const a = assignments[opId];
                  const isSoleMember = (roleCounts[a.role] || 0) <= 1;

                  return `
                    <tr style="border-bottom:1px solid var(--line);">
                      <td style="padding:8px;"><code>${opId}</code></td>
                      <td style="padding:8px;">
                        <strong>${a.name}</strong>
                        ${isSoleMember ? `<div style="font-size:10px; color:var(--warn); margin-top:2px;">Sole operator in role</div>` : ''}
                      </td>
                      <td style="padding:8px;">${a.role}</td>
                      <td style="padding:8px;">
                        <span class="tag ${a.tier === 4 ? 'danger' : (a.tier === 3 ? 'warn' : 'ok')}">Tier ${a.tier}</span>
                      </td>
                      <td style="padding:8px; text-align:right;">
                        <button type="button" class="btn ghost" 
                                style="padding:3px 8px; font-size:11px; ${isSoleMember ? 'opacity:0.45; cursor:not-allowed;' : ''}"
                                ${isSoleMember ? 'disabled title="Cannot edit tier: Only 1 person assigned to this role. Minimum 1 staff member required to maintain operational coverage."' : `onclick="VaultAccess.Workstations.handleEditTierAssignment('${opId}', prompt('Select new Tier (1, 2, 3, or 4):', '${a.tier}'))"`}>
                          Edit Tier
                        </button>
                      </td>
                    </tr>
                  `;
                }).join('');
              })()}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // --------------------------------------------------------------------------
  // Automated Terminal Freeze Overlay & Hacker DevTools Modal
  // --------------------------------------------------------------------------

  function checkTerminalFreezeState() {
    const overlay = document.getElementById('terminalFreezeOverlay');
    const lockState = VaultAccess.Banking.getTerminalLockState();
    const currentRole = VaultAccess.Auth.getCurrentRole();

    if (!overlay) return;

    // Show screen freeze ONLY if actively authenticated, terminal is locked, and user is teller
    const isAuthed = document.body.classList.contains('authed') && VaultAccess.Auth.isAuthenticated();

    if (isAuthed && lockState.isLocked && currentRole && currentRole.id === 'teller') {
      const freezeMsg = document.getElementById('freezeMsg');
      const freezeMeta = document.getElementById('freezeMeta');

      if (freezeMsg) freezeMsg.textContent = lockState.neutralTellerMessage || "Verification required. Please contact your supervisor.";
      if (freezeMeta) {
        const refStr = lockState.refCode ? `REFERENCE CODE: <strong style="color:var(--warn);">${lockState.refCode}</strong><br>` : '';
        freezeMeta.innerHTML = `
          TERMINAL ID: <strong>${lockState.terminalId}</strong><br>
          OPERATOR ID: <strong>${lockState.operatorId} (Branch Teller)</strong><br>
          TIMESTAMP:   <strong>${lockState.lockedAt || 'NOW'}</strong><br>
          ${refStr}
          STATUS:      <strong>OPERATIONAL HOLD — VERIFICATION REQUIRED</strong><br><br>
          <div style="background:rgba(255,255,255,0.06); padding:8px 10px; border-radius:6px; font-size:12px; color:var(--text); line-height:1.4; text-align:left;">
            <strong style="color:var(--accent);">What to do next:</strong><br>
            • Please contact your Branch Supervisor (Ext. 201) or Security Admin.<br>
            • Provide your Terminal ID (<code>${lockState.terminalId}</code>) and Reference Code.<br>
            • A dual-authorization security review is required to restore terminal operations.
          </div>
        `;
      }

      overlay.classList.add('active');
    } else {
      overlay.classList.remove('active');
    }
  }

  function openHackerInspectorModal() {
    const modal = document.getElementById('hackerModal');
    if (!modal) return;

    const codePreview = document.getElementById('hackerCodePreview');
    const responseBox = document.getElementById('serverResponseBox');

    if (responseBox) responseBox.classList.remove('show');

    if (codePreview) {
      codePreview.innerHTML = `// Outgoing HTTP Request from Branch Terminal #14
POST /api/v1/terminal/security/clear-fraud-lock HTTP/1.1
Host: core.vaultaccess.internal
X-Terminal-ID: TERM-BR14
X-Operator-ID: teller_402
Content-Type: application/json

{
  "terminalId": "TERM-BR14",
  "operatorId": "teller_402",
  "action": "CLEAR_FRAUD_FLAG_AND_UNLOCK",
  <span class="tampered">"isSecurityApproved": true</span>,
  <span class="tampered">"clientRoleOverride": "Security_Admin"</span>
}`;
    }

    modal.classList.add('active');
  }

  function closeHackerInspectorModal() {
    const modal = document.getElementById('hackerModal');
    if (modal) modal.classList.remove('active');
  }

  function executeTamperedRequestAttack() {
    const payload = VaultAccess.Banking.generateHackerPayload().payload;
    const response = VaultAccess.Banking.executeServerPrivilegeEscalationDefense(payload);

    const responseBox = document.getElementById('serverResponseBox');
    if (responseBox) {
      responseBox.innerHTML = `
        <div style="font-weight:700; color:var(--danger); margin-bottom:8px;">
          HTTP/1.1 ${response.httpStatus} ${response.statusText}
        </div>
        <div style="background:#090b16; border:1px solid var(--danger); border-radius:6px; padding:12px; margin-bottom:10px; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.7;">
          <div style="color:var(--danger); font-weight:700; font-size:13px; margin-bottom:6px;">PRIVILEGE MANIPULATION DETECTED</div>
          <div><span style="color:var(--muted);">Requested role:</span> <strong style="color:#ff9eaf;">${response.requestedRole}</strong></div>
          <div><span style="color:var(--muted);">Actual assigned role:</span> <strong style="color:var(--text);">${response.actualAssignedRole}</strong></div>
          <div><span style="color:var(--muted);">Result:</span> <strong style="color:var(--danger);">${response.result}</strong></div>
          <div style="margin-top:6px; color:var(--muted); font-size:11px;">Security event logged to Escalation Monitor.</div>
        </div>
        <div style="background:rgba(55,194,129,.12); border:1px solid var(--ok); border-radius:6px; padding:10px; color:var(--text); font-family:'Inter',sans-serif; font-size:12px;">
          <strong style="color:var(--ok);">[PREVENTION VERIFIED]</strong><br>
          The secure backend ignored client-supplied privilege claims, enforced the actual authenticated session role, kept the terminal frozen, and recorded a critical insider-threat event in the Escalation Monitor.
        </div>
      `;
      responseBox.classList.add('show');
    }

    renderEscalationLog();
  }

  // --------------------------------------------------------------------------
  // Event Handlers for Banking Actions
  // --------------------------------------------------------------------------

  function switchBankTab(tabName) {
    activeTab = tabName;
    const content = document.getElementById('bankTabContent');
    if (content) content.innerHTML = renderBankTabContent();
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.textContent.toLowerCase().includes(tabName));
    });
  }

  function loadCustomerSample(acctNum) {
    const found = VaultAccess.Banking.lookupCustomer(acctNum);
    if (found) {
      activeCustomer = found;
      const searchInput = document.getElementById('tellerCustomerSearch');
      if (searchInput) searchInput.value = found.name;
      document.getElementById('tellerCustomerCard').innerHTML = renderCustomerCard(found);
      document.getElementById('bankTabContent').innerHTML = renderBankTabContent();
    }
  }

  function handleTellerDeposit() {
    if (!activeCustomer) return;
    let typedAcct = document.getElementById('depositAcctNum').value;
    // Fallback to the correct account if user leaves field empty (valid deposit)
    if (!typedAcct) typedAcct = activeCustomer.acctNumber;
    const amount = document.getElementById('depositAmount').value;
    const res = VaultAccess.Banking.processDeposit(activeCustomer, typedAcct, amount);

    alert(res.message);
    if (res.success) {
      document.getElementById('tellerCustomerCard').innerHTML = renderCustomerCard(activeCustomer);
      document.getElementById('depositAmount').value = "";
      document.getElementById('depositAcctNum').value = "";
    } else if (res.terminalLocked) {
      checkTerminalFreezeState();
      renderEscalationLog();
    }
  }

  function handleTellerWithdrawal() {
    if (!activeCustomer) return;
    const amountInput = document.getElementById('withdrawAmount');
    const amount = amountInput ? amountInput.value : "";

    const res = VaultAccess.Banking.processWithdrawal(activeCustomer, amount);

    if (res.terminalLocked) {
      checkTerminalFreezeState();
      renderEscalationLog();
    } else if (res.requiresEscalation) {
      // Scenario 1: Step-up privilege escalation required
      openEscalationModal(activeCustomer, res.requestedAmount);
    } else if (res.pending) {
      alert(res.message);
    } else if (res.blocked) {
      alert(res.message);
    } else if (res.success) {
      alert(res.message);
      document.getElementById('tellerCustomerCard').innerHTML = renderCustomerCard(activeCustomer);
      document.getElementById('bankTabContent').innerHTML = renderBankTabContent();
      if (amountInput) amountInput.value = "";
      renderEscalationLog();
    } else {
      alert(res.message);
    }
  }

  function handleCompleteAuthorizedWithdrawal(overrideId) {
    if (!activeCustomer) return;
    const activeOverride = VaultAccess.Banking.findActiveOverride(activeCustomer.acctNumber);
    const amount = activeOverride ? activeOverride.amount : 85000;
    const res = VaultAccess.Banking.processWithdrawal(activeCustomer, amount);

    alert(res.message);
    if (res.success) {
      document.getElementById('tellerCustomerCard').innerHTML = renderCustomerCard(activeCustomer);
      document.getElementById('bankTabContent').innerHTML = renderBankTabContent();
      renderEscalationLog();
    }
  }

  function openEscalationModal(customer, amount) {
    const modal = document.getElementById('escalationModal');
    if (!modal) return;

    const details = document.getElementById('escalationDetails');
    const actions = document.getElementById('escalationActions');
    const parsedAmount = parseFloat(amount);

    if (details) {
      details.innerHTML = `
        <div style="background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:14px; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.7; margin-bottom:12px;">
          <div><span style="color:var(--muted);">Current Tier:</span> <strong style="color:var(--text);">Tier 1 — Branch Teller</strong></div>
          <div><span style="color:var(--muted);">Teller Limit:</span> <strong style="color:var(--text);">₱60,500.00</strong></div>
          <div><span style="color:var(--muted);">Requested Amount:</span> <strong style="color:var(--danger); font-size:13px;">₱${parsedAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })}</strong></div>
          <div><span style="color:var(--muted);">Required Tier:</span> <strong style="color:var(--warn);">Tier 2 — Branch Supervisor</strong></div>
        </div>
        <p style="font-size:13px; color:var(--text); margin:0 0 6px; font-weight:600;">
          A supervisor approval is required.
        </p>
        <p style="font-size:12px; color:var(--muted); margin:0;">
          Withdrawal exceeds Teller ₱60,500 threshold. Request a supervisor override to dispatch this transaction to the Supervisor Overrides Queue.
        </p>
      `;
    }

    if (actions) {
      actions.innerHTML = `
        <button type="button" class="btn" style="flex:1;" onclick="VaultAccess.UI.handleRequestSupervisorOverride('${customer.acctNumber}', ${parsedAmount})">
          Request Supervisor Override
        </button>
        <button type="button" class="btn ghost" onclick="VaultAccess.UI.closeEscalationModal()">
          Cancel
        </button>
      `;
    }

    modal.classList.add('active');
  }

  function closeEscalationModal() {
    const modal = document.getElementById('escalationModal');
    if (modal) modal.classList.remove('active');
  }

  function handleRequestSupervisorOverride(acctNumber, amount) {
    const res = VaultAccess.Banking.createOverrideRequest(acctNumber, amount);
    closeEscalationModal();

    if (res.success) {
      alert(`Override request ${res.override.id} generated successfully.\n\nStatus: PENDING Branch Supervisor approval.\nPlease have Branch Supervisor approve this in the Supervisor Station.`);
      const content = document.getElementById('bankTabContent');
      if (content) content.innerHTML = renderBankTabContent();
      renderEscalationLog();
    } else {
      alert(res.message);
    }
  }

  function handleApproveOverride(id) {
    const codeEl = document.getElementById('ovrReasonCode_' + id);
    const notesEl = document.getElementById('ovrNotes_' + id);
    const reasonCode = codeEl ? codeEl.value : "DUAL_ID_CONFIRMED";
    const notes = notesEl ? notesEl.value : "";

    const res = VaultAccess.Banking.approveOverride(id, reasonCode, notes);
    alert(res.message);
    renderSupervisorWorkstation(document.getElementById('bankWorkContainer'));
    renderEscalationLog();
  }

  function handleRejectOverride(id) {
    const codeEl = document.getElementById('ovrReasonCode_' + id);
    const notesEl = document.getElementById('ovrNotes_' + id);
    const reasonCode = codeEl ? codeEl.value : "SUSPICIOUS_HIGH_RISK";
    const notes = notesEl ? notesEl.value : "";

    const res = VaultAccess.Banking.rejectOverride(id, reasonCode, notes);
    alert(res.message);
    renderSupervisorWorkstation(document.getElementById('bankWorkContainer'));
    renderEscalationLog();
  }

  function handleITAdminPIIAttempt() {
    const res = VaultAccess.Banking.attemptViewCustomerPII();
    const banner = document.getElementById('itAdminPIIBanner');
    if (banner) {
      banner.textContent = res.message;
      banner.classList.add('show');
    }
    renderEscalationLog();
  }

  function handleSecAdminUnlockTerminal() {
    const justEl = document.getElementById('secUnlockJustification');
    const incEl = document.getElementById('secUnlockIncidentId');
    const justification = justEl ? justEl.value : "";
    const incidentId = incEl ? incEl.value : "";

    const res = VaultAccess.Banking.unlockTerminalBySecurityAdmin(justification, incidentId);
    alert(res.message);
    if (res.success) {
      renderSecAdminWorkstation(document.getElementById('bankWorkContainer'));
      renderEscalationLog();
      checkTerminalFreezeState();
    }
  }

  function handleSecAdminTransactionAttempt() {
    // Demonstration of Separation of Duties (G2): Tier 4 cannot move money
    const dummyCustomer = { acctNumber: "1001-4471", name: "J. Reyes" };
    const res = VaultAccess.Banking.processWithdrawal(dummyCustomer, 15000);
    const banner = document.getElementById('secAdminSoDBanner');
    if (banner) {
      banner.textContent = res.message;
      banner.style.borderColor = "var(--danger)";
      banner.style.background = "rgba(240, 86, 111, .1)";
      banner.classList.add('show');
    }
    renderEscalationLog();
    alert(res.message);
  }

  function handleFastForwardFreeze(username) {
    const lifted = VaultAccess.Auth.fastForwardFreezeExpiry(username);
    if (lifted) {
      alert(`[SIMULATION] Fast-forwarded 24 hours. The freeze on account "${username}" has reached its expiration window and was automatically lifted.`);
      renderSecAdminWorkstation(document.getElementById('bankWorkContainer'));
      renderEscalationLog();
    }
  }

  function renderActionBanner(evalResult) {
    const banner = document.getElementById('denyBanner');
    if (!banner) return;

    banner.textContent = evalResult.reason;
    banner.classList.remove('show');
    banner.classList.add('show');

    if (evalResult.allowed) {
      banner.style.borderColor = "var(--ok)";
      banner.style.background = "rgba(55, 194, 129, .08)";
    } else {
      banner.style.borderColor = "";
      banner.style.background = "";
    }
  }

  function handleFreezeAccount(username) {
    const current = VaultAccess.Auth.getCurrentRole();
    if (!current || current.id !== 'secadmin') {
      showModalNotification("Permission Denied: Only Security Admin can freeze accounts.", "Access Denied", "danger");
      return;
    }

    const users = VaultAccess.Config.USERS;
    const targetUser = users[username];
    if (targetUser) {
      // Count active operators in this role
      const primaryUsernames = Object.keys(users).filter(k => users[k].user === k);
      const sameRoleCount = primaryUsernames.filter(k => users[k].role === targetUser.role).length;
      if (sameRoleCount <= 1) {
        showModalNotification(
          `Operational Rule: Cannot freeze "${targetUser.name}". There is only 1 person assigned to the ${VaultAccess.Config.ROLES[targetUser.role].label} role. Operational continuity requires at least one active staff member.`,
          "Action Prohibited: Minimum Coverage Required",
          "warn"
        );
        return;
      }
    }

    const reason = prompt(`Enter reason to freeze account "${username}":`, "Detected unauthorized URL privilege escalation attempt (/secadmin)");
    if (!reason) return;

    VaultAccess.Auth.freezeAccount(username, reason);

    // Audit log this action
    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "SOC Command Gateway [secadmin]",
      acct: username,
      action: `ACCOUNT FREEZE ENFORCED: Account "${username}" suspended by Security Admin. Reason: ${reason}`,
      result: "reviewed"
    });

    showModalNotification(
      `Account "${username}" has been frozen. The user will be blocked from logging in with an account suspension notification.`,
      "Account Frozen",
      "ok"
    );
    renderSecAdminWorkstation(document.getElementById('bankWorkContainer'));
    renderEscalationLog();
  }

  function handleUnfreezeAccount(username) {
    const current = VaultAccess.Auth.getCurrentRole();
    if (!current || current.id !== 'secadmin') {
      showModalNotification("Permission Denied: Only Security Admin can unfreeze accounts.", "Access Denied", "danger");
      return;
    }

    if (!confirm(`Are you sure you want to lift the suspension on account "${username}"?`)) return;

    VaultAccess.Auth.unfreezeAccount(username);

    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "SOC Command Gateway [secadmin]",
      acct: username,
      action: `ACCOUNT FREEZE LIFTED: Account "${username}" restored to normal status by Security Admin.`,
      result: "reviewed"
    });

    showModalNotification(
      `Account "${username}" is now unfrozen and may log in normally.`,
      "Account Restored",
      "ok"
    );
    renderSecAdminWorkstation(document.getElementById('bankWorkContainer'));
    renderEscalationLog();
  }

  /**
   * Handles Security Admin resolution of an ASSESSING_INTENT incident (Lucid Staff Flow Step 4).
   * @param {string} incidentId
   * @param {'CONFIRMED_MALICIOUS'|'UNCONFIRMED'} decision
   */
  function handleResolveIncident(incidentId, decision) {
    const current = VaultAccess.Auth.getCurrentRole();
    if (!current || current.id !== 'secadmin') {
      alert("Permission Denied: Only Security Admin (Tier 4) can resolve escalation incidents.");
      return;
    }

    const session = VaultAccess.Auth.getSession();
    const result = VaultAccess.Audit.resolveIncident(incidentId, decision, session);

    if (!result.success) {
      alert("Resolution error: " + result.message);
      return;
    }

    renderEscalationLog();
    const bankContainer = document.getElementById('bankWorkContainer');
    if (bankContainer && current.id === 'secadmin') {
      renderSecAdminWorkstation(bankContainer);
    }

    if (decision === 'CONFIRMED_MALICIOUS') {
      alert(`[INCIDENT RESOLVED: MALICIOUS]\nCase ${incidentId} confirmed malicious. Operator account "${result.incident.username}" has been suspended and forensic log entry recorded.`);
    } else {
      alert(`[INCIDENT RESOLVED: UNCONFIRMED]\nCase ${incidentId} intent unconfirmed. Temporary elevated access revoked, operator "${result.incident.username}" flagged for monitoring, and log entry recorded.`);
    }
  }

  return {
    showView,
    updateRoleDisplay,
    renderTiers,
    renderEscalationLog,
    renderBankWorkstation,
    switchBankTab,
    loadCustomerSample,
    handleTellerDeposit,
    handleTellerWithdrawal,
    handleApproveOverride,
    handleRejectOverride,
    handleITAdminPIIAttempt,
    handleSecAdminUnlockTerminal,
    handleSecAdminTransactionAttempt,
    handleFastForwardFreeze,
    handleFreezeAccount,
    handleUnfreezeAccount,
    handleResolveIncident,
    checkTerminalFreezeState,
    openHackerInspectorModal,
    closeHackerInspectorModal,
    executeTamperedRequestAttack,
    renderActionBanner,
    openEscalationModal,
    closeEscalationModal,
    handleRequestSupervisorOverride,
    handleCompleteAuthorizedWithdrawal,
    showModalNotification
  };
})();
