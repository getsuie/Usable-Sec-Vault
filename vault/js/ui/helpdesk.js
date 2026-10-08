/**
 * ============================================================================
 * VaultAccess — UI Module: Help Desk Console (Tier 2-H)
 * ============================================================================
 * Provides customer identity triage, lockout diagnostics, human-readable
 * security context tags (USA-04), 3-minute SLA resolution timer,
 * identity re-verification, and one-click SOC escalation.
 *
 * NOTE: Customer-side data is simulated mock data only.
 * No passwords or OTP secret codes are ever displayed.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.HelpDesk = (function () {
  let tickets = [];
  let selectedTicketId = null;
  let activeFilter = 'ALL';
  let slaTimerInterval = null;

  /**
   * Initializes ticket working queue from mock data.
   */
  function init() {
    tickets = JSON.parse(JSON.stringify(VaultAccess.Config.MOCK_HELP_DESK_TICKETS || []));
    if (tickets.length > 0) {
      selectedTicketId = tickets[0].id;
    }
    startSlaTicker();
  }

  /**
   * Starts live SLA tick for open tickets to provide a live resolution timer.
   */
  function startSlaTicker() {
    if (slaTimerInterval) clearInterval(slaTimerInterval);
    slaTimerInterval = setInterval(() => {
      let updated = false;
      tickets.forEach(t => {
        if (t.status === 'OPEN') {
          t.elapsedSec = (t.elapsedSec || 0) + 1;
          updated = true;
        }
      });
      if (updated) {
        updateTimerDisplays();
      }
    }, 1000);
  }

  function formatTime(totalSeconds) {
    const mm = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
    const ss = (totalSeconds % 60).toString().padStart(2, '0');
    return `${mm}:${ss}`;
  }

  function updateTimerDisplays() {
    const activeEl = document.getElementById('hdActiveTimer');
    const selected = tickets.find(t => t.id === selectedTicketId);
    if (activeEl && selected) {
      const remaining = Math.max(0, (selected.targetSlaSec || 180) - (selected.elapsedSec || 0));
      const isBreached = (selected.elapsedSec || 0) > (selected.targetSlaSec || 180);
      activeEl.textContent = formatTime(remaining);
      activeEl.style.color = isBreached ? 'var(--danger)' : (remaining < 30 ? 'var(--warn)' : 'var(--ok)');
    }
  }

  /**
   * Main render method for the Help Desk Console view.
   */
  function render() {
    const container = document.getElementById('view-helpdesk');
    if (!container) return;

    if (tickets.length === 0) {
      init();
    }

    const currentRole = VaultAccess.Auth.getCurrentRole();
    const session = VaultAccess.Auth.getSession();
    const selected = tickets.find(t => t.id === selectedTicketId) || tickets[0];
    if (selected) selectedTicketId = selected.id;

    const filteredTickets = tickets.filter(t => {
      if (activeFilter === 'ALL') return true;
      return t.status === activeFilter;
    });

    const openCount = tickets.filter(t => t.status === 'OPEN').length;
    const resolvedCount = tickets.filter(t => t.status === 'RESOLVED').length;
    const escalatedCount = tickets.filter(t => t.status === 'ESCALATED').length;

    container.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:18px; flex-wrap:wrap; gap:12px;">
        <div>
          <h1 id="helpDeskHeading" style="margin:0 0 6px;">Help Desk Diagnostics & Customer Triage</h1>
          <p class="lede" style="margin:0;">
            Tier 2-H specialist workstation. Triage locked customers, review human-readable security tags (USA-04), and conduct identity re-verification.
          </p>
        </div>
        <div style="background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px 16px; text-align:right;">
          <div style="font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.04em;">Assigned Operator</div>
          <div style="font-weight:700; color:var(--accent); font-size:13.5px;">${session ? session.name : 'M. Torres'} (${currentRole ? currentRole.operatorId : 'hd_215'})</div>
          <div style="font-size:11px; color:var(--muted);">${currentRole ? currentRole.terminalName : 'Help Desk Station #04'}</div>
        </div>
      </div>

      <!-- SLA Resolution Posture Bar -->
      <div class="cards" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom:20px;">
        <div class="card">
          <div class="num" style="color:var(--text);">${openCount}</div>
          <div class="lbl">Active Customer Triage Tickets</div>
        </div>
        <div class="card">
          <div class="num" style="color:var(--ok);" id="hdActiveTimer">01:46</div>
          <div class="lbl">SLA Target Timer (3m Target)</div>
        </div>
        <div class="card">
          <div class="num" style="color:var(--ok);">${resolvedCount}</div>
          <div class="lbl">Re-verified / Resolved Today</div>
        </div>
        <div class="card">
          <div class="num" style="color:var(--danger);">${escalatedCount}</div>
          <div class="lbl">Escalated to Tier 4 SOC</div>
        </div>
      </div>

      <!-- Ticket Queue & Details Layout -->
      <div style="display:grid; grid-template-columns: 340px 1fr; gap:16px; align-items:start;" class="hd-grid-layout">
        
        <!-- Left: Ticket List with Filters -->
        <div class="bank-panel" style="padding:14px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <h3 style="font-size:14px; margin:0;">Inbound Customer Queue</h3>
            <span class="tag" style="font-size:11px;">Mock Input</span>
          </div>

          <div style="display:flex; gap:6px; margin-bottom:12px; flex-wrap:wrap;">
            <button type="button" class="btn ${activeFilter === 'ALL' ? '' : 'ghost'}" style="font-size:11px; padding:4px 8px;" onclick="VaultAccess.HelpDesk.setFilter('ALL')">All (${tickets.length})</button>
            <button type="button" class="btn ${activeFilter === 'OPEN' ? '' : 'ghost'}" style="font-size:11px; padding:4px 8px;" onclick="VaultAccess.HelpDesk.setFilter('OPEN')">Open (${openCount})</button>
            <button type="button" class="btn ${activeFilter === 'RESOLVED' ? '' : 'ghost'}" style="font-size:11px; padding:4px 8px;" onclick="VaultAccess.HelpDesk.setFilter('RESOLVED')">Resolved (${resolvedCount})</button>
            <button type="button" class="btn ${activeFilter === 'ESCALATED' ? '' : 'ghost'}" style="font-size:11px; padding:4px 8px;" onclick="VaultAccess.HelpDesk.setFilter('ESCALATED')">Escalated (${escalatedCount})</button>
          </div>

          <div style="display:flex; flex-direction:column; gap:8px; max-height:560px; overflow-y:auto; padding-right:4px;">
            ${filteredTickets.map(t => {
              const isSelected = selected && t.id === selected.id;
              const statusClass = t.status === 'OPEN' ? 'warn' : (t.status === 'RESOLVED' ? 'ok' : 'danger');
              return `
                <div onclick="VaultAccess.HelpDesk.selectTicket('${t.id}')"
                     style="background:${isSelected ? 'var(--panel2)' : 'var(--bg)'}; border:1px solid ${isSelected ? 'var(--accent)' : 'var(--line)'}; border-radius:8px; padding:10px 12px; cursor:pointer; transition:all .15s ease;">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                    <strong style="font-size:13px; color:var(--text);">${t.id} · ${t.customer}</strong>
                    <span class="tag ${statusClass}" style="font-size:10px; padding:2px 6px;">${t.status}</span>
                  </div>
                  <div style="font-size:11px; color:var(--muted); margin-bottom:6px;">
                    Acct: <code>${t.acctNumber}</code> · Channel: ${t.channel}
                  </div>
                  <div style="display:flex; flex-wrap:wrap; gap:4px;">
                    ${t.tags.map(tag => `<span class="tag warn" style="font-size:10px; padding:1px 6px;">${tag}</span>`).join('')}
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>

        <!-- Right: Selected Ticket Diagnostics & Resolution Panel -->
        <div class="bank-panel" id="hdTicketDetailPanel">
          ${selected ? renderTicketDetail(selected) : `<div style="color:var(--muted); padding:30px; text-align:center;">Select a ticket from the queue.</div>`}
        </div>

      </div>

      <!-- Identity Re-Verification Modal -->
      <div id="hdVerifyModal" class="denied" role="dialog" aria-modal="true" aria-labelledby="hdModalTitle" style="display:none;">
        <div class="deniedcard" style="max-width:480px; text-align:left;">
          <div style="font-size:11px; font-weight:700; color:var(--accent); letter-spacing:.05em; text-transform:uppercase; margin-bottom:4px;">STAFF-ASSISTED RECOVERY</div>
          <h2 id="hdModalTitle" style="margin:0 0 8px; font-size:17px;">Customer Identity Re-Verification</h2>
          <p class="small" style="margin-bottom:12px; color:var(--muted);">
            Zero-Trust Rule: Passwords, OTP codes, and biometrics are strictly protected and never displayed. Ask the caller to verify the following on-file attributes:
          </p>

          <div id="hdVerifyBody" style="background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px 14px; margin-bottom:14px;">
            <!-- Injected dynamically -->
          </div>

          <div style="display:flex; gap:8px; justify-content:flex-end;">
            <button type="button" class="btn ghost" onclick="VaultAccess.HelpDesk.closeVerifyModal()">Cancel</button>
            <button type="button" class="btn" style="background:var(--ok);" id="hdConfirmVerifyBtn" onclick="VaultAccess.HelpDesk.completeVerification()">Confirm Identity & Lift Hold</button>
          </div>
        </div>
      </div>
    `;

    updateTimerDisplays();
  }

  /**
   * Renders the details of the active ticket.
   */
  function renderTicketDetail(t) {
    const isEscalated = t.status === 'ESCALATED';
    const isResolved = t.status === 'RESOLVED';
    const remainingSec = Math.max(0, (t.targetSlaSec || 180) - (t.elapsedSec || 0));

    return `
      <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--line); padding-bottom:12px; margin-bottom:14px; flex-wrap:wrap; gap:8px;">
        <div>
          <div style="font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.03em;">Case Reference</div>
          <h2 style="margin:2px 0 0; font-size:18px; color:var(--text);">${t.id}: ${t.customer}</h2>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="tag ${t.status === 'OPEN' ? 'warn' : (isResolved ? 'ok' : 'danger')}" style="font-size:12px; padding:4px 10px;">
            ${t.status === 'OPEN' ? 'STATUS: OPEN' : (isResolved ? 'RESOLVED / VERIFIED' : 'ESCALATED TO SOC')}
          </span>
          <span style="font-size:11px; color:var(--muted);">Channel: <strong>${t.channel}</strong></span>
        </div>
      </div>

      <!-- Human-Readable Security Context Tags (USA-04 Requirement) -->
      <div style="background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:14px; margin-bottom:16px;">
        <div style="font-size:11px; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:.04em; margin-bottom:6px;">
          USA-04 Security Diagnostics & Threat Context
        </div>
        <div style="display:flex; flex-wrap:wrap; gap:8px; margin-bottom:10px;">
          ${t.tags.map(tag => `
            <span class="tag warn" style="font-weight:700; font-size:12px; padding:4px 10px;">
              ${tag}
            </span>
          `).join('')}
          <span class="tag" style="font-size:12px; padding:4px 10px;">Account: <code>${t.acctNumber}</code></span>
        </div>
        <p style="margin:0; font-size:13px; line-height:1.5; color:var(--text);">
          ${t.notes}
        </p>
      </div>

      <!-- 3-Minute SLA Target Counter -->
      <div style="background:rgba(55,194,129,.06); border:1px solid rgba(55,194,129,.3); border-radius:10px; padding:12px 14px; margin-bottom:16px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div>
          <strong style="font-size:13px; color:var(--text);">SLA Resolution Target: 3 Minutes (180s)</strong>
          <div style="font-size:11.5px; color:var(--muted); margin-top:2px;">
            Target defined in Submission 2 help-desk operational standards.
          </div>
        </div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:16px; font-weight:700; color:var(--ok);">
          Remaining: ${formatTime(remainingSec)}
        </div>
      </div>

      <!-- Action Buttons -->
      <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:20px;">
        <button type="button" class="btn" style="background:var(--ok); font-size:13px; padding:9px 16px;"
                ${isResolved || isEscalated ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}
                onclick="VaultAccess.HelpDesk.openVerifyModal('${t.id}')">
          Start Identity Re-Verification (Step-Up)
        </button>

        <button type="button" class="btn" style="background:var(--danger); font-size:13px; padding:9px 16px;"
                ${isEscalated ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}
                onclick="VaultAccess.HelpDesk.escalateToSecurity('${t.id}')">
          One-Click Escalate to Security (Tier 4 SOC)
        </button>
      </div>

      <div style="margin-top:16px; font-size:11.5px; color:var(--muted); line-height:1.5; border-top:1px solid var(--line); padding-top:12px;">
        <strong>Separation of Duties Policy:</strong> Help Desk operators cannot move money, override cash caps, or edit Active Directory policies. All actions write an immutable audit trail.
      </div>
    `;
  }

  function selectTicket(ticketId) {
    selectedTicketId = ticketId;
    render();
  }

  function setFilter(filter) {
    activeFilter = filter;
    render();
  }

  function openVerifyModal(ticketId) {
    const t = tickets.find(i => i.id === ticketId);
    if (!t) return;

    const modal = document.getElementById('hdVerifyModal');
    const body = document.getElementById('hdVerifyBody');
    if (!modal || !body) return;

    body.innerHTML = `
      <div style="font-size:12px; margin-bottom:10px; color:var(--text);">
        Customer: <strong>${t.customer}</strong> · Account: <code>${t.acctNumber}</code>
      </div>
      <div style="display:flex; flex-direction:column; gap:10px;">
        ${(t.verificationQuestions || [
          { q: "Confirm registered home billing city", a: "Confirmed on file" },
          { q: "Verify last authorized card transaction", a: "Confirmed on file" }
        ]).map((item, idx) => `
          <label style="display:flex; align-items:flex-start; gap:8px; font-size:12.5px; cursor:pointer;">
            <input type="checkbox" class="hd-q-check" data-idx="${idx}" style="margin-top:3px;">
            <span>
              <strong>${item.q}</strong><br>
              <span style="font-size:11px; color:var(--accent);">Expected: ${item.a}</span>
            </span>
          </label>
        `).join('')}
      </div>
    `;

    modal.style.display = 'flex';
  }

  function closeVerifyModal() {
    const modal = document.getElementById('hdVerifyModal');
    if (modal) modal.style.display = 'none';
  }

  function completeVerification() {
    const checkboxes = document.querySelectorAll('.hd-q-check');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    if (!allChecked) {
      alert("Verification incomplete: All security challenge questions must be verified with the customer.");
      return;
    }

    const t = tickets.find(i => i.id === selectedTicketId);
    if (!t) return;

    t.status = 'RESOLVED';
    closeVerifyModal();

    // Write audit event
    const session = VaultAccess.Auth.getSession() || { user: 'helpdesk' };
    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Help Desk Station #04 [hd_215]",
      acct: t.acctNumber,
      resource: `Customer Identity Record: ${t.customer}`,
      action: `ID_REVERIFICATION_COMPLETED: Re-verified identity for customer "${t.customer}" (${t.id}) after ${t.tags.join(', ')}. Security hold lifted.`,
      result: "granted",
      resultCode: "GRANTED",
      severity: "info"
    });

    if (VaultAccess.UI && VaultAccess.UI.renderEscalationLog) {
      VaultAccess.UI.renderEscalationLog();
    }
    render();
    alert(`Identity verified! Ticket ${t.id} for customer ${t.customer} is now marked RESOLVED.`);
  }

  function escalateToSecurity(ticketId) {
    const t = tickets.find(i => i.id === ticketId);
    if (!t) return;

    if (!confirm(`Escalate ticket ${t.id} (${t.customer}) to Tier 4 SOC? This will log an incident for intent assessment.`)) {
      return;
    }

    t.status = 'ESCALATED';

    const session = VaultAccess.Auth.getSession() || { user: 'helpdesk' };

    // 1. Log Escalation Monitor entry
    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Help Desk Station #04 [hd_215]",
      acct: t.acctNumber,
      resource: `Customer Account: ${t.customer}`,
      action: `TICKET_ESCALATED_TO_SOC: High-risk anomaly on ticket ${t.id} (${t.tags.join(', ')}) routed to Security Admin.`,
      result: "denied",
      resultCode: "ESCALATION_BLOCKED",
      severity: "danger"
    });

    // 2. Open SOC incident in ASSESSING_INTENT
    VaultAccess.Audit.createIncident({
      id: "INC-" + Math.floor(1000 + Math.random() * 9000),
      operatorId: "hd_215",
      username: session.user,
      role: "Tier 2 — Help Desk",
      terminal: "Help Desk Station #04",
      resource: `High-Risk Customer Account ${t.acctNumber} (${t.customer})`,
      requestedTier: 4,
      actualTier: 2,
      status: "ASSESSING_INTENT",
      details: `Escalated from Help Desk: ${t.notes} Tags: ${t.tags.join(', ')}`
    });

    if (VaultAccess.UI && VaultAccess.UI.renderEscalationLog) {
      VaultAccess.UI.renderEscalationLog();
    }
    render();
    alert(`Ticket ${t.id} escalated! SOC incident created in ASSESSING_INTENT status for Tier 4 review.`);
  }

  return {
    init,
    render,
    selectTicket,
    setFilter,
    openVerifyModal,
    closeVerifyModal,
    completeVerification,
    escalateToSecurity
  };
})();
