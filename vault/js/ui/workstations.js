/**
 * ============================================================================
 * VaultAccess — UI Module: Advanced Role Workstations & JIT Controls (G7, G8)
 * ============================================================================
 * Implements realistic workstations for all roles:
 * - Branch Teller (T1): ID verification checklist, cash drawer reconciliation,
 *   pending requests tracker, flag suspicious customer.
 * - Branch Supervisor (T2): High-value override desk, staff-assisted customer recovery,
 *   branch limits overview, security review request.
 * - IT Administrator (T3): Just-In-Time (JIT) privileged elevation with countdown,
 *   CHG-#### ticket validation, node maintenance, VPN sessions, session activity log.
 * - Security Admin (T4): Lockout cluster view, AD tier policy assignment editor,
 *   SOC incident queue timeline.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.Workstations = (function () {

  // ---- State Tracking ----
  let cashDrawerBalance = 250000.00;
  let cashDrawerStarting = 250000.00;
  let idChecklist = { nameMatched: false, idTypeVerified: false, signatureVerified: false };

  // IT Admin JIT Elevation State (Phase 7)
  let jitElevation = {
    active: false,
    ticketId: null,
    expiresAt: null,
    intervalId: null,
    remainingSeconds: 0
  };

  // IT session activity log — starts empty; entries are appended by real actions
  let itSessionActivity = [];


  // AD Tier Assignments state (T4)
  let adTierAssignments = {
    "teller_402": { name: "A. Santos", tier: 1, role: "Branch Teller", status: "Active" },
    "supv_108": { name: "R. Dizon", tier: 2, role: "Branch Supervisor", status: "Active" },
    "hd_215": { name: "M. Torres", tier: 2, role: "Help Desk Specialist", status: "Active" },
    "sys_it88": { name: "K. Lim", tier: 3, role: "IT Admin (Remote)", status: "Active" },
    "sec_soc01": { name: "L. Garcia", tier: 4, role: "Security Admin (SOC)", status: "Active" }
  };

  // Mock Customer Lockout Clusters (T4 SOC View)
  const MOCK_LOCKOUT_CLUSTERS = [
    {
      clusterId: "CLS-902",
      asn: "AS132199 (Residential Proxy Pool)",
      threatScore: "94 / 100 [CRITICAL]",
      targetedAccounts: ["1001-4471", "1002-9902", "1004-1109"],
      failedChallenges: 18,
      detectedPattern: "Distributed Credential Stuffing & Spraying",
      status: "SOC MITIGATION ACTIVE"
    }
  ];

  // --------------------------------------------------------------------------
  // 1. Branch Teller Workstation Helpers (T1)
  // --------------------------------------------------------------------------

  function updateIDChecklist(field, value) {
    idChecklist[field] = !!value;
  }

  function isIDChecklistComplete() {
    return idChecklist.nameMatched && idChecklist.idTypeVerified && idChecklist.signatureVerified;
  }

  function handleFlagSuspicious(acctNumber) {
    const reason = prompt("Enter suspicious activity report details for Supervisor & SOC:", "Customer presented conflicting ID documents and requested rapid cash withdrawal.");
    if (!reason) return;

    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Branch Terminal #14",
      acct: acctNumber || "Unknown Acct",
      resource: "Customer Fraud Flag",
      action: `[SUSPICIOUS ACTIVITY FLAGGED] Teller teller_402 flagged account ${acctNumber || 'N/A'}. Reason: "${reason}"`,
      result: "reviewed",
      resultCode: "ESCALATION_ADJUSTED",
      severity: "warn"
    });

    if (VaultAccess.Audit.createIncident) {
      VaultAccess.Audit.createIncident({
        operatorId: "teller_402",
        username: "teller",
        role: "Branch Teller",
        terminal: "Branch Terminal #14",
        resource: `Customer Account ${acctNumber}`,
        requestedTier: 2,
        actualTier: 1,
        details: `Teller flagged customer activity: ${reason}`
      });
    }

    alert(`Incident logged: Suspicious activity report submitted to Branch Supervisor and SOC triage queue.`);
    VaultAccess.UI.renderEscalationLog();
  }

  function handleReconcileCashDrawer() {
    const diff = cashDrawerBalance - cashDrawerStarting;
    const diffStr = diff >= 0 ? `+₱${diff.toLocaleString()}` : `-₱${Math.abs(diff).toLocaleString()}`;
    alert(`[END-OF-SHIFT RECONCILIATION]\n\nStarting Cash Float: ₱${cashDrawerStarting.toLocaleString('en-US', {minimumFractionDigits:2})}\nCurrent Cash in Drawer: ₱${cashDrawerBalance.toLocaleString('en-US', {minimumFractionDigits:2})}\nNet Shift Flow: ${diffStr}\nStatus: RECONCILED & BALANCED\n\nShift audit record submitted to Branch Supervisor.`);

    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Branch Terminal #14",
      acct: "teller_402",
      resource: "Teller Cash Drawer Float",
      action: `[SHIFT RECONCILIATION] Cash drawer balanced at ₱${cashDrawerBalance.toLocaleString('en-US', {minimumFractionDigits:2})} (Net flow: ${diffStr}).`,
      result: "granted",
      resultCode: "GRANTED",
      severity: "info"
    });
    VaultAccess.UI.renderEscalationLog();
  }

  function recordDrawerTransaction(amount, type) {
    if (type === 'CR') cashDrawerBalance += amount;
    else if (type === 'DR') cashDrawerBalance -= amount;
  }

  function getDrawerBalance() {
    return cashDrawerBalance;
  }

  // --------------------------------------------------------------------------
  // 2. Branch Supervisor Workstation Helpers (T2)
  // --------------------------------------------------------------------------

  function handleStaffAssistedRecovery(acctNumber) {
    const acct = VaultAccess.Config.BANK_ACCOUNTS[acctNumber];
    if (!acct) {
      alert("Customer account not found.");
      return;
    }

    if (acct.status !== "Account Locked" && !acct.status.includes("Protected")) {
      alert(`Account ${acctNumber} is already active and does not require recovery.`);
      return;
    }

    const note = prompt(`Enter Staff-Assisted Identity Verification notes for ${acct.name}:`, "Verified customer face-to-face with Philippine National ID (PhilSys) and signature card.");
    if (!note) return;

    // Staff-assisted recovery puts account in Active/Verified status
    acct.status = "Active / Verified";
    acct.note = `Staff-assisted verification completed by Branch Supervisor. ${note}`;

    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Supervisor Station #01",
      acct: acct.acctNumber,
      resource: "Customer Lockout State",
      action: `[STAFF-ASSISTED RECOVERY] Customer "${acct.name}" restored to Active status by supv_108. Verification: "${note}"`,
      result: "reviewed",
      resultCode: "GRANTED",
      severity: "info"
    });

    alert(`Customer ${acct.name} (${acct.acctNumber}) has been restored to Active / Verified status.`);
    VaultAccess.UI.renderBankWorkstation();
    VaultAccess.UI.renderEscalationLog();
  }

  function handleRequestSecurityReview() {
    const reason = prompt("Enter Security Review justification for Security Admin (Tier 4):", "Branch observed recurring step-up challenge failures across multiple commercial clients in Makati lobby.");
    if (!reason) return;

    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Supervisor Station #01",
      acct: "supv_108",
      resource: "SOC Review Desk",
      action: `[SUPERVISOR ESCALATION] Branch Supervisor requested formal security review: "${reason}"`,
      result: "reviewed",
      resultCode: "ESCALATION_ADJUSTED",
      severity: "warn"
    });

    if (VaultAccess.Audit.createIncident) {
      VaultAccess.Audit.createIncident({
        id: "INC-SUP" + Math.floor(100 + Math.random() * 900),
        operatorId: "supv_108",
        username: "supervisor",
        role: "Branch Supervisor",
        terminal: "Supervisor Station #01",
        resource: "Branch Anomaly Escalation",
        requestedTier: 4,
        actualTier: 2,
        details: reason
      });
    }

    alert("Security review request submitted to SOC Incident Triage queue.");
    VaultAccess.UI.renderEscalationLog();
  }

  // --------------------------------------------------------------------------
  // 3. IT Admin Workstation Helpers (T3 - JIT Elevation & Node Maintenance)
  // --------------------------------------------------------------------------

  function requestJITElevation(ticketId, durationMinutes) {
    const cleanTicket = (ticketId || "").trim().toUpperCase();
    if (!cleanTicket || !cleanTicket.startsWith("CHG-")) {
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: "Remote Admin VPN",
        acct: "sys_it88",
        resource: "JIT Elevation Gateway",
        action: `JIT ELEVATION DENIED: Invalid or missing Change Ticket ID [${cleanTicket || 'EMPTY'}]. Format CHG-#### required.`,
        result: "denied",
        resultCode: "ESCALATION_BLOCKED",
        severity: "danger"
      });
      return {
        success: false,
        message: "JIT Elevation Denied: A valid Change Ticket ID (format CHG-####) is strictly mandatory under enterprise change control policy."
      };
    }

    const durationSec = (durationMinutes || 5) * 60;
    jitElevation.active = true;
    jitElevation.ticketId = cleanTicket;
    jitElevation.remainingSeconds = durationSec;
    jitElevation.expiresAt = Date.now() + durationSec * 1000;

    // Start live countdown interval
    if (jitElevation.intervalId) clearInterval(jitElevation.intervalId);
    jitElevation.intervalId = setInterval(() => {
      jitElevation.remainingSeconds--;
      const timerEl = document.getElementById('jitTimerDisplay');
      if (timerEl) {
        const m = Math.floor(jitElevation.remainingSeconds / 60);
        const s = jitElevation.remainingSeconds % 60;
        timerEl.textContent = `${m}:${s.toString().padStart(2, '0')}`;
      }

      if (jitElevation.remainingSeconds <= 0) {
        expireJITElevation();
      }
    }, 1000);

    // Audit JIT Grant
    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Remote Admin VPN",
      acct: "sys_it88",
      resource: "Infrastructure Maintenance Authorization",
      action: `[JIT ELEVATION GRANTED] Time-limited maintenance access issued for ticket ${cleanTicket} (Duration: ${durationMinutes || 5} min).`,
      result: "granted",
      resultCode: "GRANTED",
      severity: "warn"
    });

    logITActivity(`JIT Elevation Granted for ${cleanTicket} (${durationMinutes || 5} min)`, "ELEVATED");

    return {
      success: true,
      ticketId: cleanTicket,
      durationMinutes: durationMinutes || 5,
      message: `JIT Privileged Access Granted for ${durationMinutes || 5} minutes under Change Ticket ${cleanTicket}. Maintenance tools unlocked.`
    };
  }

  function expireJITElevation() {
    if (jitElevation.intervalId) clearInterval(jitElevation.intervalId);
    const prevTicket = jitElevation.ticketId;
    jitElevation.active = false;
    jitElevation.ticketId = null;
    jitElevation.remainingSeconds = 0;
    jitElevation.expiresAt = null;

    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Remote Admin VPN",
      acct: "sys_it88",
      resource: "Infrastructure Maintenance Authorization",
      action: `[JIT ELEVATION EXPIRED] Access reverted to read-only for ticket ${prevTicket}.`,
      result: "reviewed",
      resultCode: "ESCALATION_ADJUSTED",
      severity: "info"
    });

    logITActivity(`JIT Elevation Expired (${prevTicket}). Returned to Read-Only.`, "REVERTED");

    if (VaultAccess.UI && VaultAccess.UI.renderBankWorkstation) {
      VaultAccess.UI.renderBankWorkstation();
    }
  }

  function executeMaintenanceAction(actionName, nodeId) {
    if (!jitElevation.active) {
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: "Remote Admin VPN",
        acct: "sys_it88",
        resource: `Server Node: ${nodeId}`,
        action: `MAINTENANCE BLOCKED: Attempted "${actionName}" on ${nodeId} without active JIT elevation.`,
        result: "denied",
        resultCode: "ESCALATION_BLOCKED",
        severity: "danger"
      });
      alert(`ACCESS DENIED: Maintenance actions on ${nodeId} require an active JIT Elevation grant and authorized Change Ticket.`);
      return;
    }

    logITActivity(`Executed "${actionName}" on node ${nodeId} (Ticket: ${jitElevation.ticketId})`, "SUCCESS");

    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Remote Admin VPN",
      acct: "sys_it88",
      resource: `Server Node: ${nodeId}`,
      action: `[INFRASTRUCTURE ACTION] Executed "${actionName}" on ${nodeId} under Change Ticket ${jitElevation.ticketId}.`,
      result: "granted",
      resultCode: "GRANTED",
      severity: "info"
    });

    alert(`Action Completed: "${actionName}" executed on ${nodeId} under Change Ticket ${jitElevation.ticketId}.`);
    VaultAccess.UI.renderBankWorkstation();
    VaultAccess.UI.renderEscalationLog();
  }

  function logITActivity(action, status) {
    itSessionActivity.unshift({
      time: VaultAccess.Audit.getTimestamp(),
      action: action,
      status: status
    });
  }

  function getITSessionActivity() {
    return itSessionActivity;
  }

  function getJITElevation() {
    return jitElevation;
  }

  // --------------------------------------------------------------------------
  // 4. Security Admin Workstation Helpers (T4)
  // --------------------------------------------------------------------------

  function getADTierAssignments() {
    return adTierAssignments;
  }

  function handleEditTierAssignment(operatorId, newTier) {
    const assignment = adTierAssignments[operatorId];
    if (!assignment) {
      if (VaultAccess.UI && VaultAccess.UI.showModalNotification) {
        VaultAccess.UI.showModalNotification("Operator record not found.", "AD Policy Editor", "warn");
      } else {
        alert("Operator record not found.");
      }
      return;
    }

    const current = VaultAccess.Auth.getCurrentRole();
    if (!current || current.tier < 4) {
      if (VaultAccess.UI && VaultAccess.UI.showModalNotification) {
        VaultAccess.UI.showModalNotification("Permission Denied: Only Tier 4 (Security Admin) can modify Active Directory Tier Assignments.", "Access Denied", "danger");
      } else {
        alert("Permission Denied: Only Tier 4 (Security Admin) can modify Active Directory Tier Assignments.");
      }
      return;
    }

    // Operational continuity rule: cannot modify tier if sole person in that role
    const roleHeadcount = Object.values(adTierAssignments).filter(a => a.role === assignment.role).length;
    if (roleHeadcount <= 1) {
      const errMsg = `Operational Rule: Cannot edit tier for "${assignment.name}". There is only 1 person assigned to the ${assignment.role} role. Operational continuity requires at least one active operator at this tier.`;
      if (VaultAccess.UI && VaultAccess.UI.showModalNotification) {
        VaultAccess.UI.showModalNotification(errMsg, "Action Prohibited: Minimum Coverage Required", "warn");
      } else {
        alert(errMsg);
      }
      return;
    }

    if (!newTier) return;
    const targetTierNum = parseInt(newTier, 10);
    if (isNaN(targetTierNum) || targetTierNum < 1 || targetTierNum > 4) {
      if (VaultAccess.UI && VaultAccess.UI.showModalNotification) {
        VaultAccess.UI.showModalNotification("Invalid tier specified. Please select Tier 1, 2, 3, or 4.", "AD Policy Editor", "warn");
      } else {
        alert("Invalid tier specified. Please select Tier 1, 2, 3, or 4.");
      }
      return;
    }

    if (targetTierNum === assignment.tier) {
      return;
    }

    const justification = prompt(`Enter justification for modifying ${assignment.name}'s tier assignment (Tier ${assignment.tier} -> Tier ${targetTierNum}):`, "Department transfer approved under Enterprise Change Ticket CHG-9021.");
    if (!justification) return;

    const oldTier = assignment.tier;
    assignment.tier = targetTierNum;

    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "SOC Command Gateway",
      acct: "sec_soc01",
      resource: `AD Tier Policy (${operatorId})`,
      action: `[AD POLICY MODIFIED] Changed operator "${operatorId}" (${assignment.name}) from Tier ${oldTier} to Tier ${targetTierNum}. Justification: "${justification}"`,
      result: "granted",
      resultCode: "GRANTED",
      severity: "warn"
    });

    const successMsg = `AD Policy Updated: Operator ${assignment.name} (${operatorId}) updated to Tier ${targetTierNum}. Audit trail recorded.`;
    if (VaultAccess.UI && VaultAccess.UI.showModalNotification) {
      VaultAccess.UI.showModalNotification(successMsg, "AD Policy Updated", "ok");
    } else {
      alert(successMsg);
    }
    VaultAccess.UI.renderBankWorkstation();
    VaultAccess.UI.renderEscalationLog();
  }

  function getLockoutClusters() {
    return MOCK_LOCKOUT_CLUSTERS;
  }

  return {
    updateIDChecklist,
    isIDChecklistComplete,
    handleFlagSuspicious,
    handleReconcileCashDrawer,
    recordDrawerTransaction,
    getDrawerBalance,
    handleStaffAssistedRecovery,
    handleRequestSecurityReview,
    requestJITElevation,
    expireJITElevation,
    executeMaintenanceAction,
    getITSessionActivity,
    getJITElevation,
    getADTierAssignments,
    handleEditTierAssignment,
    getLockoutClusters
  };
})();
