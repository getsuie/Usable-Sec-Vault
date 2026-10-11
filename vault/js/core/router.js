/**
 * ============================================================================
 * VaultAccess — Core Module: Security Router & URL Route Guard
 * ============================================================================
 * Implements URL-based access control and client-side route protection.
 * Intercepts URL changes and prevents unauthorized navigation by:
 * 1. Checking active authentication session.
 * 2. Enforcing RBAC role binding against requested hash route.
 * 3. Detecting manual URL tampering (e.g., altering #/teller to #/secadmin).
 * 4. Automatically reporting tamper violations to the Audit service.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.Router = (function () {
  const BASE_URL = "https://vaultaccess/";

  /**
   * Extracts clean route path from current window hash.
   * e.g., "#/secadmin" -> "secadmin"
   * @returns {string}
   */
  function getPathFromHash() {
    return window.location.hash.replace(/^#\/?/, '').toLowerCase();
  }

  /**
   * Programmatically navigates to a designated route path.
   * @param {string} path - Target route identifier
   */
  function navigate(path) {
    const cleanPath = (path || "").trim().replace(/\/+$/, '').toLowerCase();
    if (getPathFromHash() === cleanPath) {
      route();
    } else {
      window.location.hash = '/' + cleanPath;
    }
  }

  /**
   * Evaluates the current route against security policies.
   */
  function route() {
    const targetPath = getPathFromHash();
    hideDeniedModal();

    // Case 1: Unauthenticated user requests a route
    if (!VaultAccess.Auth.isAuthenticated()) {
      handleUnauthenticated(targetPath);
      return;
    }

    const currentSession = VaultAccess.Auth.getSession();
    const validRoles = VaultAccess.Config.ROLES;

    // Case 2: Invalid or unknown route requested -> redirect to current assigned role
    if (!validRoles[targetPath]) {
      navigate(currentSession.role);
      return;
    }

    // Case 3: Authorization Check — URL Tampering / Role Mismatch
    if (!VaultAccess.RBAC.isRouteAuthorized(currentSession.role, targetPath)) {
      handleAccessDenied(targetPath);
      return;
    }

    // Case 4: Account has an unresolved URL tampering incident under SOC review.
    // The violation warning persists across sign-out / sign-in until the SOC resolves it.
    const pendingTamper = getPendingTamperIncident(currentSession.user);
    if (pendingTamper) {
      showFlaggedAccountWarning(pendingTamper);
      updateAddressBar(targetPath);
      return;
    }

    // Case 5: Authorized Route -> Update simulated address bar
    updateAddressBar(targetPath);
  }

  /**
   * Returns the newest pending (ASSESSING_INTENT) URL tampering incident for a user.
   * @param {string} username
   * @returns {object|null}
   */
  function getPendingTamperIncident(username) {
    if (!username || !VaultAccess.Audit || !VaultAccess.Audit.getPendingIncidents) return null;
    return VaultAccess.Audit.getPendingIncidents()
      .find(inc => inc.type === "URL_TAMPER" && inc.username === username) || null;
  }

  /**
   * Shows the access denied interceptor modal.
   */
  function showDeniedModal() {
    const deniedModal = document.getElementById('denied');
    if (deniedModal) {
      if (deniedModal.style.removeProperty) {
        deniedModal.style.removeProperty('display');
      } else {
        deniedModal.style.display = '';
      }
      deniedModal.classList.add('show');
    }
    const reloginBtn = document.getElementById('reloginBtn');
    if (reloginBtn) reloginBtn.focus();
  }

  /**
   * Hides the access denied interceptor modal.
   */
  function hideDeniedModal() {
    const deniedModal = document.getElementById('denied');
    if (deniedModal) {
      if (deniedModal.style.removeProperty) {
        deniedModal.style.removeProperty('display');
      } else {
        deniedModal.style.display = '';
      }
      deniedModal.classList.remove('show');
    }
  }

  /**
   * Handles navigation requests from unauthenticated visitors.
   * @param {string} path - Target role route
   */
  function handleUnauthenticated(path) {
    const loginNote = document.getElementById('loginNote');
    const targetRole = VaultAccess.Config.ROLES[path];

    if (targetRole) {
      VaultAccess.Auth.setPendingRole(path);
      if (loginNote) {
        loginNote.textContent = `Sign in to continue to /${path} (${targetRole.label}).`;
        loginNote.classList.add('show');
      }
    } else {
      VaultAccess.Auth.clearPendingRole();
      if (loginNote) loginNote.classList.remove('show');
    }

    updateAddressBar(path);
  }

  /**
   * Intercepts unauthorized navigation, triggers security alarm & audit record.
   * @param {string} attemptedPath - Route that was blocked
   */
  function handleAccessDenied(attemptedPath) {
    const currentRole = VaultAccess.Auth.getCurrentRole() || { label: "Unknown", tier: 1 };
    const targetRole = VaultAccess.Config.ROLES[attemptedPath] || { label: attemptedPath, tier: 2 };
    const session = VaultAccess.Auth.getSession() || { user: "teller_402" };

    const srcTerminal = currentRole.terminalName || "Branch Terminal #14";
    const userAccount = (VaultAccess.Config.USERS[session.user] && VaultAccess.Config.USERS[session.user].name)
      ? VaultAccess.Config.USERS[session.user].name.split(' ')[0]
      : (session.name ? session.name.split(' ')[0] : (session.user || "teller"));

    // 1. Telemetry: Log security violation in Audit trail (Unauthorized URL escalation)
    const operatorId = (VaultAccess.Config.USERS[session.user] && VaultAccess.Config.USERS[session.user].operatorId) || "teller_402";
    const details = `Attempted access to /${attemptedPath} (Required Tier: ${targetRole.tier}, Actual Tier: ${currentRole.tier})`;
    const logEntry = {
      time: VaultAccess.Audit.getTimestamp(),
      src: srcTerminal,
      acct: userAccount,
      operatorName: userAccount,
      operatorId: operatorId,
      resource: `URL Route /${attemptedPath} (${targetRole.label})`,
      action: `[URL TAMPERING] ${details}`,
      result: "denied",
      resultCode: "ESCALATION_BLOCKED",
      severity: "danger"
    };
    VaultAccess.Audit.logEvent(logEntry);

    // 2. Report to SOC: open (or update) an ASSESSING_INTENT incident in the SOC Triage Desk
    let socIncident = getPendingTamperIncident(session.user);
    if (socIncident) {
      socIncident.attempts = (socIncident.attempts || 1) + 1;
      socIncident.timestamp = logEntry.time;
      socIncident.attemptedPath = attemptedPath;
      socIncident.resource = `URL Path Escalation: /${attemptedPath} (${targetRole.label})`;
      socIncident.requestedTier = Math.max(socIncident.requestedTier || 0, targetRole.tier);
      socIncident.details = `Direct URL path tampering detected. ${details}. Repeated attempts: ${socIncident.attempts}. Terminal locked pending SOC assessment.`;
    } else {
      socIncident = VaultAccess.Audit.createIncident({
        type: "URL_TAMPER",
        timestamp: logEntry.time,
        operatorId: operatorId,
        username: session.user || "unknown",
        role: currentRole.label,
        terminal: srcTerminal,
        resource: `URL Path Escalation: /${attemptedPath} (${targetRole.label})`,
        requestedTier: targetRole.tier,
        actualTier: currentRole.tier,
        attemptedPath: attemptedPath,
        details: `Direct URL path tampering detected. ${details}. Terminal locked pending SOC assessment.`
      });
    }

    // Track detailed incident specifically for the Security Admin Workstation review & freeze controls
    VaultAccess.Auth.recordURLTamperIncident({
      id: socIncident.id,
      timestamp: logEntry.time,
      username: session.user || "unknown",
      roleLabel: currentRole.label,
      targetRole: targetRole.label,
      attemptedPath: attemptedPath,
      details: details
    });

    // 2b. Lock Branch Terminal if breach originates from branch staff / terminal
    if (VaultAccess.Banking && VaultAccess.Banking.getTerminalLockState) {
      const lock = VaultAccess.Banking.getTerminalLockState();
      lock.isLocked = true;
      lock.reason = `Unauthorized URL privilege escalation breach: Operator attempted access to /${attemptedPath} (Required Tier: ${targetRole.tier}, Actual Tier: ${currentRole.tier}).`;
      lock.lockedAt = logEntry.time;
      lock.refCode = socIncident.id;
      lock.incidentId = socIncident.id;
      lock.type = "URL_TAMPER";
      lock.escalationAttemptCount = (lock.escalationAttemptCount || 0) + 1;
      lock.operatorId = operatorId;
    }

    // 3. Refresh UI views with newly logged event
    VaultAccess.UI.renderEscalationLog();

    // 4. Render High-Visibility Security Interceptor Modal formatted cleanly
    const deniedHeading = document.getElementById('deniedHeading');
    if (deniedHeading) deniedHeading.textContent = "[ACCESS DENIED] Not Authorized";

    const deniedMsg = document.getElementById('deniedMsg');
    if (deniedMsg) {
      deniedMsg.innerHTML = `
        <div style="background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px 14px; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.6; margin-bottom:10px;">
          <div><span style="color:var(--muted);">Requested Resource:</span> <strong style="color:var(--text);">/${attemptedPath}</strong></div>
          <div><span style="color:var(--muted);">Current Role:</span> <strong style="color:var(--text);">${currentRole.label}</strong></div>
          <div><span style="color:var(--muted);">Current Tier:</span> <strong style="color:var(--accent);">Tier ${currentRole.tier}</strong></div>
          <div><span style="color:var(--muted);">Required Tier:</span> <strong style="color:var(--danger);">Tier ${targetRole.tier}</strong></div>
          <div><span style="color:var(--muted);">SOC Case:</span> <strong style="color:var(--warn);">${socIncident.id} (ASSESSING_INTENT)</strong></div>
        </div>
        <div style="font-weight:700; color:var(--danger); font-size:13px; margin-bottom:4px;">ACCESS DENIED</div>
        <div style="font-size:12px; color:var(--muted);">This attempt has been logged in the Escalation Monitor and reported to the SOC team.</div>
      `;
    }

    const reloginBtn = document.getElementById('reloginBtn');
    if (reloginBtn) {
      reloginBtn.dataset.target = attemptedPath;
    }

    showDeniedModal();
    updateAddressBar(attemptedPath);
  }

  /**
   * Shows the persistent privilege-violation warning for an account that has an
   * unresolved URL tampering incident (e.g. after signing out and back in).
   * @param {object} incident - Pending SOC incident
   */
  function showFlaggedAccountWarning(incident) {
    const deniedHeading = document.getElementById('deniedHeading');
    if (deniedHeading) deniedHeading.textContent = "[ACCOUNT FLAGGED] Under SOC Review";

    const deniedMsg = document.getElementById('deniedMsg');
    if (deniedMsg) {
      deniedMsg.innerHTML = `
        <div style="background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px 14px; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.6; margin-bottom:10px;">
          <div><span style="color:var(--muted);">SOC Case:</span> <strong style="color:var(--warn);">${incident.id}</strong></div>
          <div><span style="color:var(--muted);">Operator:</span> <strong style="color:var(--text);">${incident.username} (${incident.operatorId})</strong></div>
          <div><span style="color:var(--muted);">Violation:</span> <strong style="color:var(--danger);">${incident.resource}</strong></div>
          <div><span style="color:var(--muted);">Attempts:</span> <strong style="color:var(--text);">${incident.attempts || 1}</strong></div>
          <div><span style="color:var(--muted);">Last Attempt:</span> <strong style="color:var(--text);">${incident.timestamp}</strong></div>
          <div><span style="color:var(--muted);">Status:</span> <strong style="color:var(--warn);">ASSESSING_INTENT</strong></div>
        </div>
        <div style="font-weight:700; color:var(--danger); font-size:13px; margin-bottom:4px;">PRIOR PRIVILEGE ESCALATION ATTEMPT DETECTED</div>
        <div style="font-size:12px; color:var(--muted);">This account attempted unauthorized URL path escalation. Terminal access remains locked until a Security Admin resolves the SOC case.</div>
      `;
    }

    showDeniedModal();
  }

  /**
   * Synchronizes the simulated browser address bar with current path.
   * @param {string} path - Current route path
   */
  function updateAddressBar(path) {
    const addrInput = document.getElementById('addr');
    if (addrInput) {
      addrInput.value = BASE_URL + (path || '');
    }
  }

  /**
   * Initializes router event listeners.
   */
  function init() {
    window.addEventListener('hashchange', route);
  }

  return {
    init,
    route,
    navigate,
    getPathFromHash,
    hideDeniedModal,
    getPendingTamperIncident,
    BASE_URL
  };
})();
