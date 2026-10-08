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
    const deniedModal = document.getElementById('denied');
    if (deniedModal) {
      deniedModal.style.display = 'none';
      deniedModal.classList.remove('show');
    }

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

    // Case 4: Authorized Route -> Update simulated address bar
    updateAddressBar(targetPath);
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
    const logEntry = {
      time: VaultAccess.Audit.getTimestamp(),
      src: srcTerminal,
      acct: userAccount,
      operatorName: userAccount,
      operatorId: (VaultAccess.Config.USERS[session.user] && VaultAccess.Config.USERS[session.user].operatorId) || "teller_402",
      action: `Attempted access to /${attemptedPath} (Required Tier: ${targetRole.tier}, Actual Tier: ${currentRole.tier})`,
      result: "denied"
    };
    VaultAccess.Audit.logEvent(logEntry);

    // Track detailed incident specifically for the Security Admin Workstation review & freeze controls
    VaultAccess.Auth.recordURLTamperIncident({
      id: "INC-" + Math.floor(1000 + Math.random() * 9000),
      timestamp: logEntry.time,
      username: session.user || "unknown",
      roleLabel: currentRole.label,
      targetRole: targetRole.label,
      attemptedPath: attemptedPath,
      details: `Attempted access to /${attemptedPath} (Required Tier: ${targetRole.tier}, Actual Tier: ${currentRole.tier})`
    });

    // 2. Refresh UI views with newly logged event
    VaultAccess.UI.renderEscalationLog();

    // 3. Render High-Visibility Security Interceptor Modal formatted cleanly
    const deniedMsg = document.getElementById('deniedMsg');
    if (deniedMsg) {
      deniedMsg.innerHTML = `
        <div style="background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px 14px; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.6; margin-bottom:10px;">
          <div><span style="color:var(--muted);">Requested Resource:</span> <strong style="color:var(--text);">/${attemptedPath}</strong></div>
          <div><span style="color:var(--muted);">Current Role:</span> <strong style="color:var(--text);">${currentRole.label}</strong></div>
          <div><span style="color:var(--muted);">Current Tier:</span> <strong style="color:var(--accent);">Tier ${currentRole.tier}</strong></div>
          <div><span style="color:var(--muted);">Required Tier:</span> <strong style="color:var(--danger);">Tier ${targetRole.tier}</strong></div>
        </div>
        <div style="font-weight:700; color:var(--danger); font-size:13px; margin-bottom:4px;">ACCESS DENIED</div>
        <div style="font-size:12px; color:var(--muted);">This attempt has been logged in the Escalation Monitor.</div>
      `;
    }

    const reloginBtn = document.getElementById('reloginBtn');
    if (reloginBtn) {
      reloginBtn.dataset.target = attemptedPath;
    }

    const deniedModal = document.getElementById('denied');
    if (deniedModal) {
      deniedModal.style.display = 'flex';
      deniedModal.classList.add('show');
    }

    updateAddressBar(attemptedPath);
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
    BASE_URL
  };
})();
