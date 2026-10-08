/**
 * ============================================================================
 * VaultAccess — Application Orchestrator & Event Controller
 * ============================================================================
 * Binds UI interactions to Authentication, RBAC, Security Router,
 * and Audit Logging modules. Initializes on page load.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.App = (function () {

  /**
   * Performs user sign-in action.
   */
  /**
   * Performs user sign-in action with Phase 6 hardening.
   */
  function handleLogin() {
    const userField = document.getElementById('user');
    const passField = document.getElementById('pass');
    const otpField = document.getElementById('loginOtp');
    const contextField = document.getElementById('loginContext');
    const mfaGroup = document.getElementById('loginMfaGroup');
    const errorField = document.getElementById('loginErr');
    const noteField = document.getElementById('loginNote');
    const banner = document.getElementById('denyBanner');
    const acctResult = document.getElementById('acctResult');

    const username = userField ? userField.value : "";
    const password = passField ? passField.value : "";
    const otp = otpField ? otpField.value : "";
    const context = contextField ? contextField.value : "branch";

    const result = VaultAccess.Auth.login(username, password, otp, context);

    if (!result.success) {
      if (result.requireMFA) {
        if (mfaGroup) mfaGroup.style.display = "block";
        if (otpField) otpField.focus();
      }

      if (errorField) {
        errorField.textContent = result.message;
        errorField.style.display = "block";
      }

      if (result.frozen) {
        alert(result.message);
      }
      return;
    }

    // Clear login errors, credentials, and hide MFA group
    if (errorField) {
      errorField.textContent = "";
      errorField.style.display = "none";
    }
    if (passField) passField.value = "";
    if (otpField) {
      otpField.value = "";
      if (mfaGroup) mfaGroup.style.display = "none";
    }

    // Switch body state to authenticated
    document.body.classList.add('authed');

    // Reset view notifications
    if (banner) banner.classList.remove('show');
    if (acctResult) acctResult.classList.remove('show');
    if (noteField) noteField.classList.remove('show');

    const pending = VaultAccess.Auth.getPendingRole();
    const session = VaultAccess.Auth.getSession();
    const targetRoute = (pending && VaultAccess.Config.ROLES[pending]) ? pending : session.role;
    VaultAccess.Auth.clearPendingRole();

    // Default view routing
    const initialView = (session && session.role === 'helpdesk') ? 'helpdesk' : 'dash';
    VaultAccess.UI.showView(initialView);
    VaultAccess.UI.updateRoleDisplay();
    VaultAccess.UI.renderEscalationLog();

    VaultAccess.Router.navigate(targetRoute);
  }

  /**
   * Performs user logout and resets security context.
   */
  function handleLogout() {
    VaultAccess.Auth.logout();
    window.history.replaceState(null, '', window.location.pathname);
    document.body.classList.remove('authed');

    // Dismiss overlays and modals on sign out so login screen is completely visible
    const freezeOverlay = document.getElementById('terminalFreezeOverlay');
    if (freezeOverlay) freezeOverlay.classList.remove('active');
    const hackerModal = document.getElementById('hackerModal');
    if (hackerModal) hackerModal.classList.remove('active');
    const deniedModal = document.getElementById('denied');
    if (deniedModal) deniedModal.classList.remove('show');
    const escModal = document.getElementById('escalationModal');
    if (escModal) escModal.classList.remove('active');
    const hdModal = document.getElementById('hdVerifyModal');
    if (hdModal) hdModal.style.display = 'none';

    VaultAccess.UI.checkTerminalFreezeState();

    const userField = document.getElementById('user');
    if (userField) {
      userField.value = "";
      userField.focus();
    }
  }

  /**
   * Simulates escalation attempt outcomes based on the 3-step Lucid staff flow:
   * 1. 'grant'    -> Request within assigned tier -> Granted (info entry)
   * 2. 'adjusted' -> Request adjacent scope -> Downgraded / ESCALATION_ADJUSTED
   * 3. 'blocked'  -> Request above tier -> Blocked / ESCALATION_BLOCKED, open incident in ASSESSING_INTENT
   *
   * @param {string} [forcedOutcome] - Optional: 'grant', 'adjusted', or 'blocked'
   */
  function handleSimulateEscalation(forcedOutcome) {
    const currentRole = VaultAccess.Auth.getCurrentRole();
    if (!currentRole) return;

    VaultAccess.Audit.simulateEscalationAttempt(currentRole, forcedOutcome);
    VaultAccess.UI.renderEscalationLog();
  }

  /**
   * Attempts an administrative action (Lift Lockout) using current role.
   * Evaluates role against Tier 4 and produces distinct Lucid outcomes.
   */
  function handleTryAdminAction() {
    const currentRole = VaultAccess.Auth.getCurrentRole();
    if (!currentRole) return;

    const evalResult = VaultAccess.RBAC.evaluateAction(currentRole, "LIFT_LOCKOUT");
    const session = VaultAccess.Auth.getSession() || { user: currentRole.id };
    const userAccount = (VaultAccess.Config.USERS[session.user] && VaultAccess.Config.USERS[session.user].operatorId)
      ? VaultAccess.Config.USERS[session.user].operatorId
      : (session.user || "op_unknown");

    if (evalResult.outcome === "GRANT") {
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: currentRole.terminalName || currentRole.connection,
        acct: userAccount,
        resource: "Lift Account Lockout",
        action: `Security Admin authorized forensic review & lockout clearance (Tier ${currentRole.tier})`,
        result: "granted",
        resultCode: "GRANTED",
        severity: "info"
      });
    } else if (evalResult.outcome === "ADJUSTED") {
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: currentRole.terminalName || currentRole.connection,
        acct: userAccount,
        resource: "Lift Account Lockout",
        action: `Lift lockout attempt by ${currentRole.label} (Tier ${currentRole.tier}) — downgraded to verification assistance view`,
        result: "adjusted",
        resultCode: "ESCALATION_ADJUSTED",
        severity: "warn"
      });
    } else {
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: currentRole.terminalName || currentRole.connection,
        acct: userAccount,
        resource: "Lift Account Lockout",
        action: `Unauthorized administrative elevation: ${currentRole.label} (Tier ${currentRole.tier}) attempted Tier 4 lockout lift`,
        result: "denied",
        resultCode: "ESCALATION_BLOCKED",
        severity: "danger"
      });

      // Opens an incident in ASSESSING_INTENT for SOC triage
      VaultAccess.Audit.createIncident({
        operatorId: userAccount,
        username: session.user,
        role: currentRole.label,
        terminal: currentRole.terminalName || currentRole.connection,
        resource: "Lift Account Lockout (Tier 4 Authority)",
        requestedTier: 4,
        actualTier: currentRole.tier,
        details: `Operator attempted to execute Tier 4 administrative lockout clearance from ${currentRole.label}. Remote access blocked pending review.`
      });
    }

    // Update UI banner and table
    VaultAccess.UI.renderActionBanner(evalResult);
    VaultAccess.UI.renderEscalationLog();
  }

  /**
   * Binds all DOM elements to event handlers.
   */
  function bindEvents() {
    // 1. Authentication bindings
    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) loginBtn.addEventListener('click', handleLogin);

    ['user', 'pass'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('keydown', e => {
          if (e.key === 'Enter') handleLogin();
        });
      }
    });

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

    // 2. Navigation bar view switching
    document.querySelectorAll('.navbtn').forEach(btn => {
      btn.addEventListener('click', () => {
        VaultAccess.UI.showView(btn.dataset.view);
      });
    });

    // 3. Address bar navigation
    const goBtn = document.getElementById('goBtn');
    const addrInput = document.getElementById('addr');
    if (goBtn && addrInput) {
      goBtn.addEventListener('click', () => {
        const val = addrInput.value.trim().replace(/\/+$/, '');
        VaultAccess.Router.navigate(val.split('/').pop().toLowerCase());
      });
      addrInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') goBtn.click();
      });
    }

    // 4. Access Denied Interceptor modal sign out button
    const reloginBtn = document.getElementById('reloginBtn');
    if (reloginBtn) {
      reloginBtn.addEventListener('click', () => {
        handleLogout();
      });
    }

    // 5. Activity tracking & idle lock check (Phase 6)
    ['mousemove', 'keydown', 'click'].forEach(evt => {
      window.addEventListener(evt, () => {
        VaultAccess.Auth.recordActivity();
      }, { passive: true });
    });

    setInterval(() => {
      if (VaultAccess.Auth.isAuthenticated()) {
        VaultAccess.Auth.checkIdleLock();
        const session = VaultAccess.Auth.getSession();
        if (session && session.isIdleLocked) {
          const pass = prompt(`[WORKSTATION IDLE LOCK]\n\nYour session has locked due to inactivity. Enter password for "${session.user}" to resume:`);
          if (pass) {
            const unlocked = VaultAccess.Auth.unlockIdleSession(pass);
            if (!unlocked.success) {
              alert("Password incorrect. Session terminated.");
              handleLogout();
            }
          } else {
            handleLogout();
          }
        }
      }
    }, 15000);
  }

  /**
   * Initializes application state on launch.
   */
  function init() {
    // Override window.alert to render accessible in-app modal popup instead of browser alerts
    window.alert = function (msg) {
      if (VaultAccess.UI && VaultAccess.UI.showModalNotification) {
        let type = 'info';
        let title = 'System Notification';
        const str = String(msg || '');
        if (str.includes('DENIED') || str.includes('Violation') || str.includes('Error') || str.includes('MALICIOUS') || str.includes('suspended') || str.includes('blocked')) {
          type = 'danger';
          title = 'Security Alert';
        } else if (str.includes('Warning') || str.includes('PENDING') || str.includes('UNCONFIRMED') || str.includes('Require')) {
          type = 'warn';
          title = 'Security Notice';
        } else if (str.includes('VERIFIED') || str.includes('SUCCESS') || str.includes('Completed') || str.includes('unfrozen') || str.includes('Restored')) {
          type = 'ok';
          title = 'Operation Successful';
        }
        VaultAccess.UI.showModalNotification(str, title, type);
      } else {
        console.log('[System Notification]', msg);
      }
    };

    bindEvents();
    VaultAccess.Router.init();
    VaultAccess.UI.renderEscalationLog();
    VaultAccess.Router.route();
  }

  return {
    init,
    handleLogin,
    handleLogout
  };
})();

// Bootstrap application once DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  VaultAccess.App.init();
});
