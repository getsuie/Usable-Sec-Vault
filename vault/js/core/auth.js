/**
 * ============================================================================
 * VaultAccess — Core Module: Hardened Authentication & Session Lifecycle (G6)
 * ============================================================================
 * Enforces enterprise-grade staff authentication security:
 * 1. Exponential rate limiting & login backoff per account & IP (no instant hard-lock).
 * 2. Step-up multi-factor authentication (MFA OTP) for Tier 3 & Tier 4 admins.
 * 3. Physical terminal and connection context binding (branch counter vs. VPN vs. SOC).
 * 4. Session idle lock (5-minute inactivity threshold) & absolute session limits.
 * 5. Time-boxed break-glass emergency elevation (15 min) with mandatory SOC auditing.
 * 6. Account freeze registry with 24-hour auto-expiration.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.Auth = (function () {
  let session = null;
  let pendingRole = null;

  // Rate limiting & backoff tracker: { [username]: { failures: number, cooldownUntil: number } }
  let loginFailures = {};

  // Simulated 6-digit TOTP for demo purposes (clearly designated for demo)
  const DEMO_MFA_OTP = "841920";

  // Account freeze registry with 24h expiration
  let accountFreezes = {};

  // URL tampering incident log
  let urlTamperIncidents = [];

  // Break-glass emergency sessions: { [user]: { expiresAt: number, reason: string } }
  let breakGlassGrants = {};

  // Idle timeout threshold in milliseconds (default 5 minutes = 300,000ms; demo supports 60s)
  let idleTimeoutMs = 300000;

  // Active terminal connection context on the client (demo selector: 'branch' | 'vpn' | 'helpdesk' | 'soc')
  let currentConnectionContext = "branch";

  // --------------------------------------------------------------------------
  // 1. Staff Sign-In & Hardened Authentication Flow
  // --------------------------------------------------------------------------

  /**
   * Sets current physical connection context for the terminal.
   * @param {'branch'|'vpn'|'helpdesk'|'soc'} ctx
   */
  function setConnectionContext(ctx) {
    currentConnectionContext = ctx;
  }

  function getConnectionContext() {
    return currentConnectionContext;
  }

  /**
   * Authenticates a user with credentials, rate-limiting backoff,
   * connection binding, and Tier 3/4 step-up MFA.
   *
   * @param {string} username
   * @param {string} password
   * @param {string} [otpCode] - 6-digit MFA token (required for Tier 3/4)
   * @param {string} [connectionContext] - Bound terminal context
   * @returns {{ success: boolean, message: string, requireMFA?: boolean, rateLimited?: boolean, frozen?: boolean }}
   */
  function login(username, password, otpCode, connectionContext) {
    const cleanUser = (username || "").trim().toLowerCase();
    const userRecord = VaultAccess.Config.USERS[cleanUser];
    const context = connectionContext || currentConnectionContext || "branch";

    // Check 1: Suspended account with 24h auto-expiry check
    checkExpiredFreezes();
    if (accountFreezes[cleanUser]) {
      return {
        success: false,
        frozen: true,
        message: `[ACCOUNT SUSPENDED] Your account "${cleanUser}" has been frozen by the Security Team due to: ${accountFreezes[cleanUser].reason}. Auto-expires at: ${accountFreezes[cleanUser].expiresAt}. Contact Security Admin (Tier 4).`
      };
    }

    if (!userRecord) {
      return { success: false, message: "Invalid username or password." };
    }

    // Check 2: Rate limiting & exponential backoff
    const failRecord = loginFailures[cleanUser] || { failures: 0, cooldownUntil: 0 };
    const now = Date.now();

    if (now < failRecord.cooldownUntil) {
      const remainingSec = Math.ceil((failRecord.cooldownUntil - now) / 1000);
      return {
        success: false,
        rateLimited: true,
        cooldownRemaining: remainingSec,
        message: `Rate limit active: ${failRecord.failures} failed attempts recorded. Exponential backoff enforced. Please wait ${remainingSec}s before retrying.`
      };
    }

    // Check 3: Terminal / Connection Context Binding
    // teller & supervisor: must be 'branch'
    // helpdesk: must be 'helpdesk'
    // itadmin: must be 'vpn'
    // secadmin: must be 'soc' or 'vpn'
    const userRole = VaultAccess.Config.ROLES[userRecord.role];
    const allowedContexts = {
      teller: ["branch"],
      supervisor: ["branch"],
      helpdesk: ["helpdesk"],
      itadmin: ["vpn"],
      secadmin: ["soc", "vpn"]
    };

    const allowed = allowedContexts[userRecord.role] || ["branch"];
    if (!allowed.includes(context)) {
      const firstName = (userRecord.name || cleanUser).split(' ')[0];
      const contextLabels = {
        branch: "Branch Terminal #14 (Counter)",
        helpdesk: "Help Desk Station #04",
        vpn: "Remote Admin VPN",
        soc: "SOC Command Gateway"
      };
      const attemptedLabel = contextLabels[context] || context;
      const requiredLabels = allowed.map(c => contextLabels[c] || c).join(" or ");

      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: attemptedLabel,
        acct: userRecord.operatorId,
        operatorName: firstName,
        resource: "Terminal Binding Policy",
        action: `TERMINAL BINDING VIOLATION: ${userRecord.name} (${userRole.label}) attempted login from untrusted context [${context}]. Required: [${allowed.join(', ')}]. Access blocked.`,
        result: "denied",
        resultCode: "ESCALATION_BLOCKED",
        severity: "danger"
      });

      return {
        success: false,
        connectionViolation: true,
        message: `Connection Context Mismatch: ${firstName} (${userRole.label}) cannot log in from "${attemptedLabel}". Please select "${requiredLabels}" as your Connection Context.`
      };
    }

    // Check 4: Password verification with progressive backoff
    if (userRecord.pass !== password) {
      failRecord.failures++;
      let backoffMs = 0;

      // Exponential backoff after 3 fails: 5s, 10s, 20s, up to 60s
      if (failRecord.failures >= 3) {
        backoffMs = Math.min(60, Math.pow(2, failRecord.failures - 3) * 5) * 1000;
        failRecord.cooldownUntil = now + backoffMs;
      }
      loginFailures[cleanUser] = failRecord;

      const backoffSec = Math.ceil(backoffMs / 1000);
      const backoffNotice = backoffSec > 0 ? ` (Cooldown active: wait ${backoffSec}s)` : '';

      return {
        success: false,
        message: `Invalid username or password. Attempt ${failRecord.failures} of 5.${backoffNotice}`
      };
    }

    // Check 5: Step-Up MFA by Tier (Tier 3 IT Admin & Tier 4 Security Admin)
    if (userRole && userRole.tier >= 3) {
      const cleanOtp = (otpCode || "").trim();
      if (!cleanOtp || cleanOtp !== DEMO_MFA_OTP) {
        return {
          success: false,
          requireMFA: true,
          demoOTP: DEMO_MFA_OTP,
          message: `Step-Up Multi-Factor Authentication Required for Tier ${userRole.tier} (${userRole.label}). Please enter your 6-digit Authenticator code.`
        };
      }
    }

    // Authentication Success: reset failure records
    delete loginFailures[cleanUser];

    session = {
      user: cleanUser,
      role: userRecord.role,
      name: userRecord.name,
      connectionContext: context,
      authenticatedAt: now,
      lastActivityAt: now,
      isIdleLocked: false
    };

    // Log successful login into audit log with first name
    const firstName = (userRecord.name || cleanUser).split(' ')[0];
    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: userRole.terminalName || userRole.connection,
      acct: firstName,
      operatorName: firstName,
      operatorId: userRecord.operatorId,
      resource: "Authentication Gateway",
      action: `[STAFF LOGIN] ${firstName} (${userRole.label}) authenticated successfully from [${context}] context.`,
      result: "granted",
      resultCode: "GRANTED",
      severity: "info"
    });

    return {
      success: true,
      session: session
    };
  }

  /**
   * Terminates active session.
   */
  function logout() {
    if (session) {
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: "Session Manager",
        acct: session.user,
        resource: "Active Session",
        action: `[STAFF LOGOUT] Session closed for user "${session.user}". Security token revoked.`,
        result: "granted",
        resultCode: "GRANTED",
        severity: "info"
      });
    }
    session = null;
    pendingRole = null;
  }

  function getSession() {
    checkIdleLock();
    return session;
  }

  function isAuthenticated() {
    return session !== null && !session.isIdleLocked;
  }

  function getCurrentRole() {
    if (!session) return null;
    return VaultAccess.Config.ROLES[session.role] || null;
  }

  function getPendingRole() {
    return pendingRole;
  }

  function setPendingRole(roleId) {
    pendingRole = roleId;
  }

  function clearPendingRole() {
    pendingRole = null;
  }

  // --------------------------------------------------------------------------
  // 2. Idle Timeout & Activity Tracking
  // --------------------------------------------------------------------------

  function recordActivity() {
    if (session && !session.isIdleLocked) {
      session.lastActivityAt = Date.now();
    }
  }

  function setIdleTimeoutSeconds(seconds) {
    idleTimeoutMs = (seconds || 300) * 1000;
  }

  function checkIdleLock() {
    if (!session || session.isIdleLocked) return;
    const now = Date.now();
    if (now - session.lastActivityAt >= idleTimeoutMs) {
      session.isIdleLocked = true;
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: "Workstation Security Daemon",
        acct: session.user,
        resource: "Session Lifetime",
        action: `[IDLE TIMEOUT] Workstation locked after ${Math.round(idleTimeoutMs / 1000)}s inactivity. Re-authentication required to resume.`,
        result: "reviewed",
        resultCode: "ESCALATION_ADJUSTED",
        severity: "warn"
      });
    }
  }

  function unlockIdleSession(password) {
    if (!session || !session.isIdleLocked) return { success: true };
    const userRec = VaultAccess.Config.USERS[session.user];
    if (userRec && userRec.pass === password) {
      session.isIdleLocked = false;
      session.lastActivityAt = Date.now();
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: "Workstation Security Daemon",
        acct: session.user,
        resource: "Session Lifetime",
        action: `[IDLE UNLOCKED] Workstation unlocked via credential re-entry by "${session.user}".`,
        result: "granted",
        resultCode: "GRANTED",
        severity: "info"
      });
      return { success: true };
    }
    return { success: false, message: "Invalid password. Workstation remains locked." };
  }

  // --------------------------------------------------------------------------
  // 3. Break-Glass Emergency Elevation (Tier 3/4)
  // --------------------------------------------------------------------------

  /**
   * Issues time-boxed emergency break-glass elevation (15 min).
   * Generates urgent SOC audit alert and automatically expires.
   */
  function requestBreakGlassAccess(username, password, justification) {
    const cleanUser = (username || "").trim().toLowerCase();
    const userRecord = VaultAccess.Config.USERS[cleanUser];

    if (!userRecord || userRecord.pass !== password) {
      return { success: false, message: "Authentication failed. Break-glass elevation denied." };
    }

    const cleanReason = (justification || "").trim();
    if (cleanReason.length < 15) {
      return { success: false, message: "Mandatory justification of at least 15 characters required for break-glass activation." };
    }

    const now = Date.now();
    const grantDurationMs = 15 * 60 * 1000; // 15 minutes
    const expiresAt = now + grantDurationMs;
    const token = "BKG-" + Math.floor(1000 + Math.random() * 9000);

    breakGlassGrants[cleanUser] = {
      token: token,
      grantedAt: now,
      expiresAt: expiresAt,
      reason: cleanReason,
      active: true
    };

    // Urgent SOC telemetry
    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Emergency Break-Glass Console",
      acct: userRecord.operatorId,
      resource: "Emergency Administrative Authority",
      action: `[BREAK-GLASS EMERGENCY ACCESS ACTIVATED] 15-minute emergency override granted to ${cleanUser} (${userRecord.name}). Token: ${token}. Justification: "${cleanReason}". Flagged for immediate SOC review.`,
      result: "granted",
      resultCode: "GRANTED",
      severity: "danger"
    });

    // Auto-create SOC Incident
    if (VaultAccess.Audit.createIncident) {
      VaultAccess.Audit.createIncident({
        id: "INC-BKG" + Math.floor(100 + Math.random() * 900),
        operatorId: userRecord.operatorId,
        username: cleanUser,
        role: "Break-Glass Emergency",
        terminal: "Emergency Gateway",
        resource: "Emergency Authority (15 min)",
        requestedTier: 4,
        actualTier: 3,
        status: "ASSESSING_INTENT",
        details: `Break-Glass activation by ${cleanUser}: "${cleanReason}". Token: ${token}. Expiry: 15 minutes.`
      });
    }

    // Establish active session
    session = {
      user: cleanUser,
      role: "secadmin", // Elevated emergency privileges
      originalRole: userRecord.role,
      name: `${userRecord.name} [BREAK-GLASS EMERGENCY]`,
      connectionContext: "soc",
      authenticatedAt: now,
      lastActivityAt: now,
      isBreakGlass: true,
      breakGlassToken: token,
      isIdleLocked: false
    };

    return {
      success: true,
      token: token,
      expiresInMinutes: 15,
      message: `EMERGENCY BREAK-GLASS ACTIVATED\n\nAuthorization Token: ${token}\nGranted Duration: 15 minutes\nSecurity Status: Logged and flagged for mandatory SOC audit.`
    };
  }

  function getBreakGlassGrants() {
    return breakGlassGrants;
  }

  // --------------------------------------------------------------------------
  // 4. Account Freeze Management (24h Expiry)
  // --------------------------------------------------------------------------

  function freezeAccount(username, reason, durationHours) {
    const hours = (typeof durationHours === 'number' && durationHours > 0) ? durationHours : 24;
    const now = Date.now();
    const expiryMs = now + hours * 3600 * 1000;
    const expiryDate = new Date(expiryMs);
    const expiryFormatted = expiryDate.getHours().toString().padStart(2, '0') + ':' + expiryDate.getMinutes().toString().padStart(2, '0');

    accountFreezes[username] = {
      frozenAt: VaultAccess.Audit.getTimestamp(),
      reason: reason || "Suspicious activity detected",
      durationHours: hours,
      expiresAtMs: expiryMs,
      expiresAt: `${expiryFormatted} (+${hours}h)`
    };
  }

  function checkExpiredFreezes() {
    const now = Date.now();
    Object.keys(accountFreezes).forEach(username => {
      const rec = accountFreezes[username];
      if (rec.expiresAtMs && now >= rec.expiresAtMs) {
        delete accountFreezes[username];
        if (VaultAccess.Audit && VaultAccess.Audit.logEvent) {
          VaultAccess.Audit.logEvent({
            time: VaultAccess.Audit.getTimestamp(),
            src: "SOC Policy Enforcement Engine",
            acct: username,
            resource: "Account Status",
            action: `[FREEZE_EXPIRED] Security freeze on operator "${username}" reached ${rec.durationHours}h expiry limit and was automatically lifted.`,
            result: "reviewed",
            resultCode: "FREEZE_EXPIRED",
            severity: "info"
          });
        }
      }
    });
  }

  function fastForwardFreezeExpiry(username) {
    if (accountFreezes[username]) {
      accountFreezes[username].expiresAtMs = Date.now() - 1000;
      checkExpiredFreezes();
      return true;
    }
    return false;
  }

  function unfreezeAccount(username) {
    delete accountFreezes[username];
  }

  function isAccountFrozen(username) {
    checkExpiredFreezes();
    return !!accountFreezes[username];
  }

  function getAccountFreezes() {
    checkExpiredFreezes();
    return accountFreezes;
  }

  function recordURLTamperIncident(incident) {
    urlTamperIncidents.unshift(incident);
  }

  function getURLTamperIncidents() {
    return urlTamperIncidents;
  }

  return {
    login,
    logout,
    getSession,
    isAuthenticated,
    getCurrentRole,
    getPendingRole,
    setPendingRole,
    clearPendingRole,
    setConnectionContext,
    getConnectionContext,
    recordActivity,
    setIdleTimeoutSeconds,
    checkIdleLock,
    unlockIdleSession,
    requestBreakGlassAccess,
    getBreakGlassGrants,
    freezeAccount,
    unfreezeAccount,
    isAccountFrozen,
    getAccountFreezes,
    checkExpiredFreezes,
    fastForwardFreezeExpiry,
    recordURLTamperIncident,
    getURLTamperIncidents,
    DEMO_MFA_OTP
  };
})();
