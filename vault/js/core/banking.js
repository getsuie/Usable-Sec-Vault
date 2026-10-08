/**
 * ============================================================================
 * VaultAccess — Core Module: Banking Operations & Security Enforcement Engine
 * ============================================================================
 * Implements realistic bank workstation functions for all 4 roles:
 * 1. Teller: Customer inquiry, deposit, low-value withdrawal (up to ₱60,500), transfer.
 * 2. Automated Security Lock: Screen freeze on mismatched account transfer.
 * 3. Privilege Escalation Simulation (Step 3): Tampered payload with isSecurityApproved: true.
 * 4. Secure Server Defense (Step 4): Session validation, 403 Forbidden, and insider threat logging.
 * 5. Supervisor: High-value override desk (>₱60,500).
 * 6. IT Admin: Infrastructure diagnostics & PII masking (Separation of Duties).
 * 7. Security Admin: SOC forensic review & terminal lockout resolution.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.Banking = (function () {

  // Active terminal security state
  let terminalLockState = {
    isLocked: false,
    terminalId: "TERM-BR14",
    operatorId: "teller_402",
    reason: "",
    neutralTellerMessage: "Verification required. Please contact your supervisor.",
    refCode: null,
    whatToDo: "",
    lockedAt: null,
    flaggedAccount: null,
    escalationAttemptCount: 0
  };

  // Graded anomaly strike counter for teller session (Phase 3)
  let tellerAnomalyStrikes = 0;

  // Working copy of bank accounts, pending supervisor overrides, and approvals registry
  let accounts = {};
  let supervisorOverrides = [];
  let approvals = [];

  function init() {
    // Clone initial data
    accounts = JSON.parse(JSON.stringify(VaultAccess.Config.BANK_ACCOUNTS));
    supervisorOverrides = JSON.parse(JSON.stringify(VaultAccess.Config.INITIAL_SUPERVISOR_OVERRIDES));
    approvals = VaultAccess.Config.INITIAL_APPROVALS ? JSON.parse(JSON.stringify(VaultAccess.Config.INITIAL_APPROVALS)) : [];
    tellerAnomalyStrikes = 0;
  }

  // --------------------------------------------------------------------------
  // 1. Teller Workstation Operations
  // --------------------------------------------------------------------------

  /**
   * Looks up a customer profile by account number or name.
   * @param {string} query
   * @returns {object|null}
   */
  function lookupCustomer(query) {
    if (!query) return null;
    const clean = query.trim().toLowerCase();

    // Search exact account number
    if (accounts[clean]) return accounts[clean];

    // Search by partial account or name
    for (const acctNum in accounts) {
      const acct = accounts[acctNum];
      if (acct.acctNumber.toLowerCase() === clean || acct.name.toLowerCase() === clean) {
        return acct;
      }
    }

    // Default fallback to first active account if non-empty
    return null;
  }

  /**
   * Helper: Validates Separation of Duties (SoD) before executing financial transactions.
   */
  function checkSeparationOfDuties(actionName) {
    const currentRole = VaultAccess.Auth ? VaultAccess.Auth.getCurrentRole() : null;
    if (currentRole && VaultAccess.RBAC) {
      const evalRes = VaultAccess.RBAC.evaluateAction(currentRole, actionName);
      if (!evalRes.allowed) {
        const session = VaultAccess.Auth.getSession();
        const user = session ? session.user : currentRole.id;
        VaultAccess.Audit.logEvent({
          time: VaultAccess.Audit.getTimestamp(),
          src: currentRole.terminalName || currentRole.connection || "SOC Command Gateway",
          acct: user,
          resource: `Financial Ledger (${actionName})`,
          action: `DENIED (Separation of Duties): ${currentRole.label} (Tier ${currentRole.tier}) attempted ${actionName}. Financial transactions strictly restricted to Branch personnel.`,
          result: "denied",
          resultCode: "ESCALATION_BLOCKED",
          severity: "danger"
        });
        return {
          allowed: false,
          response: {
            success: false,
            httpStatus: 403,
            message: `403 Forbidden — Separation of Duties: ${currentRole.label} (Tier ${currentRole.tier}) is prohibited from moving money (${actionName}). Direct financial transactions are segregated to Branch Personnel.`
          }
        };
      }
    }
    return { allowed: true };
  }

  /**
   * Processes a cash deposit with Graded Teller Anomaly Response (Phase 3).
   * - Condition 1: Malformed / non-existent account -> Inline warning, allow retry. Strike 1.
   * - Condition 2: Account exists but does not match customer -> Supervisor check required (soft hold).
   * - Condition 3: Known shadow account (9999-0000) or 2+ mismatches -> Terminal lock + SOC alert.
   *   Teller receives neutral message: "Verification required. Please contact your supervisor."
   */
  function processDeposit(customer, typedAcctNumber, amount) {
    // 1. Separation of Duties enforcement (Tier 3/4 blocked from deposits)
    const sod = checkSeparationOfDuties("DEPOSIT");
    if (!sod.allowed) return sod.response;

    if (terminalLockState.isLocked) {
      return { success: false, message: terminalLockState.neutralTellerMessage };
    }

    if (!customer) {
      return { success: false, message: "No customer profile selected." };
    }

    const cleanTyped = (typedAcctNumber || "").trim();

    // Condition 3a: Known shadow account (9999-0000) -> Immediate hard-lock trigger for demo
    if (cleanTyped === "9999-0000") {
      tellerAnomalyStrikes++;
      lockTerminal(
        `High-risk shadow account redirection attempt detected [${cleanTyped}]. Known fraudulent pattern.`,
        customer.name + ` (Expected: ${customer.acctNumber})`,
        cleanTyped
      );
      return {
        success: false,
        terminalLocked: true,
        strikeCount: tellerAnomalyStrikes,
        message: terminalLockState.neutralTellerMessage
      };
    }

    // Valid deposit: typed account exactly matches selected customer
    if (cleanTyped === customer.acctNumber) {
      const parsedAmount = parseFloat(amount);
      if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return { success: false, message: "Invalid deposit amount." };
      }

      const acct = accounts[customer.acctNumber];
      acct.balance += parsedAmount;
      acct.recentTransactions.unshift({
        date: new Date().toISOString().slice(0, 10),
        desc: "Over-the-Counter Cash Deposit",
        amount: parsedAmount,
        type: "CR"
      });

      // Reset anomaly strikes on successful transaction
      tellerAnomalyStrikes = 0;

      return {
        success: true,
        newBalance: acct.balance,
        message: `Deposit of ₱${parsedAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })} to ${acct.name} (${acct.acctNumber}) successful.`
      };
    }

    // Condition 2: Account exists in system, but does NOT match the displayed customer
    if (accounts[cleanTyped]) {
      tellerAnomalyStrikes++;
      if (tellerAnomalyStrikes >= 2) {
        // Repeated mismatch -> Escalate to terminal lock
        lockTerminal(
          `Multiple account mismatch anomalies in session (Strikes: ${tellerAnomalyStrikes}). Redirect to account [${cleanTyped}].`,
          customer.name + ` (Expected: ${customer.acctNumber})`,
          cleanTyped
        );
        return {
          success: false,
          terminalLocked: true,
          strikeCount: tellerAnomalyStrikes,
          message: terminalLockState.neutralTellerMessage
        };
      }

      // Soft hold: Supervisor check required. Teller can continue other work.
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: "Branch Terminal #14",
        acct: customer.acctNumber,
        resource: "Counter Cash Deposit",
        action: `Deposit destination mismatch: Target account ${cleanTyped} belongs to a different customer (${accounts[cleanTyped].name}). Routed for supervisor verification.`,
        result: "adjusted",
        resultCode: "ESCALATION_ADJUSTED",
        severity: "warn"
      });

      return {
        success: false,
        requiresSupervisorCheck: true,
        strikeCount: tellerAnomalyStrikes,
        targetCustomer: accounts[cleanTyped].name,
        targetAcct: cleanTyped,
        message: `Supervisor verification required: The entered destination account (${cleanTyped}) belongs to "${accounts[cleanTyped].name}". A verification request has been queued. You may continue other teller operations.`
      };
    }

    // Condition 1: Account number malformed or does not exist
    tellerAnomalyStrikes++;
    if (tellerAnomalyStrikes >= 2) {
      // 2 or more mismatches in a session -> Terminal lock + SOC alert
      lockTerminal(
        `Excessive account lookup failures (Strikes: ${tellerAnomalyStrikes}). Unregistered account typed: [${cleanTyped || 'EMPTY'}].`,
        customer.name + ` (Expected: ${customer.acctNumber})`,
        cleanTyped || "EMPTY"
      );
      return {
        success: false,
        terminalLocked: true,
        strikeCount: tellerAnomalyStrikes,
        message: terminalLockState.neutralTellerMessage
      };
    }

    // Inline warning, allow retry (Strike 1)
    return {
      success: false,
      strikeWarning: true,
      strikeCount: tellerAnomalyStrikes,
      message: `Account number "${cleanTyped || 'empty'}" not found in core registry. Please verify the account number with the customer and try again. (Strike 1 of 2)`
    };
  }

  /**
   * Processes a cash withdrawal (enforces Teller limit up to ₱60,500).
   * Amounts exceeding ₱60,500 automatically route to Branch Supervisor for approval.
   */
  function processWithdrawal(customer, amount) {
    // 1. Separation of Duties enforcement (Tier 3/4 blocked from withdrawals)
    const sod = checkSeparationOfDuties("WITHDRAWAL");
    if (!sod.allowed) return sod.response;

    if (terminalLockState.isLocked) {
      return { success: false, message: terminalLockState.neutralTellerMessage };
    }

    if (!customer) {
      return { success: false, message: "No customer profile selected." };
    }

    const acct = accounts[customer.acctNumber];
    if (!acct) return { success: false, message: "Account not found." };

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return { success: false, message: "Invalid withdrawal amount." };
    }

    if (parsedAmount > acct.balance) {
      return { success: false, message: "Insufficient account balance." };
    }

    const TELLER_LIMIT = 60500; // ₱60,500

    // High-value check: If exceeds ₱60,500, check for supervisor override
    if (parsedAmount > TELLER_LIMIT) {
      const activeOverride = findActiveOverride(acct.acctNumber);

      // Case 1: Approved override exists -> Authorize this specific transaction
      if (activeOverride && activeOverride.status === "APPROVED") {
        activeOverride.status = "CONSUMED";
        activeOverride.consumedAt = VaultAccess.Audit.getTimestamp();
        activeOverride.consumedBy = "teller_402";

        acct.balance -= parsedAmount;
        acct.recentTransactions.unshift({
          date: new Date().toISOString().slice(0, 10),
          desc: `Supervisor Approved Withdrawal (${activeOverride.id})`,
          amount: -parsedAmount,
          type: "DR"
        });

        // Audit log: Legitimate high-value escalation completed and consumed
        VaultAccess.Audit.logEvent({
          time: VaultAccess.Audit.getTimestamp(),
          src: "Branch Terminal #14",
          acct: acct.acctNumber,
          action: `Completed high-value withdrawal ₱${parsedAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })} (Override: ${activeOverride.id}, CONSUMED). Teller remains Tier 1.`,
          result: "reviewed"
        });

        return {
          success: true,
          newBalance: acct.balance,
          overrideConsumed: true,
          overrideId: activeOverride.id,
          message: `High-value withdrawal of ₱${parsedAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })} completed under supervisor authorization (${activeOverride.id}). Override status: CONSUMED. Teller privilege remains Tier 1.`
        };
      }

      // Case 2: Rejected override exists -> Block transaction
      if (activeOverride && activeOverride.status === "REJECTED") {
        return {
          success: false,
          blocked: true,
          overrideId: activeOverride.id,
          message: `TRANSACTION BLOCKED: Supervisor override ${activeOverride.id} was REJECTED by Branch Supervisor. High-value withdrawal cannot proceed.`
        };
      }

      // Case 3: Pending override exists -> Awaiting approval
      if (activeOverride && activeOverride.status === "PENDING") {
        return {
          success: false,
          pending: true,
          overrideId: activeOverride.id,
          message: `Override request ${activeOverride.id} is currently PENDING approval in the Branch Supervisor queue.`
        };
      }

      // Case 4: No override exists -> Trigger privilege escalation requirement
      return {
        success: false,
        requiresEscalation: true,
        requestedAmount: parsedAmount,
        limit: TELLER_LIMIT,
        currentTier: 1,
        requiredTier: 2,
        currentRole: "Branch Teller",
        requiredRole: "Branch Supervisor",
        customer: acct.name,
        acct: acct.acctNumber,
        message: `PRIVILEGE ESCALATION REQUIRED\n\nCurrent Tier: Tier 1 — Branch Teller\nTeller Limit: ₱60,500\nRequested Amount: ₱${parsedAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })}\nRequired Tier: Tier 2 — Branch Supervisor\n\nA supervisor approval is required.`
      };
    }

    // Within limit: process standard teller withdrawal
    acct.balance -= parsedAmount;
    acct.recentTransactions.unshift({
      date: new Date().toISOString().slice(0, 10),
      desc: "Branch Counter Withdrawal",
      amount: -parsedAmount,
      type: "DR"
    });

    return {
      success: true,
      newBalance: acct.balance,
      message: `Withdrawal of ₱${parsedAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })} approved and processed.`
    };
  }

  /**
   * Finds the latest active or pending override for a customer account.
   */
  function findActiveOverride(acctNumber) {
    if (!acctNumber) return null;
    return supervisorOverrides.find(o =>
      o.acct === acctNumber &&
      (o.status === "PENDING" || o.status === "APPROVED" || o.status === "REJECTED")
    ) || null;
  }

  /**
   * Creates a formal supervisor override request for amounts > ₱60,500.
   */
  function createOverrideRequest(acctNumber, amount, justification) {
    const acct = accounts[acctNumber];
    if (!acct) return { success: false, message: "Account not found." };

    const parsedAmount = parseFloat(amount);
    const TELLER_LIMIT = 60500;

    const overrideRecord = {
      id: "OVR-" + Math.floor(1000 + Math.random() * 9000),
      time: VaultAccess.Audit.getTimestamp(),
      tellerId: "teller_402",
      terminal: "Branch Terminal #14",
      acct: acct.acctNumber,
      customer: acct.name,
      type: "High-Value Cash Withdrawal",
      amount: parsedAmount,
      threshold: TELLER_LIMIT,
      currentTier: 1,
      requiredTier: 2,
      status: "PENDING",
      justification: justification || "Withdrawal exceeds Teller ₱60,500 threshold; awaiting Branch Supervisor approval."
    };

    supervisorOverrides.unshift(overrideRecord);

    // Record legitimate escalation attempt in Escalation Monitor
    VaultAccess.Audit.logEvent({
      time: overrideRecord.time,
      src: "Branch Terminal #14",
      acct: acct.acctNumber,
      action: `Requested high-value withdrawal ₱${parsedAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })} (Override: ${overrideRecord.id}, Status: PENDING)`,
      result: "warn"
    });

    return {
      success: true,
      override: overrideRecord,
      message: `Override request ${overrideRecord.id} generated and submitted to Branch Supervisor queue.`
    };
  }

  /**
   * Step 1 & 2: Process transfer with automated security lock on mismatch.
   * If recipient account does not match the system, automatically freezes terminal.
   */
  function processTransfer(sourceAcctNumber, destinationAcctNumber, amount) {
    // 1. Separation of Duties enforcement (Tier 3/4 blocked from transfers)
    const sod = checkSeparationOfDuties("TRANSFER");
    if (!sod.allowed) return sod.response;

    if (terminalLockState.isLocked) {
      return { success: false, message: terminalLockState.neutralTellerMessage };
    }

    const sourceAcct = accounts[sourceAcctNumber];
    if (!sourceAcct) {
      return { success: false, message: "Source account not found." };
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return { success: false, message: "Invalid transfer amount." };
    }

    // Step 1: Detect account mismatch (destination account does not exist in system)
    const cleanDest = (destinationAcctNumber || "").trim();
    const destAcct = accounts[cleanDest];

    if (!destAcct) {
      // Step 2: Automated Security Lock triggered!
      lockTerminal(
        `Account mismatch detected: Recipient account [${cleanDest || 'EMPTY'}] not registered in system.`,
        sourceAcct.acctNumber,
        cleanDest
      );

      return {
        success: false,
        terminalLocked: true,
        message: terminalLockState.neutralTellerMessage
      };
    }

    // Valid transfer
    if (parsedAmount > sourceAcct.balance) {
      return { success: false, message: "Insufficient balance for transfer." };
    }

    sourceAcct.balance -= parsedAmount;
    destAcct.balance += parsedAmount;

    return {
      success: true,
      message: `Transfer of ₱${parsedAmount.toLocaleString('en-US', { minimumFractionDigits: 2 })} to ${destAcct.name} (${destAcct.acctNumber}) successful.`
    };
  }

  // --------------------------------------------------------------------------
  // 2. Terminal Security Freeze & Lockout
  // --------------------------------------------------------------------------

  function lockTerminal(reason, sourceAcct, invalidDestAcct, refCodeOverride) {
    const refCode = refCodeOverride || ("REF-" + Math.floor(1000 + Math.random() * 9000));
    terminalLockState.isLocked = true;
    terminalLockState.reason = reason;
    terminalLockState.neutralTellerMessage = "Verification required. Please contact your supervisor.";
    terminalLockState.refCode = refCode;
    terminalLockState.whatToDo = `1. Advise customer of a routine verification hold.\n2. Contact Branch Supervisor (Ext. 201) with Terminal ID: ${terminalLockState.terminalId} and Ref: ${refCode}.\n3. Security Team review is required to clear this condition.`;
    terminalLockState.lockedAt = VaultAccess.Audit.getTimestamp();
    terminalLockState.flaggedAccount = sourceAcct;

    // Log incident in audit trail — appears in Security Admin's Escalation Monitor with full forensic detail
    VaultAccess.Audit.logEvent({
      time: terminalLockState.lockedAt,
      src: "Branch Terminal #14 [Anomaly Engine]",
      acct: sourceAcct || "teller_402",
      resource: "Terminal Security State",
      action: `ANOMALY LOCKOUT: ${reason} [Invalid Destination: ${invalidDestAcct || 'UNKNOWN'}, Ref: ${refCode}] — Terminal frozen for SOC review.`,
      result: "denied",
      resultCode: "ESCALATION_BLOCKED",
      severity: "danger"
    });

    // Automatically queue an incident in the SOC triage queue
    if (VaultAccess.Audit.createIncident) {
      VaultAccess.Audit.createIncident({
        id: "INC-" + Math.floor(6000 + Math.random() * 3000),
        operatorId: terminalLockState.operatorId,
        username: "teller",
        role: "Branch Teller",
        terminal: terminalLockState.terminalId,
        resource: "Terminal Fraud Lock",
        requestedTier: 4,
        actualTier: 1,
        details: `${reason} [Source: ${sourceAcct || 'N/A'}, Typed: ${invalidDestAcct || 'UNKNOWN'}, Ref: ${refCode}]`
      });
    }
  }

  function getTerminalLockState() {
    return terminalLockState;
  }

  // --------------------------------------------------------------------------
  // 3 & 4. Privilege Escalation Attack & Server Prevention Engine
  // --------------------------------------------------------------------------

  /**
   * Generates the baseline tampered payload that a malicious or frustrated
   * teller injects via DevTools or API request interceptor.
   */
  function generateHackerPayload() {
    return {
      endpoint: "/api/v1/terminal/security/clear-fraud-lock",
      method: "POST",
      headers: {
        "X-Terminal-ID": "TERM-BR14",
        "X-Operator-ID": "teller_402",
        "Content-Type": "application/json"
      },
      payload: {
        terminalId: "TERM-BR14",
        operatorId: "teller_402",
        action: "CLEAR_FRAUD_FLAG_AND_UNLOCK",
        // Client-injected privilege escalation fields:
        isSecurityApproved: true,
        clientRoleOverride: "Security_Admin"
      }
    };
  }

  /**
   * Step 4: The Secure Server-Side Prevention.
   * Simulates the server-side authentication gateway processing the tampered request.
   * The server checks session identity, rejects forged flags, returns 403, and logs alert.
   */
  /**
   * Step 4: The Secure Server-Side Prevention (Phase 3 allowlist schema enforcement).
   * Simulates the server-side authentication gateway processing the tampered request.
   * Uses a strict allowlist schema of accepted parameters and rejects forged claims.
   */
  function executeServerPrivilegeEscalationDefense(submittedPayload) {
    terminalLockState.escalationAttemptCount++;
    const activeSession = VaultAccess.Auth.getSession();

    // Server-side verification: check real authenticated session token
    const authenticatedUser = activeSession ? activeSession.user : "teller";
    const realUserRecord = VaultAccess.Config.USERS[authenticatedUser];
    const realRole = realUserRecord ? VaultAccess.Config.ROLES[realUserRecord.role] : VaultAccess.Config.ROLES.teller;
    const realTier = realRole ? realRole.tier : 1;

    const payload = submittedPayload || {};

    // Allowlist schema: only expected parameters are accepted by the backend API
    const ALLOWLISTED_FIELDS = ["terminalId", "operatorId", "action", "justification", "incidentId"];
    const payloadKeys = Object.keys(payload);
    const disallowedKeys = payloadKeys.filter(k => !ALLOWLISTED_FIELDS.includes(k));

    const clientAttemptedOverride = disallowedKeys.length > 0 ||
      payload.isSecurityApproved === true ||
      payload.clientRoleOverride === "Security_Admin" ||
      payload.role === "Security_Admin";

    if (clientAttemptedOverride && realTier < 4) {
      // 1. Telemetry: Log critical insider threat with exact rejected fields
      const timestamp = VaultAccess.Audit.getTimestamp();
      const rejectedFieldList = disallowedKeys.length > 0 ? disallowedKeys.join(', ') : 'isSecurityApproved, clientRoleOverride';

      VaultAccess.Audit.logEvent({
        time: timestamp,
        src: "Branch Terminal #14 [API Payload Tamper]",
        acct: realUserRecord ? realUserRecord.operatorId : "teller_402",
        resource: "API Endpoint: /clear-fraud-lock",
        action: `CRITICAL INSIDER THREAT: Payload schema violation. Disallowed fields rejected: [${rejectedFieldList}]. Client attempted privilege elevation to Security_Admin without Tier 4 token. (Result: denied, Severity: critical)`,
        result: "denied",
        resultCode: "ESCALATION_BLOCKED",
        severity: "danger"
      });

      // 2. Terminal remains frozen
      terminalLockState.isLocked = true;

      // 3. Return 403 Forbidden with exact forensic diagnostic
      return {
        httpStatus: 403,
        statusText: "Forbidden",
        error: "SCHEMA_VALIDATION_FAILED_PRIVILEGE_MANIPULATION",
        serverVerdict: "DENIED",
        disallowedFieldsRejected: disallowedKeys,
        requestedRole: "Security_Admin",
        actualAssignedRole: realRole.label,
        currentTier: realTier,
        requiredTier: 4,
        result: "DENIED",
        severity: "CRITICAL",
        message: `PRIVILEGE MANIPULATION DETECTED\n\nSchema Violation: Disallowed fields [${rejectedFieldList}] rejected by API gateway.\n\nRequested role:\nSecurity_Admin\n\nActual assigned role:\n${realRole.label}\n\nResult:\nDENIED\n\nSecurity event logged.`,
        forensics: {
          clientSuppliedRole: payload.clientRoleOverride || payload.role || "Security_Admin",
          authenticatedRealRole: `${realUserRecord ? realUserRecord.name : 'A. Santos'} (${realRole.label})`,
          authenticatedTier: realTier,
          requiredTier: 4,
          disallowedParameters: rejectedFieldList,
          actionTaken: "Untrusted client schema claims rejected; critical insider threat flagged in Escalation Monitor"
        }
      };
    }

    return {
      httpStatus: 200,
      statusText: "OK",
      message: "Authorized"
    };
  }

  // --------------------------------------------------------------------------
  // 5. Security Admin Terminal Unlock (Maker-Checker Enforced - Phase 4)
  // --------------------------------------------------------------------------

  /**
   * Clears terminal fraud freeze under Maker-Checker (four-eyes) controls.
   * Requires: written justification (minimum 15 characters) and a valid Incident ID.
   *
   * @param {string} justification - Mandatory rationale (min 15 chars)
   * @param {string} incidentId - Related security incident reference (e.g. INC-4011)
   */
  function unlockTerminalBySecurityAdmin(justification, incidentId) {
    const activeSession = VaultAccess.Auth.getSession();
    const currentRole = VaultAccess.Auth.getCurrentRole();

    if (!currentRole || currentRole.tier < 4) {
      return {
        success: false,
        message: `Permission Denied: Only Tier 4 (Security Admin) can clear terminal fraud locks. Current role: ${currentRole ? currentRole.label : 'None'}.`
      };
    }

    // Maker-Checker Check 1: Mandatory written justification (min 15 characters)
    const cleanJustification = (justification || "").trim();
    if (cleanJustification.length < 15) {
      return {
        success: false,
        makerCheckerError: true,
        message: `Maker-Checker Policy Violation: A written justification of at least 15 characters is required to clear a security lock. (Provided: ${cleanJustification.length} chars).`
      };
    }

    // Maker-Checker Check 2: Mandatory incident ID link
    const cleanIncident = (incidentId || "").trim();
    if (!cleanIncident) {
      return {
        success: false,
        makerCheckerError: true,
        message: "Maker-Checker Policy Violation: A valid Security Incident ID (e.g. INC-4011) must be attached to the clearance record."
      };
    }

    const approverName = activeSession ? (VaultAccess.Config.USERS[activeSession.user]?.name || activeSession.user) : "sec_soc01";

    // Record maker-checker authorization record
    const approvalRecord = {
      id: "APR-" + Math.floor(100 + Math.random() * 900),
      type: "TERMINAL_UNLOCK",
      requestedBy: terminalLockState.operatorId,
      approvedBy: approverName,
      reason: cleanJustification,
      reasonCode: "FORENSIC_TRIAGE_CLEARED",
      incidentId: cleanIncident,
      timestamp: VaultAccess.Audit.getTimestamp(),
      status: "APPROVED"
    };
    approvals.unshift(approvalRecord);

    // Reset terminal lock & anomaly strikes
    terminalLockState.isLocked = false;
    terminalLockState.reason = "";
    terminalLockState.neutralTellerMessage = "Verification required. Please contact your supervisor.";
    terminalLockState.refCode = null;
    terminalLockState.whatToDo = "";
    terminalLockState.lockedAt = null;
    terminalLockState.flaggedAccount = null;
    tellerAnomalyStrikes = 0;

    // Log Maker-Checker audit entry
    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "SOC Gateway (secadmin)",
      acct: "TERM-BR14",
      resource: "Terminal Anomaly State",
      action: `[MAKER-CHECKER CLEARANCE] Terminal #14 fraud freeze lifted by ${approverName} (Case: ${cleanIncident}, Approval: ${approvalRecord.id}). Justification: "${cleanJustification}"`,
      result: "reviewed",
      resultCode: "GRANTED",
      severity: "info"
    });

    return {
      success: true,
      approval: approvalRecord,
      message: `Branch Terminal #14 officially unlocked under Maker-Checker authorization (${approvalRecord.id}). Linked case: ${cleanIncident}.`
    };
  }

  // --------------------------------------------------------------------------
  // 6. Supervisor Approvals & Overrides (Maker-Checker Enforced - Phase 4)
  // --------------------------------------------------------------------------

  function getSupervisorOverrides() {
    return supervisorOverrides;
  }

  function getApprovals() {
    return approvals;
  }

  function approveOverride(overrideId, reasonCode, customReason) {
    const rec = supervisorOverrides.find(o => o.id === overrideId);
    if (!rec) return { success: false, message: "Override record not found." };

    const activeSession = VaultAccess.Auth.getSession();
    const currentUser = activeSession ? activeSession.user : "supervisor";
    const userRecord = VaultAccess.Config.USERS[currentUser];
    const currentOperatorId = userRecord ? userRecord.operatorId : currentUser;

    // Maker-Checker Check: Supervisor cannot approve an override they requested (Four-Eyes Principle)
    if (rec.tellerId === currentOperatorId || rec.tellerId === currentUser) {
      VaultAccess.Audit.logEvent({
        time: VaultAccess.Audit.getTimestamp(),
        src: "Supervisor Station #01",
        acct: currentOperatorId,
        resource: "Override " + rec.id,
        action: `MAKER-CHECKER VIOLATION: Operator attempted self-approval of own override request (${rec.id}). Dual authorization policy enforced.`,
        result: "denied",
        resultCode: "ESCALATION_BLOCKED",
        severity: "danger"
      });

      return {
        success: false,
        selfApprovalBlocked: true,
        message: `MAKER-CHECKER ENFORCEMENT ERROR\n\nSelf-approval is strictly prohibited: You cannot approve override ${rec.id} because it was submitted by your account (${rec.tellerId}). An independent supervisor must review this request.`
      };
    }

    const code = reasonCode || "DUAL_ID_CONFIRMED";
    const justification = customReason || "Customer identity and signature verified in person by branch supervisor.";

    rec.status = "APPROVED";
    rec.approvedBy = `${currentOperatorId} (${userRecord ? userRecord.name : 'Supervisor'})`;
    rec.approvedAt = VaultAccess.Audit.getTimestamp();
    rec.reasonCode = code;
    rec.justificationNote = justification;
    rec.scope = "Single transaction";

    // Record in Maker-Checker approvals audit
    const approvalRecord = {
      id: "APR-" + Math.floor(100 + Math.random() * 900),
      type: "HIGH_VALUE_OVERRIDE",
      requestedBy: rec.tellerId,
      approvedBy: rec.approvedBy,
      reason: justification,
      reasonCode: code,
      timestamp: rec.approvedAt,
      status: "APPROVED"
    };
    approvals.unshift(approvalRecord);

    VaultAccess.Audit.logEvent({
      time: rec.approvedAt,
      src: "Supervisor Station #01",
      acct: rec.acct,
      resource: "High-Value Transaction Desk",
      action: `[MAKER-CHECKER APPROVED] High-value override ${rec.id} approved by ${rec.approvedBy} for ₱${rec.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })}. Code: ${code}. Scope: Single transaction.`,
      result: "reviewed",
      resultCode: "GRANTED",
      severity: "info"
    });

    return {
      success: true,
      override: rec,
      message: `HIGH-VALUE OVERRIDE APPROVED\n\nOverride: ${rec.id}\nApproved by: ${rec.approvedBy}\nReason Code: ${code}\nAuthorized: ₱${rec.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })} withdrawal\nScope: Single transaction\nStatus: APPROVED`
    };
  }

  function rejectOverride(overrideId, reasonCode, customReason) {
    const rec = supervisorOverrides.find(o => o.id === overrideId);
    if (!rec) return { success: false, message: "Override record not found." };

    const activeSession = VaultAccess.Auth.getSession();
    const currentUser = activeSession ? activeSession.user : "supervisor";
    const userRecord = VaultAccess.Config.USERS[currentUser];
    const currentOperatorId = userRecord ? userRecord.operatorId : currentUser;

    const code = reasonCode || "SUSPICIOUS_HIGH_RISK";
    const justification = customReason || "Customer failed secondary verification or declined standard security procedures.";

    rec.status = "REJECTED";
    rec.rejectedBy = `${currentOperatorId} (${userRecord ? userRecord.name : 'Supervisor'})`;
    rec.rejectedAt = VaultAccess.Audit.getTimestamp();
    rec.reasonCode = code;
    rec.justificationNote = justification;

    // Record in Maker-Checker approvals audit
    approvals.unshift({
      id: "APR-" + Math.floor(100 + Math.random() * 900),
      type: "HIGH_VALUE_OVERRIDE",
      requestedBy: rec.tellerId,
      approvedBy: rec.rejectedBy,
      reason: justification,
      reasonCode: code,
      timestamp: rec.rejectedAt,
      status: "REJECTED"
    });

    VaultAccess.Audit.logEvent({
      time: rec.rejectedAt,
      src: "Supervisor Station #01",
      acct: rec.acct,
      resource: "High-Value Transaction Desk",
      action: `[MAKER-CHECKER REJECTED] High-value override ${rec.id} rejected by ${rec.rejectedBy} (₱${rec.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })}). Code: ${code}.`,
      result: "denied",
      resultCode: "ESCALATION_BLOCKED",
      severity: "danger"
    });

    return {
      success: true,
      override: rec,
      message: `HIGH-VALUE OVERRIDE REJECTED\n\nOverride: ${rec.id}\nRejected by: ${rec.rejectedBy}\nReason Code: ${code}\nStatus: REJECTED\nTransaction will be blocked.`
    };
  }

  // --------------------------------------------------------------------------
  // 7. IT Admin Workstation (Infrastructure & SoD PII Check)
  // --------------------------------------------------------------------------

  function getInfrastructureNodes() {
    return VaultAccess.Config.IT_INFRASTRUCTURE_NODES;
  }

  function attemptViewCustomerPII() {
    VaultAccess.Audit.logEvent({
      time: VaultAccess.Audit.getTimestamp(),
      src: "Remote Admin VPN",
      acct: "PII Ledger",
      action: "Attempted query on Customer Financial PII",
      result: "denied"
    });

    return {
      allowed: false,
      message: "ACCESS DENIED (Separation of Duties): IT Administrators manage server health and system services. Access to customer balances, identity profiles, and fraud records is strictly restricted to branch personnel and Security Admins."
    };
  }

  // Initialize data
  init();

  return {
    init,
    lookupCustomer,
    processDeposit,
    processWithdrawal,
    processTransfer,
    findActiveOverride,
    createOverrideRequest,
    lockTerminal,
    getTerminalLockState,
    generateHackerPayload,
    executeServerPrivilegeEscalationDefense,
    unlockTerminalBySecurityAdmin,
    getSupervisorOverrides,
    getApprovals,
    getTellerStrikes: () => tellerAnomalyStrikes,
    approveOverride,
    rejectOverride,
    getInfrastructureNodes,
    attemptViewCustomerPII,
    checkSeparationOfDuties
  };
})();
