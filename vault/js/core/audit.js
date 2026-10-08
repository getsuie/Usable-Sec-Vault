/**
 * ============================================================================
 * VaultAccess — Core Module: Cryptographic Security Audit & Escalation Monitor
 * ============================================================================
 * Implements SEC-03 compliant, tamper-evident audit logging with SHA-256
 * cryptographic hash chaining (Blockchain-style backward chaining).
 *
 * Each record contains:
 * - id, timestamp, severity, sourceIP, deviceSignature, terminalId, operatorId,
 *   tier, action, resource, resultCode, reasonCode, caseId, reviewer, status,
 *   prevHash, and hash.
 *
 * Provides cryptographic verification, tamper injection simulation for testing,
 * role-gated export (Tier 4 CSV/JSON), and SOC incident queue assessment.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.Audit = (function () {
  const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

  // Working in-memory audit log initialized with hash-chained records (newest first)
  let escalationLogs = [];

  // Active Security Incidents Queue (Lucid Staff Flow: Assessing Intent)
  let incidents = [];

  // Incremental audit counter
  let auditSequence = 1000;

  // --------------------------------------------------------------------------
  // Cryptographic Engine: Pure JavaScript SHA-256
  // --------------------------------------------------------------------------

  /**
   * Pure JS SHA-256 implementation (FIPS 180-4 compliant).
   * Fully synchronous, zero-dependency, works in browser & Node.js test runs.
   * @param {string} ascii
   * @returns {string} 64-character lowercase hex digest
   */
  function sha256(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }

    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    const lengthProperty = 'length';
    let i, j;
    let result = '';
    const words = [];
    const asciiBitLength = ascii[lengthProperty] * 8;

    const k = sha256.k = sha256.k || [];
    let primeCounter = k[lengthProperty];

    const isComposite = {};
    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (i = 0; i < 313; i += candidate) {
          isComposite[i] = candidate;
        }
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }

    // Standard SHA-256 initial hash values (H0..H7) must be fresh for every call
    const hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    ascii += '\x80';
    while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
    for (i = 0; i < ascii[lengthProperty]; i++) {
      j = ascii.charCodeAt(i);
      if (j >> 8) return '';
      words[i >> 2] |= j << ((3 - i % 4) * 8);
    }
    words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
    words[words[lengthProperty]] = asciiBitLength;

    for (j = 0; j < words[lengthProperty];) {
      const w = words.slice(j, j += 16);
      const oldHash = hash.slice(0, 8);

      for (i = 0; i < 64; i++) {
        const w15 = w[i - 15], w2 = w[i - 2];
        const a = hash[0], e = hash[4];
        const temp1 = hash[7]
          + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
          + ((e & hash[5]) ^ ((~e) & hash[6]))
          + k[i]
          + (w[i] = (i < 16) ? w[i] : (
              w[i - 16]
              + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
              + w[i - 7]
              + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
            ) | 0
          );
        const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
          + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

        hash.unshift((temp1 + temp2) | 0);
        hash.length = 8;
        hash[4] = (hash[4] + temp1) | 0;
      }

      for (i = 0; i < 8; i++) {
        hash[i] = (hash[i] + oldHash[i]) | 0;
      }
    }

    for (i = 0; i < 8; i++) {
      for (j = 3; j + 1; j--) {
        const b = (hash[i] >> (j * 8)) & 255;
        result += ((b < 16) ? '0' : '') + b.toString(16);
      }
    }
    return result;
  }

  /**
   * Produces the canonical JSON representation of an entry for hash chaining.
   * Deterministic ordering of security-critical attributes.
   */
  function canonicalRepresentation(entry) {
    return JSON.stringify({
      id: entry.id,
      timestamp: entry.timestamp,
      severity: entry.severity,
      sourceIP: entry.sourceIP,
      deviceSignature: entry.deviceSignature,
      terminalId: entry.terminalId,
      operatorId: entry.operatorId,
      tier: entry.tier,
      action: entry.action,
      resource: entry.resource,
      resultCode: entry.resultCode,
      reasonCode: entry.reasonCode,
      caseId: entry.caseId,
      reviewer: entry.reviewer,
      status: entry.status,
      prevHash: entry.prevHash
    });
  }

  /**
   * Computes the cryptographic hash of an audit entry linked to its predecessor.
   */
  function calculateEntryHash(prevHash, entry) {
    const canonical = canonicalRepresentation(entry);
    return sha256(prevHash + ":" + canonical);
  }

  // --------------------------------------------------------------------------
  // Audit Lifecycle & Initialization
  // --------------------------------------------------------------------------

  /**
   * Formats current time as HH:MM.
   */
  function getTimestamp() {
    const now = new Date();
    const hh = now.getHours().toString().padStart(2, '0');
    const mm = now.getMinutes().toString().padStart(2, '0');
    return `${hh}:${mm}`;
  }

  /**
   * Initializes or resets the audit log with chained seed records.
   */
  function init() {
    escalationLogs = [];
    auditSequence = 1000;

    // Incidents start empty — generated live by real operator actions during the session
    incidents = [];
  }


  /**
   * Records a security event to the escalation monitor, cryptographically chained (SEC-03).
   * @param {object} entry - Log details
   * @returns {object} Formatted and chained record
   */
  function logEvent(entry) {
    auditSequence++;
    const prevHash = escalationLogs.length > 0 ? escalationLogs[0].hash : GENESIS_HASH;

    const resultCode = entry.resultCode || (entry.result === 'granted' ? 'GRANTED' : (entry.result === 'adjusted' ? 'ESCALATION_ADJUSTED' : 'ESCALATION_BLOCKED'));
    const severity = entry.severity || (entry.result === 'granted' ? 'info' : (entry.result === 'adjusted' ? 'warn' : 'danger'));
    const timestamp = entry.time || getTimestamp();

    const activeSession = VaultAccess.Auth ? VaultAccess.Auth.getSession() : null;
    const currentRole = VaultAccess.Auth ? VaultAccess.Auth.getCurrentRole() : null;
    const userRec = (activeSession && VaultAccess.Config && VaultAccess.Config.USERS) ? VaultAccess.Config.USERS[activeSession.user] : null;

    const record = {
      id: "AUD-" + auditSequence,
      timestamp: timestamp,
      time: timestamp, // Backward compatibility
      severity: severity,
      sourceIP: entry.sourceIP || (currentRole && currentRole.connection.includes("VPN") ? "10.240.5.21" : "10.240.3.14"),
      deviceSignature: entry.deviceSignature || "DEV-SIG-" + Math.floor(1000 + Math.random() * 9000).toString(16),
      terminalId: entry.terminalId || (currentRole ? currentRole.terminalName || "TERM-BR14" : "TERM-BR14"),
      operatorId: entry.operatorId || (userRec ? userRec.operatorId : (entry.acct || "operator")),
      operatorName: entry.operatorName || (userRec ? (userRec.name ? userRec.name.split(' ')[0] : userRec.user) : (entry.acct || "Staff")),
      tier: entry.tier || (currentRole ? currentRole.tier : 1),
      action: entry.action || "Unspecified Action",
      resource: entry.resource || "Core Banking Gateway",
      result: entry.result || (resultCode === 'GRANTED' ? 'granted' : (resultCode === 'ESCALATION_ADJUSTED' ? 'adjusted' : 'denied')),
      resultCode: resultCode,
      reasonCode: entry.reasonCode || (resultCode === 'GRANTED' ? 'AUTHORIZED' : 'POLICY_BOUNDARY'),
      caseId: entry.caseId || "N/A",
      reviewer: entry.reviewer || "sec_soc01",
      status: "RECORDED",
      src: entry.src || (currentRole ? currentRole.terminalName || currentRole.connection : "Branch Terminal #14"),
      acct: entry.acct || (userRec ? userRec.operatorId : "n/a"),
      prevHash: prevHash,
      hash: ""
    };

    record.hash = calculateEntryHash(prevHash, record);
    escalationLogs.unshift(record);
    return record;
  }

  // --------------------------------------------------------------------------
  // Cryptographic Log Verification & Tampering Demo (SEC-03)
  // --------------------------------------------------------------------------

  /**
   * Verifies the cryptographic integrity of the entire audit chain.
   * Traverses chronologically from the oldest entry to newest.
   * @returns {{ valid: boolean, message: string, brokenEntryId?: string, index?: number }}
   */
  function verifyLogIntegrity() {
    if (escalationLogs.length === 0) {
      return { valid: true, message: "Log is empty. Cryptographic state is clean." };
    }

    // Traverse in chronological order (oldest to newest)
    const chronological = [...escalationLogs].reverse();
    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < chronological.length; i++) {
      const entry = chronological[i];

      // Check 1: Previous hash link
      if (entry.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          brokenEntryId: entry.id,
          index: i + 1,
          expected: expectedPrevHash,
          actual: entry.prevHash,
          message: `HASH CHAIN BROKEN: Entry ${entry.id} (sequence #${i + 1}) has an invalid prevHash link. Tampering or record deletion detected!`
        };
      }

      // Check 2: Content hash recalculation
      const recomputedHash = calculateEntryHash(expectedPrevHash, entry);
      if (recomputedHash !== entry.hash) {
        return {
          valid: false,
          brokenEntryId: entry.id,
          index: i + 1,
          expected: recomputedHash,
          actual: entry.hash,
          message: `CRYPTOGRAPHIC INTEGRITY FAILURE: Entry ${entry.id} content was modified after signing! Recorded hash does not match recomputed SHA-256 digest.`
        };
      }

      expectedPrevHash = entry.hash;
    }

    return {
      valid: true,
      totalEntries: escalationLogs.length,
      tipHash: escalationLogs[0].hash,
      message: `CRYPTOGRAPHIC INTEGRITY VERIFIED: All ${escalationLogs.length} audit entries verified intact. SHA-256 hash chain unbroken (Tip: ${escalationLogs[0].hash.substring(0, 16)}...).`
    };
  }

  /**
   * Simulates an attacker tampering with an audit entry (Demo control for Phase 5).
   * Modifies the action payload of the target entry without recalculating the hash chain.
   * @param {string} [targetId]
   * @returns {object} Tamper status
   */
  function tamperLogEntry(targetId) {
    if (escalationLogs.length === 0) return { success: false, message: "No logs to tamper." };

    const target = targetId
      ? escalationLogs.find(e => e.id === targetId)
      : escalationLogs[Math.floor(escalationLogs.length / 2)];

    if (!target) return { success: false, message: "Target entry not found." };

    // Inject unauthorized modification while preserving old hash to break chain
    const originalAction = target.action;
    target.action = `[UNAUTHORIZED TAMPER] Malicious payload injected into ${target.id} — altered from: "${originalAction}"`;

    return {
      success: true,
      tamperedEntryId: target.id,
      originalAction: originalAction,
      newAction: target.action,
      message: `Entry ${target.id} has been artificially tampered in memory. Run 'Verify Log Integrity' to demonstrate cryptographic tamper detection.`
    };
  }

  /**
   * Exports audit logs in CSV or JSON format (strictly restricted to Tier 4).
   * Generates an audit log entry recording the export operation itself.
   * @param {'csv'|'json'} format
   * @returns {{ success: boolean, data?: string, message?: string }}
   */
  function exportAuditLogs(format) {
    const currentRole = VaultAccess.Auth ? VaultAccess.Auth.getCurrentRole() : null;
    if (!currentRole || currentRole.tier < 4) {
      return {
        success: false,
        message: `Permission Denied: Only Tier 4 (Security Admin) is authorized to export cryptographic audit trails. Current: ${currentRole ? currentRole.label : 'None'}.`
      };
    }

    const exportType = (format || 'json').toLowerCase();

    // Log the export event itself into the hash chain
    logEvent({
      time: getTimestamp(),
      src: "SOC Forensic Export Subsystem",
      acct: "sec_soc01",
      resource: "Audit Log Database",
      action: `[AUDIT EXPORT] Security Admin exported ${escalationLogs.length} audit entries in ${exportType.toUpperCase()} format. Cryptographic verification signed.`,
      result: "granted",
      resultCode: "GRANTED",
      severity: "info"
    });

    if (exportType === 'csv') {
      const headers = ["ID", "Timestamp", "Severity", "Terminal", "Operator", "Tier", "Action", "Resource", "ResultCode", "ReasonCode", "PrevHash", "Hash"];
      const rows = escalationLogs.map(e => [
        e.id,
        `"${e.timestamp}"`,
        e.severity,
        `"${e.terminalId}"`,
        `"${e.operatorId}"`,
        e.tier,
        `"${e.action.replace(/"/g, '""')}"`,
        `"${e.resource}"`,
        e.resultCode,
        e.reasonCode,
        e.prevHash,
        e.hash
      ].join(","));
      const csvData = [headers.join(","), ...rows].join("\n");
      return { success: true, format: "csv", data: csvData, count: escalationLogs.length };
    }

    // Default: JSON export
    const jsonData = JSON.stringify({
      exportedAt: new Date().toISOString(),
      exporter: "sec_soc01",
      totalRecords: escalationLogs.length,
      chainTipHash: escalationLogs.length > 0 ? escalationLogs[0].hash : GENESIS_HASH,
      integrityVerified: verifyLogIntegrity().valid,
      records: escalationLogs
    }, null, 2);

    return { success: true, format: "json", data: jsonData, count: escalationLogs.length };
  }

  // --------------------------------------------------------------------------
  // SOC Incident Queue & Lucid Escalation Outcomes
  // --------------------------------------------------------------------------

  function createIncident(incData) {
    const incident = {
      id: incData.id || "INC-" + Math.floor(1000 + Math.random() * 9000),
      timestamp: incData.timestamp || getTimestamp(),
      operatorId: incData.operatorId || "unknown_op",
      username: incData.username || "unknown",
      role: incData.role || "Branch Operator",
      terminal: incData.terminal || "Branch Terminal",
      resource: incData.resource || "Elevated Administrative Action",
      requestedTier: incData.requestedTier || 4,
      actualTier: incData.actualTier || 1,
      status: "ASSESSING_INTENT",
      details: incData.details || "Unauthorized elevation attempt detected. Remote access blocked pending SOC assessment."
    };

    incidents.unshift(incident);
    return incident;
  }

  function resolveIncident(incidentId, decision, reviewerSession) {
    const inc = incidents.find(i => i.id === incidentId);
    if (!inc) {
      return { success: false, message: "Incident not found" };
    }

    const reviewer = reviewerSession ? reviewerSession.user : "sec_soc01";
    inc.status = decision;
    inc.resolvedAt = getTimestamp();
    inc.resolvedBy = reviewer;

    if (decision === "CONFIRMED_MALICIOUS") {
      inc.decisionNotes = `Confirmed malicious intent by ${reviewer}. Account suspended and forensic evidence archived.`;
      
      // Auto-freeze operator account in Auth system with 24h retention
      if (VaultAccess.Auth && VaultAccess.Auth.freezeAccount) {
        VaultAccess.Auth.freezeAccount(
          inc.username,
          `Malicious privilege escalation on ${inc.resource} (Case: ${inc.id})`,
          24
        );
      }

      // Audit entry: identity, resource, timestamp
      logEvent({
        time: getTimestamp(),
        src: `SOC Command Gateway [${reviewer}]`,
        acct: `${inc.username} (${inc.operatorId})`,
        resource: inc.resource,
        action: `[INCIDENT RESOLUTION: MALICIOUS] Suspended operator account "${inc.username}" for unauthorized escalation on resource "${inc.resource}". Case ${inc.id} closed.`,
        result: "denied",
        resultCode: "CONFIRMED_MALICIOUS",
        severity: "danger"
      });
    } else {
      inc.decisionNotes = `Unconfirmed intent by ${reviewer}. Temporary elevation revoked and operator flagged for monitoring.`;

      logEvent({
        time: getTimestamp(),
        src: `SOC Command Gateway [${reviewer}]`,
        acct: `${inc.username} (${inc.operatorId})`,
        resource: inc.resource,
        action: `[INCIDENT RESOLUTION: UNCONFIRMED] Revoked elevated access and flagged operator "${inc.username}" on resource "${inc.resource}". Case ${inc.id} closed.`,
        result: "reviewed",
        resultCode: "UNCONFIRMED",
        severity: "warn"
      });
    }

    return { success: true, incident: inc };
  }

  function simulateEscalationAttempt(currentRole, forcedOutcome) {
    const isBranch = currentRole.connection === "Branch terminal" || currentRole.connection === "Help Desk terminal";
    const src = isBranch
      ? `${currentRole.terminalName || currentRole.connection}`
      : `${currentRole.terminalName || currentRole.connection + " VPN"}`;

    const session = VaultAccess.Auth ? VaultAccess.Auth.getSession() : null;
    const userKey = session ? session.user : currentRole.id;
    const randomAcct = (VaultAccess.Config && VaultAccess.Config.USERS && VaultAccess.Config.USERS[userKey])
      ? VaultAccess.Config.USERS[userKey].operatorId
      : `op_${Math.floor(100 + Math.random() * 900)}`;

    let outcome = forcedOutcome;
    if (!outcome) {
      if (currentRole.tier >= 4) outcome = 'grant';
      else if (currentRole.tier >= 2) outcome = 'adjusted';
      else outcome = 'blocked';
    }

    if (outcome === 'grant') {
      return logEvent({
        time: getTimestamp(),
        src: src,
        acct: randomAcct,
        resource: "Customer Profile Inquiry",
        action: `Standard operation within Tier ${currentRole.tier} scope (${currentRole.label})`,
        result: "granted",
        resultCode: "GRANTED",
        severity: "info"
      });
    } else if (outcome === 'adjusted') {
      return logEvent({
        time: getTimestamp(),
        src: src,
        acct: randomAcct,
        resource: "Branch Cash Limit Configuration",
        action: `Request exceeded assigned tier boundary — downgraded to read-only diagnostics under Tier ${currentRole.tier} policy`,
        result: "adjusted",
        resultCode: "ESCALATION_ADJUSTED",
        severity: "warn"
      });
    } else {
      const logRecord = logEvent({
        time: getTimestamp(),
        src: src,
        acct: randomAcct,
        resource: "Tier 4 SOC Security Policy Override",
        action: `Above-tier access blocked: ${currentRole.label} (Tier ${currentRole.tier}) attempted Tier 4 administrative authorization`,
        result: "denied",
        resultCode: "ESCALATION_BLOCKED",
        severity: "danger"
      });

      createIncident({
        operatorId: randomAcct,
        username: userKey,
        role: currentRole.label,
        terminal: src,
        resource: "Tier 4 SOC Security Policy Override",
        requestedTier: 4,
        actualTier: currentRole.tier,
        details: `Remote access blocked. Operator attempted unauthorized elevation to Tier 4.`
      });

      return logRecord;
    }
  }

  function getLogs() {
    return escalationLogs;
  }

  function getAlertCount() {
    return escalationLogs.length;
  }

  function getIncidents() {
    return incidents;
  }

  function getPendingIncidents() {
    return incidents.filter(i => i.status === "ASSESSING_INTENT");
  }

  // Initialize on module load
  init();

  return {
    init,
    logEvent,
    sha256,
    verifyLogIntegrity,
    tamperLogEntry,
    exportAuditLogs,
    simulateEscalationAttempt,
    createIncident,
    resolveIncident,
    getIncidents,
    getPendingIncidents,
    getLogs,
    getAlertCount,
    getTimestamp
  };
})();
