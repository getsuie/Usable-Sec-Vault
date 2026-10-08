/**
 * ============================================================================
 * VaultAccess — Core Module: Role-Based Access Control (RBAC) Engine
 * ============================================================================
 * Enforces hierarchical Tiered Administration and the Principle of
 * Least Privilege (PoLP).
 *
 * Rules:
 * - A user at Tier N cannot access routes or assets assigned to Tier M where M > N.
 * - Even within the same tier or across horizontal roles, specific actions
 *   (e.g., Lifting Lockouts, Editing AD Roles) strictly require Tier 4 (Security Admin).
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.RBAC = (function () {
  /**
   * Checks whether the given user session satisfies the required tier.
   * @param {object} session - Active user session
   * @param {number} requiredTier - Minimum numeric tier required (1-4)
   * @returns {boolean}
   */
  function hasMinimumTier(session, requiredTier) {
    if (!session || !session.role) return false;
    const role = VaultAccess.Config.ROLES[session.role];
    if (!role) return false;
    return role.tier >= requiredTier;
  }

  /**
   * Validates whether a user role is permitted to navigate to a target role route.
   * VaultAccess enforces strict role binding: users may only access their assigned role workspace.
   * @param {string} userRoleId - Role ID of the logged in user
   * @param {string} targetRoleId - Route role requested
   * @returns {boolean}
   */
  function isRouteAuthorized(userRoleId, targetRoleId) {
    if (!userRoleId || !targetRoleId) return false;
    return userRoleId === targetRoleId;
  }

  /**
   * Evaluates permission for sensitive admin actions following the Lucid staff flow:
   * 1. Within tier -> Grant
   * 2. Outside tier but adjacent -> Downgrade and grant (ESCALATION_ADJUSTED)
   * 3. Above tier -> Block and open incident (ESCALATION_BLOCKED)
   *
   * @param {object} role - Current user role object
   * @param {string} actionType - Action key identifier
   * @returns {{ allowed: boolean, outcome: string, resultCode: string, reason: string, requiredTier: number, currentTier: number }}
   */
  function evaluateAction(role, actionType) {
    if (!role) {
      return { allowed: false, outcome: "BLOCKED", resultCode: "ESCALATION_BLOCKED", reason: "No active authenticated session." };
    }

    if (actionType === "DEPOSIT" || actionType === "WITHDRAWAL" || actionType === "TRANSFER") {
      // Separation of Duties: Security Admins (Tier 4) and IT Admins (Tier 3) are strictly prohibited from moving money.
      // Financial transactions are strictly reserved for branch personnel (Tier 1 & Tier 2).
      if (role.tier >= 3) {
        return {
          allowed: false,
          outcome: "BLOCKED",
          resultCode: "ESCALATION_BLOCKED",
          requiredTier: 1,
          currentTier: role.tier,
          reason: `Access Denied (Separation of Duties): ${role.label} (Tier ${role.tier}) cannot process financial transactions (${actionType}). Money movement is strictly segregated to Branch personnel.`
        };
      }
      return {
        allowed: true,
        outcome: "GRANT",
        resultCode: "GRANTED",
        requiredTier: 1,
        currentTier: role.tier,
        reason: `Authorized: ${role.label} permitted to initiate ${actionType}.`
      };
    }

    if (actionType === "VIEW_PII") {
      // IT Admin (Tier 3) is strictly barred from customer financial PII under SoD policy
      if (role.tier === 3 || role.id === 'itadmin') {
        return {
          allowed: false,
          outcome: "BLOCKED",
          resultCode: "ESCALATION_BLOCKED",
          requiredTier: 1,
          currentTier: role.tier,
          reason: "Access Denied (Separation of Duties): IT Administrators manage server health and system services. Customer PII and financial balances are strictly restricted from Tier 3."
        };
      }
      return {
        allowed: true,
        outcome: "GRANT",
        resultCode: "GRANTED",
        requiredTier: 1,
        currentTier: role.tier,
        reason: `Authorized: ${role.label} permitted to view customer record.`
      };
    }

    if (actionType === "LIFT_LOCKOUT") {
      const requiredTier = 4;
      if (role.tier === 4) {
        return {
          allowed: true,
          outcome: "GRANT",
          resultCode: "GRANTED",
          requiredTier,
          currentTier: role.tier,
          reason: "Granted: Security Admin (Tier 4) authorized to lift account lockouts after forensic review."
        };
      } else if (role.tier === 3 || role.tier === 2) {
        // Adjacent tier attempt: downgrade to verification assistance view
        return {
          allowed: true,
          adjusted: true,
          outcome: "ADJUSTED",
          resultCode: "ESCALATION_ADJUSTED",
          requiredTier,
          currentTier: role.tier,
          reason: `Adjusted: "${role.label}" (Tier ${role.tier}) cannot directly lift lockouts. Action downgraded to read-only diagnostics.`
        };
      } else {
        return {
          allowed: false,
          outcome: "BLOCKED",
          resultCode: "ESCALATION_BLOCKED",
          requiredTier,
          currentTier: role.tier,
          reason: `Blocked: "${role.label}" is Tier ${role.tier}. Lifting lockouts strictly requires Tier 4. Remote access blocked; incident opened.`
        };
      }
    }

    // Default policy: deny unknown action
    return {
      allowed: false,
      outcome: "BLOCKED",
      resultCode: "ESCALATION_BLOCKED",
      reason: "Action not recognized under current security policy."
    };
  }

  return {
    hasMinimumTier,
    isRouteAuthorized,
    evaluateAction
  };
})();
