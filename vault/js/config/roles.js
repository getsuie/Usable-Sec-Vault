/**
 * ============================================================================
 * VaultAccess — Security Configuration: Roles & Privilege Tiers
 * ============================================================================
 * Defines the Active Directory (AD) Role-Based Access Control (RBAC) hierarchy
 * with realistic banking operational scopes and privilege limits.
 *
 * Tier Hierarchy:
 * - Tier 1: Branch Teller        (Operator teller_402 / Terminal #14 - Max withdrawal PHP 60,500)
 * - Tier 2: Branch Supervisor    (Supervisor Terminal - Overrides > PHP 60,500, customer recovery)
 * - Tier 3: IT Administrator     (Remote Admin VPN - Server infra, Zero customer PII access)
 * - Tier 4: Security Admin       (Remote Admin VPN - SOC incident triage, terminal unlock, fraud)
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.Config = VaultAccess.Config || {};

// Role Definitions & Context-Aware Connection Binding
VaultAccess.Config.ROLES = {
  teller: {
    id: "teller",
    operatorId: "teller_402",
    terminalId: "TERM-BR14",
    label: "Branch Teller",
    tier: 1,
    connection: "Branch terminal",
    terminalName: "Branch Terminal #14",
    maxWithdrawalLimit: 60500, // PHP 60,500
    description: "Front-line teller duties: customer profile search, deposits, and low-value withdrawals up to ₱60,500."
  },
  supervisor: {
    id: "supervisor",
    operatorId: "supv_108",
    terminalId: "TERM-BR-SUPV1",
    label: "Branch Supervisor",
    tier: 2,
    connection: "Branch terminal",
    terminalName: "Supervisor Station #01",
    maxWithdrawalLimit: 500000,
    description: "Branch approvals: override high-value withdrawals (>₱60,500), approve identity exceptions."
  },
  helpdesk: {
    id: "helpdesk",
    operatorId: "hd_215",
    terminalId: "TERM-HD04",
    label: "Tier 2 — Help Desk",
    tier: 2,
    tierSub: "2-H",
    connection: "Help Desk terminal",
    terminalName: "Help Desk Station #04",
    maxWithdrawalLimit: 0,
    description: "Customer verification triage, lockout diagnostics, and step-up assistance. No financial transactions."
  },
  itadmin: {
    id: "itadmin",
    operatorId: "sys_it88",
    terminalId: "VPN-CORP-ADMIN3",
    label: "IT Admin (Remote)",
    tier: 3,
    connection: "Remote admin",
    terminalName: "Remote Admin VPN [Encrypted]",
    maxWithdrawalLimit: 0,
    description: "Infrastructure maintenance: ATM nodes, database connectivity. ZERO access to customer PII."
  },
  secadmin: {
    id: "secadmin",
    operatorId: "sec_soc01",
    terminalId: "VPN-SOC-GATEWAY",
    label: "Security Admin",
    tier: 4,
    connection: "Remote admin",
    terminalName: "SOC Command Gateway [Encrypted]",
    maxWithdrawalLimit: 0,
    description: "Highest authority: Insider threat analysis, fraud investigation, and terminal lockout lifts."
  }
};

// Personnel User Credentials & Identity Profiles
VaultAccess.Config.USERS = {
  // Primary staff name accounts
  "a.santos": {
    user: "a.santos",
    pass: "santos123",
    role: "teller",
    name: "A. Santos",
    operatorId: "teller_402",
    terminal: "Branch Terminal #14"
  },
  "r.dizon": {
    user: "r.dizon",
    pass: "dizon123",
    role: "supervisor",
    name: "R. Dizon",
    operatorId: "supv_108",
    terminal: "Supervisor Station #01"
  },
  "m.torres": {
    user: "m.torres",
    pass: "torres123",
    role: "helpdesk",
    name: "M. Torres",
    operatorId: "hd_215",
    terminal: "Help Desk Station #04"
  },
  "k.lim": {
    user: "k.lim",
    pass: "lim123",
    role: "itadmin",
    name: "K. Lim",
    operatorId: "sys_it88",
    terminal: "Remote Admin VPN"
  },
  "l.garcia": {
    user: "l.garcia",
    pass: "garcia123",
    role: "secadmin",
    name: "L. Garcia",
    operatorId: "sec_soc01",
    terminal: "SOC Command Gateway"
  },

  // Aliases for compatibility
  teller: {
    user: "a.santos",
    pass: "santos123",
    role: "teller",
    name: "A. Santos",
    operatorId: "teller_402",
    terminal: "Branch Terminal #14"
  },
  supervisor: {
    user: "r.dizon",
    pass: "dizon123",
    role: "supervisor",
    name: "R. Dizon",
    operatorId: "supv_108",
    terminal: "Supervisor Station #01"
  },
  helpdesk: {
    user: "m.torres",
    pass: "torres123",
    role: "helpdesk",
    name: "M. Torres",
    operatorId: "hd_215",
    terminal: "Help Desk Station #04"
  },
  itadmin: {
    user: "k.lim",
    pass: "lim123",
    role: "itadmin",
    name: "K. Lim",
    operatorId: "sys_it88",
    terminal: "Remote Admin VPN"
  },
  secadmin: {
    user: "l.garcia",
    pass: "garcia123",
    role: "secadmin",
    name: "L. Garcia",
    operatorId: "sec_soc01",
    terminal: "SOC Command Gateway"
  }
};

// Privilege Matrix by Tier
VaultAccess.Config.TIER_DATA = [
  {
    name: "Branch Teller (Tier 1)",
    min: 1,
    desc: "Front-line banking operations on physical branch terminal #14.",
    perms: "Read-only balance inquiries · Search customer profiles · Deposits · Low-value withdrawals (up to ₱60,500) · No overrides"
  },
  {
    name: "Branch Supervisor (Tier 2)",
    min: 2,
    desc: "Branch exception desk and high-value override station.",
    perms: "Approve withdrawals > ₱60,500 · Staff-assisted recovery · Customer identity review · Cannot edit AD policies or server configs"
  },
  {
    name: "Help Desk Specialist (Tier 2-H)",
    min: 2,
    desc: "Customer lockout triage, security context diagnostics, and identity re-verification.",
    perms: "Customer lockout diagnostics · USA-04 security tags review · Identity re-verification · One-click SOC escalation · Zero money movement"
  },
  {
    name: "IT Admin (Tier 3)",
    min: 3,
    desc: "Remote administrative VPN for infrastructure and core banking server maintenance.",
    perms: "Database connectivity & ATM network diagnostics · Zero Customer PII access · Cannot clear fraud flags or unlock terminals"
  },
  {
    name: "Security Admin (Tier 4)",
    min: 4,
    desc: "SOC administrative console — fraud investigations & insider threat containment.",
    perms: "Review forensic escalation log · Read-only customer ledger (forensic scope only) · Zero money movement (no deposits/withdrawals/transfers) · Lift terminal freeze/lockouts · Freeze/unfreeze accounts · Edit AD tier policy"
  }
];
