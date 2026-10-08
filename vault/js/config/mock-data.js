/**
 * ============================================================================
 * VaultAccess — Mock Data: Banking Ledgers, Profiles & Security Telemetry
 * ============================================================================
 * Contains realistic banking data: customer accounts, balance ledgers (PHP),
 * supervisor override queues, and IT server infrastructure nodes.
 */

window.VaultAccess = window.VaultAccess || {};
VaultAccess.Config = VaultAccess.Config || {};

// Customer Banking Records & Balance Ledgers
VaultAccess.Config.BANK_ACCOUNTS = {
  "1001-4471": {
    acctNumber: "1001-4471",
    name: "J. Reyes",
    accountType: "Savings Plus",
    balance: 145200.00,
    status: "Protected Mode",
    branch: "Makati Central",
    tags: ["New Device Location", "Failed Step-Up Code"],
    note: "Login from an unrecognized device failed OTP twice. No lockout yet — one more failed attempt routes to identity challenge.",
    action: "Offer staff-assisted verification or advise customer to check registered mobile.",
    recentTransactions: [
      { date: "2026-10-05", desc: "Payroll Direct Deposit", amount: 48500.00, type: "CR" },
      { date: "2026-10-04", desc: "ATM Withdrawal - BGC", amount: -5000.00, type: "DR" }
    ]
  },
  "1002-9902": {
    acctNumber: "1002-9902",
    name: "M. Cruz",
    accountType: "Checking Premier",
    balance: 520000.00,
    status: "Account Locked",
    branch: "Quezon City Main",
    tags: ["Failed Final Identity Challenge", "Fraud Review Flagged"],
    note: "Final identity challenge expired. Password sign-in disabled; account frozen pending SOC clearance.",
    action: "Verify customer in person with government ID and biometric scan, then lift lockout (Tier 4 required).",
    recentTransactions: [
      { date: "2026-10-03", desc: "Overseas Wire Transfer Attempt", amount: -210000.00, type: "DR" }
    ]
  },
  "1003-8821": {
    acctNumber: "1003-8821",
    name: "E. Villanueva",
    accountType: "High-Yield Savings",
    balance: 184350.00,
    status: "Active / Verified",
    branch: "BGC High Street",
    tags: ["Verified Tier-1", "Standard Security"],
    note: "Account in good standing. Standard verification completed.",
    action: "Standard servicing.",
    recentTransactions: [
      { date: "2026-10-06", desc: "Over-the-Counter Deposit", amount: 12000.00, type: "CR" }
    ]
  },
  "1004-1109": {
    acctNumber: "1004-1109",
    name: "S. Mendoza",
    accountType: "Personal Checking",
    balance: 32100.00,
    status: "Active / Verified",
    branch: "Ortigas Center",
    tags: ["Verified Tier-1", "Standard Security"],
    note: "Account in good standing.",
    action: "Standard servicing.",
    recentTransactions: [
      { date: "2026-10-01", desc: "Utility Bill Payment", amount: -4250.00, type: "DR" }
    ]
  }
};

// Map legacy search keys to primary accounts
VaultAccess.Config.ACCOUNTS = {
  "j. reyes": VaultAccess.Config.BANK_ACCOUNTS["1001-4471"],
  "m. cruz": VaultAccess.Config.BANK_ACCOUNTS["1002-9902"],
  "e. villanueva": VaultAccess.Config.BANK_ACCOUNTS["1003-8821"],
  "s. mendoza": VaultAccess.Config.BANK_ACCOUNTS["1004-1109"]
};

// Initial Pending Supervisor Overrides Queue (Tier 2 approvals) — starts empty; created by teller actions
VaultAccess.Config.INITIAL_SUPERVISOR_OVERRIDES = [];

// Maker-Checker Approvals Audit Registry (G4) — starts empty; populated during session
VaultAccess.Config.INITIAL_APPROVALS = [];

// IT Admin Infrastructure Node Health (Tier 3)
VaultAccess.Config.IT_INFRASTRUCTURE_NODES = [
  { id: "NODE-CORE-DB01", name: "Core Banking Oracle Cluster", ip: "10.240.1.12", status: "HEALTHY", cpu: "28%", latency: "1.2ms" },
  { id: "NODE-ATM-GW02", name: "National ATM Switch Gateway", ip: "10.240.2.45", status: "HEALTHY", cpu: "42%", latency: "4.8ms" },
  { id: "NODE-TERM-MGR01", name: "Branch Terminal Authorization Hub", ip: "10.240.3.10", status: "HEALTHY", cpu: "19%", latency: "0.9ms" },
  { id: "NODE-HSM-CRYPTO1", name: "Hardware Security Module (HSM)", ip: "10.240.4.99", status: "SECURE", cpu: "14%", latency: "0.4ms" }
];

// Security Telemetry & Audit Seed Logs — starts empty; events are recorded live during the session
VaultAccess.Config.INITIAL_LOGS = [];

// Help Desk Inbound Queue — starts empty; tickets arrive via real actions during testing
VaultAccess.Config.MOCK_HELP_DESK_TICKETS = [];

