# VaultAccess — Personnel Console & Banking Security Prototype

> A Tiered Privilege, Role-Based Access Control (RBAC), and Insider Threat Defence Demonstration.

[![Security: Tiered RBAC](https://img.shields.io/badge/Security-Tiered%20RBAC-blueviolet)]()
[![Principle: Least Privilege](https://img.shields.io/badge/Principle-Least%20Privilege-success)]()
[![Governance: Maker--Checker](https://img.shields.io/badge/Governance-Maker--Checker-informational)]()
[![Audit: SHA--256 Hash Chain](https://img.shields.io/badge/Audit-SHA--256%20Chain-orange)]()

---

## Project Overview

**VaultAccess** is an interactive banking security demonstration built to model enterprise defences against flat Active Directory (AD) networks, privilege escalation, and insider threats.

It features realistic banking workstations for five Active Directory tiers, an interactive **4-step privilege escalation attack and prevention workflow**, a cryptographic SHA-256 audit log with tamper detection, maker-checker four-eyes controls, staff authentication hardening with MFA and idle lock, and Just-in-Time (JIT) elevation for IT Admins.

---

## Personnel Tiers & Demo Credentials

| Role | Tier | Username | Password | MFA OTP | Assigned Context |
| :--- | :---: | :--- | :--- | :---: | :--- |
| **Branch Teller** | 1 | `teller` | `teller123` | — | Branch Terminal #14 (`teller_402`) |
| **Branch Supervisor** | 2 | `supervisor` | `super123` | — | Supervisor Station #01 (`supv_108`) |
| **Help Desk Operator** | 2-H | `helpdesk` | `helpdesk1` | — | Help Desk Station #04 (`hd_215`) |
| **IT Administrator** | 3 | `itadmin` | `itadmin123` | `841920` | Remote Admin VPN (`sys_it88`) |
| **Security Admin (SOC)** | 4 | `secadmin` | `secadmin123` | `841920` | SOC Command Gateway (`sec_soc01`) |

---

## Implemented Security Controls

| Phase | Control | Key Behaviour |
| :---: | :--- | :--- |
| 1 | **Help Desk Console** | 7 mock triage tickets; USA-04 human-readable security tags; 3-min SLA timer; identity re-verification modal; one-click SOC escalation |
| 2 | **Separation of Duties (G2)** | Tier 3/4 blocked from all money-movement actions (`DEPOSIT`, `WITHDRAWAL`, `TRANSFER`); 403 response + audit |
| 3 | **Graded Anomaly Response (G3)** | Strike 1 → warning; Strike 2+ → neutral teller lock ("Verification required…"); SOC gets full fraud detail; teller gets reference code only |
| 4 | **Maker-Checker Controls (G4)** | High-value overrides and terminal unlocks require two independent operators; self-approval blocked; justification ≥ 15 chars + incident ID required |
| 5 | **SHA-256 Audit Chain (SEC-03)** | Pure-JS SHA-256; every event is `Hash_N = SHA-256(prevHash + ":" + canonicalJSON)`; verify integrity button; tamper demo; Tier 4 JSON/CSV export |
| 6 | **Auth Hardening (G6)** | Exponential backoff (5s/10s/20s…); Step-up MFA for Tier 3/4; connection context binding; 5-min idle lock; 15-min break-glass; 24h account freeze |
| 7 | **JIT Elevation (G7)** | IT Admin read-only by default; `CHG-####` ticket required; countdown timer; maintenance buttons auto-disabled on expiry; no PII visible |
| 8 | **Role Workstations (G8)** | Each tier lands on its own workstation with role-specific tooling (ID checklist, override queue, JIT panel, audit export, cluster intelligence) |
| 9 | **Server-Side Defence** *(Optional)* | Phase 9 (real Node/Express server) is marked optional. Demo mode uses simulated 403 responses. |
| 10 | **Docs & Presentation** | TEST_CHECKLIST.md · REQUIREMENTS_TRACE.md · Updated PRESENTATION_GUIDE.md · Accessibility pass |

---

## The 4-Step Privilege Escalation Attack (Deposit Workflow)

```mermaid
sequenceDiagram
    autonumber
    actor Teller as Branch Teller (teller_402)
    participant UI as Terminal #14 UI
    participant Server as Zero-Trust Gateway
    participant SOC as SOC Escalation Monitor

    Teller->>UI: 1. Types mismatched destination account (9999-0000) during cash deposit
    UI->>UI: 2. Automated freeze — neutral message shown; reference code generated
    Teller->>UI: 3. Opens DevTools and injects isSecurityApproved:true + role:Security_Admin
    UI->>Server: Sends tampered POST payload
    Server->>Server: 4. Server checks DB session: teller_402 is Tier 1, drops forged flags
    Server-->>UI: Returns 403 Forbidden (terminal stays frozen)
    Server->>SOC: Dispatches Critical Insider Threat Alert with full forensic detail
```

---

## Code Organisation & Directory Structure

```
VaultAccess - Personnel Console/
├── index.html                              # Application entry point
├── VaultAccess - Personnel Console.html    # Named console entry point (kept in sync)
├── README.md                               # This file
│
├── css/
│   ├── base.css          # Design tokens, colour palette, typography, .sr-only
│   ├── layout.css        # Shell layout, sidebar navigation, address bar
│   ├── components.css    # Cards, badges, buttons, audit table, alert banner
│   ├── views.css         # Banking workstation, terminal freeze, hacker modal, tiers
│   └── styles.css        # Master stylesheet (imports all modules)
│
├── js/
│   ├── config/
│   │   ├── roles.js       # 4-tier AD model, operator IDs, ₱60,500 limits, demo credentials
│   │   └── mock-data.js   # Customer ledgers (PHP), override queue, IT nodes, help-desk tickets
│   ├── core/
│   │   ├── auth.js        # Hardened auth: backoff, MFA, context binding, idle lock, break-glass, freeze
│   │   ├── rbac.js        # RBAC engine: evaluateAction(), SoD blocking, tier validation
│   │   ├── audit.js       # SEC-03: pure-JS SHA-256, logEvent, verifyLogIntegrity, export
│   │   ├── banking.js     # Banking engine: limits, graded anomaly, maker-checker, SoD enforcement
│   │   └── router.js      # Hash-based routing, URL tamper detection, route guard
│   ├── ui/
│   │   ├── helpdesk.js    # Help Desk Console: tickets, SLA timer, re-verification, escalation
│   │   ├── audit-view.js  # SEC-03 audit table renderer, hash-chain controls, export buttons
│   │   ├── workstations.js # JIT elevation, teller checklist/drawer, AD editor, cluster intel
│   │   └── renderers.js   # All role workstation DOM renderers and event handlers
│   └── app.js             # Application orchestrator: event binding, login, idle polling
│
└── docs/
    ├── PRESENTATION_GUIDE.md      # 7-scenario live demo script and panel defence Q&A
    ├── SECURITY_ARCHITECTURE.md   # Threat model, STRIDE, privilege matrix, SEC-03 design
    ├── ARCHITECTURE_FLOWCHART.md  # Mermaid flowcharts: system, attack, SoD, hash chain, maker-checker
    ├── TEST_CHECKLIST.md          # Manual test table: role × action × expected result
    └── REQUIREMENTS_TRACE.md      # Maps SEC-02, SEC-03, USA-01, USA-04, G2–G8 to code & tests
```

---

## Getting Started

Double-click `index.html` (or `VaultAccess - Personnel Console.html`) in Windows Explorer to open directly in any modern browser — no server, no npm, no build step required.

### Demo Path (Quickest)

1. Open the file in Chrome or Edge.
2. Log in as `teller` / `teller123`.
3. Follow **Scenario B** in [`docs/PRESENTATION_GUIDE.md`](docs/PRESENTATION_GUIDE.md) for the full attack demo.
4. For all other scenarios, refer to the Presentation Guide.

---

## Accessibility

- All modal dialogs use `role="dialog"`, `aria-modal="true"`, and `aria-labelledby`.
- Status banners use `role="status"` / `aria-live="polite"`.
- The audit table uses `aria-label`.
- Screen-reader-only labels are provided for icon-only UI elements via `.sr-only`.
- Status is always communicated with text labels (OPEN / RESOLVED / ESCALATED), not colour alone.
- Full keyboard navigation: Tab, Shift-Tab, Enter, Space, and Escape (to dismiss modals).
