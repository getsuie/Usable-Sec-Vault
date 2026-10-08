# VaultAccess — Personnel Console (Project Presentation Overview)

This project showcases a **Tiered Privilege & Role-Based Access Control (RBAC)** security architecture designed to counter flat Active Directory vulnerabilities, parameter tampering, and insider threats.

For full presentation documents and architectural breakdown, refer to:
- **[README.md](file:///c:/Users/russe/Downloads/VaultAccess%20%E2%80%94%20Personnel%20Console/README.md)**: Main project documentation and setup.
- **[docs/SECURITY_ARCHITECTURE.md](file:///c:/Users/russe/Downloads/VaultAccess%20%E2%80%94%20Personnel%20Console/docs/SECURITY_ARCHITECTURE.md)**: Threat model, Active Directory tiering, and security principles.
- **[docs/PRESENTATION_GUIDE.md](file:///c:/Users/russe/Downloads/VaultAccess%20%E2%80%94%20Personnel%20Console/docs/PRESENTATION_GUIDE.md)**: Live demo script, slide walkthrough, and Q&A defense.

---

### Key Demo Accounts
- `teller` (`teller123`) — **Tier 1**: Branch Teller (Branch Terminal #14)
- `supervisor` (`super123`) — **Tier 2**: Branch Supervisor (Supervisor Station #01)
- `itadmin` (`itadmin123`) — **Tier 3**: IT Admin (Remote Admin VPN)
- `secadmin` (`secadmin123`) — **Tier 4**: Security Admin (SOC Command Gateway)

### Core Security Highlights
1. **Security Team Console Access:** **AD Privilege Tiers** and **Escalation Monitor** are restricted exclusively to the Security Team (`secadmin`).
2. **Teller Withdrawal Anomaly Lock (Attack Demo):** In the Teller Banking Workstation, the selected customer displays only the customer's name. The teller must manually enter the account number. If an account number that does not match the system is typed (e.g. `9999-0000`), the automated security engine immediately freezes the screen with `[ALERT] Account mismatch detected. Terminal locked.`
3. **Privilege Escalation Simulation:** A locked teller attempts to inject forged parameters (`isSecurityApproved: true` and `role: "Security_Admin"`) via DevTools/API manipulation.
4. **Zero-Trust Server Prevention:** The secure backend validates the real session token from the database, detects the Tier 1 operator, drops the forged flag, returns **403 Forbidden**, maintains the terminal lock, and alerts the SOC.
5. **Separation of Duties:** IT administrators have zero access to customer PII; only Tier 4 Security Admins can lift terminal fraud freezes.