# Risk Assessment

**Ticket ID:** SOC-LAB-2026-001
**Analyst:** Praharsh
**Date:** 2026-06-04

---

## Risk Rating

| Factor | Assessment |
|---|---|
| Account type | Privileged service account |
| Access gained | Successful RDP with special privileges |
| Commands executed | Encoded PowerShell + reconnaissance |
| Scope | Single host confirmed — lateral movement not confirmed but possible |
| Data exposure | Unknown at this stage |
| Overall risk | **High** |

---

## Risk Summary

A privileged service account was accessed from an external IP after multiple failed logon attempts. The attacker executed encoded PowerShell and ran discovery commands, suggesting post-compromise activity.

The risk is assessed as High because:
- A privileged account was compromised
- Encoded PowerShell indicates possible further payload delivery
- Reconnaissance suggests the attacker was gathering environment information
- Lateral movement cannot be ruled out at this stage

---

## Recommended Risk Reduction Actions

1. Disable or restrict `svc_admin_backup` immediately
2. Block `185.203.118.44` at the firewall
3. Isolate `NBC-WIN-034` for forensic review
4. Enforce MFA on all privileged accounts
5. Restrict RDP access to approved IPs only
6. Disable interactive logon for service accounts
7. Add SIEM detection rules for encoded PowerShell and brute force patterns
