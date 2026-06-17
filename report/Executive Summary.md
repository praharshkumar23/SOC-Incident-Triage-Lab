# Executive Summary

**Ticket ID:** SOC-LAB-2026-001
**Analyst:** Praharsh
**Date:** 2026-06-04
**Severity:** High
**Status:** Escalated

---

## What Happened

On 4 June 2026, a suspicious authentication pattern was detected on host `NBC-WIN-034`. An external IP address (`185.203.118.44`) made five failed logon attempts against the privileged service account `svc_admin_backup`. The attempts were followed by a successful remote login, after which the attacker executed encoded PowerShell and ran discovery commands.

---

## Business Risk

- A privileged account may have been compromised by an external attacker
- Encoded PowerShell was executed — this may have delivered a payload or enabled further access
- Reconnaissance activity suggests the attacker was mapping the environment
- Lateral movement and data access cannot be ruled out at this stage

---

## Key Actions Required

| Priority | Action |
|---|---|
| Immediate | Disable `svc_admin_backup` and block source IP `185.203.118.44` |
| Immediate | Isolate `NBC-WIN-034` for forensic review |
| Short term | Enforce MFA on all privileged and remote access accounts |
| Short term | Restrict RDP access to approved IPs or VPN only |
| Long term | Improve detection rules for brute force and encoded PowerShell |

---

## Analyst Recommendation

Escalate to Tier 2 SOC / Incident Response for endpoint investigation, containment confirmation, and a full environment review to check for lateral movement or persistence.
