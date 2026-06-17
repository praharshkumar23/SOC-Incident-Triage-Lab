# Ticket Triage Notes

**Ticket ID:** SOC-LAB-2026-001
**Analyst:** Praharsh
**Date:** 2026-06-04
**Detection Source:** Windows Security Event Logs (Splunk)
**Time Window:** 09:12 – 09:42 UTC
**Severity:** High
**Status:** Escalated

---

## Alert Summary

The SIEM triggered an alert for multiple failed logon attempts against a privileged service account (`svc_admin_backup`), followed by a successful RDP logon from the same external IP address.

---

## Initial Triage Questions

| Question | Answer |
|---|---|
| Is the source IP internal or external? | External — `185.203.118.44` |
| Is the account a standard user or privileged? | Privileged service account |
| Did the failed logons lead to a successful logon? | Yes — same IP, same account, same host |
| Was special privilege assigned? | Yes — Event ID 4672 at 09:19 UTC |
| Was suspicious code executed? | Yes — encoded PowerShell at 09:21 UTC |
| Were any discovery commands run? | Yes — `whoami`, `net user`, `ipconfig` |
| Is the activity expected or authorised? | No indication of authorised activity |

---

## Triage Decision

**Severity:** High
**Escalate:** Yes — to Tier 2 SOC / Incident Response
**Reason:** The sequence of brute force → successful privileged logon → encoded PowerShell → recon commands is consistent with a real compromise attempt. This cannot be dismissed as a false positive without further investigation.

---

## Immediate Actions Taken

1. Flagged ticket as High severity
2. Documented evidence from event log data
3. Built attack timeline
4. Identified IOCs
5. Mapped to MITRE ATT&CK
6. Written incident report
7. Recommended containment and escalation actions
