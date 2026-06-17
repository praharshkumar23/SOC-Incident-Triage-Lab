# SOC Incident Report

**Report Title:** Suspicious Privileged Account Activity — Possible Account Compromise
**Ticket ID:** SOC-LAB-2026-001
**Analyst:** Praharsh
**Date:** 2026-06-04
**Environment:** Home lab — simulated Windows Security event logs (Splunk)
**Severity:** High
**Status:** Escalated to Tier 2

---

## 1. Initial Assessment

Between 09:12 and 09:16 UTC, five failed logon attempts were observed against privileged account `svc_admin_backup` from external IP `185.203.118.44` targeting host `NBC-WIN-034`.

At 09:18 UTC, a successful RDP logon occurred using the same account, same source IP, and same host. Within 45 seconds, special privileges were assigned to the session (09:19 UTC).

At 09:21 UTC, `powershell.exe` was executed with an `EncodedCommand` parameter and `-ExecutionPolicy Bypass` flag. This was followed immediately by reconnaissance commands: `whoami /groups`, `net user`, and `ipconfig /all`.

The full sequence — brute force, privileged RDP access, encoded PowerShell, and discovery — is assessed as a High Severity incident requiring escalation.

---

## 2. Incident Overview

| Field | Value |
|---|---|
| Affected Host | NBC-WIN-034 |
| Affected Account | svc_admin_backup |
| Source IP | 185.203.118.44 |
| First Observed | 2026-06-04 09:12:03 UTC |
| Last Observed | 2026-06-04 09:42:00 UTC |
| Event IDs | 4625, 4624, 4672, 4688, 4634 |
| Severity | High |
| Escalation | Required — Tier 2 SOC / Incident Response |

---

## 3. Evidence Reviewed

| Event ID | Time | Description |
|---|---|---|
| 4625 ×5 | 09:12 – 09:16 | Failed logon attempts against `svc_admin_backup` |
| 4624 | 09:18 | Successful RDP logon from `185.203.118.44` |
| 4672 | 09:19 | Special privileges assigned to session |
| 4688 | 09:21 | Encoded PowerShell with `-ExecutionPolicy Bypass` |
| 4688 | 09:22 | `cmd.exe /c whoami /groups` |
| 4688 | 09:23 | `cmd.exe /c net user` |
| 4688 | 09:24 | `cmd.exe /c ipconfig /all` |
| 4634 | 09:42 | Logoff after suspicious session |

---

## 4. Key Findings

### Finding 1 — Brute Force Against Privileged Account
Five consecutive failed logon attempts were observed from the same external IP against `svc_admin_backup`. This is consistent with brute force or password spraying (MITRE T1110).

### Finding 2 — Successful RDP After Failures
A successful RDP logon occurred from the same source IP immediately after the failed attempts. This strongly suggests the attacker succeeded in guessing or obtaining the account password (MITRE T1078, T1021.001).

### Finding 3 — Special Privileges Assigned
Event ID 4672 confirmed special privileges were assigned to the session within 45 seconds of the successful logon. This elevates the severity because the account may have administrative or sensitive access rights.

### Finding 4 — Encoded PowerShell Execution
PowerShell was executed with:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=
```
Decoding the base64 string reveals `IEX (New-Object)` — a pattern commonly used to download and execute payloads in memory. This is a high-confidence indicator of malicious intent (MITRE T1059.001, T1027).

### Finding 5 — Post-Compromise Reconnaissance
Three discovery commands were executed after the successful logon:
- `whoami /groups` — identify group membership
- `net user` — enumerate local accounts
- `ipconfig /all` — map the network configuration

This pattern is consistent with an attacker gathering environment information after initial access (MITRE T1033, T1087, T1016).

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | 5 failed logons |
| Initial Access | Valid Accounts | T1078 | Successful logon |
| Lateral Movement | Remote Services: RDP | T1021.001 | Logon Type 10 |
| Privilege Escalation | Access Token Manipulation | T1134 | Event 4672 |
| Execution | PowerShell | T1059.001 | Encoded PowerShell |
| Defense Evasion | Obfuscated Files or Info | T1027 | Base64 command |
| Discovery | System Owner/User Discovery | T1033 | `whoami /groups` |
| Discovery | Account Discovery | T1087 | `net user` |
| Discovery | Network Config Discovery | T1016 | `ipconfig /all` |

---

## 6. Validation Steps

Before confirming this as a true incident, the following should be verified:

1. Confirm all events share the same account, IP, host, and timeline.
2. Verify whether `185.203.118.44` is a known or expected IP.
3. Confirm whether `svc_admin_backup` is permitted to log in via RDP.
4. Check whether the RDP session at 09:18 UTC was authorised.
5. Determine whether the encoded PowerShell can be explained as legitimate activity.
6. Search for the same source IP across other hosts in the environment.
7. Check for lateral movement, persistence, or additional process execution.

---

## 7. Containment Recommendations

### Immediate Actions

1. Reset or temporarily disable `svc_admin_backup`.
2. Revoke all active sessions for the affected account.
3. Isolate `NBC-WIN-034` from the network.
4. Block `185.203.118.44` at the firewall.
5. Preserve logs and evidence for Tier 2 investigation.

### Short-Term Improvements

1. Enforce MFA on all privileged accounts and remote access.
2. Restrict RDP to approved IP ranges or VPN only.
3. Disable interactive logon for service accounts.
4. Add SIEM detection rules for encoded PowerShell and brute force patterns.
5. Review privileged account usage and access rights.

---

## 8. Analyst Conclusion

The evidence shows a clear and deliberate attack sequence — brute force leading to successful privileged RDP access, followed by encoded PowerShell execution and post-compromise reconnaissance. This is not consistent with normal administrative behaviour.

This incident should be escalated to Tier 2 SOC / Incident Response for containment, endpoint forensics, and a wider environment review to determine whether the attacker moved laterally or established persistence.

**Escalation Decision:** Escalate — High Severity
**Tier 2 Action Required:** Endpoint forensics on NBC-WIN-034, block source IP, full environment review for lateral movement.
