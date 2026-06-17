# MITRE ATT&CK Mapping

**Ticket ID:** SOC-LAB-2026-001
**Analyst:** Praharsh
**Date:** 2026-06-04

---

## Summary

The simulated attack maps to 9 MITRE ATT&CK techniques across 5 tactics — from initial credential access through to post-compromise discovery.

---

## Technique Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | 5 failed logons (Event 4625) against `svc_admin_backup` |
| Initial Access | Valid Accounts | T1078 | Successful logon using compromised privileged account |
| Lateral Movement | Remote Services: RDP | T1021.001 | Logon Type 10 — RDP session from external IP |
| Execution | PowerShell | T1059.001 | `powershell.exe -EncodedCommand` executed after logon |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64-encoded PowerShell command used to hide payload |
| Privilege Escalation | Access Token Manipulation | T1134 | Special privileges assigned (Event 4672) |
| Discovery | System Owner/User Discovery | T1033 | `whoami /groups` command |
| Discovery | Account Discovery | T1087 | `net user` command |
| Discovery | Network Configuration Discovery | T1016 | `ipconfig /all` command |

---

## Attack Chain

```text
T1110 (Brute Force)
→ T1078 (Valid Accounts — successful login)
→ T1021.001 (RDP — remote session established)
→ T1134 (Token/Privilege — special privileges assigned)
→ T1059.001 (PowerShell — encoded execution)
→ T1027 (Obfuscation — encoded command)
→ T1033 + T1087 + T1016 (Discovery — whoami, net user, ipconfig)
```

---

## Analyst Notes

The most significant indicator is the transition from failed logons (T1110) directly to a successful privileged RDP logon (T1078 + T1021.001), followed by encoded PowerShell execution within 3 minutes.

This speed and sequence is not consistent with authorised administrative activity. The encoded PowerShell (`IEX (New-Object)` pattern) is commonly used to download and run payloads in memory, suggesting the attacker may have attempted to establish persistence or download additional tools.
