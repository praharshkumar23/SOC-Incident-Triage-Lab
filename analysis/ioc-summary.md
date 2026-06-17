# IOC Summary

**Ticket ID:** SOC-LAB-2026-001
**Analyst:** Praharsh
**Date:** 2026-06-04

---

## Indicators of Compromise

| IOC Type | Value | Context |
|---|---|---|
| Source IP | `185.203.118.44` | External IP used for all failed and successful logons |
| Account | `svc_admin_backup` | Privileged service account targeted and compromised |
| Host | `NBC-WIN-034` | Endpoint targeted in the attack |
| Process | `powershell.exe` | Used with `-EncodedCommand` and `-ExecutionPolicy Bypass` |
| Encoded Command | `SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=` | Suspicious base64-encoded PowerShell payload |
| Command | `whoami /groups` | Post-compromise user discovery |
| Command | `net user` | Local account enumeration |
| Command | `ipconfig /all` | Network reconnaissance |

---

## Analyst Note

The source IP `185.203.118.44` should be checked against threat intelligence feeds (AbuseIPDB, VirusTotal, OTX) to determine if it has a known malicious history.

The encoded PowerShell command decodes to IEX (New-Object) — a common pattern used to download and execute payloads in memory.
