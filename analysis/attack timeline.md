# Attack Timeline

**Ticket ID:** SOC-LAB-2026-001
**Analyst:** Praharsh
**Date:** 2026-06-04

---

## Timeline of Events

| Time (UTC) | Event ID | Account | Source IP | Host | Activity | Severity |
|---|---|---|---|---|---|---|
| 09:12:03 | 4625 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | Failed logon attempt 1 | Medium |
| 09:13:11 | 4625 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | Failed logon attempt 2 | Medium |
| 09:14:27 | 4625 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | Failed logon attempt 3 | Medium |
| 09:15:42 | 4625 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | Failed logon attempt 4 | Medium |
| 09:16:58 | 4625 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | Failed logon attempt 5 | Medium |
| 09:18:21 | 4624 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | Successful RDP logon (Logon Type 10) | **High** |
| 09:19:06 | 4672 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | Special privileges assigned to session | **High** |
| 09:21:44 | 4688 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | `powershell.exe -EncodedCommand` executed | **High** |
| 09:22:10 | 4688 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | `cmd.exe /c whoami /groups` | **High** |
| 09:23:18 | 4688 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | `cmd.exe /c net user` | **High** |
| 09:24:31 | 4688 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | `cmd.exe /c ipconfig /all` | Medium |
| 09:42:00 | 4634 | svc_admin_backup | 185.203.118.44 | NBC-WIN-034 | Logoff after suspicious session | Medium |

---

## Attack Flow

```text
Brute Force (4625 ×5)
→ Successful RDP Logon (4624)
→ Privilege Escalation (4672)
→ Encoded PowerShell Execution (4688)
→ Post-Compromise Reconnaissance (4688 ×3)
→ Session Logoff (4634)
```

---

## Analyst Note

The entire attack sequence occurred within 30 minutes. The speed and pattern of activity — especially moving from failed logons to privileged access to encoded PowerShell in under 10 minutes — is not consistent with normal administrative behaviour.
