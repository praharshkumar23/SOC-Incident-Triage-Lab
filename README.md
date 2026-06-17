# SOC Incident Triage Lab — Privileged Account Compromise Investigation

**Author:** Praharsh
**Lab Environment:** Splunk Enterprise (home lab) + simulated Windows Security logs
**Skill Focus:** Alert triage · Windows Event Log analysis · SPL detection queries · MITRE ATT&CK mapping · Incident escalation
**Ticket ID:** SOC-LAB-2026-001
**Status:** Escalated to Tier 2

---

## What I Did

I built a simulated privileged account compromise scenario in my home lab and investigated it the way a SOC L1 analyst would — from the first alert all the way to escalation.

The scenario starts with brute-force attempts against a service account (`svc_admin_backup`), followed by a successful RDP login from a suspicious external IP, encoded PowerShell execution, and post-authentication reconnaissance commands.

I wrote Splunk SPL queries to detect each phase, built an attack timeline, identified indicators of compromise (IOCs), mapped the full attack chain to MITRE ATT&CK, and documented everything as a formal SOC incident report.

---

## Skills Demonstrated

| Skill Area | Evidence in This Project |
|---|---|
| Alert triage | Ticket triage notes, severity decision, escalation reasoning |
| Windows log analysis | Event IDs 4624, 4625, 4672, 4688, 4634 |
| Incident investigation | Attack timeline, IOC summary, evidence correlation |
| Detection engineering | SPL queries for each attack phase |
| Threat mapping | Full MITRE ATT&CK technique mapping |
| SOC reporting | Incident report + executive summary |

---

## Key Windows Event IDs

| Event ID | Meaning | Why It Matters |
|---|---|---|
| 4625 | Failed logon | Detects brute force or password spraying |
| 4624 | Successful logon | Confirms account access |
| 4672 | Special privileges assigned | Flags privileged account activity |
| 4688 | New process created | Detects suspicious command execution |
| 4634 | Account logoff | Completes the session timeline |

---

## Attack Timeline Summary

| Time (UTC) | Event ID | Activity | Severity |
|---|---|---|---|
| 09:12 – 09:16 | 4625 ×5 | 5 failed RDP logons on `svc_admin_backup` | Medium |
| 09:18 | 4624 | Successful RDP logon from same source IP | High |
| 09:19 | 4672 | Special privileges assigned after logon | High |
| 09:21 | 4688 | Encoded PowerShell executed | High |
| 09:22 – 09:24 | 4688 ×3 | `whoami /groups`, `net user`, `ipconfig /all` | High |
| 09:42 | 4634 | Logoff after suspicious session | Medium |

**Source IP:** `185.203.118.44` | **Host:** `NBC-WIN-034` | **Account:** `svc_admin_backup`

---

## Repository Structure

```text
SOC-Incident-Triage-Lab/
├── README.md
├── logs/
│   └── simulated-security-events.csv
├── analysis/
│   ├── ticket-triage-notes.md
│   ├── attack-timeline.md
│   ├── ioc-summary.md
│   └── risk-assessment.md
├── queries/
│   ├── splunk-detection-queries.spl
│   └── kql-queries.kql
├── mapping/
│   └── mitre-attack-mapping.md
├── reports/
│   ├── soc-incident-report.md
│   └── executive-summary.md
└── screenshots/
    └── add-screenshots-here.txt
```

---

## Investigation Workflow

```text
Alert received
→ Ticket triage
→ Evidence review
→ Attack timeline built
→ IOCs identified
→ MITRE ATT&CK mapped
→ SPL detection queries written
→ Risk assessed
→ Incident report written
→ Escalation recommended
```

---

## Key Findings

- 5 failed logon attempts against a privileged service account from an external IP
- Successful RDP logon from the same suspicious source IP immediately after
- Special privileges assigned to the account within 45 seconds of logon
- Encoded PowerShell executed with `-ExecutionPolicy Bypass` flag
- Discovery commands: `whoami /groups`, `net user`, `ipconfig /all`
- Full sequence consistent with post-compromise reconnaissance

---

## Detection Queries

SPL and KQL queries are in the `queries/` folder. They cover:

- Failed logon burst detection
- Successful RDP logon after failures
- Privileged account logon detection
- Encoded PowerShell execution
- Reconnaissance command patterns
- Full timeline reconstruction

---

## Disclaimer

This is a simulated lab project created for learning and portfolio purposes.
No real organisation, user, IP address, or incident is represented.
