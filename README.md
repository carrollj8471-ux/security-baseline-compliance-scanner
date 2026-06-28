\# Security Baseline Compliance Scanner



\## Overview



This project demonstrates a Python-based security baseline compliance scanner for Windows and Linux systems.



The scanner validates common security controls, calculates a compliance score, assigns risk ratings, and generates CSV and Markdown reports with remediation guidance.



\## Tools Used



\- Python

\- PowerShell

\- Linux systemctl

\- Windows security services

\- CSV reporting

\- Markdown reporting



\## Skills Demonstrated



\- Security control validation

\- Linux hardening checks

\- Windows security checks

\- Compliance-style reporting

\- Risk scoring

\- Remediation planning

\- Security automation

\- Technical documentation



\## Controls Checked



\### Windows



\- Windows Firewall status

\- Microsoft Defender service status

\- Wazuh agent service status

\- Sysmon service status

\- Remote Desktop status

\- Local administrators group

\- Password policy

\- Account lockout policy



\### Linux



\- UFW firewall status

\- SSH root login setting

\- SSH password authentication setting

\- auditd service status

\- fail2ban service status

\- Automatic security update package

\- Wazuh agent status

\- Listening network services



\## Project Workflow



1\. Run the scanner on a Windows or Linux system.

2\. Collect security control evidence.

3\. Assign pass, fail, warning, or informational status.

4\. Calculate a compliance score.

5\. Generate CSV and Markdown reports.

6\. Review remediation guidance.

7\. Validate improvements with a follow-up scan.



\## Screenshots



\### Windows Scan Output



!\[Windows Scan Output](screenshots/01-windows-scan-output.png)



\### Windows Compliance Report



!\[Windows Compliance Report](screenshots/02-windows-compliance-report.png)



\### Linux Scan Output



!\[Linux Scan Output](screenshots/03-linux-scan-output.png)



\### Linux Compliance Report



!\[Linux Compliance Report](screenshots/04-linux-compliance-report.png)



\## Scoring Note



The `Risk If Failed` field represents the impact if a control is missing or misconfigured.



A control can have a `PASS` status and still show a high `Risk If Failed` value because failure of that control would create significant risk.



For example, Windows Firewall may show `PASS` with `High` risk if failed. This means the firewall is enabled, but disabling it would create high risk.



\## Security Takeaway



Security engineering requires validating that controls are deployed and operating as expected. This project demonstrates how baseline checks can be automated to support hardening, audit readiness, and continuous security improvement.

