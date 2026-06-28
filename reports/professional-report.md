&#x20;Security Baseline Compliance Assessment Report



\## Executive Summary



This assessment evaluated Windows and Linux systems against a practical security baseline to determine whether key host security controls were deployed, enabled, and operating as expected.



The purpose of this project was to demonstrate a security engineering workflow for validating controls, identifying configuration gaps, assigning risk-based priority, and producing remediation guidance.



The assessment found that several important controls were operating successfully, including host firewall protection, endpoint monitoring services, and account lockout policy. The scan also identified areas requiring review, including password policy configuration, remote access settings, privileged access membership, and Linux service hardening controls.



This type of baseline validation supports continuous security improvement, audit readiness, and operational hardening.



\---



\## Assessment Scope



The assessment included baseline checks for the following system types:



| System Type | Control Areas Reviewed |

|---|---|

| Windows Endpoint | Firewall, Microsoft Defender, Wazuh agent, Sysmon, Remote Desktop, local administrators, password policy, account lockout policy |

| Linux System | UFW firewall, SSH configuration, audit logging, fail2ban, automatic updates, Wazuh agent status, listening services |



The checks were performed using a custom Python-based compliance scanner that generated both CSV and Markdown reports.



\---



\## Methodology



The scanner collected host-level configuration evidence and assigned each control one of the following statuses:



| Status | Meaning |

|---|---|

| PASS | The control is configured as expected |

| FAIL | The control is missing or misconfigured |

| WARN | The control requires review or improvement |

| INFO | Evidence was collected for manual review |



Each result also included a `Risk If Failed` value. This value represents the impact if the control is missing or misconfigured.



For example, Windows Firewall may show `PASS` with `High` risk if failed. This means the firewall is enabled, but disabling it would create high risk.



\---



\## Windows Assessment Summary



The Windows system completed the baseline scan with the following result:



| Metric | Result |

|---|---|

| Compliance Score | 71.4% |

| Risk Rating | High |

| Report Type | Markdown and CSV |

| Evidence Captured | Yes |



\### Windows Control Results



| Control | Status | Risk If Failed | Assessment |

|---|---|---|---|

| Windows Firewall enabled on all profiles | PASS | High | Firewall protection was enabled across Windows profiles |

| Microsoft Defender service running | PASS | High | Endpoint protection service was active |

| Wazuh agent service running | PASS | High | Security monitoring agent was active |

| Sysmon service running | PASS | Medium | Endpoint telemetry collection was active |

| Remote Desktop disabled | WARN | Medium | Remote access configuration should be reviewed |

| Local administrators group reviewed | INFO | Medium | Administrative membership should be manually validated |

| Minimum password length is at least 8 | WARN | Medium | Password policy should be strengthened |

| Account lockout threshold configured | PASS | Medium | Brute-force protection control was configured |



\### Windows Key Observations



The Windows system had several strong baseline controls in place. Firewall protection, Microsoft Defender, Wazuh, and Sysmon were all running successfully. These controls provide important prevention, detection, and monitoring capabilities.



The main improvement areas were related to identity and access controls. Password length requirements should be reviewed and strengthened, and local administrator group membership should be validated to ensure unnecessary privileged access is removed.



Remote Desktop should also be reviewed. If RDP is not required, it should be disabled. If it is required, it should be restricted to trusted networks and monitored.



\---



\## Linux Assessment Summary



The Linux system was assessed against host hardening and monitoring controls commonly used in security baseline reviews.



\### Linux Control Areas Reviewed



| Control Area | Security Purpose |

|---|---|

| UFW firewall | Restricts unnecessary inbound network access |

| SSH root login | Reduces direct privileged login risk |

| SSH password authentication | Reduces credential-based remote access risk |

| auditd | Supports audit logging and forensic visibility |

| fail2ban | Helps reduce brute-force authentication attempts |

| Automatic updates | Supports patch management and vulnerability reduction |

| Wazuh agent | Provides endpoint monitoring and security telemetry |

| Listening services | Identifies exposed services requiring review |



\### Linux Key Observations



The Linux checks help validate whether the system is hardened and monitored. SSH configuration, firewall state, audit logging, and endpoint monitoring are especially important because they directly affect remote access risk and detection visibility.



Any failed or warning Linux controls should be prioritized based on exposure, system criticality, and whether the system is used as a server or endpoint.



\---



\## Risk Analysis



The assessment identified the following risk themes:



| Risk Theme | Description | Priority |

|---|---|---|

| Access control review | Local administrator membership and password policy require validation | High |

| Remote access exposure | Remote Desktop and SSH settings should be restricted where possible | Medium |

| Monitoring coverage | Wazuh and Sysmon should remain active for visibility | High |

| Linux hardening | Firewall, audit logging, and brute-force protection should be confirmed | Medium |

| Continuous validation | Systems should be rescanned after remediation | Medium |



\---



\## Recommended Remediation Plan



\### Priority 1: Strengthen Identity and Access Controls



Review the local administrators group and remove unnecessary privileged users.



Recommended Windows command:



