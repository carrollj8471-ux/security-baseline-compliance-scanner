# Security Baseline Compliance Report - J-A-C

## Executive Summary

**Hostname:** J-A-C  
**Operating System:** Windows-11-10.0.26200-SP0  
**Scan Time:** 2026-06-27 19:19:17  
**Compliance Score:** 75.0%  
**Risk Rating:** Medium  

## Scoring Note

`Risk If Failed` represents the impact if the control is missing or misconfigured. A control can have a `PASS` status and still have a high `Risk If Failed` value because failure of that control would create significant risk.

Example: Windows Firewall may show `PASS` with `High` risk if failed. This means the firewall is enabled, but disabling it would create high risk.

## Control Results

| Check ID | Control | Status | Risk If Failed | Evidence | Recommendation |
|---|---|---|---|---|---|
| WIN-001 | Windows Firewall enabled on all profiles | PASS | High | All firewall profiles are enabled | No action required. |
| WIN-002 | Microsoft Defender service running | PASS | High | Running | No action required. |
| WIN-003 | Wazuh agent service running | PASS | High | Running | No action required. |
| WIN-004 | Sysmon service running | PASS | Medium | Running | No action required. |
| WIN-005 | Remote Desktop disabled | WARN | Medium | fDenyTSConnections = 0 | Disable RDP if not required or restrict access to trusted networks. |
| WIN-006 | Local administrators group reviewed | INFO | Medium | Alias name     administrators Comment        Administrators have complete and unrestricted access to the computer/domain  Members  ------------------------------------------------------------------------------- Administrator User The command completed successfully. | Review members and remove unnecessary local admin access. |
| WIN-007 | Minimum password length is at least 8 | WARN | Medium | Minimum password length: 0 | Set minimum password length to at least 8 or higher. |
| WIN-008 | Account lockout threshold configured | PASS | Medium | Lockout threshold: 10 | No action required. |

## Remediation Priorities

### High Priority

- Address failed controls with High or Critical risk first.
- Prioritize internet-facing systems and critical business assets.
- Validate remediation with a follow-up scan.

### Medium Priority

- Review warning controls and document accepted risk where appropriate.
- Confirm monitoring and logging agents are functioning.

### Low Priority

- Continue routine hardening and baseline validation.