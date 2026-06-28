# Security Baseline Compliance Report - Wahu-Server

## Executive Summary

**Hostname:** Wahu-Server  
**Operating System:** Linux-6.8.0-1059-azure-x86_64-with-glibc2.35  
**Scan Time:** 2026-06-27 20:21:39  
**Compliance Score:** 62.5%  
**Risk Rating:** High  

## Scoring Note

`Risk If Failed` represents the impact if the control is missing or misconfigured. A control can have a `PASS` status and still have a high `Risk If Failed` value because failure of that control would create significant risk.

Example: Windows Firewall may show `PASS` with `High` risk if failed. This means the firewall is enabled, but disabling it would create high risk.

## Control Results

| Check ID | Control | Status | Risk If Failed | Evidence | Recommendation |
|---|---|---|---|---|---|
| LIN-001 | UFW firewall enabled | PASS | High | ufw service is active | No action required. |
| LIN-002 | SSH root login disabled | FAIL | High | permitrootlogin without-password | Set PermitRootLogin no in SSH configuration and restart SSH. |
| LIN-003 | SSH password authentication disabled | WARN | Medium | passwordauthentication yes | Consider disabling SSH password authentication and using SSH keys. |
| LIN-004 | auditd service running | PASS | Medium | auditd is active | No action required. |
| LIN-005 | fail2ban service running | PASS | Medium | fail2ban is active | No action required. |
| LIN-006 | Automatic security updates package installed | PASS | Medium | unattended-upgrades package is installed | Confirm automatic update policy is configured. |
| LIN-007 | Wazuh agent running | WARN | High | wazuh-agent status: failed | Install, configure, or restart the Wazuh agent. |
| LIN-008 | Listening network services reviewed | INFO | Low | Netid State  Recv-Q Send-Q      Local Address:Port  Peer Address:PortProcess udp   UNCONN 0      0                 0.0.0.0:5353       0.0.0.0:*           udp   UNCONN 0      0                 0.0.0.0:42906      0.0.0.0:*           udp   UNCONN 0      0           127.0.0.53%lo:53         0.0.0.0:*           udp   UNCONN 0      0                    [::]:5353          [::]:*           udp   UNCONN 0      0                    [::]:38944         [::]:*           tcp   LISTEN 0      2048              0.0.0.0:55000      0.0.0.0:*           tcp   LISTEN 0      128               0.0.0.0:1514       0.0.0.0:*           tcp   LISTEN 0      128               0.0.0.0:1515       0.0.0.0:*           tcp   LISTEN 0      511               0.0.0.0:443        0.0.0.0:*           tcp   LISTEN 0      128               0.0.0.0:22         0.0.0.0:*           tcp   LISTEN 0      128             127.0.0.1:631        0.0.0.0:*           tcp   LISTEN 0      4096        127.0.0.53%lo:53         0.0.0.0:*           tcp   LISTEN 0      2048                 [::]:55000         [::]:*           tcp   LISTEN 0      128                 [::1]:631           [::]:*           tcp   LISTEN 0      128                  [::]:22            [::]:*           tcp   LISTEN 0      4096   [::ffff:127.0.0.1]:9300             *:*           tcp   LISTEN 0      2                   [::1]:3350          [::]:*           tcp   LISTEN 0      4096   [::ffff:127.0.0.1]:9200             *:* | Review listening services and disable anything unnecessary. |

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