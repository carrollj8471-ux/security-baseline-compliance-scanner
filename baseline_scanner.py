import csv
import platform
import re
import socket
import subprocess
from datetime import datetime
from pathlib import Path


REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


def run_command(command, shell=True):
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as error:
        return 1, "", str(error)


def run_powershell(command):
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            shell=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as error:
        return 1, "", str(error)


def clean_markdown(value):
    if value is None:
        return ""

    return (
        str(value)
        .replace("|", "-")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def add_result(
    results,
    check_id,
    control,
    status,
    risk_if_failed,
    evidence,
    recommendation,
):
    results.append(
        {
            "check_id": check_id,
            "control": control,
            "status": status,
            "risk_if_failed": risk_if_failed,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def status_points(status):
    if status in ["PASS", "INFO"]:
        return 1
    return 0


def calculate_score(results):
    scorable = [r for r in results if r["status"] in ["PASS", "FAIL", "WARN", "INFO"]]

    if not scorable:
        return 0

    passed = sum(status_points(r["status"]) for r in scorable)
    return round((passed / len(scorable)) * 100, 1)


def risk_rating(score):
    if score >= 90:
        return "Low"
    if score >= 75:
        return "Medium"
    if score >= 60:
        return "High"
    return "Critical"


def write_csv_report(results, hostname):
    output_file = REPORTS_DIR / f"{hostname}-compliance-report.csv"

    with output_file.open("w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "check_id",
            "control",
            "status",
            "risk_if_failed",
            "evidence",
            "recommendation",
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    return output_file


def write_markdown_report(results, hostname, os_name, score):
    output_file = REPORTS_DIR / f"{hostname}-compliance-report.md"
    rating = risk_rating(score)

    lines = [
        f"# Security Baseline Compliance Report - {hostname}",
        "",
        "## Executive Summary",
        "",
        f"**Hostname:** {hostname}  ",
        f"**Operating System:** {os_name}  ",
        f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Compliance Score:** {score}%  ",
        f"**Risk Rating:** {rating}  ",
        "",
        "## Scoring Note",
        "",
        "`Risk If Failed` represents the impact if the control is missing or misconfigured. "
        "A control can have a `PASS` status and still have a high `Risk If Failed` value because failure of that control would create significant risk.",
        "",
        "Example: Windows Firewall may show `PASS` with `High` risk if failed. This means the firewall is enabled, but disabling it would create high risk.",
        "",
        "## Control Results",
        "",
        "| Check ID | Control | Status | Risk If Failed | Evidence | Recommendation |",
        "|---|---|---|---|---|---|",
    ]

    for result in results:
        lines.append(
            f"| {clean_markdown(result['check_id'])} "
            f"| {clean_markdown(result['control'])} "
            f"| {clean_markdown(result['status'])} "
            f"| {clean_markdown(result['risk_if_failed'])} "
            f"| {clean_markdown(result['evidence'])} "
            f"| {clean_markdown(result['recommendation'])} |"
        )

    lines.extend(
        [
            "",
            "## Remediation Priorities",
            "",
            "### High Priority",
            "",
            "- Address failed controls with High or Critical risk first.",
            "- Prioritize internet-facing systems and critical business assets.",
            "- Validate remediation with a follow-up scan.",
            "",
            "### Medium Priority",
            "",
            "- Review warning controls and document accepted risk where appropriate.",
            "- Confirm monitoring and logging agents are functioning.",
            "",
            "### Low Priority",
            "",
            "- Continue routine hardening and baseline validation.",
        ]
    )

    output_file.write_text("\n".join(lines), encoding="utf-8")
    return output_file


def check_linux(results):
    code, stdout, stderr = run_command("systemctl is-active ufw")

    if stdout.strip() == "active":
        add_result(
            results,
            "LIN-001",
            "UFW firewall enabled",
            "PASS",
            "High",
            "ufw service is active",
            "No action required.",
        )
    else:
        add_result(
            results,
            "LIN-001",
            "UFW firewall enabled",
            "FAIL",
            "High",
            f"ufw service status: {stdout or stderr}",
            "Enable UFW and allow only required services.",
        )

    code, stdout, stderr = run_command("sshd -T 2>/dev/null | grep '^permitrootlogin'")

    if "permitrootlogin no" in stdout.lower():
        add_result(
            results,
            "LIN-002",
            "SSH root login disabled",
            "PASS",
            "High",
            stdout,
            "No action required.",
        )
    else:
        add_result(
            results,
            "LIN-002",
            "SSH root login disabled",
            "FAIL",
            "High",
            stdout or "Could not confirm PermitRootLogin is disabled",
            "Set PermitRootLogin no in SSH configuration and restart SSH.",
        )

    code, stdout, stderr = run_command(
        "sshd -T 2>/dev/null | grep '^passwordauthentication'"
    )

    if "passwordauthentication no" in stdout.lower():
        add_result(
            results,
            "LIN-003",
            "SSH password authentication disabled",
            "PASS",
            "Medium",
            stdout,
            "No action required.",
        )
    elif "passwordauthentication yes" in stdout.lower():
        add_result(
            results,
            "LIN-003",
            "SSH password authentication disabled",
            "WARN",
            "Medium",
            stdout,
            "Consider disabling SSH password authentication and using SSH keys.",
        )
    else:
        add_result(
            results,
            "LIN-003",
            "SSH password authentication reviewed",
            "WARN",
            "Medium",
            stdout or stderr or "Could not determine SSH password authentication setting",
            "Review SSH authentication configuration.",
        )

    code, stdout, stderr = run_command("systemctl is-active auditd")

    if stdout.strip() == "active":
        add_result(
            results,
            "LIN-004",
            "auditd service running",
            "PASS",
            "Medium",
            "auditd is active",
            "No action required.",
        )
    else:
        add_result(
            results,
            "LIN-004",
            "auditd service running",
            "FAIL",
            "Medium",
            f"auditd status: {stdout or stderr}",
            "Install and enable auditd for Linux audit logging.",
        )

    code, stdout, stderr = run_command("systemctl is-active fail2ban")

    if stdout.strip() == "active":
        add_result(
            results,
            "LIN-005",
            "fail2ban service running",
            "PASS",
            "Medium",
            "fail2ban is active",
            "No action required.",
        )
    else:
        add_result(
            results,
            "LIN-005",
            "fail2ban service running",
            "WARN",
            "Medium",
            f"fail2ban status: {stdout or stderr}",
            "Install and configure fail2ban to reduce brute-force risk.",
        )

    code, stdout, stderr = run_command(
        "dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'"
    )

    if stdout:
        add_result(
            results,
            "LIN-006",
            "Automatic security updates package installed",
            "PASS",
            "Medium",
            "unattended-upgrades package is installed",
            "Confirm automatic update policy is configured.",
        )
    else:
        add_result(
            results,
            "LIN-006",
            "Automatic security updates package installed",
            "WARN",
            "Medium",
            "unattended-upgrades package not found",
            "Install unattended-upgrades or document manual patching process.",
        )

    code, stdout, stderr = run_command("systemctl is-active wazuh-agent")

    if stdout.strip() == "active":
        add_result(
            results,
            "LIN-007",
            "Wazuh agent running",
            "PASS",
            "High",
            "wazuh-agent is active",
            "No action required.",
        )
    else:
        add_result(
            results,
            "LIN-007",
            "Wazuh agent running",
            "WARN",
            "High",
            f"wazuh-agent status: {stdout or stderr}",
            "Install, configure, or restart the Wazuh agent.",
        )

    code, stdout, stderr = run_command("ss -tuln | head -20")

    add_result(
        results,
        "LIN-008",
        "Listening network services reviewed",
        "INFO",
        "Low",
        stdout or stderr,
        "Review listening services and disable anything unnecessary.",
    )


def parse_net_accounts(output):
    min_length = None
    lockout_threshold = None

    for line in output.splitlines():
        lower = line.lower()

        if "minimum password length" in lower:
            match = re.search(r"(\d+)", line)
            if match:
                min_length = int(match.group(1))

        if "lockout threshold" in lower:
            match = re.search(r"(\d+)", line)
            if match:
                lockout_threshold = int(match.group(1))

    return min_length, lockout_threshold


def check_windows(results):
    code, stdout, stderr = run_powershell(
        "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Count"
    )

    if stdout.strip() == "0":
        add_result(
            results,
            "WIN-001",
            "Windows Firewall enabled on all profiles",
            "PASS",
            "High",
            "All firewall profiles are enabled",
            "No action required.",
        )
    else:
        add_result(
            results,
            "WIN-001",
            "Windows Firewall enabled on all profiles",
            "FAIL",
            "High",
            stdout or stderr,
            "Enable Windows Firewall for Domain, Private, and Public profiles.",
        )

    code, stdout, stderr = run_powershell("(Get-Service WinDefend).Status")

    if "Running" in stdout:
        add_result(
            results,
            "WIN-002",
            "Microsoft Defender service running",
            "PASS",
            "High",
            stdout,
            "No action required.",
        )
    else:
        add_result(
            results,
            "WIN-002",
            "Microsoft Defender service running",
            "FAIL",
            "High",
            stdout or stderr,
            "Start Microsoft Defender or verify endpoint protection coverage.",
        )

    code, stdout, stderr = run_powershell(
        "Get-Service WazuhSvc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"
    )

    if "Running" in stdout:
        add_result(
            results,
            "WIN-003",
            "Wazuh agent service running",
            "PASS",
            "High",
            stdout,
            "No action required.",
        )
    else:
        add_result(
            results,
            "WIN-003",
            "Wazuh agent service running",
            "WARN",
            "High",
            stdout or stderr or "Wazuh service not found",
            "Install, configure, or restart the Wazuh agent.",
        )

    code, stdout, stderr = run_powershell(
        "Get-Service Sysmon64,Sysmon -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"
    )

    if "Running" in stdout:
        add_result(
            results,
            "WIN-004",
            "Sysmon service running",
            "PASS",
            "Medium",
            stdout,
            "No action required.",
        )
    else:
        add_result(
            results,
            "WIN-004",
            "Sysmon service running",
            "WARN",
            "Medium",
            stdout or stderr or "Sysmon service not found",
            "Install Sysmon to improve endpoint telemetry.",
        )

    code, stdout, stderr = run_powershell(
        "(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"
    )

    if stdout.strip() == "1":
        add_result(
            results,
            "WIN-005",
            "Remote Desktop disabled",
            "PASS",
            "Medium",
            "fDenyTSConnections = 1",
            "No action required.",
        )
    elif stdout.strip() == "0":
        add_result(
            results,
            "WIN-005",
            "Remote Desktop disabled",
            "WARN",
            "Medium",
            "fDenyTSConnections = 0",
            "Disable RDP if not required or restrict access to trusted networks.",
        )
    else:
        add_result(
            results,
            "WIN-005",
            "Remote Desktop status reviewed",
            "WARN",
            "Medium",
            stdout or stderr or "Could not determine RDP status",
            "Review Remote Desktop configuration.",
        )

    code, stdout, stderr = run_command("net localgroup administrators")

    add_result(
        results,
        "WIN-006",
        "Local administrators group reviewed",
        "INFO",
        "Medium",
        stdout or stderr,
        "Review members and remove unnecessary local admin access.",
    )

    code, stdout, stderr = run_command("net accounts")
    min_length, lockout_threshold = parse_net_accounts(stdout)

    if min_length is not None and min_length >= 8:
        add_result(
            results,
            "WIN-007",
            "Minimum password length is at least 8",
            "PASS",
            "Medium",
            f"Minimum password length: {min_length}",
            "No action required.",
        )
    else:
        add_result(
            results,
            "WIN-007",
            "Minimum password length is at least 8",
            "WARN",
            "Medium",
            f"Minimum password length: {min_length if min_length is not None else 'Unknown'}",
            "Set minimum password length to at least 8 or higher.",
        )

    if lockout_threshold is not None and lockout_threshold > 0:
        add_result(
            results,
            "WIN-008",
            "Account lockout threshold configured",
            "PASS",
            "Medium",
            f"Lockout threshold: {lockout_threshold}",
            "No action required.",
        )
    else:
        add_result(
            results,
            "WIN-008",
            "Account lockout threshold configured",
            "WARN",
            "Medium",
            f"Lockout threshold: {lockout_threshold if lockout_threshold is not None else 'Unknown'}",
            "Configure account lockout threshold to reduce brute-force risk.",
        )


def main():
    hostname = socket.gethostname()
    os_name = platform.platform()
    system = platform.system()

    results = []

    if system == "Windows":
        check_windows(results)
    elif system == "Linux":
        check_linux(results)
    else:
        add_result(
            results,
            "GEN-001",
            "Supported operating system check",
            "FAIL",
            "High",
            f"Unsupported OS: {system}",
            "Run this scanner on Windows or Linux.",
        )

    score = calculate_score(results)

    csv_report = write_csv_report(results, hostname)
    md_report = write_markdown_report(results, hostname, os_name, score)

    print("\n=== Security Baseline Compliance Scanner ===\n")
    print(f"Hostname: {hostname}")
    print(f"Operating System: {os_name}")
    print(f"Compliance Score: {score}%")
    print(f"Risk Rating: {risk_rating(score)}")

    print("\nControl Results:")

    for result in results:
        print(
            f"{result['status']} | "
            f"Risk If Failed: {result['risk_if_failed']} | "
            f"{result['check_id']} | "
            f"{result['control']}"
        )

    print("\nReports created:")
    print(f"- {csv_report}")
    print(f"- {md_report}")


if __name__ == "__main__":
    main()