\# Remediation Guide



\## Windows Remediation



\### Windows Firewall Disabled



Enable firewall profiles:



```powershell

Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

