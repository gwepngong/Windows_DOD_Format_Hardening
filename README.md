# Windows_DOD_Format_Hardening
This project documents the manual and scripted application of DISA STIG security controls to a fresh Windows Server 2025 installation. The configurations mirror what system administrators apply in DoD IL2–IL5 environments during the Risk Management Framework (RMF) Authorization to Operate (ATO) process.
# Windows Server 2025 — DoD STIG Hardening Lab

> **Author:** Gilbert  
> **Environment:** GOVCON Cybersecurity Home Lab  
> **Date:** July 2026  
> **OS Target:** Windows Server 2025 Standard (Desktop Experience)  
> **Framework:** DISA STIG V2R2 + NSA/CISA Server 2025 Hardening Guide

## Lab Environment

| Component | Details |
|---|---|
| Target OS | Windows Server 2025 Standard |
| Monitoring | Wazuh SIEM (Rocky Linux 9) |
| Domain | Lab AD domain (Windows Server 2025 DC) |
| Network | Internal NAT / Host-Only |

---

## Controls Applied

| # | Control | STIG Reference | Why It Matters |
|---|---|---|---|
| 1 | Rename Administrator account | V-253265 | Default name is targeted in brute force attacks |
| 2 | Legal warning banner | V-253274 | Federal law requirement — verified at every ATO inspection |
| 3 | Password & lockout policy | V-253288 | 14-char min, 3-attempt lockout, 24-password history |
| 4 | Full audit policy | V-253303–320 | Enables Wazuh/SIEM visibility — blank system is blind |
| 5 | Disable unused services | V-253344–350 | Minimum attack surface — least functionality principle |
| 6 | Host-based firewall | V-253358 | Default-deny inbound on all three profiles |
| 7 | Disable SMBv1 + signing | V-253361 | Eliminates EternalBlue/WannaCry attack vector |
| 8 | Windows Defender | V-253380 | Tamper-protected AV required on all DoD endpoints |
| 9 | Event log sizes | V-253295–300 | Prevents log overwrite before SIEM collection |
| 10 | Disable AutoRun | V-253370 | USB malware cannot auto-execute |
| 11 | Credential Guard (VBS) | NSA/CISA | Blocks Mimikatz / pass-the-hash entirely |
| 12 | ATO baseline reports | RMF requirement | GPO + SecPol + AuditPol exported as ATO artifacts |

---

## Screenshots

### Password Policy — Verified (`net accounts` output)
![Password Policy](screenshots/password-policy-verified.png)

### Firewall Policy — Verified (`netsh advfirewall` output)
![Firewall Policy](screenshots/firewall-policy-verified.png)

### Registry Path Troubleshooting
![Registry Troubleshoot](screenshots/registry-error-troubleshoot.png)

---

## How to Run

```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\WS2025-DoD-STIG-Hardening.ps1
# Reports saved to C:\STIG-Reports\
# Reboot after to activate Credential Guard
```

---

## Known Issues & Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| `LegalNoticeCaption` path not found | Key doesn't exist on fresh install | Script creates it with `New-Item -Force` |
| `Set-NetFirewallProfile` SID mapping error | WMI bug on pre-domain-joined Server 2025 | Script uses `netsh` instead — policy IS applied correctly |
| Credential Guard not active | Requires reboot | Reboot and re-check `Get-ComputerInfo` |

---

## References

- [DISA STIG — Windows Server 2025](https://public.cyber.mil/stigs/)
- [NSA/CISA Windows Server 2025 Hardening Guide](https://www.nsa.gov/Press-Room/Cybersecurity-Advisories/)
- [NIST RMF SP 800-37](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

## Part of Larger Portfolio

- ✅ Active Directory — DC deployed and STIG hardened (Windows Server 2022)
- ✅ Wazuh SIEM — Rocky Linux 9, agents on all endpoints
- ✅ OpenSCAP — RHEL9 STIG baseline: 168 pass / 266 fail (pre-remediation)
- ✅ Windows Server 2025 — STIG hardening applied (this repo)
