#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 DoD STIG Hardening Script
    Author: Gilbert (GOVCON Cybersecurity Lab)
    Date: July 2026
    Version: 1.0

.DESCRIPTION
    Applies DISA STIG-aligned security controls to a Windows Server 2025 system.
    Controls mirror what is enforced in DoD IL2-IL5 environments during RMF ATO processes.

.NOTES
    - Run as Administrator in PowerShell
    - Tested on: Windows Server 2025 Standard (Desktop Experience)
    - Some settings require a reboot (Credential Guard)

.EXAMPLE
    .\WS2025-DoD-STIG-Hardening.ps1
#>

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}
function Write-Pass { param([string]$Msg) Write-Host "[PASS] $Msg" -ForegroundColor Green }
function Write-Info { param([string]$Msg) Write-Host "[INFO] $Msg" -ForegroundColor Yellow }

# Report directory
$ReportPath = "C:\STIG-Reports"
if (-not (Test-Path $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null }
$LogFile = "$ReportPath\WS2025-Hardening-Log-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
Start-Transcript -Path $LogFile
Write-Host "  Windows Server 2025 DoD STIG Hardening Script" -ForegroundColor White
Write-Host "  Started: $(Get-Date)" -ForegroundColor Gray

# ============================================================
# 1 — RENAME ADMINISTRATOR ACCOUNT | V-253265
# ============================================================
Write-Section "1/12 — Rename Administrator Account (V-253265)"
try {
    Rename-LocalUser -Name "Administrator" -NewName "DoD-SysAdmin" -ErrorAction Stop
    Write-Pass "Administrator renamed to DoD-SysAdmin"
} catch { Write-Info "Account may already be renamed: $_" }
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize

# ============================================================
# 2 — LEGAL WARNING BANNER | V-253274
# ============================================================
Write-Section "2/12 — Legal Warning Banner (V-253274)"
$BannerTitle = "WARNING: This is a U.S. Government Information System"
$BannerText  = "This system is subject to monitoring. Individuals using this system without authority, or in excess of their authority, are subject to having all activities on this system monitored. Anyone using this system expressly consents to such monitoring."
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null; Write-Info "Registry path created." }
Set-ItemProperty -Path $RegPath -Name "LegalNoticeCaption" -Value $BannerTitle -Type String
Set-ItemProperty -Path $RegPath -Name "LegalNoticeText"    -Value $BannerText  -Type String
Write-Pass "Legal banner set"
Get-ItemProperty $RegPath | Select-Object LegalNoticeCaption, LegalNoticeText

# ============================================================
# 3 — PASSWORD & LOCKOUT POLICY | V-253288
# ============================================================
Write-Section "3/12 — Password & Lockout Policy (V-253288)"
net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:24 `
             /lockoutthreshold:3 /lockoutduration:15 /lockoutwindow:15
secedit /export /cfg "$ReportPath\secpol-backup.cfg" /quiet
$SecPol = Get-Content "$ReportPath\secpol-backup.cfg"
$SecPol = $SecPol -replace "PasswordComplexity = 0","PasswordComplexity = 1"
$SecPol | Set-Content "$ReportPath\secpol-modified.cfg"
secedit /configure /db "$ReportPath\secpol.sdb" /cfg "$ReportPath\secpol-modified.cfg" /quiet
Write-Pass "Password policy applied"
net accounts

# ============================================================
# 4 — AUDIT POLICY | V-253303 through V-253320
# ============================================================
Write-Section "4/12 — Audit Policy — STIG Baseline (V-253303-320)"
auditpol /set /subcategory:"Credential Validation"               /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service"     /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations"  /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management"             /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management"         /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"           /success:enable /failure:enable
auditpol /set /subcategory:"Logon"                               /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"                              /success:enable
auditpol /set /subcategory:"Account Lockout"                     /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon"                       /success:enable
auditpol /set /subcategory:"File System"                         /success:enable /failure:enable
auditpol /set /subcategory:"Registry"                            /success:enable /failure:enable
auditpol /set /subcategory:"SAM"                                 /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage"                   /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change"                 /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change"        /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use"             /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension"           /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity"                    /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change"               /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation"                    /success:enable
Write-Pass "Audit policy applied"
auditpol /get /category:* | Where-Object { $_ -notmatch "No Auditing" }

# ============================================================
# 5 — DISABLE UNNECESSARY SERVICES | V-253344-350
# ============================================================
Write-Section "5/12 — Disable Unnecessary Services (V-253344-350)"
$ServicesToDisable = @("Fax","XblAuthManager","XblGameSave","XboxNetApiSvc",
                        "WMPNetworkSvc","RemoteRegistry","SSDPSRV","upnphost")
foreach ($svc in $ServicesToDisable) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service  -Name $svc -StartupType Disabled
        Write-Pass "$svc disabled"
    } else { Write-Info "$svc not found (may already be removed)" }
}
Get-Service $ServicesToDisable -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize

# ============================================================
# 6 — HOST-BASED FIREWALL | V-253358
# NOTE: Using netsh — PowerShell cmdlets have WMI SID mapping
#       bug on fresh pre-domain-joined Server 2025 installs.
# ============================================================
Write-Section "6/12 — Host-Based Firewall (V-253358)"
netsh advfirewall reset | Out-Null
netsh advfirewall set allprofiles state on
netsh advfirewall set domainprofile  firewallpolicy blockinbound,allowoutbound
netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set publicprofile  firewallpolicy blockinbound,allowoutbound
netsh advfirewall firewall add rule name="DoD-Allow-RDP-LAN" `
    dir=in action=allow protocol=TCP localport=3389 remoteip=192.168.0.0/24
netsh advfirewall firewall add rule name="DoD-Allow-WinRM-LAN" `
    dir=in action=allow protocol=TCP localport=5985,5986 remoteip=192.168.0.0/24
Write-Pass "Firewall configured — BlockInbound on all profiles"
netsh advfirewall show allprofiles | findstr "State\|Firewall Policy"

# ============================================================
# 7 — DISABLE SMBv1 + ENABLE SMB SIGNING | V-253361
# ============================================================
Write-Section "7/12 — Disable SMBv1 + Enable SMB Signing (V-253361)"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
Write-Pass "SMBv1 disabled, SMB signing required"
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature

# ============================================================
# 8 — WINDOWS DEFENDER | V-253380
# ============================================================
Write-Section "8/12 — Windows Defender Hardening (V-253380)"
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection     $false
Set-MpPreference -MAPSReporting             Advanced
Set-MpPreference -SubmitSamplesConsent      SendAllSamples
Set-MpPreference -ScanScheduleDay           Sunday
Set-MpPreference -ScanScheduleTime          120
Update-MpSignature
Write-Pass "Defender configured and definitions updated"
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled,
    AntivirusEnabled, AntispywareEnabled, NISEnabled

# ============================================================
# 9 — EVENT LOG SIZES | V-253295-300
# ============================================================
Write-Section "9/12 — Event Log Sizes (V-253295-300)"
wevtutil sl Security    /ms:1024000
wevtutil sl System      /ms:32768
wevtutil sl Application /ms:32768
wevtutil sl Security    /r:false
wevtutil sl System      /r:false
wevtutil sl Application /r:false
Write-Pass "Event log sizes configured"
wevtutil gl Security    | findstr "maxSize"
wevtutil gl System      | findstr "maxSize"
wevtutil gl Application | findstr "maxSize"

# ============================================================
# 10 — DISABLE AUTORUN / AUTOPLAY | V-253370
# ============================================================
Write-Section "10/12 — Disable AutoRun / AutoPlay (V-253370)"
$ExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $ExplorerPath)) { New-Item -Path $ExplorerPath -Force | Out-Null }
Set-ItemProperty -Path $ExplorerPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
Set-ItemProperty -Path $ExplorerPath -Name "NoAutorun"          -Value 1   -Type DWord
Write-Pass "AutoRun/AutoPlay disabled for all drive types"
Get-ItemProperty $ExplorerPath | Select-Object NoDriveTypeAutoRun, NoAutorun

# ============================================================
# 11 — CREDENTIAL GUARD (VBS) | NSA/CISA
# ============================================================
Write-Section "11/12 — Credential Guard / VBS (NSA/CISA)"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity"  -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "RequirePlatformSecurityFeatures"    -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags" -Value 1 -Type DWord
Write-Pass "Credential Guard enabled — REBOOT REQUIRED to activate"

# ============================================================
# 12 — ATO BASELINE REPORTS
# ============================================================
Write-Section "12/12 — Generate ATO Baseline Reports"
gpresult /H "$ReportPath\WS2025-GPO-Baseline.html" /F
secedit /export /cfg "$ReportPath\WS2025-SecPol-Baseline.cfg" /quiet
auditpol /get /category:* > "$ReportPath\WS2025-AuditPol-Baseline.txt"
Write-Pass "Reports saved to $ReportPath"

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host "  HARDENING COMPLETE — Reboot to activate Credential Guard" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green
Stop-Transcript
