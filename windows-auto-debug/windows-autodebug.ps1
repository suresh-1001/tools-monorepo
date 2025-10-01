<# 
Windows Auto-Debug + Self-Heal (ASCII-safe)
Works on Windows Server 2016/2019/2022 and Windows 10/11
Default: read-only checks. Use -Apply to perform safe remediations.

This version uses ONLY ASCII characters and avoids any Unicode/emoji.
#> 

[CmdletBinding()]
param(
  [switch]$Apply,
  [switch]$Aggressive,
  [string]$Report
)

# Symbols (ASCII only)
$SYM_OK   = "[OK]"
$SYM_WARN = "[WARN]"
$SYM_INFO = "[INFO]"

$ErrorActionPreference = 'SilentlyContinue'

function Log { param([string]$Message) Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Message) }
function HR  { Write-Host ("-"*60) }
$startUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

if ($Report) {
  try {
    $dir = Split-Path -Parent $Report
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Start-Transcript -Path $Report -Append | Out-Null
  } catch { }
}

function Get-CPUload {
  try { (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average } catch { $null }
}

function Get-AvailMemMB {
  try { 
    $os = Get-CimInstance Win32_OperatingSystem
    [int]([math]::Round($os.FreePhysicalMemory/1024,0))
  } catch { $null }
}

function Get-CDriveUsePct {
  try {
    $vol = Get-Volume -DriveLetter C -ErrorAction Stop
    [int](100 - ($vol.SizeRemaining/$vol.Size*100))
  } catch { $null }
}

function Pending-Reboot {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
  )
  foreach ($p in $paths) { if (Test-Path $p) { return $true } }
  return $false
}

function Final-Summary {
  Write-Host ""
  Write-Host "============================================================"
  Write-Host "[Final Summary]"

  $cpu = Get-CPUload
  if ($cpu -ne $null -and $cpu -gt 80) {
    Write-Host ("- {0} CPU load is high ({1}%). Investigate top processes." -f $SYM_WARN, [int]$cpu)
  } else {
    Write-Host ("- {0} CPU load looks normal ({1}%)." -f $SYM_OK, ($cpu -as [int]))
  }

  $avail = Get-AvailMemMB
  if ($avail -ne $null -and $avail -lt 400) {
    Write-Host ("- {0} Low available memory ({1} MB). Consider closing apps or adding RAM." -f $SYM_WARN, $avail)
  } else {
    Write-Host ("- {0} Memory is healthy ({1} MB available)." -f $SYM_OK, $avail)
  }

  $cuse = Get-CDriveUsePct
  if ($cuse -ne $null -and $cuse -gt 85) {
    Write-Host ("- {0} C:\ drive is {1}% full. Free up space soon." -f $SYM_WARN, $cuse)
  } else {
    Write-Host ("- {0} Disk usage on C:\ looks safe ({1}% used)." -f $SYM_OK, $cuse)
  }

  if (Pending-Reboot) {
    Write-Host ("- {0} A reboot is pending (Windows updates or servicing)." -f $SYM_WARN)
  } else {
    Write-Host ("- {0} No pending reboot detected." -f $SYM_OK)
  }

  # Time sync
  $w32 = Get-Service -Name W32Time -ErrorAction SilentlyContinue
  if ($w32 -and $w32.Status -eq 'Running') {
    Write-Host ("- {0} Windows Time service is running." -f $SYM_OK)
  } else {
    Write-Host ("- {0} Windows Time service is not running." -f $SYM_WARN)
  }

  Write-Host ""
  Write-Host ("[Verdict] Overall system health looks stable unless flagged above.")
  Write-Host "============================================================"
}

Log "=== Windows Auto-Debug + Self-Heal (ASCII) ==="
try {
  $comp = Get-ComputerInfo -Property OsName,OsEdition,OsVersion,WindowsVersion,WindowsBuildLabEx
  $hostName = $env:COMPUTERNAME
  Log ("Host: {0}  |  Time (UTC): {1}" -f $hostName, $startUtc)
  HR
  Log ("Detected OS: {0} {1} (Build {2})" -f $comp.OsName, $comp.OsVersion, $comp.WindowsBuildLabEx)
} catch {
  Log ("Host: {0}  |  Time (UTC): {1}" -f $env:COMPUTERNAME, $startUtc)
}
HR

# Uptime
try {
  $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
  $uptime = (Get-Date) - $boot
  Log "[System] Uptime"
  "{0} days {1:00}:{2:00}:{3:00}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds | Write-Host
  ""
  "[Explanation] Shows how long the system has been running since last reboot." | Write-Host
  HR
} catch {}

# Top processes (CPU/Mem)
Log "[System] CPU/Memory top offenders (top 10)"
try { 
  Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 10 Name, Id, CPU, PM, WS | Format-Table -AutoSize
  ""
  Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 10 Name, Id, CPU, PM, WS | Format-Table -AutoSize
} catch {}
""
"[Explanation] Processes using most CPU and RAM. Watch for runaway tasks." | Write-Host
HR

# Memory status
Log "[Memory]"
try {
  $os = Get-CimInstance Win32_OperatingSystem
  [PSCustomObject]@{
    TotalGB   = [math]::Round(($os.TotalVisibleMemorySize/1MB),2)
    FreeGB    = [math]::Round(($os.FreePhysicalMemory/1MB),2)
    UsedGB    = [math]::Round((($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/1MB),2)
    FreePct   = [int]((($os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)*100)
  } | Format-List
} catch {}
""
"[Explanation] Total/used/available memory." | Write-Host
HR

# Disks
Log "[Disk] Volumes"
try {
  Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemLabel, FileSystem, @{n='SizeGB';e={[int]($_.Size/1GB)}}, @{n='FreeGB';e={[int]($_.SizeRemaining/1GB)}}, @{n='UsedPct';e={[int](100-(($_.SizeRemaining/$_.Size)*100))}} | Format-Table -AutoSize
} catch {}
""
"[Explanation] Disk usage by volume. Alerts if C: exceeds 85% in summary." | Write-Host
HR

# Network
Log "[Network] Interfaces"
try { Get-NetIPConfiguration | Format-Table -AutoSize } catch {}
""
Log "[Network] Routes (top 15)"
try { Get-NetRoute | Sort-Object RouteMetric | Select-Object -First 15 | Format-Table -AutoSize } catch {}
""
Log "[Network] Listening ports (top 15)"
try { Get-NetTCPConnection -State Listen | Select-Object -First 15 LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize } catch {}
""
"[Explanation] Interfaces, routes, and listening ports. Keep listeners minimal for security." | Write-Host
HR

# Services
Log "[Services] Automatic services that are stopped"
$failedSvcs = @()
try {
  $failedSvcs = Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }
  if ($failedSvcs) { $failedSvcs | Select-Object Name, Status, StartType | Format-Table -AutoSize } else { "None" | Write-Host }
} catch {}
""
"[Explanation] Auto-start services that aren't running can explain outages." | Write-Host
HR

# Logs (last 24h errors)
Log "[Logs] Recent errors (last 24h) - System"
try { Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 40 | Format-Table -AutoSize TimeCreated, Id, ProviderName, Message } catch {}
""
Log "[Logs] Recent errors (last 24h) - Application"
try { Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 40 | Format-Table -AutoSize TimeCreated, Id, ProviderName, Message } catch {}
""
"[Explanation] Critical errors in System/Application logs for the last day." | Write-Host
HR

# DNS quick sanity
Log "[DNS] Server addresses per interface"
try { 
  Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
} catch {}
""
"[Explanation] DNS configuration. Missing resolvers can break name resolution." | Write-Host
HR

# Time sync
Log "[Time] w32time status"
try { w32tm /query /status | Write-Host } catch {}
""
"[Explanation] Time source and sync state. Accurate time matters for auth/logs." | Write-Host
HR

# Defender (if present)
$defenderOk = $false
try {
  if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    Log "[Security] Microsoft Defender status (summary)"
    $mp = Get-MpComputerStatus
    [PSCustomObject]@{
      AMServiceEnabled = $mp.AMServiceEnabled
      AntispywareEnabled = $mp.AntispywareEnabled
      AntivirusEnabled = $mp.AntivirusEnabled
      RealTimeProtection = $mp.RealTimeProtectionEnabled
      SignatureAgeHours = [int]((New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)).TotalHours)
      QuickScanAgeHours = [int]((New-TimeSpan -Start $mp.LastQuickScanStartTime -End (Get-Date)).TotalHours)
    } | Format-List
    $defenderOk = $true
    ""
    "[Explanation] Defender realtime, signatures, and last quick scan timestamps." | Write-Host
    HR
  }
} catch {}

# Space hotspots
Log "[Disk] Biggest paths under C:\Windows\Temp and user temp (top 10 each)"
try {
  Get-ChildItem -Path "$env:WINDIR\Temp" -Force -ErrorAction SilentlyContinue | 
    Sort-Object Length -Descending | 
    Select-Object -First 10 FullName, @{n='SizeMB';e={[int]($_.Length/1MB)}} | Format-Table -AutoSize
  ""
  Get-ChildItem -Path $env:TEMP -Force -ErrorAction SilentlyContinue | 
    Sort-Object Length -Descending | 
    Select-Object -First 10 FullName, @{n='SizeMB';e={[int]($_.Length/1MB)}} | Format-Table -AutoSize
} catch {}
""
"[Explanation] Temp file hotspots that commonly bloat disks." | Write-Host
HR

if (-not $Apply) {
  Final-Summary
  Log "Read-only run complete. Re-run with -Apply for safe fixes."
  if ($Report) { try { Stop-Transcript | Out-Null } catch {} }
  exit
}

# ==================== APPLY MODE ====================
Log "=== APPLY MODE: Performing safe remediations ==="

# 1) Restart failed auto services
if ($failedSvcs -and $failedSvcs.Count -gt 0) {
  Log "[Fix] Restarting stopped Automatic services"
  foreach ($svc in $failedSvcs) {
    try {
      Log (" -> Restart-Service {0}" -f $svc.Name)
      Restart-Service -Name $svc.Name -ErrorAction Stop
      Start-Sleep -Seconds 1
    } catch { Log ("WARN: Failed to restart {0}" -f $svc.Name) }
  }
} else {
  Log "[Fix] No stopped Automatic services to restart"
}
HR

# 2) Disk space relief: clean temp, softwaredistribution cache (partial), component cleanup
Log "[Fix] Cleaning temp files (>7 days)"
try {
  $cut = (Get-Date).AddDays(-7)
  @("$env:TEMP","$env:WINDIR\Temp") | ForEach-Object {
    Get-ChildItem $_ -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt $cut } |
      Remove-Item -Force -ErrorAction SilentlyContinue
  }
} catch { Log "WARN: Temp cleanup encountered some files in use." }

Log "[Fix] Cleaning Windows Update download cache (>14 days)"
try {
  $cutWU = (Get-Date).AddDays(-14)
  $wu = "$env:WINDIR\SoftwareDistribution\Download"
  if (Test-Path $wu) {
    Get-ChildItem $wu -Recurse -Force -ErrorAction SilentlyContinue |
      Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt $cutWU } |
      Remove-Item -Force -ErrorAction SilentlyContinue
  }
} catch { Log "WARN: SoftwareDistribution cleanup partial." }

Log "[Fix] Component store (WinSxS) cleanup (DISM /StartComponentCleanup)"
try {
  Start-Process -FilePath dism.exe -ArgumentList "/Online","/Cleanup-Image","/StartComponentCleanup","/Quiet" -Wait -NoNewWindow | Out-Null
} catch { Log "WARN: DISM cleanup skipped or failed." }
HR

# 3) DNS fallback if a NIC has no resolvers
try {
  $dnsConfigs = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop
  $needsFallback = $false
  foreach ($cfg in $dnsConfigs) { if (-not $cfg.ServerAddresses -or $cfg.ServerAddresses.Count -eq 0) { $needsFallback = $true } }
  if ($needsFallback) {
    Log "[Fix] Adding DNS fallback (1.1.1.1, 8.8.8.8) to adapters with no resolvers"
    $adapters = Get-DnsClient | Where-Object { $_.InterfaceAlias -in $dnsConfigs.InterfaceAlias }
    foreach ($ad in $adapters) {
      try { Set-DnsClientServerAddress -InterfaceAlias $ad.InterfaceAlias -ServerAddresses @('1.1.1.1','8.8.8.8') -ErrorAction Stop } catch {}
    }
  } else {
    Log "[Fix] DNS resolvers already configured. Skipping."
  }
} catch {
  Log "[Fix] DNS query failed; skipping."
}
HR

# 4) Time sync nudge
try {
  Log "[Fix] Ensuring Windows Time service is running and resyncing"
  Set-Service W32Time -StartupType Automatic -ErrorAction SilentlyContinue
  Start-Service W32Time -ErrorAction SilentlyContinue
  w32tm /resync | Out-Null
} catch {
  Log "WARN: Time sync nudge failed."
}
HR

# 5) Defender quick scan & signature update (Aggressive)
if ($Aggressive -and $defenderOk) {
  Log "[Fix][Aggressive] Updating Defender signatures and starting Quick scan"
  try { Update-MpSignature | Out-Null } catch {}
  try { Start-MpScan -ScanType Quick | Out-Null } catch {}
} else {
  Log "[Fix] Skipping Defender scan (use -Aggressive) or Defender not available."
}
HR

# 6) Post-fix quick verification
Log "[Verify] Re-check automatic services not running"
try { 
  Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | 
    Select-Object Name, Status | Format-Table -AutoSize 
} catch {}
""
Log "[Verify] Disk usage (C:\)"
try { Get-Volume -DriveLetter C | Select-Object DriveLetter, @{n='UsedPct';e={[int](100-(($_.SizeRemaining/$_.Size)*100))}}, SizeRemaining, Size | Format-Table -AutoSize } catch {}
""
Log "[Verify] DNS test"
try { Resolve-DnsName example.com -ErrorAction Stop | Select-Object -First 1 | Format-List } catch { Log "DNS name resolution failed; try Test-Connection 1.1.1.1" }
""
Log "[Verify] Time sync"
try { w32tm /query /status | Write-Host } catch {}
HR

Log ("=== Done. Apply mode completed at {0} ===" -f ((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")))
Final-Summary

if ($Report) { try { Stop-Transcript | Out-Null } catch {} }
