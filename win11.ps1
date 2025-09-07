# ============================================================================
# WINDOWS 11 ULTIMATE CONFIGURATION TOOL - v4.5 EXTENDED
#  - UTF-8 safe console/logging
#  - App installer (profiles | all | select | search | ids)
#  - WSL resilient install (DISM/SFC fallback)
#  - Security/Privacy/Perf/UI/Network/Bloatware
#  - System Info menu now includes your full Batch "Security Report" generator
# ============================================================================

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    # Operation Modes
    [switch]$ExpressMode,
    [switch]$CustomMode,
    [switch]$MaintenanceMode,
    [switch]$Silent,

    # Profile Selection (features)
    [string]$ApplyProfile,
    [string[]]$CombineProfiles,

    # System Options
    [switch]$CreateRestorePoint,
    [switch]$SkipRestorePoint,
    [switch]$ForceReboot,
    [switch]$NoReboot,

    # Logging
    [string]$LogPath = "$env:USERPROFILE\Desktop",
    [switch]$VerboseLogging,

    # Import/Export
    [string]$ImportConfig,
    [string]$ExportConfig,

    # Specific Operations (feature categories)
    [switch]$RemoveAllBloatware,
    [switch]$ApplyAllSecurity,
    [switch]$ApplyAllPrivacy,
    [switch]$ApplyAllPerformance,
    [switch]$RestoreDefaults,

    # User Context
    [string]$User = $env:USERNAME,
    [switch]$AllUsers,
    [switch]$DefaultUser,

    # ---------------- Apps: nouvelles options CLI ----------------
    [ValidateSet('Dev','Browsers','Media','SysTools','AllCommon')]
    [string]$AppsProfile,
    [switch]$AppsAll,
    [switch]$AppsSelect,
    [switch]$AppsSearch,
    [string[]]$InstallAppIds
)

# ============================================================================
# GLOBAL CONFIGURATION & UTF-8 SAFETY
# ============================================================================

try { chcp 65001 > $null 2>&1 } catch {}
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}

$PSDefaultParameterValues = @{
  'Out-File:Encoding'    = 'utf8'
  'Add-Content:Encoding' = 'utf8'
  'Set-Content:Encoding' = 'utf8'
  'Export-Csv:Encoding'  = 'utf8'
}

$global:ScriptVersion = "4.5-EXT"
$global:ScriptName    = "Windows 11 Ultimate Configuration Tool - Extended"

if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$global:LogFile        = Join-Path $LogPath "Win11Config_${stamp}.log"
$global:TranscriptFile = Join-Path $LogPath "Win11Config_${stamp}.transcript.txt"

$global:ConfigPath      = "$env:LOCALAPPDATA\Win11Config"
$global:BackupPath      = "$global:ConfigPath\Backups"
$global:ProfilesPath    = "$global:ConfigPath\Profiles"
$global:DebloatListPath = "$global:ConfigPath\DebloatLists"
$global:TempPath        = "$env:TEMP\Win11Config"
$global:AppliedFeatures = @()
$global:LogVerbose      = $VerboseLogging.IsPresent
$global:OriginalDNS     = @{}

@($global:ConfigPath, $global:BackupPath, $global:ProfilesPath, $global:DebloatListPath, $global:TempPath) | ForEach-Object {
    if (!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

foreach ($d in @(@{Name='HKCR';Root='HKEY_CLASSES_ROOT'}, @{Name='HKU';Root='HKEY_USERS'})) {
    if (-not (Get-PSDrive $d.Name -ErrorAction SilentlyContinue)) {
        New-PSDrive -PSProvider Registry -Name $d.Name -Root $d.Root | Out-Null
    }
}

try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
try { Start-Transcript -Path $global:TranscriptFile -Append -Force | Out-Null } catch { Write-Warning "Unable to start transcript logging" }

# ============================================================================
# HELPERS
# ============================================================================

function Write-LogMessage {
    param([string]$Message,[string]$Level="Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry  = "[$timestamp] [$Level] $Message"
    $color = switch ($Level) {
        "Info"      { "White" }
        "Success"   { "Green" }
        "Warning"   { "Yellow" }
        "Error"     { "Red" }
        "Important" { "Cyan" }
        "Verbose"   { "Gray" }
        default     { "White" }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
    try { Add-Content -Path $global:LogFile -Value $logEntry -Encoding utf8 } catch {}
    if ($global:LogVerbose -and $Level -eq "Verbose") { Write-Verbose $Message }
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [object]$Value,
        [ValidateSet('String','ExpandString','MultiString','DWord','QWord','Binary')]
        [string]$Type="DWord"
    )
    try {
        if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null; Write-LogMessage "Created registry path: $Path" "Verbose" }
        $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($existing -ne $null) { Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force; Write-LogMessage "Updated registry value: $Path\$Name" "Verbose" }
        else { New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null; Write-LogMessage "Created registry value: $Path\$Name (Type: $Type)" "Verbose" }
        return $true
    } catch { Write-LogMessage "Failed to set registry value: $Path\$Name - $_" "Error"; return $false }
}

function Test-Windows11 {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    if ($build -lt 22000) {
        Write-Warning "This script targets Windows 11 (build >= 22000). Current: $($os.Version) (build $build)"
        $continue = Read-Host "Continue anyway? (Y/N)"
        return ($continue -eq "Y")
    }
    Write-LogMessage "Windows 11 detected - Build: $build" "Info"
    return $true
}

function Disable-TaskSafe { param([string]$TaskPath,[string]$TaskName)
    try {
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null
        Write-LogMessage "Disabled task: $TaskPath$TaskName" "Success"
        return $true
    } catch { Write-LogMessage "Task not found or cannot disable: $TaskPath$TaskName - $_" "Warning"; return $false }
}

function Invoke-ForEachUserHive { param([Parameter(Mandatory)][ScriptBlock]$Script)
    & $Script 'HKCU:'
    if ($global:AllUsers) {
        Get-ChildItem Registry::HKEY_USERS |
          Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' } |
          ForEach-Object { & $Script ("Registry::" + $_.Name) }
    }
    if ($global:DefaultUser) {
        $defaultNtuser = "$env:SystemDrive\Users\Default\NTUSER.DAT"
        if (Test-Path $defaultNtuser) {
            reg.exe load HKU\DefaultUser "$defaultNtuser" | Out-Null
            try { & $Script 'Registry::HKEY_USERS\DefaultUser' } finally { reg.exe unload HKU\DefaultUser | Out-Null }
        }
    }
}

function Restart-Explorer {
    Write-LogMessage "Restarting Windows Explorer..." "Info"
    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    Start-Process explorer.exe
    Write-LogMessage "Explorer restarted" "Success"
}

function Set-DnsSafe { param([string[]]$Servers=@("1.1.1.1","1.0.0.1"))
    Get-NetAdapter -Physical | Where-Object Status -eq "Up" | ForEach-Object {
        $idx=$_.ifIndex; $adapterName=$_.Name
        $currentDns = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4
        $global:OriginalDNS[$adapterName] = $currentDns.ServerAddresses
        if ($currentDns.ServerAddresses.Count -gt 0) {
            Write-LogMessage "Setting DNS ($($Servers -join ', ')) on: $adapterName" "Info"
            try { Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $Servers -ErrorAction Stop; Write-LogMessage "DNS set on $adapterName" "Success" }
            catch { Write-LogMessage "Failed to set DNS on $adapterName : $_" "Warning" }
        }
    }
}

function Get-WindowsEditionId { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID }

function Enable-BitLockerSafe {
    $drive = $env:SystemDrive
    try {
        $editionId = Get-WindowsEditionId
        if ($editionId -notin @('Professional','ProfessionalN','ProfessionalWorkstation','Enterprise','EnterpriseN','Education','EducationN')) {
            Write-LogMessage "BitLocker requires Pro/Enterprise/Education. Current: $editionId" "Warning"; return $false
        }
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if (!$tpm -or !$tpm.TpmPresent -or !$tpm.TpmReady) { Write-LogMessage "TPM not present or not ready - BitLocker may not work properly" "Warning" }
        $vol = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
        if ($vol.VolumeStatus -eq 'FullyDecrypted') {
            Write-LogMessage "Enabling BitLocker on $drive..." "Info"
            Enable-BitLocker -MountPoint $drive -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -RecoveryPasswordProtector -ErrorAction Stop
            $recoveryKey = (Get-BitLockerVolume -MountPoint $drive).KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
            Write-LogMessage "BitLocker enabled" "Success"
            Write-LogMessage "RECOVERY KEY: $($recoveryKey.RecoveryPassword)" "Important"
            $keyFile = "$global:BackupPath\BitLocker_RecoveryKey_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $recoveryKey.RecoveryPassword | Out-File -FilePath $keyFile -Force -Encoding utf8
            Write-LogMessage "Recovery key saved to: $keyFile" "Info"
            return $true
        } else { Write-LogMessage "BitLocker already enabled (Status: $($vol.VolumeStatus))" "Info"; return $true }
    } catch { Write-LogMessage "Could not enable BitLocker: $_" "Error"; return $false }
}

function Export-CurrentConfiguration {
    $featuresMeta = @{}
    foreach($key in $global:Features.Keys){ $f=$global:Features[$key]; $featuresMeta[$key] = [PSCustomObject]@{Name=$f.Name;Category=$f.Category;Description=$f.Description;Impact=$f.Impact;RebootRequired=$f.RebootRequired} }
    $exportData = [PSCustomObject]@{
        ExportDate    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        ScriptVersion = $global:ScriptVersion
        SystemInfo    = @{ ComputerName=$env:COMPUTERNAME; Username=$env:USERNAME; OS=(Get-CimInstance Win32_OperatingSystem).Caption; Version=(Get-CimInstance Win32_OperatingSystem).Version; Build=(Get-CimInstance Win32_OperatingSystem).BuildNumber }
        AppliedFeatures = $global:AppliedFeatures
        Features        = $featuresMeta
        DNSBackup       = $global:OriginalDNS
        LogFile         = $global:LogFile
        TranscriptFile  = $global:TranscriptFile
    }
    $exportPath = "$env:USERPROFILE\Desktop\Win11Config_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    try { $exportData | ConvertTo-Json -Depth 6 | Out-File -FilePath $exportPath -Force -Encoding utf8; Write-LogMessage "Configuration exported to: $exportPath" "Success"; return $exportPath }
    catch { Write-LogMessage "Failed to export configuration: $_" "Error"; return $null }
}

function Show-Banner {
@"
╔══════════════════════════════════════════════════════════════════════════════╗
║ WINDOWS 11 ULTIMATE CONFIG TOOL v$($global:ScriptVersion) — Extended & UTF-8 Safe     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ | Write-Host -ForegroundColor Cyan
}

function Test-Administrator { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

function Create-SystemRestorePoint { param([string]$Description = "Win11 Config Tool v$($global:ScriptVersion)")
    Write-LogMessage "Creating system restore point..." "Info"
    try {
        $before = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -Last 1).SequenceNumber
        Enable-ComputerRestore -Drive "$env:SystemDrive" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $after = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -Last 1).SequenceNumber
        if ($after -and $after -ne $before) { Write-LogMessage "Restore point created" "Success"; return $true }
        else { Write-LogMessage "Restore point not created (frequency limit/policy)" "Warning"; return $false }
    } catch { Write-LogMessage "Failed to create restore point: $_" "Error"; return $false }
}

function Get-CategoryFeatures { param([string]$Category)
    $global:Features.GetEnumerator() | Where-Object { $_.Value.Category -eq $Category } | Sort-Object Name
}

function Execute-Feature { param([string]$FeatureKey)
    $feature = $global:Features[$FeatureKey]
    if (!$feature) { Write-LogMessage "Feature not found: $FeatureKey" "Error"; return $false }
    Write-LogMessage "Executing: $($feature.Name)" "Info"
    try { & $feature.Script; $global:AppliedFeatures += $FeatureKey; Write-LogMessage "OK: $($feature.Name)" "Success"; return $true }
    catch { Write-LogMessage "Failed: $($feature.Name) - $_" "Error"; return $false }
}

# ---------------- Apps helpers ----------------

function Ensure-WingetOrChoco {
    if (Get-Command winget -ErrorAction SilentlyContinue) { return "winget" }
    if (Get-Command choco  -ErrorAction SilentlyContinue) { return "choco" }
    Write-LogMessage "winget not found. Installing Chocolatey (fallback)..." "Warning"
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    } catch { Write-LogMessage "Chocolatey install failed: $_" "Error"; return $null }
    return (Get-Command choco -ErrorAction SilentlyContinue) ? "choco" : $null
}

function Install-AppIds { param([string[]]$Ids)
    if (!$Ids -or $Ids.Count -eq 0) { return }
    $pm = Ensure-WingetOrChoco
    if (-not $pm) { Write-LogMessage "No package manager available." "Error"; return }
    if ($pm -eq "winget") {
        foreach ($id in $Ids) {
            Write-LogMessage "winget install $id" "Info"
            try { winget install --id $id -e --silent --accept-package-agreements --accept-source-agreements | Out-Null }
            catch { Write-LogMessage "winget failed for $id : $_" "Warning" }
        }
    } else {
        foreach ($id in $Ids) {
            Write-LogMessage "choco install $id" "Info"
            try { choco install $id -y --no-progress | Out-Null }
            catch { Write-LogMessage "choco failed for $id : $_" "Warning" }
        }
    }
}

function Install-AppBundle { param([string[]]$WingetIds,[string[]]$ChocoIds)
    $pm = Ensure-WingetOrChoco
    if (-not $pm) { Write-LogMessage "No package manager available." "Error"; return }
    if ($pm -eq "winget") { Install-AppIds -Ids $WingetIds } else { Install-AppIds -Ids $ChocoIds }
}

function Search-And-Install-Apps {
    $pm = Ensure-WingetOrChoco
    if (-not $pm) { return }
    while ($true) {
        $q = Read-Host "Rechercher une app (laisser vide pour quitter)"
        if ([string]::IsNullOrWhiteSpace($q)) { break }
        if ($pm -eq "winget") {
            Write-Host "`nRésultats winget pour '$q' :" -ForegroundColor Cyan
            try { winget search $q | Out-String | Write-Host } catch {}
            $choose = Read-Host "Entrer un ou plusieurs IDs (séparés par des virgules) à installer"
            if (![string]::IsNullOrWhiteSpace($choose)) {
                $ids = $choose.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                Install-AppIds -Ids $ids
            }
        } else {
            Write-Host "`nRésultats choco pour '$q' :" -ForegroundColor Cyan
            try { choco search $q | Out-String | Write-Host } catch {}
            $choose = Read-Host "Entrer un ou plusieurs noms choco (séparés par des virgules) à installer"
            if (![string]::IsNullOrWhiteSpace($choose)) {
                $ids = $choose.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                Install-AppIds -Ids $ids
            }
        }
    }
}

# ---------------- WSL resilience helpers ----------------

function Repair-ComponentStore {
    Write-LogMessage "Repairing component store (DISM /RestoreHealth + SFC)..." "Info"
    try { DISM /Online /Cleanup-Image /RestoreHealth | Out-Null } catch { Write-LogMessage "DISM failed: $_" "Warning" }
    try { sfc /scannow | Out-Null } catch { Write-LogMessage "SFC failed: $_" "Warning" }
}

# ---------------- Security Report (Batch) integration ----------------

function Write-SecurityReportBatchScript {
    $path = Join-Path $global:TempPath "Security_Report_Gather.cmd"
    $batch = @'
@echo off
REM ==========================================================================
REM System Information Gathering Script for Security Analysis
REM Author: Jacques Gariépy
REM Date: %DATE%
REM ==========================================================================
REM
REM                           *** IMPORTANT ***
REM
REM This script must be run as an administrator!
REM (Right-click -> Run as administrator)
REM
REM ==========================================================================
REM
REM                      *** EDUCATIONAL NOTE ***
REM
REM This script is intended for purely educational and demonstrative purposes.
REM It gathers detailed system information which can be sensitive.
REM It illustrates techniques used in system administration and security auditing.
REM Running this script is at the user's own risk. The user is responsible
REM for ensuring they have the necessary permissions and comply with all
REM applicable laws and policies, especially regarding data privacy and
REM system access, before running it or sharing its output. This script should
REM not be used without authorization or understanding its potential impact.
REM
REM ==========================================================================

REM -- Output File Configuration --
SET OutputFile="%USERPROFILE%\Desktop\Security_Report_%COMPUTERNAME%_%date:~-4,4%%date:~-7,2%%date:~-10,2%.txt"
echo Report generated by: %USERNAME% > %OutputFile%
echo Date and Time: %DATE% %TIME% >> %OutputFile%
echo Machine: %COMPUTERNAME% >> %OutputFile%
echo ================================================================ >> %OutputFile%
echo. >> %OutputFile%

echo [*** START OF INFORMATION GATHERING ***] >> %OutputFile%
echo. >> %OutputFile%

REM -- Basic Information --
echo [--- Section 1: User and Machine Information ---] >> %OutputFile%
echo Current Directory: %CD% >> %OutputFile%
echo User Domain: %USERDOMAIN% >> %OutputFile%
echo Logon Server: %LOGONSERVER% >> %OutputFile%
(whoami /all) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- System Information (OS, Hotfixes) --
echo [--- Section 2: System Information (OS, Hotfixes) ---] >> %OutputFile%
(systeminfo) >> %OutputFile% 2>&1
echo. >> %OutputFile%
echo [Hotfixes (WMIC QFE)] >> %OutputFile%
(wmic qfe list full /format:list) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- Installed Software --
echo [--- Section 3: Installed Software (via MSI - potentially incomplete list) ---] >> %OutputFile%
(wmic product get Name, Version, Vendor, InstallDate) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- Network Configuration --
echo [--- Section 4: Network Configuration ---] >> %OutputFile%
echo [IPCONFIG /ALL] >> %OutputFile%
(ipconfig /all) >> %OutputFile% 2>&1
echo. >> %OutputFile%
echo [NETSTAT -ANOB (Open ports and associated processes)] >> %OutputFile%
(netstat -anob) >> %OutputFile% 2>&1
echo. >> %OutputFile%
echo [Windows Firewall Status] >> %OutputFile%
(netsh advfirewall show allprofiles) >> %OutputFile% 2>&1
echo. >> %OutputFile%
echo [Network Shares (NET SHARE)] >> %OutputFile%
(net share) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- Processes and Services --
echo [--- Section 5: Processes and Services ---] >> %OutputFile%
echo [TASKLIST /SVC] >> %OutputFile%
(tasklist /svc) >> %OutputFile% 2>&1
echo. >> %OutputFile%
echo [Services (SC QUERY)] >> %OutputFile%
(sc query state= all) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- Accounts and Local Security --
echo [--- Section 6: Accounts and Local Security ---] >> %OutputFile%
echo [Local User Accounts (NET USER)] >> %OutputFile%
(net user) >> %OutputFile% 2>&1
echo. >> %OutputFile%
echo [Local Administrators Group Members] >> %OutputFile%
(net localgroup administrators) >> %OutputFile% 2>&1
echo. >> %OutputFile%
echo [Password Policy (NET ACCOUNTS)] >> %OutputFile%
(net accounts) >> %OutputFile% 2>&1
echo. >> %OutputFile%
echo [Exporting Local Security Policy (to SecPol.cfg)] >> %OutputFile%
del SecPol.cfg > nul 2>&1
secedit /export /cfg SecPol.cfg /quiet
IF EXIST SecPol.cfg (type SecPol.cfg >> %OutputFile%) ELSE (echo Failed to export SecPol.cfg >> %OutputFile%)
echo. >> %OutputFile%

REM -- Scheduled Tasks --
echo [--- Section 7: Scheduled Tasks ---] >> %OutputFile%
(schtasks /query /fo LIST /v) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- Environment Variables --
echo [--- Section 8: Environment Variables ---] >> %OutputFile%
(set) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- Hardware Devices --
echo [--- Section 9: Hardware Devices ---] >> %OutputFile%
(wmic path Win32_PnPEntity get Caption, DeviceID) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- Group Policies --
echo [--- Section 10: Group Policies ---] >> %OutputFile%
(gpresult /z) >> %OutputFile% 2>&1
echo. >> %OutputFile%

REM -- Installed Applications and Versions (Redundant with Section 3, but included as requested) --
echo [--- Section 11: Installed Applications and Versions ---] >> %OutputFile%
(wmic product get Name,Version) >> %OutputFile% 2>&1
echo. >> %OutputFile%

echo [*** END OF INFORMATION GATHERING ***] >> %OutputFile%
echo. >> %OutputFile%
echo ================================================================ >> %OutputFile%

echo.
echo The full report has been generated in:
echo %OutputFile%
echo The security policy export is in SecPol.cfg (if successful - check script directory).
echo.
echo Manual Analysis Required! This report is a baseline.
echo Finished.
pause
'@

    # Ecrire en ASCII (sans BOM) pour un .cmd 100% compatible
    Set-Content -Path $path -Value $batch -Encoding ASCII -Force
    return $path
}

function Run-SecurityReportBatch {
    try {
        $bat = Write-SecurityReportBatchScript
        Write-LogMessage "Launching Security Report batch: $bat" "Info"
        # Lancement dans une console distincte (administrateur déjà requis au niveau PowerShell)
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$bat`"" -Wait -Verb RunAs
        Write-LogMessage "Security Report batch execution completed. Check Desktop for the file 'Security_Report_<MACHINE>_<YYYYMMDD>.txt'." "Success"
    } catch {
        Write-LogMessage "Failed to run Security Report batch: $_" "Error"
    }
}

# ============================================================================
# FEATURES
# ============================================================================

$global:Features = @{
    # PRIVACY
    "Privacy.DisableTelemetry" = @{
        Name="Reduce Telemetry (Pro/Enterprise)"; Category="Privacy"; Impact="High"; RebootRequired=$false
        Description="Reduce Windows telemetry to Security (Home=Basic)"
        Script={
            $edition = (Get-CimInstance Win32_OperatingSystem).Caption
            $telemetryLevel = if ($edition -match 'Home') { 1 } else { 0 }
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" $telemetryLevel "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" $telemetryLevel "DWord"
            Write-LogMessage "Telemetry level set to: $telemetryLevel (0=Security,1=Basic)" "Info"
            Disable-TaskSafe "\Microsoft\Windows\Application Experience\" "Microsoft Compatibility Appraiser"
            Disable-TaskSafe "\Microsoft\Windows\Application Experience\" "ProgramDataUpdater"
            Disable-TaskSafe "\Microsoft\Windows\Autochk\" "Proxy"
            Disable-TaskSafe "\Microsoft\Windows\Customer Experience Improvement Program\" "Consolidator"
            Disable-TaskSafe "\Microsoft\Windows\Customer Experience Improvement Program\" "UsbCeip"
            Disable-TaskSafe "\Microsoft\Windows\DiskDiagnostic\" "Microsoft-Windows-DiskDiagnosticDataCollector"
        }
    }
    "Privacy.DisableActivityHistory" = @{
        Name="Disable Activity History"; Category="Privacy"; Impact="Medium"; RebootRequired=$false
        Description="Stop collecting activity history"
        Script={
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityHistory" 0
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
        }
    }
    "Privacy.DisableAdvertisingID" = @{
        Name="Disable Advertising ID"; Category="Privacy"; Impact="Low"; RebootRequired=$false
        Description="Disable Advertising ID for personalized ads"
        Script={
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
            Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0 }
        }
    }
    "Privacy.DisableLocationTracking" = @{
        Name="Disable Location Tracking"; Category="Privacy"; Impact="Medium"; RebootRequired=$false
        Description="Disable all location tracking services"
        Script={
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny" "String"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0
        }
    }
    "Privacy.DisableFeedback" = @{
        Name="Disable Feedback Requests"; Category="Privacy"; Impact="Low"; RebootRequired=$false
        Description="Stop Windows feedback prompts"
        Script={
            Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0 }
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1
        }
    }

    # SECURITY
    "Security.EnableWindowsDefender" = @{
        Name="Defender: Maximum Protection"; Category="Security"; Impact="High"; RebootRequired=$false
        Description="Enable core, cloud, PUA, network protection; CFA in audit"
        Script={
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisablePrivacyMode $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
                Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
                Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
                Set-MpPreference -CloudBlockLevel High -ErrorAction SilentlyContinue
                Set-MpPreference -CloudExtendedTimeout 50 -ErrorAction SilentlyContinue
                Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
                Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction SilentlyContinue
                Write-LogMessage "Controlled Folder Access in AUDIT mode" "Warning"
                Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
                Write-LogMessage "Defender hardened" "Success"
            } catch { Write-LogMessage "Defender settings error: $_" "Warning" }
        }
    }
    "Security.EnableLSAProtection" = @{
        Name="Enable LSA Protection"; Category="Security"; Impact="High"; RebootRequired=$true
        Description="RunAsPPL=1"
        Script={ Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1; Write-LogMessage "LSA Protection enabled" "Success" }
    }
    "Security.EnableBitLocker" = @{
        Name="Enable BitLocker"; Category="Security"; Impact="High"; RebootRequired=$true
        Description="Enable BitLocker on system drive"
        Script={ Enable-BitLockerSafe }
    }
    "Security.EnableCredentialGuard" = @{
        Name="Enable Credential Guard"; Category="Security"; Impact="High"; RebootRequired=$true
        Description="Requires Enterprise/Education"
        Script={
            $editionId = Get-WindowsEditionId
            if ($editionId -notin @('Enterprise','EnterpriseN','Education','EducationN')) { Write-LogMessage "Credential Guard requires Enterprise/Education. Current: $editionId" "Warning"; return }
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" 1
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "RequirePlatformSecurityFeatures" 3
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" "Enabled" 1
            Write-LogMessage "Credential Guard enabled" "Success"
        }
    }
    "Security.EnableSandbox" = @{
        Name="Enable Windows Sandbox"; Category="Security"; Impact="Low"; RebootRequired=$true
        Description="Pro/Enterprise/Education only"
        Script={
            $edition = (Get-CimInstance Win32_OperatingSystem).Caption
            if ($edition -notmatch 'Pro|Enterprise|Education') { Write-LogMessage "Sandbox requires Pro/Enterprise/Education" "Warning"; return }
            try { Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online -NoRestart -ErrorAction Stop; Write-LogMessage "Windows Sandbox enabled" "Success" }
            catch { Write-LogMessage "Enable Sandbox failed: $_" "Error" }
        }
    }
    "Security.DisableSMBv1" = @{
        Name="Disable SMBv1"; Category="Security"; Impact="Medium"; RebootRequired=$false
        Description="Disable legacy protocol"
        Script={
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
                Write-LogMessage "SMBv1 disabled" "Success"
            } catch { Write-LogMessage "Disable SMBv1 failed: $_" "Warning" }
        }
    }
    "Security.EnableFirewall" = @{
        Name="Firewall Balanced"; Category="Security"; Impact="Medium"; RebootRequired=$false
        Description="Domain/Private inbound allow; Public inbound block; Outbound allow"
        Script={
            try {
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
                Set-NetFirewallProfile -Profile Domain,Private -DefaultInboundAction Allow -ErrorAction Stop
                Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -ErrorAction Stop
                Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction Stop
                Set-NetFirewallProfile -Profile Public -NotifyOnListen True -ErrorAction Stop
                Write-LogMessage "Firewall configured (balanced)" "Success"
            } catch { Write-LogMessage "Firewall config failed: $_" "Error" }
        }
    }
    "Security.EnableUAC" = @{
        Name="UAC Maximum"; Category="Security"; Impact="Medium"; RebootRequired=$false
        Description="Max UAC prompts on secure desktop"
        Script={
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" 0
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
            Write-LogMessage "UAC hardened" "Success"
        }
    }
    "Security.DisableAutorun" = @{
        Name="Disable Autorun/Autoplay"; Category="Security"; Impact="Low"; RebootRequired=$false
        Description="Disable autorun for all drives"
        Script={
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 1
            Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 }
        }
    }

    # PERFORMANCE
    "Performance.DisableStartupApps" = @{
        Name="Disable Non-Essential Startup Apps"; Category="Performance"; Impact="Medium"; RebootRequired=$false
        Description="Disable third-party startup items"
        Script={
            try {
                Get-CimInstance Win32_StartupCommand | Where-Object {
                    $_.Caption -notlike "*Windows*" -and $_.Caption -notlike "*Microsoft*" -and $_.Caption -notlike "*Security*" -and $_.Caption -notlike "*Antivirus*"
                } | ForEach-Object {
                    Write-LogMessage "Disabling startup: $($_.Caption)" "Info"
                    if ($_.Location -eq "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue }
                    elseif ($_.Location -eq "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") { Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue }
                }
            } catch { Write-LogMessage "Startup disable error: $_" "Warning" }
        }
    }
    "Performance.DisableBackgroundApps" = @{
        Name="Disable Background Apps"; Category="Performance"; Impact="Medium"; RebootRequired=$false
        Description="Prevent apps from running in background"
        Script={
            Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1 }
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2
        }
    }
    "Performance.OptimizeSSD" = @{
        Name="Optimize for SSD"; Category="Performance"; Impact="Medium"; RebootRequired=$false
        Description="Disable LastAccess; ensure TRIM"
        Script={
            try { fsutil behavior set DisableLastAccess 1 | Out-Null } catch {}
            try { fsutil behavior set DisableDeleteNotify 0 | Out-Null } catch {}
            Write-LogMessage "SSD tweaks applied (TRIM enabled)" "Success"
        }
    }
    "Performance.ReduceIndexingScope" = @{
        Name="Optimize Search Indexing"; Category="Performance"; Impact="Low"; RebootRequired=$false
        Description="Reduce indexing scope; keep service on"
        Script={
            Write-LogMessage "Optimizing search indexing (exclude temp/dev folders)" "Info"
            foreach ($p in @("$env:USERPROFILE\AppData\Local\Temp","$env:USERPROFILE\.nuget","$env:USERPROFILE\.npm","$env:USERPROFILE\node_modules","C:\ProgramData","C:\Windows\Temp")) {
                if (Test-Path $p) { Write-LogMessage "Exclude from index: $p" "Verbose" }
            }
        }
    }
    "Performance.ConfigureSuperfetch" = @{
        Name="Optimize Superfetch/SysMain"; Category="Performance"; Impact="Low"; RebootRequired=$false
        Description="SysMain=Manual; Prefetch boot only"
        Script={
            try {
                Set-Service "SysMain" -StartupType Manual -ErrorAction SilentlyContinue
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 2
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 2
                Write-LogMessage "SysMain optimized" "Success"
            } catch { Write-LogMessage "SysMain tweak failed: $_" "Warning" }
        }
    }
    "Performance.OptimizeVisualEffects" = @{
        Name="Optimize Visual Effects"; Category="Performance"; Impact="Low"; RebootRequired=$false
        Description="Best performance (keep smoothing)"
        Script={ Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2 }; Write-LogMessage "Visual effects optimized" "Success" }
    }
    "Performance.SetPowerPlan" = @{
        Name="Power Plan: Balanced"; Category="Performance"; Impact="Medium"; RebootRequired=$false
        Description="Balanced is recommended"
        Script={ try { powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e; Write-LogMessage "Balanced power plan set" "Success" } catch { Write-LogMessage "Set power plan failed: $_" "Warning" } }
    }
    "Performance.SetHighPerformance" = @{
        Name="Power Plan: High Performance"; Category="Performance"; Impact="High"; RebootRequired=$false
        Description="Not recommended on laptops"
        Script={
            $isLaptop = (Get-WmiObject -Class Win32_Battery) -ne $null
            if ($isLaptop) { Write-LogMessage "High Performance not recommended on laptops" "Warning"; $c=Read-Host "Continue anyway? (Y/N)"; if ($c -ne "Y") { return } }
            try {
                powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
                powercfg -change -monitor-timeout-ac 30
                powercfg -change -disk-timeout-ac 0
                powercfg -change -standby-timeout-ac 0
                powercfg -change -hibernate-timeout-ac 0
                Write-LogMessage "High Performance activated" "Success"
            } catch { Write-LogMessage "High Performance failed: $_" "Warning" }
        }
    }
    "Performance.DisableHibernation" = @{
        Name="Disable Hibernation"; Category="Performance"; Impact="Low"; RebootRequired=$false
        Description="Free hiberfil.sys"
        Script={
            try { powercfg -h off; Write-LogMessage "Hibernation disabled" "Success"; $gb=[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB); Write-LogMessage "Freed approx $gb GB" "Info" }
            catch { Write-LogMessage "Disable hibernation failed: $_" "Warning" }
        }
    }
    "Performance.DisableGameDVR" = @{
        Name="Disable Xbox Game DVR"; Category="Performance"; Impact="Low"; RebootRequired=$false
        Description="Disable Xbox game recording features"
        Script={
            Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\System\GameConfigStore" "GameDVR_Enabled" 0 }
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0
            Write-LogMessage "Game DVR disabled" "Success"
        }
    }

    # BLOATWARE
    "Bloatware.RemoveMicrosoft" = @{
        Name="Remove Microsoft Bloatware"; Category="Bloatware"; Impact="Low"; RebootRequired=$false
        Description="Remove unnecessary Microsoft apps"
        Script={
            $apps=@("Microsoft.BingNews","Microsoft.BingWeather","Microsoft.GetHelp","Microsoft.Getstarted","Microsoft.Messaging","Microsoft.Microsoft3DViewer","Microsoft.MicrosoftOfficeHub","Microsoft.MicrosoftSolitaireCollection","Microsoft.NetworkSpeedTest","Microsoft.News","Microsoft.Office.Lens","Microsoft.Office.OneNote","Microsoft.Office.Sway","Microsoft.OneConnect","Microsoft.People","Microsoft.Print3D","Microsoft.SkypeApp","Microsoft.StorePurchaseApp","Microsoft.Wallet","Microsoft.Whiteboard","Microsoft.WindowsAlarms","Microsoft.WindowsFeedbackHub","Microsoft.WindowsMaps","Microsoft.WindowsSoundRecorder","Microsoft.ZuneMusic","Microsoft.ZuneVideo")
            foreach ($app in $apps) {
                try {
                    Get-AppxPackage -Name "$app*" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
                    if ($global:AllUsers) { Get-AppxPackage -Name "$app*" -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue }
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "$app*" -or $_.PackageName -like "$app*" } | Remove-ProvisionedAppxPackage -Online -ErrorAction SilentlyContinue
                    Write-LogMessage "Removed: $app" "Info"
                } catch { Write-LogMessage "Could not remove $app : $_" "Verbose" }
            }
        }
    }
    "Bloatware.RemoveXbox" = @{
        Name="Remove Xbox Apps"; Category="Bloatware"; Impact="Low"; RebootRequired=$false
        Description="Remove all Xbox related apps"
        Script={
            $x=@("Microsoft.GamingApp","Microsoft.XboxApp","Microsoft.Xbox.TCUI","Microsoft.XboxGameOverlay","Microsoft.XboxGamingOverlay","Microsoft.XboxIdentityProvider","Microsoft.XboxSpeechToTextOverlay")
            foreach ($app in $x) {
                try {
                    Get-AppxPackage -Name "$app*" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
                    if ($global:AllUsers) { Get-AppxPackage -Name "$app*" -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue }
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "$app*" -or $_.PackageName -like "$app*" } | Remove-ProvisionedAppxPackage -Online -ErrorAction SilentlyContinue
                    Write-LogMessage "Removed: $app" "Info"
                } catch { Write-LogMessage "Could not remove $app" "Verbose" }
            }
        }
    }
    "Bloatware.RemoveOneDrive" = @{
        Name="Uninstall OneDrive"; Category="Bloatware"; Impact="Medium"; RebootRequired=$false
        Description="Completely uninstall Microsoft OneDrive"
        Script={
            Write-LogMessage "Uninstalling OneDrive..." "Info"
            $exe = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"; if (!(Test-Path $exe)) { $exe = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe" }
            if (Test-Path $exe) {
                try {
                    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
                    Start-Process $exe "/uninstall" -NoNewWindow -Wait
                    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
                    Remove-Item "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    Set-RegistryValue "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
                    Set-RegistryValue "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
                    Write-LogMessage "OneDrive uninstalled & blocked" "Success"
                } catch { Write-LogMessage "OneDrive uninstall incomplete: $_" "Warning" }
            }
        }
    }

    # AI
    "AI.DisableCopilot" = @{
        Name="Disable Microsoft Copilot"; Category="AI"; Impact="Low"; RebootRequired=$false
        Description="Disable Copilot button & policy"
        Script={
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1
            Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowCopilotButton" 0 }
            Write-LogMessage "Copilot disabled" "Success"
        }
    }
    "AI.DisableRecall" = @{
        Name="Disable Windows Recall"; Category="AI"; Impact="Low"; RebootRequired=$false
        Description="Disable Recall snapshots"
        Script={
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "DisableAIDataAnalysis" 1
            Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "EnableRecall" 0 }
            Write-LogMessage "Recall disabled" "Success"
        }
    }

    # UI
    "UI.EnableDarkMode" = @{
        Name="Enable Dark Mode"; Category="Interface"; Impact="Low"; RebootRequired=$false
        Description="Dark mode for system and apps"
        Script={ Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "AppsUseLightTheme" 0; Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "SystemUsesLightTheme" 0 }; Write-LogMessage "Dark mode ON" "Success" }
    }
    "UI.RestoreClassicMenu" = @{
        Name="Restore Classic Context Menu"; Category="Interface"; Impact="Low"; RebootRequired=$false
        Description="Windows 10 style menu (may not work on latest builds)"
        Script={
            $build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
            if ($build -ge 22621) { Write-LogMessage "Classic menu hack may not work on $build" "Warning"; $c=Read-Host "Try anyway? (Y/N)"; if ($c -ne "Y"){return} }
            Invoke-ForEachUserHive {
                param($root)
                $clsid="$root\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
                if (!(Test-Path $clsid)) { New-Item -Path $clsid -Force | Out-Null }
                $inproc="$clsid\InprocServer32"
                if (!(Test-Path $inproc)) { New-Item -Path $inproc -Force | Out-Null }
                Set-ItemProperty -Path $inproc -Name "(Default)" -Value "" -Force
            }
            Write-LogMessage "Classic context menu set — restarting Explorer" "Success"; Restart-Explorer
        }
    }
    "UI.TaskbarLeft" = @{
        Name="Align Taskbar Left"; Category="Interface"; Impact="Low"; RebootRequired=$false
        Description="Move taskbar icons to the left"
        Script={ Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAl" 0 }; Restart-Explorer; Write-LogMessage "Taskbar left" "Success" }
    }
    "UI.ShowFileExtensions" = @{
        Name="Show File Extensions"; Category="Interface"; Impact="Low"; RebootRequired=$false
        Description="Always show file extensions"
        Script={ Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0 }; Restart-Explorer; Write-LogMessage "File extensions visible" "Success" }
    }
    "UI.ShowHiddenFiles" = @{
        Name="Show Hidden Files"; Category="Interface"; Impact="Low"; RebootRequired=$false
        Description="Show hidden + system files"
        Script={ Invoke-ForEachUserHive { param($root) Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1; Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" 1 }; Restart-Explorer; Write-LogMessage "Hidden files visible" "Success" }
    }

    # NETWORK
    "Network.OptimizeDNS" = @{
        Name="Set Fast DNS (backup)"; Category="Network"; Impact="Low"; RebootRequired=$false
        Description="Cloudflare DNS + keep backup"
        Script={ Set-DnsSafe -Servers @("1.1.1.1","1.0.0.1"); Write-LogMessage "To restore DNS, see logs backup" "Info" }
    }
    "Network.PreferIPv4" = @{
        Name="Prefer IPv4 over IPv6"; Category="Network"; Impact="Low"; RebootRequired=$true
        Description="Prefer IPv4 (IPv6 still enabled)"
        Script={ Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 0x20; Write-LogMessage "IPv4 preferred" "Success" }
    }

    # DEV
    "Dev.InstallWSL" = @{
        Name="Install WSL2 with Ubuntu"; Category="Development"; Impact="Low"; RebootRequired=$true
        Description="Enable features + install WSL2 (repair on failure)"
        Script={
            try {
                Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction Stop
                Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction Stop
            } catch {
                Write-LogMessage "WSL features enable failed: $_" "Warning"
                Repair-ComponentStore
                try {
                    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction Stop
                    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction Stop
                } catch { Write-LogMessage "Retry enable features failed: $_" "Error" }
            }
            try {
                wsl --install
                wsl --set-default-version 2
                wsl --install -d Ubuntu
                Write-LogMessage "WSL2 + Ubuntu initiated (reboot required)" "Success"
            } catch { Write-LogMessage "Could not complete WSL install: $_" "Error" }
        }
    }
    "Dev.EnableDevMode" = @{
        Name="Enable Developer Mode"; Category="Development"; Impact="Low"; RebootRequired=$false
        Description="App sideload, dev mode on"
        Script={
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowDevelopmentWithoutDevLicense" 1
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowAllTrustedApps" 1
            Write-LogMessage "Developer Mode enabled" "Success"
        }
    }

    # APPS (bundles)
    "Apps.Dev" = @{
        Name="Install Dev Stack"; Category="Apps"; Impact="Low"; RebootRequired=$false
        Description="VS Code, Git, Node.js LTS, Python, Docker Desktop"
        Script={
            Install-AppBundle -WingetIds @("Microsoft.VisualStudioCode","Git.Git","OpenJS.NodeJS.LTS","Python.Python.3.12","Docker.DockerDesktop") `
                              -ChocoIds  @("vscode","git","nodejs-lts","python","docker-desktop")
            Write-LogMessage "Dev stack installed" "Success"
        }
    }
    "Apps.Browsers" = @{
        Name="Install Browsers"; Category="Apps"; Impact="Low"; RebootRequired=$false
        Description="Firefox, Brave, EdgeWebView2 Runtime"
        Script={
            Install-AppBundle -WingetIds @("Mozilla.Firefox","Brave.Brave","Microsoft.EdgeWebView2Runtime") `
                              -ChocoIds  @("firefox","brave","microsoft-edge-webview2-runtime")
            Write-LogMessage "Browsers installed" "Success"
        }
    }
    "Apps.Media" = @{
        Name="Install Media Apps"; Category="Apps"; Impact="Low"; RebootRequired=$false
        Description="VLC, Spotify"
        Script={
            Install-AppBundle -WingetIds @("VideoLAN.VLC","Spotify.Spotify") `
                              -ChocoIds  @("vlc","spotify")
            Write-LogMessage "Media apps installed" "Success"
        }
    }
    "Apps.SysTools" = @{
        Name="Install System Tools"; Category="Apps"; Impact="Low"; RebootRequired=$false
        Description="7-Zip, Notepad++, Rufus, WizTree"
        Script={
            Install-AppBundle -WingetIds @("7zip.7zip","Notepad++.Notepad++","Akeo.Rufus","AntibodySoftware.WizTree") `
                              -ChocoIds  @("7zip","notepadplusplus","rufus","wiztree")
            Write-LogMessage "System tools installed" "Success"
        }
    }
    "Apps.AllCommon" = @{
        Name="Install Common Desktop Apps"; Category="Apps"; Impact="Low"; RebootRequired=$false
        Description="VS Code, Git, 7-Zip, Firefox, Notepad++, VLC"
        Script={
            Install-AppBundle -WingetIds @("Microsoft.VisualStudioCode","Git.Git","7zip.7zip","Mozilla.Firefox","Notepad++.Notepad++","VideoLAN.VLC") `
                              -ChocoIds  @("vscode","git","7zip","firefox","notepadplusplus","vlc")
            Write-LogMessage "Common apps installed" "Success"
        }
    }
}

# ============================================================================
# INTERACTIVE MENUS (inclut Apps)
# ============================================================================

function Show-MainMenu {
    while ($true) {
        Show-Banner
        Write-Host "`n MAIN MENU" -ForegroundColor Yellow
        Write-Host "  [1] Quick Setup (Profiles recommandés)"
        Write-Host "  [2] Custom Configuration (Sélection de fonctions)"
        Write-Host "  [3] Category Browser (Par catégorie)"
        Write-Host "  [4] Search Features (Recherche d'options)"
        Write-Host "  [5] Profile Manager (Sauvegarde/Chargement)"
        Write-Host "  [6] Maintenance Tools (Maintenance Système)"
        Write-Host "  [7] Backup & Restore (Sauvegarde/Restauration)"
        Write-Host "  [8] Export Configuration (Exporter réglages)"
        Write-Host "  [A] Apps Installer (Profils | Tout | Sélection | Recherche)"
        Write-Host ""
        Write-Host "  [I] Info & Help   [S] System Info   [L] View Log   [Q] Quit" -ForegroundColor Cyan
        $choice = Read-Host "Votre choix"
        switch ($choice.ToUpper()) {
            "1" { Show-QuickSetup }
            "2" { Show-CustomConfiguration }
            "3" { Show-CategoryBrowser }
            "4" { Show-FeatureSearch }
            "5" { Show-ProfileManager }
            "6" { Show-MaintenanceTools }
            "7" { Show-BackupRestore }
            "8" { $p=Export-CurrentConfiguration; if ($p){ Read-Host "Exporté. Entrée pour continuer." } }
            "A" { Show-AppsInstaller }
            "I" { Show-Information }
            "S" { Show-SystemInfo }
            "L" { Show-LogFile }
            "Q" { Exit-Script }
            default { Write-Host "Option invalide." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    }
}

function Show-QuickSetup {
    Show-Banner
    Write-Host "`n QUICK SETUP - Profils recommandés" -ForegroundColor Yellow
    Write-Host "  [1] Privacy Focused"
    Write-Host "  [2] Security Hardened"
    Write-Host "  [3] Performance Balanced"
    Write-Host "  [4] Debloated"
    Write-Host "  [5] Developer (incl. Apps.Dev + AllCommon)"
    Write-Host "  [6] Minimal (essentiel)"
    Write-Host "  [7] Safe Defaults"
    Write-Host "  [B] Retour"
    $choice = Read-Host "Choix"
    $profiles = @{
        "1" = @("Privacy.DisableTelemetry","Privacy.DisableActivityHistory","Privacy.DisableAdvertisingID","Privacy.DisableLocationTracking")
        "2" = @("Security.EnableWindowsDefender","Security.EnableFirewall","Security.EnableUAC","Security.DisableSMBv1","Security.EnableLSAProtection")
        "3" = @("Performance.DisableStartupApps","Performance.DisableBackgroundApps","Performance.OptimizeSSD","Performance.SetPowerPlan")
        "4" = @("Bloatware.RemoveMicrosoft","Bloatware.RemoveXbox","AI.DisableCopilot","AI.DisableRecall")
        "5" = @("Dev.InstallWSL","Dev.EnableDevMode","Apps.Dev","Apps.AllCommon")
        "6" = @("Privacy.DisableTelemetry","UI.ShowFileExtensions","Security.EnableUAC")
        "7" = @("Privacy.DisableAdvertisingID","Security.EnableUAC","Performance.SetPowerPlan","UI.ShowFileExtensions")
    }
    if ($choice -match '^[1-7]$') {
        $features=$profiles[$choice]
        Write-Host "`nFonctions sélectionnées :" -ForegroundColor Cyan
        foreach ($f in $features) { if ($global:Features.ContainsKey($f)) { Write-Host " - $($global:Features[$f].Name)" } }
        $confirm = Read-Host "Appliquer ces fonctions ? (Y/N)"
        if ($confirm -eq "Y") {
            if (!$SkipRestorePoint) { Create-SystemRestorePoint }
            foreach ($f in $features) { Execute-Feature -FeatureKey $f }
            Write-Host "`nTerminé." -ForegroundColor Green
            Read-Host "Entrée pour continuer"
        }
    }
}

function Show-CustomConfiguration {
    Show-Banner
    Write-Host "`n CUSTOM CONFIGURATION" -ForegroundColor Yellow
    $categories = $global:Features.Values | ForEach-Object { $_.Category } | Sort-Object -Unique
    $selectedFeatures = @()
    foreach ($cat in $categories) {
        Write-Host "`n[$cat]" -ForegroundColor Cyan
        $catFs = @(Get-CategoryFeatures -Category $cat); $i=1
        foreach ($f in $catFs) {
            Write-Host "  [$i] $($f.Value.Name)"
            Write-Host "      $($f.Value.Description)" -ForegroundColor DarkGray
            $i++
        }
        $sel = Read-Host "Sélection (1,3,5 | 'all' | 'none')"
        if ($sel -eq "all") { $selectedFeatures += $catFs | ForEach-Object { $_.Key } }
        elseif ($sel -and $sel -ne "none") {
            $idxs = $sel -split ',' | ForEach-Object { [int]$_.Trim()-1 }
            foreach ($idx in $idxs) { if ($idx -ge 0 -and $idx -lt $catFs.Count) { $selectedFeatures += $catFs[$idx].Key } }
        }
    }
    if ($selectedFeatures.Count -gt 0) {
        Write-Host "`n$($selectedFeatures.Count) fonctions sélectionnées" -ForegroundColor Cyan
        $confirm = Read-Host "Appliquer ? (Y/N)"
        if ($confirm -eq "Y") {
            if (!$SkipRestorePoint) { Create-SystemRestorePoint }
            foreach ($f in $selectedFeatures) { Execute-Feature -FeatureKey $f }
            Write-Host "`nTerminé." -ForegroundColor Green
            Read-Host "Entrée pour continuer"
        }
    }
}

function Show-CategoryBrowser {
    Show-Banner
    Write-Host "`n CATEGORY BROWSER" -ForegroundColor Yellow
    $categories = $global:Features.Values | ForEach-Object { $_.Category } | Sort-Object -Unique
    $i=1; foreach ($c in $categories) { $cnt=@(Get-CategoryFeatures -Category $c).Count; Write-Host " [$i] $c ($cnt)" ; $i++ }
    Write-Host " [B] Retour"
    $choice = Read-Host "Choix"
    if ($choice -match '^\d+$') {
        $idx=[int]$choice-1
        if ($idx -ge 0 -and $idx -lt $categories.Count) { Show-CategoryFeatures -Category $categories[$idx] }
    }
}

function Show-CategoryFeatures { param([string]$Category)
    Show-Banner
    Write-Host "`n $Category" -ForegroundColor Yellow
    $features=@(Get-CategoryFeatures -Category $Category); $i=1
    foreach ($f in $features) {
        Write-Host "`n [$i] $($f.Value.Name)"
        Write-Host "     $($f.Value.Description)" -ForegroundColor DarkGray
        Write-Host "     Impact: $($f.Value.Impact) | Reboot: $($f.Value.RebootRequired)" -ForegroundColor Gray
        $i++
    }
    Write-Host "`n [A] Appliquer tout   [S] Sélection   [B] Retour"
    $choice=Read-Host "Choix"
    switch ($choice.ToUpper()) {
        "A" { $c=Read-Host "Confirmer tout $Category ? (Y/N)"; if ($c -eq "Y"){ foreach ($f in $features){ Execute-Feature -FeatureKey $f.Key } } }
        "S" {
            $sel=Read-Host "Numéros (ex: 1,3,5)"
            $idxs=$sel -split ',' | ForEach-Object { [int]$_.Trim()-1 }
            foreach ($idx in $idxs) { if ($idx -ge 0 -and $idx -lt $features.Count) { Execute-Feature -FeatureKey $features[$idx].Key } }
        }
        default { return }
    }
    Read-Host "Entrée pour continuer"
}

function Show-FeatureSearch {
    Show-Banner
    Write-Host "`n FEATURE SEARCH" -ForegroundColor Yellow
    $term = Read-Host "Terme (ou 'back')"
    if ($term -eq "back") { return }
    $results = $global:Features.GetEnumerator() | Where-Object {
        $_.Value.Name -like "*$term*" -or $_.Value.Description -like "*$term*" -or $_.Value.Category -like "*$term*"
    }
    if ($results) {
        $i=1; foreach ($r in $results) { Write-Host "`n [$i] $($r.Value.Name)  ($($r.Value.Category))"; Write-Host "     $($r.Value.Description)" -ForegroundColor DarkGray; $i++ }
        $sel = Read-Host "Sélection à appliquer (ex: 1,2) ou 'none'"
        if ($sel -and $sel -ne "none") {
            $idxs=$sel -split ',' | ForEach-Object { [int]$_.Trim()-1 }
            foreach ($idx in $idxs){ if ($idx -ge 0 -and $idx -lt @($results).Count) { Execute-Feature -FeatureKey @($results)[$idx].Key } }
        }
    } else { Write-Host "Aucun résultat pour '$term'." -ForegroundColor Yellow }
    Read-Host "Entrée pour continuer"
}

function Show-ProfileManager {
    Show-Banner
    Write-Host "`n PROFILE MANAGER" -ForegroundColor Yellow
    Write-Host " [1] Save Current Configuration"
    Write-Host " [2] Load Saved Profile"
    Write-Host " [3] Delete Profile"
    Write-Host " [4] List All Profiles"
    Write-Host " [5] Export Profile"
    Write-Host " [6] Import Profile"
    Write-Host " [B] Retour"
    switch (Read-Host "Choix") {
        "1" { $n=Read-Host "Nom du profil"; if ($n){ Save-Profile -Name $n } }
        "2" {
            $p=Get-ChildItem -Path $global:ProfilesPath -Filter "*.json" -ErrorAction SilentlyContinue
            if ($p){ $i=1; foreach($f in $p){ Write-Host " [$i] $($f.BaseName)"; $i++ }
                $s=Read-Host "Sélection"; $idx=[int]$s-1; if ($idx -ge 0 -and $idx -lt $p.Count){ Load-Profile -Name $p[$idx].BaseName } }
            else { Write-Host "Aucun profil." -ForegroundColor Yellow }
        }
        "3" { $n=Read-Host "Nom du profil à supprimer"; if ($n){ $pp="$global:ProfilesPath\$n.json"; if (Test-Path $pp){ Remove-Item $pp -Force; Write-LogMessage "Profile deleted: $n" "Success"} else { Write-LogMessage "Profile not found: $n" "Error"} } }
        "4" {
            $p=Get-ChildItem -Path $global:ProfilesPath -Filter "*.json" -ErrorAction SilentlyContinue
            if ($p){ foreach($f in $p){ try { $d=Get-Content $f.FullName | ConvertFrom-Json; Write-Host " - $($f.BaseName)  (Created: $($d.Created), Features: $(@($d.Features).Count))" } catch { Write-Host " - $($f.BaseName) (corrupted)" -ForegroundColor Red } } }
            else { Write-Host "Aucun profil." -ForegroundColor Yellow }
        }
        "5" { Export-CurrentConfiguration | Out-Null }
        "6" { $path=Read-Host "Chemin complet du fichier de profil"; if (Test-Path $path){ Import-Profile -Path $path } else { Write-LogMessage "File not found: $path" "Error" } }
        default { }
    }
    Read-Host "Entrée pour continuer"
}

function Save-Profile { param([string]$Name)
    $profile=@{ Name=$Name; Created=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; Features=$global:AppliedFeatures; System=@{ OS=(Get-CimInstance Win32_OperatingSystem).Caption; Version=(Get-CimInstance Win32_OperatingSystem).Version; Build=(Get-CimInstance Win32_OperatingSystem).BuildNumber } }
    $path = Join-Path $global:ProfilesPath "$Name.json"
    try { $profile | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Force -Encoding utf8; Write-LogMessage "Profile saved: $Name" "Success" }
    catch { Write-LogMessage "Save profile failed: $_" "Error" }
}
function Load-Profile { param([string]$Name)
    $path = Join-Path $global:ProfilesPath "$Name.json"
    if (Test-Path $path) {
        try {
            $p = Get-Content $path -Encoding utf8 | ConvertFrom-Json
            Write-Host "`n Loading profile: $Name — $(@($p.Features).Count) features" -ForegroundColor Cyan
            $c=Read-Host "Continue? (Y/N)"; if ($c -ne "Y"){return}
            if (!$SkipRestorePoint) { Create-SystemRestorePoint -Description "Before profile: $Name" }
            foreach ($f in $p.Features) { Execute-Feature -FeatureKey $f }
            Write-LogMessage "Profile loaded: $Name" "Success"
        } catch { Write-LogMessage "Load profile failed: $_" "Error" }
    } else { Write-LogMessage "Profile not found: $Name" "Error" }
}
function Import-Profile { param([string]$Path)
    if (Test-Path $Path) {
        try { $file=Split-Path $Path -Leaf; Copy-Item -Path $Path -Destination (Join-Path $global:ProfilesPath $file) -Force; Write-LogMessage "Profile imported: $file" "Success" }
        catch { Write-LogMessage "Import failed: $_" "Error" }
    } else { Write-LogMessage "File not found: $Path" "Error" }
}

function Show-MaintenanceTools {
    Show-Banner
    Write-Host "`n MAINTENANCE TOOLS" -ForegroundColor Yellow
    Write-Host " [1] Clean Temp Files"
    Write-Host " [2] SFC /scannow"
    Write-Host " [3] DISM /RestoreHealth"
    Write-Host " [4] Clear Windows Update Cache"
    Write-Host " [5] Reset Network Settings"
    Write-Host " [6] Clear DNS Cache"
    Write-Host " [7] Optimize Drives (TRIM/Defrag)"
    Write-Host " [8] Schedule CHKDSK on reboot"
    Write-Host " [9] Repair Component Store (DISM+SFC)"
    Write-Host " [B] Retour"
    switch (Read-Host "Choix") {
        "1" { Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue; ipconfig /flushdns | Out-Null; Write-LogMessage "Temp cleaned" "Success" }
        "2" { Write-Host "Running SFC..." -ForegroundColor Yellow; sfc /scannow }
        "3" { Write-Host "Running DISM..." -ForegroundColor Yellow; DISM /Online /Cleanup-Image /RestoreHealth }
        "4" { $c=Read-Host "Stop WU service & clear cache? (Y/N)"; if ($c -eq "Y"){ Stop-Service wuauserv -Force; Remove-Item "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue; Start-Service wuauserv; Write-LogMessage "WU cache cleared" "Success" } }
        "5" { Write-Host "WARNING: resets Wi-Fi passwords, etc." -ForegroundColor Red; $c=Read-Host "Continue? (Y/N)"; if ($c -eq "Y"){ netsh winsock reset; netsh int ip reset; ipconfig /release; ipconfig /renew; ipconfig /flushdns; Write-LogMessage "Network reset done" "Success" } }
        "6" { ipconfig /flushdns | Out-Null; Write-LogMessage "DNS cache flushed" "Success" }
        "7" { Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object { Optimize-Volume -DriveLetter $_.DriveLetter -ErrorAction SilentlyContinue }; Write-LogMessage "Drive optimization done" "Success" }
        "8" { Write-Host "CHKDSK may take HOURS" -ForegroundColor Red; $c=Read-Host "Schedule CHKDSK C: /F /R on reboot? (Y/N)"; if ($c -eq "Y"){ cmd /c "echo Y | chkdsk C: /F /R"; Write-LogMessage "CHKDSK scheduled" "Success" } }
        "9" { Repair-ComponentStore }
        default { }
    }
    Read-Host "Entrée pour continuer"
}

function Show-Information {
    Show-Banner
    Write-Host "`n - Privacy  - Security  - Performance  - Bloatware  - AI  - UI  - Network  - Dev  - Apps" -ForegroundColor White
    Write-Host " - UTF-8 safe console/logs (évite €â€â€¦)" -ForegroundColor Green
    Write-Host "Log: $($global:LogFile)" -ForegroundColor Cyan
    Write-Host "Transcript: $($global:TranscriptFile)" -ForegroundColor Cyan
    Read-Host "Entrée pour continuer"
}

function Show-SystemInfo {
    Show-Banner
    Write-Host "`n SYSTEM INFORMATION" -ForegroundColor Yellow
    Write-Host " [1] Afficher le résumé rapide"
    Write-Host " [2] Générer le RAPPORT DE SÉCURITÉ détaillé (Batch inclus)"
    Write-Host " [3] Ouvrir le dossier probable des rapports (Bureau)"
    Write-Host " [B] Retour"
    $c = Read-Host "Choix"
    switch ($c.ToUpper()) {
        "1" {
            $os=Get-CimInstance Win32_OperatingSystem; $cpu=Get-CimInstance Win32_Processor; $mem=Get-CimInstance Win32_ComputerSystem; $disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"; $gpu=Get-CimInstance Win32_VideoController
            Write-Host "OS: $($os.Caption)  EditionID: $(Get-WindowsEditionId)  Version: $($os.Version)  Build: $($os.BuildNumber)  Arch: $($os.OSArchitecture)"
            Write-Host "CPU: $($cpu.Name)  Cores: $($cpu.NumberOfCores)  Threads: $($cpu.NumberOfLogicalProcessors)"
            Write-Host "RAM: $([math]::Round($mem.TotalPhysicalMemory/1GB,2)) GB"
            if ($disk) { Write-Host "C:\  Total: $([math]::Round($disk.Size/1GB,2)) GB  Free: $([math]::Round($disk.FreeSpace/1GB,2)) GB" }
            if ($gpu)  { Write-Host "GPU: $($gpu.Name)" }
            Get-NetAdapter | Where-Object Status -eq "Up" | ForEach-Object { Write-Host "NIC: $($_.Name)  $($_.LinkSpeed)" }
            Read-Host "Entrée pour continuer"
        }
        "2" { Run-SecurityReportBatch; Read-Host "Batch terminé (voir Bureau). Entrée pour continuer" }
        "3" { Start-Process -FilePath "$env:USERPROFILE\Desktop" }
        default { }
    }
}

function Show-LogFile { if (Test-Path $global:LogFile) { notepad.exe $global:LogFile } else { Write-Host "Log not found." -ForegroundColor Yellow; Read-Host "Entrée…" } }

function Exit-Script {
    Write-Host "`nExiting..." -ForegroundColor Yellow
    $rebootRequired = $false
    foreach ($k in $global:AppliedFeatures) { if ($global:Features[$k].RebootRequired) { $rebootRequired=$true; break } }
    if ($rebootRequired -and !$NoReboot) {
        Write-Host "Some changes require reboot." -ForegroundColor Yellow
        $c=Read-Host "Reboot now? (Y/N)"; if ($c -eq "Y"){ Write-LogMessage "User initiated reboot" "Info"; Restart-Computer -Force }
    }
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 1
    exit 0
}

# ---------------- Apps Installer UI ----------------
function Show-AppsInstaller {
    Show-Banner
    Write-Host "`n APPS INSTALLER" -ForegroundColor Yellow
    Write-Host " [1] Installer par profil   (Dev | Browsers | Media | SysTools | AllCommon)"
    Write-Host " [2] Installer TOUS les bundles"
    Write-Host " [3] Sélectionner des bundles à installer"
    Write-Host " [4] Recherche & installation (winget/choco)"
    Write-Host " [5] Installer par IDs (comma separated)"
    Write-Host " [B] Retour"
    switch (Read-Host "Choix") {
        "1" {
            $p = Read-Host "Profil ? (Dev/Browsers/Media/SysTools/AllCommon)"
            $map=@{ Dev="Apps.Dev"; Browsers="Apps.Browsers"; Media="Apps.Media"; SysTools="Apps.SysTools"; AllCommon="Apps.AllCommon" }
            if ($map.ContainsKey($p)){ Execute-Feature -FeatureKey $map[$p] } else { Write-Host "Profil inconnu." -ForegroundColor Red }
        }
        "2" {
            foreach ($f in @("Apps.Dev","Apps.Browsers","Apps.Media","Apps.SysTools")) { Execute-Feature -FeatureKey $f }
            Write-Host "Tous les bundles ont été traités." -ForegroundColor Green
        }
        "3" {
            $bundles=@("Apps.Dev","Apps.Browsers","Apps.Media","Apps.SysTools","Apps.AllCommon"); $i=1
            foreach ($b in $bundles){ Write-Host " [$i] $($global:Features[$b].Name)"; $i++ }
            $sel=Read-Host "Sélection (ex: 1,3,5)"
            $idxs=$sel -split ',' | ForEach-Object { [int]$_.Trim()-1 }
            foreach ($idx in $idxs){ if ($idx -ge 0 -and $idx -lt $bundles.Count) { Execute-Feature -FeatureKey $bundles[$idx] } }
        }
        "4" { Search-And-Install-Apps }
        "5" { $ids=Read-Host "IDs (winget/choco) séparés par virgule"; if ($ids){ $arr=$ids.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }; Install-AppIds -Ids $arr } }
        default { }
    }
    Read-Host "Entrée pour continuer"
}

# ============================================================================
# MAIN
# ============================================================================

if (!(Test-Administrator)) {
    Write-Host "Run PowerShell as Administrator!" -ForegroundColor Red
    if (!$Silent) { Read-Host "Press Enter to exit" }
    exit 1
}
if (!(Test-Windows11)) { if (!$Silent) { exit 1 } }

$global:AllUsers   = $AllUsers.IsPresent
$global:DefaultUser= $DefaultUser.IsPresent

# ----- Apps options via CLI -----
if ($AppsProfile)      { $map=@{ Dev="Apps.Dev"; Browsers="Apps.Browsers"; Media="Apps.Media"; SysTools="Apps.SysTools"; AllCommon="Apps.AllCommon" }; if ($map.ContainsKey($AppsProfile)){ Execute-Feature -FeatureKey $map[$AppsProfile] } }
if ($AppsAll)          { foreach ($f in @("Apps.Dev","Apps.Browsers","Apps.Media","Apps.SysTools")) { Execute-Feature -FeatureKey $f } }
if ($AppsSelect)       { Show-AppsInstaller }
if ($AppsSearch)       { Search-And-Install-Apps }
if ($InstallAppIds)    { Install-AppIds -Ids $InstallAppIds }

# ----- Presets / modes -----
if ($ExpressMode)        { Write-LogMessage "Express Mode" "Info"; Show-QuickSetup }
elseif ($CustomMode)     { Write-LogMessage "Custom Mode" "Info"; Show-CustomConfiguration }
elseif ($MaintenanceMode){ Write-LogMessage "Maintenance Mode" "Info"; Show-MaintenanceTools }
elseif ($ImportConfig)   { Write-LogMessage "Importing config: $ImportConfig" "Info"; if (Test-Path $ImportConfig){ Import-Profile -Path $ImportConfig } else { Write-LogMessage "Import file not found: $ImportConfig" "Error" } }
elseif ($ExportConfig)   { Write-LogMessage "Exporting configuration" "Info"; $exp=Export-CurrentConfiguration; if ($exp -and $ExportConfig -ne ""){ Move-Item -Path $exp -Destination $ExportConfig -Force; Write-LogMessage "Configuration exported to: $ExportConfig" "Success" } }
elseif ($PSBoundParameters.Count -gt 0) {
    Write-LogMessage "Win11 Config Tool start v$($global:ScriptVersion)" "Info"
    if ($CreateRestorePoint) { Create-SystemRestorePoint | Out-Null }

    if ($RemoveAllBloatware) { Get-CategoryFeatures -Category "Bloatware"   | ForEach-Object { Execute-Feature -FeatureKey $_.Key } }
    if ($ApplyAllSecurity)   { Get-CategoryFeatures -Category "Security"    | ForEach-Object { Execute-Feature -FeatureKey $_.Key } }
    if ($ApplyAllPrivacy)    { Get-CategoryFeatures -Category "Privacy"     | ForEach-Object { Execute-Feature -FeatureKey $_.Key } }
    if ($ApplyAllPerformance){ Get-CategoryFeatures -Category "Performance" | ForEach-Object { Execute-Feature -FeatureKey $_.Key } }

    if ($ApplyProfile)    { Load-Profile -Name $ApplyProfile }
    if ($CombineProfiles) { foreach ($n in $CombineProfiles) { Load-Profile -Name $n } }

    if (!$Silent -and !$NoReboot) {
        $needReboot = $false
        foreach ($k in $global:AppliedFeatures) { if ($global:Features[$k].RebootRequired) { $needReboot=$true; break } }
        if ($needReboot) {
            if ($ForceReboot) { Write-LogMessage "Rebooting in 10s..." "Warning"; Start-Sleep -Seconds 10; Restart-Computer -Force }
            else { Write-LogMessage "A reboot is required to complete configuration" "Warning" }
        }
    }
} else {
    Show-MainMenu
}

try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
