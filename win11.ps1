# ============================================================================
# WINDOWS 11 ULTIMATE CONFIGURATION TOOL - VERSION 4.3 PATCHED (+ logging fix + Apps)
# Complete Bug Fixes & Security Hardening Edition
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
    
    # Profile Selection
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
    
    # Specific Operations
    [switch]$RemoveAllBloatware,
    [switch]$ApplyAllSecurity,
    [switch]$ApplyAllPrivacy,
    [switch]$ApplyAllPerformance,
    [switch]$RestoreDefaults,
    
    # User Context
    [string]$User = $env:USERNAME,
    [switch]$AllUsers,
    [switch]$DefaultUser
)

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

$global:ScriptVersion = "4.3-PATCHED"
$global:ScriptName = "Windows 11 Ultimate Configuration Tool - Patched Edition"

# Ensure log directory exists
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# ---- Logging FIX: séparer transcript et log applicatif pour éviter les locks ----
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$global:LogFile        = Join-Path $LogPath "Win11Config_${stamp}.log"             # log applicatif (Write-LogMessage)
$global:TranscriptFile = Join-Path $LogPath "Win11Config_${stamp}.transcript.txt"  # transcript séparé

$global:ConfigPath = "$env:LOCALAPPDATA\Win11Config"
$global:BackupPath = "$global:ConfigPath\Backups"
$global:ProfilesPath = "$global:ConfigPath\Profiles"
$global:DebloatListPath = "$global:ConfigPath\DebloatLists"
$global:TempPath = "$env:TEMP\Win11Config"
$global:AppliedFeatures = @()
$global:LogVerbose = $VerboseLogging.IsPresent
$global:OriginalDNS = @{}

# Create necessary directories
@($global:ConfigPath, $global:BackupPath, $global:ProfilesPath, $global:DebloatListPath, $global:TempPath) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# PATCH 2: Mount HKCR/HKU PS Drives if they don't exist
foreach ($d in @(@{Name='HKCR';Root='HKEY_CLASSES_ROOT'},
                 @{Name='HKU' ;Root='HKEY_USERS'})) {
    if (-not (Get-PSDrive $d.Name -ErrorAction SilentlyContinue)) {
        New-PSDrive -PSProvider Registry -Name $d.Name -Root $d.Root | Out-Null
    }
}

# Start logging with error handling (transcript séparé)
try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
try { Start-Transcript -Path $global:TranscriptFile -Append -Force | Out-Null } catch { Write-Warning "Unable to start transcript logging" }

# ============================================================================
# CORRECTED HELPER FUNCTIONS (+ Apps helpers)
# ============================================================================

function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with color and level (capturé par transcript)
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
    
    # Écriture dans le fichier log applicatif séparé (pas le même que transcript)
    try { Add-Content -Path $global:LogFile -Value $logEntry } catch {}
    
    # Verbose logging
    if ($global:LogVerbose -and $Level -eq "Verbose") {
        Write-Verbose $Message
    }
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [object]$Value,
        [ValidateSet('String','ExpandString','MultiString','DWord','QWord','Binary')] 
        [string]$Type = "DWord"
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-LogMessage "Created registry path: $Path" "Verbose"
        }
        
        $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($existing -ne $null) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
            Write-LogMessage "Updated registry value: $Path\$Name" "Verbose"
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
            Write-LogMessage "Created registry value: $Path\$Name (Type: $Type)" "Verbose"
        }
        return $true
    } catch {
        Write-LogMessage "Failed to set registry value: $Path\$Name - $_" "Error"
        return $false
    }
}

function Test-Windows11 {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    
    # Windows 11 builds: 22000 = 21H2, 22621/22631 = 22H2/23H2, 26100+ = 24H2
    if ($build -lt 22000) {
        Write-Warning "This script is designed for Windows 11 (build >= 22000). Current: $($os.Version) (build $build)"
        Write-Warning "Some features may not work correctly on Windows 10 or earlier."
        $continue = Read-Host "Continue anyway? (Y/N)"
        return ($continue -eq "Y")
    }
    
    Write-LogMessage "Windows 11 detected - Build: $build" "Info"
    return $true
}

function Disable-TaskSafe {
    param(
        [Parameter(Mandatory)] [string]$TaskPath,
        [Parameter(Mandatory)] [string]$TaskName
    )
    
    try {
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null
        Write-LogMessage "Disabled task: $TaskPath$TaskName" "Success"
        return $true
    } catch {
        Write-LogMessage "Task not found or cannot disable: $TaskPath$TaskName - $_" "Warning"
        return $false
    }
}

# PATCH 1: Corrected Invoke-ForEachUserHive function
function Invoke-ForEachUserHive {
    param([Parameter(Mandatory)][ScriptBlock]$Script)

    # Current user
    & $Script 'HKCU:'

    if ($global:AllUsers) {
        Get-ChildItem Registry::HKEY_USERS |
          Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' } |
          ForEach-Object {
              $root = "Registry::" + $_.Name
              Write-LogMessage "Applying to user hive: $($_.Name)" "Verbose"
              & $Script $root
          }
    }

    if ($global:DefaultUser) {
        $defaultNtuser = "$env:SystemDrive\Users\Default\NTUSER.DAT"
        if (Test-Path $defaultNtuser) {
            Write-LogMessage "Loading default user hive" "Verbose"
            reg.exe load HKU\DefaultUser "$defaultNtuser" | Out-Null
            try {
                & $Script 'Registry::HKEY_USERS\DefaultUser'
                Write-LogMessage "Applied to default user profile" "Success"
            } finally {
                reg.exe unload HKU\DefaultUser | Out-Null
            }
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

function Set-DnsSafe {
    param([string[]]$Servers = @("1.1.1.1", "1.0.0.1"))
    
    Get-NetAdapter -Physical | Where-Object Status -eq "Up" | ForEach-Object {
        $idx = $_.ifIndex
        $adapterName = $_.Name
        
        # Backup current DNS
        $currentDns = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4
        $global:OriginalDNS[$adapterName] = $currentDns.ServerAddresses
        
        # Check if DHCP configured
        if ($currentDns.ServerAddresses.Count -gt 0) {
            Write-LogMessage "Setting DNS ($($Servers -join ', ')) on adapter: $adapterName" "Info"
            Write-LogMessage "Original DNS: $($currentDns.ServerAddresses -join ', ')" "Verbose"
            
            try {
                Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $Servers -ErrorAction Stop
                Write-LogMessage "DNS configured successfully on $adapterName" "Success"
            } catch {
                Write-LogMessage "Failed to set DNS on $adapterName : $_" "Warning"
            }
        } else {
            Write-LogMessage "Skipping adapter $adapterName : No DNS configuration detected" "Verbose"
        }
    }
}

# PATCH 3: Add locale-independent EditionID helper
function Get-WindowsEditionId {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
}

function Enable-BitLockerSafe {
    $drive = $env:SystemDrive
    
    try {
        # PATCH 3: Use locale-independent EditionID
        $editionId = Get-WindowsEditionId
        if ($editionId -notin @('Professional','ProfessionalN','ProfessionalWorkstation',
                                'Enterprise','EnterpriseN','Education','EducationN')) {
            Write-LogMessage "BitLocker requires Pro/Enterprise/Education. Current: $editionId" "Warning"
            return $false
        }
        
        # Check TPM
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if (!$tpm -or !$tpm.TpmPresent -or !$tpm.TpmReady) {
            Write-LogMessage "TPM not present or not ready - BitLocker may not work properly" "Warning"
        }
        
        # Check current BitLocker status
        $vol = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
        if ($vol.VolumeStatus -eq 'FullyDecrypted') {
            Write-LogMessage "Enabling BitLocker on $drive..." "Info"
            
            # Enable with best practices
            Enable-BitLocker -MountPoint $drive `
                -EncryptionMethod XtsAes256 `
                -UsedSpaceOnly `
                -TpmProtector `
                -RecoveryPasswordProtector `
                -ErrorAction Stop
            
            # Get and display recovery key
            $recoveryKey = (Get-BitLockerVolume -MountPoint $drive).KeyProtector | 
                Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
            
            Write-LogMessage "BitLocker enabled successfully" "Success"
            Write-LogMessage "IMPORTANT - BitLocker Recovery Key: $($recoveryKey.RecoveryPassword)" "Important"
            Write-LogMessage "SAVE THIS RECOVERY KEY IN A SECURE LOCATION!" "Important"
            
            # Save to file
            $keyFile = "$global:BackupPath\BitLocker_RecoveryKey_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $recoveryKey.RecoveryPassword | Out-File -FilePath $keyFile -Force
            Write-LogMessage "Recovery key saved to: $keyFile" "Info"
            
            return $true
        } else {
            Write-LogMessage "BitLocker already enabled on $drive (Status: $($vol.VolumeStatus))" "Info"
            return $true
        }
    } catch {
        Write-LogMessage "Could not enable BitLocker: $_" "Error"
        return $false
    }
}

function Export-CurrentConfiguration {
    $featuresMeta = @{}
    
    foreach($key in $global:Features.Keys) {
        $feature = $global:Features[$key]
        $featuresMeta[$key] = [PSCustomObject]@{
            Name           = $feature.Name
            Category       = $feature.Category
            Description    = $feature.Description
            Impact         = $feature.Impact
            RebootRequired = $feature.RebootRequired
        }
    }
    
    $exportData = [PSCustomObject]@{
        ExportDate      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        ScriptVersion   = $global:ScriptVersion
        SystemInfo      = @{
            ComputerName = $env:COMPUTERNAME
            Username     = $env:USERNAME
            OS           = (Get-CimInstance Win32_OperatingSystem).Caption
            Version      = (Get-CimInstance Win32_OperatingSystem).Version
            Build        = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        }
        AppliedFeatures = $global:AppliedFeatures
        Features        = $featuresMeta
        DNSBackup       = $global:OriginalDNS
    }
    
    $exportPath = "$env:USERPROFILE\Desktop\Win11Config_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    try {
        $exportData | ConvertTo-Json -Depth 6 | Out-File -FilePath $exportPath -Force -Encoding UTF8
        Write-LogMessage "Configuration exported to: $exportPath" "Success"
        return $exportPath
    } catch {
        Write-LogMessage "Failed to export configuration: $_" "Error"
        return $null
    }
}

function Show-Banner {
    Clear-Host
    $banner = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║           WINDOWS 11 ULTIMATE CONFIGURATION TOOL v$($global:ScriptVersion)            ║
║                Complete Feature Set - Patched & Hardened Edition               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# PATCH 4: Corrected Create-SystemRestorePoint function with verification
function Create-SystemRestorePoint {
    param([string]$Description = "Windows 11 Configuration Tool v$($global:ScriptVersion)")

    Write-LogMessage "Creating system restore point..." "Info"
    try {
        $before = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -Last 1).SequenceNumber
        Enable-ComputerRestore -Drive "$env:SystemDrive" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $after = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -Last 1).SequenceNumber

        if ($after -and $after -ne $before) {
            Write-LogMessage "System restore point created successfully" "Success"
            return $true
        } else {
            Write-LogMessage "Restore point not created (frequency limit or policy)" "Warning"
            return $false
        }
    } catch {
        Write-LogMessage "Failed to create restore point: $_" "Error"
        return $false
    }
}

function Get-CategoryFeatures {
    param([string]$Category)
    
    return $global:Features.GetEnumerator() | Where-Object {
        $_.Value.Category -eq $Category
    } | Sort-Object Name
}

function Execute-Feature {
    param([string]$FeatureKey)
    
    $feature = $global:Features[$FeatureKey]
    if (!$feature) {
        Write-LogMessage "Feature not found: $FeatureKey" "Error"
        return $false
    }
    
    Write-LogMessage "Executing: $($feature.Name)" "Info"
    
    try {
        & $feature.Script
        $global:AppliedFeatures += $FeatureKey
        Write-LogMessage "Successfully executed: $($feature.Name)" "Success"
        return $true
    } catch {
        Write-LogMessage "Failed to execute: $($feature.Name) - $_" "Error"
        return $false
    }
}

# ---------- Helpers pour installation d'applications (winget/choco) ----------

function Ensure-WingetOrChoco {
    if (Get-Command winget -ErrorAction SilentlyContinue) { return "winget" }
    if (Get-Command choco  -ErrorAction SilentlyContinue) { return "choco"  }

    Write-LogMessage "winget non trouvé. Installation de Chocolatey (fallback)..." "Warning"
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    } catch {
        Write-LogMessage "Echec installation Chocolatey: $_" "Error"
        return $null
    }
    return (Get-Command choco -ErrorAction SilentlyContinue) ? "choco" : $null
}

function Install-AppBundle {
    param(
        [string[]]$WingetIds,
        [string[]]$ChocoIds
    )
    $pm = Ensure-WingetOrChoco
    if (-not $pm) { Write-LogMessage "Aucun gestionnaire de paquets disponible." "Error"; return }

    if ($pm -eq "winget") {
        foreach ($id in $WingetIds) {
            Write-LogMessage "winget install $id" "Info"
            try {
                winget install --id $id -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
            } catch {
                Write-LogMessage "Echec winget pour $id : $_" "Warning"
            }
        }
    } else {
        foreach ($id in $ChocoIds) {
            Write-LogMessage "choco install $id" "Info"
            try {
                choco install $id -y --no-progress | Out-Null
            } catch {
                Write-LogMessage "Echec choco pour $id : $_" "Warning"
            }
        }
    }
}

# ============================================================================
# COMPREHENSIVE FEATURE DEFINITIONS - SAFE & CORRECTED (+ Apps)
# ============================================================================

$global:Features = @{
    # PRIVACY & TELEMETRY
    "Privacy.DisableTelemetry" = @{
        Name = "Reduce Telemetry (Pro/Enterprise)"
        Category = "Privacy"
        Description = "Reduce Windows telemetry to Security level (may be ignored on Home edition)"
        Impact = "High"
        RebootRequired = $false
        Script = {
            # Note: On Home edition, minimum is Basic (1), not Security (0)
            $edition = (Get-CimInstance Win32_OperatingSystem).Caption
            $telemetryLevel = if ($edition -match 'Home') { 1 } else { 0 }
            
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" $telemetryLevel "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" $telemetryLevel "DWord"
            
            Write-LogMessage "Telemetry level set to: $telemetryLevel (0=Security, 1=Basic)" "Info"
            
            # Disable telemetry scheduled tasks safely
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "Microsoft Compatibility Appraiser"
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "ProgramDataUpdater"
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Autochk\" -TaskName "Proxy"
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "Consolidator"
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "UsbCeip"
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\DiskDiagnostic\" -TaskName "Microsoft-Windows-DiskDiagnosticDataCollector"
        }
    }
    
    "Privacy.DisableActivityHistory" = @{
        Name = "Disable Activity History"
        Category = "Privacy"
        Description = "Stop Windows from collecting your activity history"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityHistory" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0 "DWord"
        }
    }
    
    "Privacy.DisableAdvertisingID" = @{
        Name = "Disable Advertising ID"
        Category = "Privacy"
        Description = "Disable advertising ID for personalized ads"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1 "DWord"
            
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0 "DWord"
            }
        }
    }
    
    "Privacy.DisableLocationTracking" = @{
        Name = "Disable Location Tracking"
        Category = "Privacy"
        Description = "Disable all location tracking services"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny" "String"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0 "DWord"
        }
    }
    
    "Privacy.DisableBiometrics" = @{
        Name = "Disable Biometrics"
        Category = "Privacy"
        Description = "Disable Windows Hello biometric features"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" "Enabled" 0 "DWord"
        }
    }
    
    "Privacy.DisableFeedback" = @{
        Name = "Disable Feedback Requests"
        Category = "Privacy"
        Description = "Stop Windows from asking for feedback"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0 "DWord"
            }
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1 "DWord"
        }
    }
    
    # SECURITY FEATURES - ENHANCED
    "Security.EnableWindowsDefender" = @{
        Name = "Configure Windows Defender Maximum Security"
        Category = "Security"
        Description = "Enable all Windows Defender security features with safe defaults"
        Impact = "High"
        RebootRequired = $false
        Script = {
            try {
                # Core protection
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisablePrivacyMode $false -ErrorAction SilentlyContinue
                Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
                
                # Cloud protection
                Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
                Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
                Set-MpPreference -CloudBlockLevel High -ErrorAction SilentlyContinue
                Set-MpPreference -CloudExtendedTimeout 50 -ErrorAction SilentlyContinue
                
                # PUA Protection
                Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
                
                # Controlled Folder Access in Audit mode first
                Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction SilentlyContinue
                Write-LogMessage "Controlled Folder Access set to AUDIT mode (monitor only)" "Warning"
                
                # Network protection
                Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
                
                Write-LogMessage "Windows Defender configured with maximum protection" "Success"
            } catch {
                Write-LogMessage "Some Windows Defender settings could not be applied: $_" "Warning"
            }
        }
    }
    
    "Security.EnableLSAProtection" = @{
        Name = "Enable LSA Protection"
        Category = "Security"
        Description = "Enable Local Security Authority (LSA) protection"
        Impact = "High"
        RebootRequired = $true
        Script = {
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" 1 "DWord"
            Write-LogMessage "LSA Protection enabled - reboot required" "Success"
        }
    }
    
    "Security.EnableBitLocker" = @{
        Name = "Enable BitLocker Encryption"
        Category = "Security"
        Description = "Enable BitLocker drive encryption with TPM (Pro/Enterprise only)"
        Impact = "High"
        RebootRequired = $true
        Script = {
            Enable-BitLockerSafe
        }
    }
    
    "Security.EnableCredentialGuard" = @{
        Name = "Enable Credential Guard"
        Category = "Security"
        Description = "Enable Windows Defender Credential Guard (Enterprise only)"
        Impact = "High"
        RebootRequired = $true
        Script = {
            # PATCH 3: Use locale-independent EditionID
            $editionId = Get-WindowsEditionId
            if ($editionId -notin @('Enterprise','EnterpriseN','Education','EducationN')) {
                Write-LogMessage "Credential Guard requires Enterprise/Education. Current: $editionId" "Warning"
                return
            }
            
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" 1 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "RequirePlatformSecurityFeatures" 3 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" "Enabled" 1 "DWord"
            
            Write-LogMessage "Credential Guard enabled - reboot required" "Success"
        }
    }
    
    "Security.EnableSandbox" = @{
        Name = "Enable Windows Sandbox"
        Category = "Security"
        Description = "Enable Windows Sandbox feature (Pro/Enterprise only)"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            try {
                $edition = (Get-CimInstance Win32_OperatingSystem).Caption
                if ($edition -notmatch 'Pro|Enterprise|Education') {
                    Write-LogMessage "Windows Sandbox requires Pro/Enterprise/Education edition" "Warning"
                    return
                }
                
                Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online -NoRestart -ErrorAction Stop
                Write-LogMessage "Windows Sandbox enabled - reboot required" "Success"
            } catch {
                Write-LogMessage "Could not enable Windows Sandbox: $_" "Error"
            }
        }
    }
    
    "Security.DisableSMBv1" = @{
        Name = "Disable SMBv1"
        Category = "Security"
        Description = "Disable insecure SMBv1 protocol"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
                Write-LogMessage "SMBv1 disabled successfully" "Success"
            } catch {
                Write-LogMessage "Could not disable SMBv1: $_" "Warning"
            }
        }
    }
    
    "Security.EnableFirewall" = @{
        Name = "Configure Firewall (Balanced)"
        Category = "Security"
        Description = "Enable Windows Firewall with balanced rules"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                # Enable firewall for all profiles
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
                
                # Balanced configuration - not too strict
                Set-NetFirewallProfile -Profile Domain,Private -DefaultInboundAction Allow -ErrorAction Stop
                Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -ErrorAction Stop
                Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction Stop
                
                # Notifications for Public
                Set-NetFirewallProfile -Profile Public -NotifyOnListen True -ErrorAction Stop
                
                Write-LogMessage "Firewall configured with balanced settings" "Success"
                Write-LogMessage "Public: Inbound blocked | Private/Domain: Inbound allowed | All: Outbound allowed" "Info"
            } catch {
                Write-LogMessage "Could not configure firewall: $_" "Error"
            }
        }
    }
    
    "Security.EnableUAC" = @{
        Name = "Enable UAC Maximum Level"
        Category = "Security"
        Description = "Set UAC to maximum security level"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1 "DWord"
            
            Write-LogMessage "UAC set to maximum security level" "Success"
        }
    }
    
    "Security.DisableAutorun" = @{
        Name = "Disable Autorun/Autoplay"
        Category = "Security"
        Description = "Disable autorun for all drives"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" 1 "DWord"
            
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 "DWord"
            }
        }
    }
    
    # PERFORMANCE OPTIMIZATIONS - SAFER
    "Performance.DisableStartupApps" = @{
        Name = "Disable Non-Essential Startup Applications"
        Category = "Performance"
        Description = "Disable third-party startup applications"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                Get-CimInstance Win32_StartupCommand | Where-Object {
                    $_.Caption -notlike "*Windows*" -and 
                    $_.Caption -notlike "*Microsoft*" -and
                    $_.Caption -notlike "*Security*" -and
                    $_.Caption -notlike "*Antivirus*"
                } | ForEach-Object {
                    Write-LogMessage "Disabling startup app: $($_.Caption)" "Info"
                    
                    if ($_.Location -eq "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") {
                        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
                    }
                    elseif ($_.Location -eq "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") {
                        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                Write-LogMessage "Error disabling startup apps: $_" "Warning"
            }
        }
    }
    
    "Performance.DisableBackgroundApps" = @{
        Name = "Disable Background Apps"
        Category = "Performance"
        Description = "Prevent apps from running in background"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1 "DWord"
            }
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2 "DWord"
        }
    }
    
    "Performance.OptimizeSSD" = @{
        Name = "Optimize for SSD"
        Category = "Performance"
        Description = "Apply SSD-specific optimizations (keeps TRIM enabled)"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                # Disable last access update
                fsutil behavior set DisableLastAccess 1
                
                # Ensure TRIM is enabled
                fsutil behavior set DisableDeleteNotify 0
                
                # Keep the defrag task for TRIM operations - DO NOT DISABLE
                Write-LogMessage "SSD optimizations applied (TRIM remains enabled)" "Success"
            } catch {
                Write-LogMessage "Could not apply all SSD optimizations: $_" "Warning"
            }
        }
    }
    
    "Performance.ReduceIndexingScope" = @{
        Name = "Optimize Search Indexing"
        Category = "Performance"
        Description = "Reduce indexing scope to essential locations only"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Write-LogMessage "Optimizing search indexing scope..." "Info"
            
            try {
                $excludePaths = @(
                    "$env:USERPROFILE\AppData\Local\Temp",
                    "$env:USERPROFILE\.nuget",
                    "$env:USERPROFILE\.npm",
                    "$env:USERPROFILE\node_modules",
                    "C:\ProgramData",
                    "C:\Windows\Temp"
                )
                
                foreach ($path in $excludePaths) {
                    if (Test-Path $path) {
                        Write-LogMessage "Excluding from index: $path" "Verbose"
                    }
                }
                
                Write-LogMessage "Search indexing optimized - service remains active" "Success"
            } catch {
                Write-LogMessage "Could not optimize indexing: $_" "Warning"
            }
        }
    }
    
    "Performance.ConfigureSuperfetch" = @{
        Name = "Optimize Superfetch/SysMain"
        Category = "Performance"
        Description = "Configure Superfetch for optimal performance"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            try {
                Set-Service "SysMain" -StartupType Manual -ErrorAction SilentlyContinue
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 2 "DWord"
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 2 "DWord"
                
                Write-LogMessage "Superfetch/SysMain optimized (set to Manual)" "Success"
            } catch {
                Write-LogMessage "Could not optimize Superfetch: $_" "Warning"
            }
        }
    }
    
    "Performance.OptimizeVisualEffects" = @{
        Name = "Optimize Visual Effects"
        Category = "Performance"
        Description = "Balance performance and appearance"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2 "DWord"
            }
            
            Write-LogMessage "Visual effects optimized for performance" "Success"
            Write-LogMessage "You can fine-tune in System Properties > Advanced > Performance" "Info"
        }
    }
    
    "Performance.SetPowerPlan" = @{
        Name = "Set Balanced Power Plan"
        Category = "Performance"
        Description = "Set power plan to Balanced (recommended for most users)"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e
                Write-LogMessage "Power plan set to Balanced" "Success"
                Write-LogMessage "Use High Performance only if on desktop with good cooling" "Info"
            } catch {
                Write-LogMessage "Could not set power plan: $_" "Warning"
            }
        }
    }
    
    "Performance.SetHighPerformance" = @{
        Name = "Set High Performance Power Plan"
        Category = "Performance"
        Description = "Set power plan to High Performance (not recommended for laptops)"
        Impact = "High"
        RebootRequired = $false
        Script = {
            $isLaptop = (Get-WmiObject -Class Win32_Battery) -ne $null
            
            if ($isLaptop) {
                Write-LogMessage "High Performance not recommended for laptops - impacts battery life" "Warning"
                $confirm = Read-Host "Continue anyway? (Y/N)"
                if ($confirm -ne "Y") { return }
            }
            
            try {
                powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
                powercfg -change -monitor-timeout-ac 30
                powercfg -change -disk-timeout-ac 0
                powercfg -change -standby-timeout-ac 0
                powercfg -change -hibernate-timeout-ac 0
                
                Write-LogMessage "High Performance power plan activated" "Success"
            } catch {
                Write-LogMessage "Could not set power plan: $_" "Warning"
            }
        }
    }
    
    "Performance.DisableHibernation" = @{
        Name = "Disable Hibernation"
        Category = "Performance"
        Description = "Disable hibernation and delete hiberfil.sys"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            try {
                powercfg -h off
                Write-LogMessage "Hibernation disabled" "Success"
                
                $hibernateFileSize = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
                Write-LogMessage "Freed approximately $hibernateFileSize GB of disk space" "Info"
            } catch {
                Write-LogMessage "Could not disable hibernation: $_" "Warning"
            }
        }
    }
    
    "Performance.DisableGameDVR" = @{
        Name = "Disable Xbox Game DVR"
        Category = "Performance"
        Description = "Disable Xbox game recording features"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\System\GameConfigStore" "GameDVR_Enabled" 0 "DWord"
            }
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0 "DWord"
            
            Write-LogMessage "Xbox Game DVR disabled" "Success"
        }
    }
    
    # BLOATWARE REMOVAL - CORRECTED
    "Bloatware.RemoveMicrosoft" = @{
        Name = "Remove Microsoft Bloatware"
        Category = "Bloatware"
        Description = "Remove unnecessary Microsoft apps"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            $apps = @(
                "Microsoft.BingNews",
                "Microsoft.BingWeather",
                "Microsoft.GetHelp",
                "Microsoft.Getstarted",
                "Microsoft.Messaging",
                "Microsoft.Microsoft3DViewer",
                "Microsoft.MicrosoftOfficeHub",
                "Microsoft.MicrosoftSolitaireCollection",
                "Microsoft.NetworkSpeedTest",
                "Microsoft.News",
                "Microsoft.Office.Lens",
                "Microsoft.Office.OneNote",
                "Microsoft.Office.Sway",
                "Microsoft.OneConnect",
                "Microsoft.People",
                "Microsoft.Print3D",
                "Microsoft.SkypeApp",
                "Microsoft.StorePurchaseApp",
                "Microsoft.Wallet",
                "Microsoft.Whiteboard",
                "Microsoft.WindowsAlarms",
                "Microsoft.WindowsFeedbackHub",
                "Microsoft.WindowsMaps",
                "Microsoft.WindowsSoundRecorder",
                "Microsoft.ZuneMusic",
                "Microsoft.ZuneVideo"
            )
            
            foreach ($app in $apps) {
                try {
                    # Remove for current user
                    Get-AppxPackage -Name "$app*" -ErrorAction SilentlyContinue | 
                        Remove-AppxPackage -ErrorAction SilentlyContinue
                    
                    # Remove for all users if specified
                    if ($global:AllUsers) {
                        Get-AppxPackage -Name "$app*" -AllUsers -ErrorAction SilentlyContinue | 
                            Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                    }
                    
                    # Remove provisioned package
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DisplayName -like "$app*" -or $_.PackageName -like "$app*" } |
                        Remove-ProvisionedAppxPackage -Online -ErrorAction SilentlyContinue
                    
                    Write-LogMessage "Removed: $app" "Info"
                } catch {
                    Write-LogMessage "Could not remove $app : $_" "Verbose"
                }
            }
        }
    }
    
    "Bloatware.RemoveXbox" = @{
        Name = "Remove Xbox Apps"
        Category = "Bloatware"
        Description = "Remove all Xbox related applications"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            $xboxApps = @(
                "Microsoft.GamingApp",
                "Microsoft.XboxApp",
                "Microsoft.Xbox.TCUI",
                "Microsoft.XboxGameOverlay",
                "Microsoft.XboxGamingOverlay",
                "Microsoft.XboxIdentityProvider",
                "Microsoft.XboxSpeechToTextOverlay"
            )
            
            foreach ($app in $xboxApps) {
                try {
                    Get-AppxPackage -Name "$app*" -ErrorAction SilentlyContinue | 
                        Remove-AppxPackage -ErrorAction SilentlyContinue
                    
                    if ($global:AllUsers) {
                        Get-AppxPackage -Name "$app*" -AllUsers -ErrorAction SilentlyContinue | 
                            Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                    }
                    
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DisplayName -like "$app*" -or $_.PackageName -like "$app*" } |
                        Remove-ProvisionedAppxPackage -Online -ErrorAction SilentlyContinue
                    
                    Write-LogMessage "Removed: $app" "Info"
                } catch {
                    Write-LogMessage "Could not remove $app" "Verbose"
                }
            }
        }
    }
    
    "Bloatware.RemoveOneDrive" = @{
        Name = "Uninstall OneDrive"
        Category = "Bloatware"
        Description = "Completely uninstall Microsoft OneDrive"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Write-LogMessage "Uninstalling OneDrive..." "Info"
            
            $oneDrivePath = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
            if (!(Test-Path $oneDrivePath)) {
                $oneDrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
            }
            
            if (Test-Path $oneDrivePath) {
                try {
                    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
                    Start-Process $oneDrivePath "/uninstall" -NoNewWindow -Wait
                    
                    # Prevent re-installation
                    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1 "DWord"
                    
                    # Remove folders
                    Remove-Item "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    
                    # Remove from Explorer
                    Set-RegistryValue "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0 "DWord"
                    Set-RegistryValue "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0 "DWord"
                    
                    Write-LogMessage "OneDrive uninstalled and blocked from reinstallation" "Success"
                } catch {
                    Write-LogMessage "Could not fully uninstall OneDrive: $_" "Warning"
                }
            }
        }
    }
    
    # AI FEATURES
    "AI.DisableCopilot" = @{
        Name = "Disable Microsoft Copilot"
        Category = "AI"
        Description = "Completely disable Microsoft Copilot"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" 1 "DWord"
            
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowCopilotButton" 0 "DWord"
            }
            
            Write-LogMessage "Microsoft Copilot disabled" "Success"
        }
    }
    
    "AI.DisableRecall" = @{
        Name = "Disable Windows Recall"
        Category = "AI"
        Description = "Disable Windows Recall AI snapshots"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "DisableAIDataAnalysis" 1 "DWord"
            
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "EnableRecall" 0 "DWord"
            }
            
            Write-LogMessage "Windows Recall disabled" "Success"
        }
    }
    
    # INTERFACE CUSTOMIZATION - CORRECTED
    "UI.EnableDarkMode" = @{
        Name = "Enable Dark Mode"
        Category = "Interface"
        Description = "Enable dark mode for system and apps"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "AppsUseLightTheme" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "SystemUsesLightTheme" 0 "DWord"
            }
            
            Write-LogMessage "Dark mode enabled" "Success"
        }
    }
    
    "UI.RestoreClassicMenu" = @{
        Name = "Restore Classic Context Menu"
        Category = "Interface"
        Description = "Restore Windows 10 style context menu (may not work on newer builds)"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            try {
                $build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
                
                if ($build -ge 22621) {
                    Write-LogMessage "Classic menu hack may not work on build $build" "Warning"
                    $confirm = Read-Host "Try anyway? (Y/N)"
                    if ($confirm -ne "Y") { return }
                }
                
                Invoke-ForEachUserHive {
                    param($root)
                    $clsidPath = "$root\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
                    
                    if (!(Test-Path $clsidPath)) {
                        New-Item -Path $clsidPath -Force | Out-Null
                    }
                    
                    $inprocPath = "$clsidPath\InprocServer32"
                    if (!(Test-Path $inprocPath)) {
                        New-Item -Path $inprocPath -Force | Out-Null
                    }
                    
                    # Utiliser Set-ItemProperty; '(Default)' est la valeur par défaut
                    Set-ItemProperty -Path $inprocPath -Name "(Default)" -Value "" -Force
                }
                
                Write-LogMessage "Classic context menu restored - restarting Explorer" "Success"
                Restart-Explorer
            } catch {
                Write-LogMessage "Could not restore classic menu: $_" "Error"
            }
        }
    }
    
    "UI.TaskbarLeft" = @{
        Name = "Align Taskbar Left"
        Category = "Interface"
        Description = "Move taskbar icons to the left"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAl" 0 "DWord"
            }
            
            Write-LogMessage "Taskbar aligned to left - restarting Explorer" "Success"
            Restart-Explorer
        }
    }
    
    "UI.ShowFileExtensions" = @{
        Name = "Show File Extensions"
        Category = "Interface"
        Description = "Always show file extensions"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0 "DWord"
            }
            
            Write-LogMessage "File extensions will now be shown" "Success"
            Restart-Explorer
        }
    }
    
    "UI.ShowHiddenFiles" = @{
        Name = "Show Hidden Files"
        Category = "Interface"
        Description = "Show hidden files and folders"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1 "DWord"
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" 1 "DWord"
            }
            
            Write-LogMessage "Hidden files will now be shown" "Success"
            Restart-Explorer
        }
    }
    
    # NETWORK CONFIGURATION - SAFER
    "Network.OptimizeDNS" = @{
        Name = "Set Fast DNS (with backup)"
        Category = "Network"
        Description = "Configure Cloudflare DNS with backup of current settings"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-DnsSafe -Servers @("1.1.1.1", "1.0.0.1")
            Write-LogMessage "To restore original DNS, check logs for backup values" "Info"
        }
    }
    
    "Network.PreferIPv4" = @{
        Name = "Prefer IPv4 over IPv6"
        Category = "Network"
        Description = "Prefer IPv4 connections while keeping IPv6 enabled"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            # Use 0x20 to prefer IPv4, not 0xFF which completely disables IPv6
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 0x20 "DWord"
            Write-LogMessage "System will prefer IPv4 over IPv6 (IPv6 remains enabled)" "Success"
        }
    }
    
    # DEVELOPMENT TOOLS
    "Dev.InstallWSL" = @{
        Name = "Install WSL2 with Ubuntu"
        Category = "Development"
        Description = "Install Windows Subsystem for Linux 2 with Ubuntu"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            try {
                # Enable WSL features
                Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction Stop
                Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction Stop
                
                # Install WSL2
                wsl --install
                wsl --set-default-version 2
                
                # Install Ubuntu
                wsl --install -d Ubuntu
                
                Write-LogMessage "WSL2 with Ubuntu installation initiated - reboot required" "Success"
            } catch {
                Write-LogMessage "Could not install WSL2: $_" "Error"
            }
        }
    }
    
    "Dev.EnableDevMode" = @{
        Name = "Enable Developer Mode"
        Category = "Development"
        Description = "Enable Windows Developer Mode"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowDevelopmentWithoutDevLicense" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowAllTrustedApps" 1 "DWord"
            
            Write-LogMessage "Developer Mode enabled" "Success"
        }
    }

    # APPS (nouvelle catégorie)
    "Apps.InstallCommon" = @{
        Name = "Install Common Desktop Apps"
        Category = "Apps"
        Description = "Installe VS Code, Git, 7-Zip, Firefox, Notepad++, VLC"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Install-AppBundle `
                -WingetIds @(
                    "Microsoft.VisualStudioCode",
                    "Git.Git",
                    "7zip.7zip",
                    "Mozilla.Firefox",
                    "Notepad++.Notepad++",
                    "VideoLAN.VLC"
                ) `
                -ChocoIds @("vscode","git","7zip","firefox","notepadplusplus","vlc")
            Write-LogMessage "Bundle d'applications installé" "Success"
        }
    }
}

# ============================================================================
# INTERACTIVE MODE FUNCTIONS
# ============================================================================

function Show-MainMenu {
    while ($true) {
        Show-Banner
        Write-Host "`n MAIN MENU" -ForegroundColor Yellow
        Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
        Write-Host ""
        Write-Host " [1] Quick Setup (Recommended Profiles)" -ForegroundColor White
        Write-Host " [2] Custom Configuration (Select Features)" -ForegroundColor White  
        Write-Host " [3] Category Browser (Browse by Category)" -ForegroundColor White
        Write-Host " [4] Search Features (Find Specific Options)" -ForegroundColor White
        Write-Host " [5] Profile Manager (Save/Load Profiles)" -ForegroundColor White
        Write-Host " [6] Maintenance Tools (System Maintenance)" -ForegroundColor White
        Write-Host " [7] Backup & Restore (System Backup)" -ForegroundColor White
        Write-Host " [8] Export Configuration (Export Settings)" -ForegroundColor White
        Write-Host ""
        Write-Host " [I] Information & Help" -ForegroundColor Cyan
        Write-Host " [S] System Information" -ForegroundColor Cyan
        Write-Host " [L] View Log File" -ForegroundColor Cyan
        Write-Host " [Q] Quit" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host " Enter your choice"
        
        switch ($choice.ToUpper()) {
            "1" { Show-QuickSetup }
            "2" { Show-CustomConfiguration }
            "3" { Show-CategoryBrowser }
            "4" { Show-FeatureSearch }
            "5" { Show-ProfileManager }
            "6" { Show-MaintenanceTools }
            "7" { Show-BackupRestore }
            "8" { 
                $exported = Export-CurrentConfiguration
                if ($exported) {
                    Read-Host "`n Press Enter to continue"
                }
            }
            "I" { Show-Information }
            "S" { Show-SystemInfo }
            "L" { Show-LogFile }
            "Q" { Exit-Script }
            default { 
                Write-Host " Invalid option. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2 
            }
        }
    }
}

function Show-QuickSetup {
    Show-Banner
    Write-Host "`n QUICK SETUP - RECOMMENDED PROFILES" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    Write-Host " [1] Privacy Focused - Maximum privacy, minimal telemetry" -ForegroundColor White
    Write-Host " [2] Security Hardened - Maximum security settings" -ForegroundColor White
    Write-Host " [3] Performance Balanced - Safe performance tweaks" -ForegroundColor White
    Write-Host " [4] Debloated - Remove unnecessary apps" -ForegroundColor White
    Write-Host " [5] Developer - Development tools and settings" -ForegroundColor White
    Write-Host " [6] Minimal - Essential tweaks only" -ForegroundColor White
    Write-Host " [7] Safe Defaults - Recommended for most users" -ForegroundColor Green
    Write-Host ""
    Write-Host " [B] Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host " Enter your choice"
    
    $profiles = @{
        "1" = @("Privacy.DisableTelemetry", "Privacy.DisableActivityHistory", "Privacy.DisableAdvertisingID", "Privacy.DisableLocationTracking")
        "2" = @("Security.EnableWindowsDefender", "Security.EnableFirewall", "Security.EnableUAC", "Security.DisableSMBv1", "Security.EnableLSAProtection")
        "3" = @("Performance.DisableStartupApps", "Performance.DisableBackgroundApps", "Performance.OptimizeSSD", "Performance.SetPowerPlan")
        "4" = @("Bloatware.RemoveMicrosoft", "Bloatware.RemoveXbox", "AI.DisableCopilot", "AI.DisableRecall")
        "5" = @("Dev.InstallWSL", "Dev.EnableDevMode", "Apps.InstallCommon")   # <-- ajout Apps
        "6" = @("Privacy.DisableTelemetry", "UI.ShowFileExtensions", "Security.EnableUAC")
        "7" = @("Privacy.DisableAdvertisingID", "Security.EnableUAC", "Performance.SetPowerPlan", "UI.ShowFileExtensions")
    }
    
    if ($choice -eq "B" -or $choice -eq "b") {
        return
    }
    
    if ($profiles.ContainsKey($choice)) {
        $features = $profiles[$choice]
        Write-Host "`n Selected features:" -ForegroundColor Cyan
        foreach ($feature in $features) {
            if ($global:Features.ContainsKey($feature)) {
                Write-Host "  - $($global:Features[$feature].Name)" -ForegroundColor White
            }
        }
        
        Write-Host ""
        $confirm = Read-Host " Apply these features? (Y/N)"
        
        if ($confirm -eq "Y") {
            if (!$SkipRestorePoint) {
                Create-SystemRestorePoint
            }
            
            foreach ($feature in $features) {
                Execute-Feature -FeatureKey $feature
            }
            
            Write-Host "`n All features applied successfully!" -ForegroundColor Green
            Read-Host " Press Enter to continue"
        }
    }
}

function Show-CustomConfiguration {
    Show-Banner
    Write-Host "`n CUSTOM CONFIGURATION" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    
    $categories = $global:Features.Values | ForEach-Object { $_.Category } | Sort-Object -Unique
    $selectedFeatures = @()
    
    foreach ($category in $categories) {
        Write-Host "`n [$category]" -ForegroundColor Cyan
        
        $categoryFeatures = @(Get-CategoryFeatures -Category $category)
        $i = 1
        
        foreach ($feature in $categoryFeatures) {
            Write-Host "  [$i] $($feature.Value.Name)" -ForegroundColor White
            Write-Host "       $($feature.Value.Description)" -ForegroundColor Gray
            $i++
        }
        
        Write-Host ""
        $selections = Read-Host " Select features (e.g., 1,3,5 or 'all' or 'none')"
        
        if ($selections -eq "all") {
            $selectedFeatures += $categoryFeatures | ForEach-Object { $_.Key }
        } elseif ($selections -ne "none" -and $selections -ne "") {
            $indices = $selections -split ',' | ForEach-Object { [int]$_.Trim() - 1 }
            foreach ($index in $indices) {
                if ($index -ge 0 -and $index -lt $categoryFeatures.Count) {
                    $selectedFeatures += $categoryFeatures[$index].Key
                }
            }
        }
    }
    
    if ($selectedFeatures.Count -gt 0) {
        Write-Host "`n Selected $($selectedFeatures.Count) features" -ForegroundColor Cyan
        $confirm = Read-Host " Apply selected features? (Y/N)"
        
        if ($confirm -eq "Y") {
            if (!$SkipRestorePoint) {
                Create-SystemRestorePoint
            }
            
            foreach ($feature in $selectedFeatures) {
                Execute-Feature -FeatureKey $feature
            }
            
            Write-Host "`n All features applied successfully!" -ForegroundColor Green
            Read-Host " Press Enter to continue"
        }
    }
}

function Show-CategoryBrowser {
    Show-Banner
    Write-Host "`n CATEGORY BROWSER" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    
    $categories = $global:Features.Values | ForEach-Object { $_.Category } | Sort-Object -Unique
    
    Write-Host ""
    $i = 1
    foreach ($category in $categories) {
        $count = @(Get-CategoryFeatures -Category $category).Count
        Write-Host " [$i] $category ($count features)" -ForegroundColor White
        $i++
    }
    
    Write-Host ""
    Write-Host " [B] Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host " Select category"
    
    if ($choice -eq "B" -or $choice -eq "b") {
        return
    }
    
    $index = [int]$choice - 1
    if ($index -ge 0 -and $index -lt $categories.Count) {
        Show-CategoryFeatures -Category $categories[$index]
    }
}

function Show-CategoryFeatures {
    param([string]$Category)
    
    Show-Banner
    Write-Host "`n $Category Features" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    
    $features = @(Get-CategoryFeatures -Category $Category)
    $i = 1
    
    foreach ($feature in $features) {
        Write-Host "`n [$i] $($feature.Value.Name)" -ForegroundColor White
        Write-Host "      $($feature.Value.Description)" -ForegroundColor Gray
        Write-Host "      Impact: $($feature.Value.Impact) | Reboot Required: $($feature.Value.RebootRequired)" -ForegroundColor DarkGray
        $i++
    }
    
    Write-Host ""
    Write-Host " [A] Apply All" -ForegroundColor Green
    Write-Host " [S] Select Specific" -ForegroundColor Yellow
    Write-Host " [B] Back" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host " Enter your choice"
    
    switch ($choice.ToUpper()) {
        "A" {
            $confirm = Read-Host " Apply all $Category features? (Y/N)"
            if ($confirm -eq "Y") {
                foreach ($feature in $features) {
                    Execute-Feature -FeatureKey $feature.Key
                }
            }
        }
        "S" {
            $selections = Read-Host " Select features (e.g., 1,3,5)"
            $indices = $selections -split ',' | ForEach-Object { [int]$_.Trim() - 1 }
            
            foreach ($index in $indices) {
                if ($index -ge 0 -and $index -lt $features.Count) {
                    Execute-Feature -FeatureKey $features[$index].Key
                }
            }
        }
        "B" { return }
    }
    
    Read-Host " Press Enter to continue"
}

function Show-FeatureSearch {
    Show-Banner
    Write-Host "`n FEATURE SEARCH" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    
    $searchTerm = Read-Host " Enter search term (or 'back' to return)"
    
    if ($searchTerm -eq "back") {
        return
    }
    
    $results = $global:Features.GetEnumerator() | Where-Object {
        $_.Value.Name -like "*$searchTerm*" -or 
        $_.Value.Description -like "*$searchTerm*" -or
        $_.Value.Category -like "*$searchTerm*"
    }
    
    if ($results) {
        Write-Host "`n Found $(@($results).Count) matching features:" -ForegroundColor Cyan
        $i = 1
        foreach ($result in $results) {
            Write-Host "`n [$i] $($result.Value.Name)" -ForegroundColor White
            Write-Host "      Category: $($result.Value.Category)" -ForegroundColor Gray
            Write-Host "      $($result.Value.Description)" -ForegroundColor Gray
            $i++
        }
        
        Write-Host ""
        $selection = Read-Host " Select features to apply (e.g., 1,3,5) or 'none'"
        
        if ($selection -ne "none" -and $selection -ne "") {
            $indices = $selection -split ',' | ForEach-Object { [int]$_.Trim() - 1 }
            
            foreach ($index in $indices) {
                if ($index -ge 0 -and $index -lt @($results).Count) {
                    Execute-Feature -FeatureKey @($results)[$index].Key
                }
            }
        }
    } else {
        Write-Host " No features found matching '$searchTerm'" -ForegroundColor Yellow
    }
    
    Read-Host "`n Press Enter to continue"
}

function Show-ProfileManager {
    Show-Banner
    Write-Host "`n PROFILE MANAGER" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    Write-Host " [1] Save Current Configuration" -ForegroundColor White
    Write-Host " [2] Load Saved Profile" -ForegroundColor White
    Write-Host " [3] Delete Profile" -ForegroundColor White
    Write-Host " [4] List All Profiles" -ForegroundColor White
    Write-Host " [5] Export Profile" -ForegroundColor White
    Write-Host " [6] Import Profile" -ForegroundColor White
    Write-Host ""
    Write-Host " [B] Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host " Enter your choice"
    
    switch ($choice) {
        "1" {
            $profileName = Read-Host " Enter profile name"
            if ($profileName) {
                Save-Profile -Name $profileName
            }
        }
        "2" {
            $profiles = Get-ChildItem -Path $global:ProfilesPath -Filter "*.json" -ErrorAction SilentlyContinue
            if ($profiles) {
                Write-Host "`n Available profiles:" -ForegroundColor Cyan
                $i = 1
                foreach ($profile in $profiles) {
                    Write-Host " [$i] $($profile.BaseName)" -ForegroundColor White
                    $i++
                }
                $selection = Read-Host "`n Select profile to load"
                $index = [int]$selection - 1
                if ($index -ge 0 -and $index -lt $profiles.Count) {
                    Load-Profile -Name $profiles[$index].BaseName
                }
            } else {
                Write-Host " No saved profiles found" -ForegroundColor Yellow
            }
        }
        "3" {
            $profileName = Read-Host " Enter profile name to delete"
            if ($profileName) {
                $profilePath = "$global:ProfilesPath\$profileName.json"
                if (Test-Path $profilePath) {
                    Remove-Item -Path $profilePath -Force
                    Write-LogMessage "Profile deleted: $profileName" "Success"
                } else {
                    Write-LogMessage "Profile not found: $profileName" "Error"
                }
            }
        }
        "4" {
            $profiles = Get-ChildItem -Path $global:ProfilesPath -Filter "*.json" -ErrorAction SilentlyContinue
            if ($profiles) {
                Write-Host "`n Saved profiles:" -ForegroundColor Cyan
                foreach ($profile in $profiles) {
                    try {
                        $data = Get-Content $profile.FullName | ConvertFrom-Json
                        Write-Host " - $($profile.BaseName)" -ForegroundColor White
                        Write-Host "    Created: $($data.Created)" -ForegroundColor Gray
                        Write-Host "    Features: $(@($data.Features).Count)" -ForegroundColor Gray
                    } catch {
                        Write-Host " - $($profile.BaseName) (corrupted)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host " No saved profiles found" -ForegroundColor Yellow
            }
        }
        "5" {
            Export-CurrentConfiguration
        }
        "6" {
            $importPath = Read-Host " Enter full path to profile file"
            if (Test-Path $importPath) {
                Import-Profile -Path $importPath
            } else {
                Write-LogMessage "File not found: $importPath" "Error"
            }
        }
        "B" { return }
        "b" { return }
    }
    
    Read-Host "`n Press Enter to continue"
}

function Save-Profile {
    param([string]$Name)
    
    $profile = @{
        Name = $Name
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Features = $global:AppliedFeatures
        System = @{
            OS = (Get-CimInstance Win32_OperatingSystem).Caption
            Version = (Get-CimInstance Win32_OperatingSystem).Version
            Build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        }
    }
    
    $profilePath = Join-Path $global:ProfilesPath "$Name.json"
    
    try {
        $profile | ConvertTo-Json -Depth 10 | Out-File -FilePath $profilePath -Force -Encoding UTF8
        Write-LogMessage "Profile saved: $Name" "Success"
    } catch {
        Write-LogMessage "Failed to save profile: $_" "Error"
    }
}

function Load-Profile {
    param([string]$Name)
    
    $profilePath = Join-Path $global:ProfilesPath "$Name.json"
    if (Test-Path $profilePath) {
        try {
            $profile = Get-Content $profilePath | ConvertFrom-Json
            
            Write-Host "`n Loading profile: $Name" -ForegroundColor Cyan
            Write-Host " Features to apply: $(@($profile.Features).Count)" -ForegroundColor White
            
            $confirm = Read-Host " Continue? (Y/N)"
            if ($confirm -eq "Y") {
                if (!$SkipRestorePoint) {
                    Create-SystemRestorePoint -Description "Before loading profile: $Name"
                }
                
                foreach ($feature in $profile.Features) {
                    Execute-Feature -FeatureKey $feature
                }
                
                Write-LogMessage "Profile loaded successfully: $Name" "Success"
            }
        } catch {
            Write-LogMessage "Failed to load profile: $_" "Error"
        }
    } else {
        Write-LogMessage "Profile not found: $Name" "Error"
    }
}

function Import-Profile {
    param([string]$Path)
    
    if (Test-Path $Path) {
        try {
            $fileName = Split-Path $Path -Leaf
            $destPath = Join-Path $global:ProfilesPath $fileName
            Copy-Item -Path $Path -Destination $destPath -Force
            Write-LogMessage "Profile imported: $fileName" "Success"
        } catch {
            Write-LogMessage "Failed to import profile: $_" "Error"
        }
    } else {
        Write-LogMessage "File not found: $Path" "Error"
    }
}

function Show-MaintenanceTools {
    Show-Banner
    Write-Host "`n MAINTENANCE TOOLS" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    Write-Host " [1] Clean Temporary Files" -ForegroundColor White
    Write-Host " [2] Run System File Checker (SFC)" -ForegroundColor White
    Write-Host " [3] Run DISM Health Check" -ForegroundColor White
    Write-Host " [4] Clear Windows Update Cache" -ForegroundColor White
    Write-Host " [5] Reset Network Settings" -ForegroundColor White
    Write-Host " [6] Clear DNS Cache" -ForegroundColor White
    Write-Host " [7] Optimize Drives" -ForegroundColor White
    Write-Host " [8] Check Disk (Schedule on reboot)" -ForegroundColor White
    Write-Host ""
    Write-Host " [B] Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host " Enter your choice"
    
    switch ($choice) {
        "1" {
            Write-Host " Cleaning temporary files..." -ForegroundColor Yellow
            
            # Clean user temp
            Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Clean Windows temp
            Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Clean prefetch
            Remove-Item "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
            
            # Flush DNS cache
            ipconfig /flushdns | Out-Null
            
            Write-LogMessage "Temporary files cleaned" "Success"
        }
        "2" {
            Write-Host " Running System File Checker..." -ForegroundColor Yellow
            Write-Host " This may take 10-20 minutes..." -ForegroundColor Gray
            sfc /scannow
        }
        "3" {
            Write-Host " Running DISM Health Check..." -ForegroundColor Yellow
            Write-Host " This may take 10-20 minutes..." -ForegroundColor Gray
            DISM /Online /Cleanup-Image /RestoreHealth
        }
        "4" {
            Write-Host " Clearing Windows Update cache..." -ForegroundColor Yellow
            
            $confirm = Read-Host " This will stop Windows Update service temporarily. Continue? (Y/N)"
            if ($confirm -eq "Y") {
                Stop-Service wuauserv -Force
                Remove-Item "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
                Start-Service wuauserv
                Write-LogMessage "Windows Update cache cleared" "Success"
            }
        }
        "5" {
            Write-Host " Resetting network settings..." -ForegroundColor Yellow
            Write-Host " WARNING: This will reset all network settings including WiFi passwords!" -ForegroundColor Red
            
            $confirm = Read-Host " Continue? (Y/N)"
            if ($confirm -eq "Y") {
                netsh winsock reset
                netsh int ip reset
                ipconfig /release
                ipconfig /renew
                ipconfig /flushdns
                Write-LogMessage "Network settings reset - reboot recommended" "Success"
            }
        }
        "6" {
            Write-Host " Clearing DNS cache..." -ForegroundColor Yellow
            ipconfig /flushdns
            Write-LogMessage "DNS cache cleared" "Success"
        }
        "7" {
            Write-Host " Optimizing drives..." -ForegroundColor Yellow
            Write-Host " This will optimize (defrag HDDs, TRIM SSDs)..." -ForegroundColor Gray
            
            Get-Volume | Where-Object { $_.DriveLetter -ne $null } | ForEach-Object {
                Write-Host " Optimizing drive $($_.DriveLetter):\" -ForegroundColor Gray
                Optimize-Volume -DriveLetter $_.DriveLetter -ErrorAction SilentlyContinue
            }
            
            Write-LogMessage "Drive optimization completed" "Success"
        }
        "8" {
            Write-Host " CHKDSK will scan for disk errors on next reboot" -ForegroundColor Yellow
            Write-Host " This can take SEVERAL HOURS depending on disk size!" -ForegroundColor Red
            
            $confirm = Read-Host " Schedule CHKDSK for next reboot? (Y/N)"
            if ($confirm -eq "Y") {
                cmd /c "echo Y | chkdsk C: /F /R"
                Write-LogMessage "CHKDSK scheduled for next reboot" "Success"
            }
        }
        "B" { return }
        "b" { return }
    }
    
    Read-Host "`n Press Enter to continue"
}

function Show-BackupRestore {
    Show-Banner
    Write-Host "`n BACKUP & RESTORE" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    Write-Host " [1] Create System Restore Point" -ForegroundColor White
    Write-Host " [2] Backup Registry" -ForegroundColor White
    Write-Host " [3] Restore Registry Backup" -ForegroundColor White
    Write-Host " [4] Export All Settings" -ForegroundColor White
    Write-Host " [5] List Restore Points" -ForegroundColor White
    Write-Host ""
    Write-Host " [B] Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host " Enter your choice"
    
    switch ($choice) {
        "1" {
            $description = Read-Host " Enter restore point description"
            if (!$description) { $description = "Manual Restore Point" }
            Create-SystemRestorePoint -Description $description
        }
        "2" {
            Write-Host " Backing up registry..." -ForegroundColor Yellow
            
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $backupFile = "$global:BackupPath\Registry_HKLM_$timestamp.reg"
            $backupFileUser = "$global:BackupPath\Registry_HKCU_$timestamp.reg"
            
            reg export HKLM "$backupFile" /y 2>&1 | Out-Null
            reg export HKCU "$backupFileUser" /y 2>&1 | Out-Null
            
            Write-LogMessage "Registry backed up to: $global:BackupPath" "Success"
        }
        "3" {
            $backups = Get-ChildItem -Path $global:BackupPath -Filter "*.reg" -ErrorAction SilentlyContinue
            if ($backups) {
                Write-Host "`n Available backups:" -ForegroundColor Cyan
                $i = 1
                foreach ($backup in $backups) {
                    Write-Host " [$i] $($backup.Name)" -ForegroundColor White
                    $i++
                }
                $selection = Read-Host "`n Select backup to restore"
                $index = [int]$selection - 1
                if ($index -ge 0 -and $index -lt $backups.Count) {
                    Write-Host " WARNING: This will modify the registry!" -ForegroundColor Red
                    $confirm = Read-Host " Are you sure? (yes/no)"
                    if ($confirm -eq "yes") {
                        reg import $backups[$index].FullName 2>&1 | Out-Null
                        Write-LogMessage "Registry restored from: $($backups[$index].Name)" "Success"
                    }
                }
            } else {
                Write-Host " No backup files found" -ForegroundColor Yellow
            }
        }
        "4" {
            Export-CurrentConfiguration
        }
        "5" {
            Write-Host "`n Available restore points:" -ForegroundColor Cyan
            try {
                Get-ComputerRestorePoint | Format-Table -AutoSize
            } catch {
                Write-Host " Could not retrieve restore points" -ForegroundColor Red
            }
        }
        "B" { return }
        "b" { return }
    }
    
    Read-Host "`n Press Enter to continue"
}

function Show-Information {
    Show-Banner
    Write-Host "`n INFORMATION & HELP" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    Write-Host " Windows 11 Ultimate Configuration Tool" -ForegroundColor White
    Write-Host " Version: $($global:ScriptVersion)" -ForegroundColor White
    Write-Host ""
    Write-Host " This tool provides comprehensive Windows 11 optimization and" -ForegroundColor Gray
    Write-Host " configuration options including:" -ForegroundColor Gray
    Write-Host ""
    Write-Host " • Privacy & Telemetry Management" -ForegroundColor White
    Write-Host " • Security Hardening" -ForegroundColor White
    Write-Host " • Performance Optimization" -ForegroundColor White
    Write-Host " • Bloatware Removal" -ForegroundColor White
    Write-Host " • AI Features Control" -ForegroundColor White
    Write-Host " • Interface Customization" -ForegroundColor White
    Write-Host " • Network Configuration" -ForegroundColor White
    Write-Host " • Development Tools" -ForegroundColor White
    Write-Host " • Apps Installation (winget/choco)" -ForegroundColor White
    Write-Host ""
    Write-Host " IMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host " - Always create a restore point before making changes" -ForegroundColor Gray
    Write-Host " - Some features require a system restart" -ForegroundColor Gray
    Write-Host " - Run this tool as Administrator" -ForegroundColor Gray
    Write-Host " - Review each feature's impact before applying" -ForegroundColor Gray
    Write-Host " - Some features may not work on Home edition" -ForegroundColor Gray
    Write-Host ""
    Write-Host " PATCHED MODE:" -ForegroundColor Green
    Write-Host " This version includes critical bug fixes for stability" -ForegroundColor Gray
    Write-Host " and more accurate system detection." -ForegroundColor Gray
    Write-Host ""
    Write-Host " Log file: $($global:LogFile)" -ForegroundColor Cyan
    Write-Host " Transcript: $($global:TranscriptFile)" -ForegroundColor Cyan
    Write-Host " Config path: $($global:ConfigPath)" -ForegroundColor Cyan
    Write-Host ""
    
    Read-Host " Press Enter to continue"
}

function Show-SystemInfo {
    Show-Banner
    Write-Host "`n SYSTEM INFORMATION" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor
    $mem = Get-CimInstance Win32_ComputerSystem
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $gpu = Get-CimInstance Win32_VideoController
    
    Write-Host " Operating System" -ForegroundColor Cyan
    Write-Host " ────────────────" -ForegroundColor Gray
    Write-Host " OS: $($os.Caption)" -ForegroundColor White
    Write-Host " EditionID: $(Get-WindowsEditionId)" -ForegroundColor White
    Write-Host " Version: $($os.Version)" -ForegroundColor White
    Write-Host " Build: $($os.BuildNumber)" -ForegroundColor White
    Write-Host " Architecture: $($os.OSArchitecture)" -ForegroundColor White
    Write-Host " Install Date: $($os.InstallDate)" -ForegroundColor White
    Write-Host ""
    
    Write-Host " Hardware" -ForegroundColor Cyan
    Write-Host " ────────" -ForegroundColor Gray
    Write-Host " Computer: $($env:COMPUTERNAME)" -ForegroundColor White
    Write-Host " User: $($env:USERNAME)" -ForegroundColor White
    Write-Host " CPU: $($cpu.Name)" -ForegroundColor White
    Write-Host " Cores: $($cpu.NumberOfCores) / Threads: $($cpu.NumberOfLogicalProcessors)" -ForegroundColor White
    Write-Host " RAM: $([math]::Round($mem.TotalPhysicalMemory / 1GB, 2)) GB" -ForegroundColor White
    Write-Host " GPU: $($gpu.Name)" -ForegroundColor White
    Write-Host ""
    
    Write-Host " Storage" -ForegroundColor Cyan
    Write-Host " ───────" -ForegroundColor Gray
    Write-Host " Drive C: $([math]::Round($disk.Size / 1GB, 2)) GB Total" -ForegroundColor White
    Write-Host " Free Space: $([math]::Round($disk.FreeSpace / 1GB, 2)) GB" -ForegroundColor White
    Write-Host " Used: $([math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)) GB" -ForegroundColor White
    Write-Host ""
    
    Write-Host " Network" -ForegroundColor Cyan
    Write-Host " ───────" -ForegroundColor Gray
    Get-NetAdapter | Where-Object Status -eq "Up" | ForEach-Object {
        Write-Host " Adapter: $($_.Name)" -ForegroundColor White
        Write-Host " Status: $($_.Status)" -ForegroundColor White
        Write-Host " Speed: $($_.LinkSpeed)" -ForegroundColor White
    }
    Write-Host ""
    
    Read-Host " Press Enter to continue"
}

function Show-LogFile {
    if (Test-Path $global:LogFile) {
        Write-Host "`n Opening log file..." -ForegroundColor Yellow
        notepad.exe $global:LogFile
    } else {
        Write-Host " Log file not found" -ForegroundColor Yellow
        Read-Host " Press Enter to continue"
    }
}

function Exit-Script {
    Write-Host "`n Exiting Windows 11 Configuration Tool..." -ForegroundColor Yellow
    
    # Check for pending reboots
    $rebootRequired = $false
    foreach ($featureKey in $global:AppliedFeatures) {
        if ($global:Features[$featureKey].RebootRequired) {
            $rebootRequired = $true
            break
        }
    }
    
    if ($rebootRequired -and !$NoReboot) {
        Write-Host " Some changes require a reboot to take effect." -ForegroundColor Yellow
        $confirm = Read-Host " Reboot now? (Y/N)"
        if ($confirm -eq "Y") {
            Write-LogMessage "System reboot initiated by user" "Info"
            Restart-Computer -Force
        }
    }
    
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
    } catch {}
    
    Write-Host " Thank you for using Windows 11 Configuration Tool!" -ForegroundColor Green
    Start-Sleep -Seconds 2
    
    exit 0
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Check administrator privileges
if (!(Test-Administrator)) {
    Write-Host "This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator." -ForegroundColor Yellow
    
    if (!$Silent) {
        Read-Host "Press Enter to exit"
    }
    exit 1
}

# Check Windows 11 compatibility
if (!(Test-Windows11)) {
    if (!$Silent) {
        exit 1
    }
}

# Set global flags from parameters
$global:AllUsers = $AllUsers.IsPresent
$global:DefaultUser = $DefaultUser.IsPresent

# Handle command-line parameters
if ($ExpressMode) {
    Write-LogMessage "Starting Express Mode" "Info"
    Show-QuickSetup
} 
elseif ($CustomMode) {
    Write-LogMessage "Starting Custom Mode" "Info"
    Show-CustomConfiguration
}
elseif ($MaintenanceMode) {
    Write-LogMessage "Starting Maintenance Mode" "Info"
    Show-MaintenanceTools
}
elseif ($ImportConfig) {
    Write-LogMessage "Importing configuration from: $ImportConfig" "Info"
    if (Test-Path $ImportConfig) {
        Import-Profile -Path $ImportConfig
    } else {
        Write-LogMessage "Import file not found: $ImportConfig" "Error"
    }
}
elseif ($ExportConfig) {
    Write-LogMessage "Exporting configuration" "Info"
    $exported = Export-CurrentConfiguration
    if ($exported -and $ExportConfig -ne "") {
        # Move to specified location
        Move-Item -Path $exported -Destination $ExportConfig -Force
        Write-LogMessage "Configuration exported to: $ExportConfig" "Success"
    }
}
elseif ($PSBoundParameters.Count -gt 0) {
    Write-LogMessage "Starting Windows 11 Configuration Tool v$($global:ScriptVersion)" "Info"
    
    # Create restore point if requested
    if ($CreateRestorePoint) {
        Create-SystemRestorePoint
    }
    
    # Handle specific parameter operations
    if ($RemoveAllBloatware) {
        $bloatwareFeatures = Get-CategoryFeatures -Category "Bloatware"
        foreach ($feature in $bloatwareFeatures) {
            Execute-Feature -FeatureKey $feature.Key
        }
    }
    
    if ($ApplyAllSecurity) {
        $securityFeatures = Get-CategoryFeatures -Category "Security"
        foreach ($feature in $securityFeatures) {
            Execute-Feature -FeatureKey $feature.Key
        }
    }
    
    if ($ApplyAllPrivacy) {
        $privacyFeatures = Get-CategoryFeatures -Category "Privacy"
        foreach ($feature in $privacyFeatures) {
            Execute-Feature -FeatureKey $feature.Key
        }
    }
    
    if ($ApplyAllPerformance) {
        $performanceFeatures = Get-CategoryFeatures -Category "Performance"
        foreach ($feature in $performanceFeatures) {
            Execute-Feature -FeatureKey $feature.Key
        }
    }
    
    if ($ApplyProfile) {
        Load-Profile -Name $ApplyProfile
    }
    
    if ($CombineProfiles) {
        foreach ($profileName in $CombineProfiles) {
            Load-Profile -Name $profileName
        }
    }
    
    if (!$Silent -and !$NoReboot) {
        # Check for reboot requirement
        $rebootRequired = $false
        foreach ($featureKey in $global:AppliedFeatures) {
            if ($global:Features[$featureKey].RebootRequired) {
                $rebootRequired = $true
                break
            }
        }
        
        if ($rebootRequired) {
            if ($ForceReboot) {
                Write-LogMessage "Rebooting system in 10 seconds..." "Warning"
                Start-Sleep -Seconds 10
                Restart-Computer -Force
            } else {
                Write-LogMessage "A reboot is required to complete configuration" "Warning"
            }
        }
    }
} 
else {
    # Interactive mode
    Show-MainMenu
}

# Cleanup
try {
    Stop-Transcript -ErrorAction SilentlyContinue
} catch {}
