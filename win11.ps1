# ============================================================================
# WINDOWS 11 ULTIMATE CONFIGURATION TOOL - VERSION 4.3 PATCHED (+ logging fix + Apps)
# Complete Bug Fixes & Security Hardening Edition (Refactored)
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
    [switch]$RestoreDefaults, # Not implemented yet, but good for future expansion
    
    # User Context
    [string]$User = $env:USERNAME, # This parameter isn't fully utilized for all user-specific settings, mainly for logging
    [switch]$AllUsers,
    [switch]$DefaultUser
)

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

$global:ScriptVersion = "4.3-PATCHED (Refactored)"
$global:ScriptName = "Windows 11 Ultimate Configuration Tool - Patched Edition"

# Ensure log directory exists
if (!(Test-Path $LogPath)) {
    try {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    } catch {
        Write-Warning "Unable to create log directory: $LogPath. Logs may not be saved. Error: $_"
        $LogPath = "$env:TEMP" # Fallback to temp
    }
}

# ---- Logging FIX: séparer transcript et log applicatif pour éviter les locks ----
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$global:LogFile        = Join-Path $LogPath "Win11Config_${stamp}.log"             # log applicatif (Write-LogMessage)
$global:TranscriptFile = Join-Path $LogPath "Win11Config_${stamp}.transcript.txt"  # transcript séparé

$global:ConfigPath = "$env:LOCALAPPDATA\Win11Config"
$global:BackupPath = Join-Path $global:ConfigPath "Backups"
$global:ProfilesPath = Join-Path $global:ConfigPath "Profiles"
$global:DebloatListPath = Join-Path $global:ConfigPath "DebloatLists" # Not used in current script, but kept for consistency
$global:TempPath = "$env:TEMP\Win11Config"
$global:AppliedFeatures = @() # Array to store keys of applied features
$global:LogVerbose = $VerboseLogging.IsPresent
$global:OriginalDNS = @{} # Hashtable to store original DNS settings

# Create necessary directories
@($global:ConfigPath, $global:BackupPath, $global:ProfilesPath, $global:DebloatListPath, $global:TempPath) | ForEach-Object {
    if (!(Test-Path $_)) {
        try {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        } catch {
            Write-Warning "Unable to create script directory $_. Error: $_"
        }
    }
}

# PATCH 2: Mount HKCR/HKU PS Drives if they don't exist
foreach ($d in @(@{Name='HKCR';Root='HKEY_CLASSES_ROOT'},
                 @{Name='HKU' ;Root='HKEY_USERS'})) {
    if (-not (Get-PSDrive $d.Name -ErrorAction SilentlyContinue)) {
        try {
            New-PSDrive -PSProvider Registry -Name $d.Name -Root $d.Root | Out-Null
        } catch {
            Write-Warning "Failed to mount PSDrive $($d.Name). Registry operations may be impacted. Error: $_"
        }
    }
}

# Start logging with error handling (transcript séparé)
try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
try { Start-Transcript -Path $global:TranscriptFile -Append -Force | Out-Null } catch { Write-Warning "Unable to start transcript logging: $_" }

# ============================================================================
# CORRECTED HELPER FUNCTIONS (+ Apps helpers)
# ============================================================================

function Write-LogMessage {
    param(
        [Parameter(Mandatory)] [string]$Message,
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
    try { Add-Content -Path $global:LogFile -Value $logEntry -Encoding UTF8 } catch {
        # Fallback if log file cannot be written
        Write-Host "[$timestamp] [Error] Failed to write to log file: $global:LogFile - $_" -ForegroundColor Red
    }
    
    # Verbose logging (using built-in Write-Verbose)
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
        
        # Check if the property exists before attempting to set it to avoid unnecessary "New-ItemProperty"
        # and to correctly handle (Default) values.
        $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($existing -ne $null -or $Name -eq '(Default)') {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            Write-LogMessage "Updated registry value: $Path\$Name" "Verbose"
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
            Write-LogMessage "Created registry value: $Path\$Name (Type: $Type)" "Verbose"
        }
        return $true
    } catch {
        Write-LogMessage "Failed to set registry value: $Path\$Name - $($_.Exception.Message)" "Error"
        return $false
    }
}

function Test-Windows11 {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $build = [int]$os.BuildNumber
        
        # Windows 11 builds: 22000 = 21H2, 22621/22631 = 22H2/23H2, 26100+ = 24H2
        if ($build -lt 22000) {
            Write-Warning "This script is designed for Windows 11 (build >= 22000). Current: $($os.Version) (build $build)"
            Write-Warning "Some features may not work correctly on Windows 10 or earlier."
            if (-not $global:Silent) {
                $continue = Read-Host "Continue anyway? (Y/N)"
                return ($continue -eq "Y" -or $continue -eq "y")
            } else {
                Write-LogMessage "Script running on non-Windows 11 system in silent mode. Proceeding with caution." "Warning"
                return $true
            }
        }
        
        Write-LogMessage "Windows 11 detected - Build: $build" "Info"
        return $true
    } catch {
        Write-LogMessage "Failed to detect OS version: $($_.Exception.Message)" "Error"
        Write-Warning "Unable to determine OS. Assuming Windows 11 for now, but proceed with caution."
        if (-not $global:Silent) {
            $continue = Read-Host "Continue anyway? (Y/N)"
            return ($continue -eq "Y" -or $continue -eq "y")
        } else {
            return $true
        }
    }
}

function Disable-TaskSafe {
    param(
        [Parameter(Mandatory)] [string]$TaskPath,
        [Parameter(Mandatory)] [string]$TaskName
    )
    
    try {
        # Use -ErrorAction SilentlyContinue for Get-ScheduledTask as it will error if task doesn't exist
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            if ($task.State -ne "Disabled") {
                $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null
                Write-LogMessage "Disabled task: $TaskPath$TaskName" "Success"
                return $true
            } else {
                Write-LogMessage "Task already disabled: $TaskPath$TaskName" "Verbose"
                return $true
            }
        } else {
            Write-LogMessage "Scheduled task not found: $TaskPath$TaskName" "Verbose"
            return $false
        }
    } catch {
        Write-LogMessage "Failed to disable task: $TaskPath$TaskName - $($_.Exception.Message)" "Warning"
        return $false
    }
}

# PATCH 1: Corrected Invoke-ForEachUserHive function
function Invoke-ForEachUserHive {
    param([Parameter(Mandatory)][ScriptBlock]$Script)

    # Current user
    Write-LogMessage "Applying to current user hive: HKCU:" "Verbose"
    & $Script 'HKCU:'

    if ($global:AllUsers) {
        Write-LogMessage "Applying to all user hives..." "Info"
        Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue |
          Where-Object { $_.PSChildName -match 'S-1-5-21-\d+-\d+-\d+-\d+$' -and $_.PSChildName -notmatch '_Classes$' } | # Exclude _Classes sub-hives
          ForEach-Object {
              $root = "Registry::" + $_.PSPath # Use PSPath for full path
              Write-LogMessage "Applying to user hive: $($_.PSChildName)" "Verbose"
              & $Script $root
          }
    }

    if ($global:DefaultUser) {
        $defaultNtuser = "$env:SystemDrive\Users\Default\NTUSER.DAT"
        if (Test-Path $defaultNtuser) {
            Write-LogMessage "Loading default user hive for modifications..." "Info"
            try {
                # Load the hive
                reg.exe load HKU\DefaultUser "$defaultNtuser" | Out-Null
                Start-Sleep -Milliseconds 500 # Small delay for hive to be fully loaded
                
                & $Script 'Registry::HKEY_USERS\DefaultUser'
                Write-LogMessage "Applied to default user profile" "Success"
            } catch {
                Write-LogMessage "Failed to apply settings to default user profile: $($_.Exception.Message)" "Error"
            } finally {
                # Unload the hive
                Start-Sleep -Milliseconds 500 # Small delay before unloading
                reg.exe unload HKU\DefaultUser | Out-Null
                Write-LogMessage "Unloaded default user hive" "Verbose"
            }
        } else {
            Write-LogMessage "Default user NTUSER.DAT not found at $defaultNtuser. Skipping default user profile." "Warning"
        }
    }
}

function Restart-Explorer {
    Write-LogMessage "Restarting Windows Explorer..." "Info"
    try {
        Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2 # Give explorer time to fully terminate
        Start-Process explorer.exe
        Write-LogMessage "Explorer restarted" "Success"
    } catch {
        Write-LogMessage "Failed to restart Explorer: $($_.Exception.Message)" "Warning"
    }
}

function Set-DnsSafe {
    param([string[]]$Servers = @("1.1.1.1", "1.0.0.1"))
    
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq "Up" | ForEach-Object {
        $idx = $_.ifIndex
        $adapterName = $_.Name
        
        try {
            # Backup current DNS only if there are existing settings
            $currentDns = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop
            
            # Check if there are actual DNS servers configured (ServerAddresses property is not null or empty)
            if ($currentDns.ServerAddresses -and $currentDns.ServerAddresses.Count -gt 0) {
                $global:OriginalDNS[$adapterName] = $currentDns.ServerAddresses
                Write-LogMessage "Setting DNS ($($Servers -join ', ')) on adapter: $adapterName" "Info"
                Write-LogMessage "Original DNS backed up for $adapterName: $($currentDns.ServerAddresses -join ', ')" "Verbose"
                
                Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $Servers -ErrorAction Stop
                Write-LogMessage "DNS configured successfully on $adapterName" "Success"
            } else {
                Write-LogMessage "Skipping adapter $adapterName : No existing DNS configuration detected, assuming DHCP." "Verbose"
            }
        } catch {
            Write-LogMessage "Failed to set DNS on $adapterName : $($_.Exception.Message)" "Warning"
        }
    }
}

# PATCH 3: Add locale-independent EditionID helper
function Get-WindowsEditionId {
    try {
        (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).EditionID
    } catch {
        Write-LogMessage "Failed to retrieve Windows Edition ID: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Enable-BitLockerSafe {
    $drive = $env:SystemDrive
    
    try {
        $editionId = Get-WindowsEditionId
        if (-not $editionId -or $editionId -notin @('Professional','ProfessionalN','ProfessionalWorkstation',
                                'Enterprise','EnterpriseN','Education','EducationN')) {
            Write-LogMessage "BitLocker requires Pro/Enterprise/Education. Current: $editionId" "Warning"
            return $false
        }
        
        # Check TPM
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if (!$tpm -or !$tpm.TpmPresent -or !$tpm.TpmReady) {
            Write-LogMessage "TPM not present or not ready - BitLocker may not work properly without TPM protector." "Warning"
            # Decide if you want to proceed without TPM, or require it
        }
        
        # Check current BitLocker status
        $vol = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
        
        if ($vol.VolumeStatus -eq 'FullyDecrypted') {
            Write-LogMessage "Enabling BitLocker on $drive..." "Info"
            
            # Enable with best practices
            # Use -SkipHardwareTest as it can sometimes cause issues or require manual intervention
            Enable-BitLocker -MountPoint $drive `
                -EncryptionMethod XtsAes256 `
                -UsedSpaceOnly `
                -TpmProtector `
                -RecoveryPasswordProtector `
                -SkipHardwareTest `
                -ErrorAction Stop
            
            # Get and display recovery key
            $recoveryKey = (Get-BitLockerVolume -MountPoint $drive).KeyProtector | 
                Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -ExpandProperty RecoveryPassword
            
            Write-LogMessage "BitLocker enabled successfully" "Success"
            Write-LogMessage "IMPORTANT - BitLocker Recovery Key: $recoveryKey" "Important"
            Write-LogMessage "SAVE THIS RECOVERY KEY IN A SECURE LOCATION!" "Important"
            
            # Save to file
            $keyFile = Join-Path $global:BackupPath "BitLocker_RecoveryKey_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $recoveryKey | Out-File -FilePath $keyFile -Force -Encoding UTF8
            Write-LogMessage "Recovery key saved to: $keyFile" "Info"
            
            return $true
        } elseif ($vol.VolumeStatus -eq 'EncryptionInProgress' -or $vol.VolumeStatus -eq 'PartiallyEncrypted') {
            Write-LogMessage "BitLocker encryption already in progress on $drive. Status: $($vol.VolumeStatus)" "Info"
            return $true
        } elseif ($vol.VolumeStatus -eq 'FullyEncrypted') {
            Write-LogMessage "BitLocker already fully enabled on $drive." "Info"
            return $true
        } else {
            Write-LogMessage "BitLocker status on $drive: $($vol.VolumeStatus). No action taken." "Warning"
            return $false
        }
    } catch {
        Write-LogMessage "Could not enable BitLocker: $($_.Exception.Message)" "Error"
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
            OS           = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
            Version      = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Version
            Build        = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).BuildNumber
        }
        AppliedFeatures = $global:AppliedFeatures
        Features        = $featuresMeta
        DNSBackup       = $global:OriginalDNS
    }
    
    $defaultExportPath = Join-Path $env:USERPROFILE "Desktop\Win11Config_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    try {
        $exportData | ConvertTo-Json -Depth 6 | Out-File -FilePath $defaultExportPath -Force -Encoding UTF8
        Write-LogMessage "Configuration exported to: $defaultExportPath" "Success"
        return $defaultExportPath
    } catch {
        Write-LogMessage "Failed to export configuration: $($_.Exception.Message)" "Error"
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
        # Check if System Restore is enabled for the system drive
        $rpStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if (-not $rpStatus -or -not (Get-Volume -DriveLetter $env:SystemDrive.Substring(0,1) | Select-Object -ExpandProperty DriveType) -eq 'Fixed') {
            Write-LogMessage "System Restore is not enabled for C: drive or it's not a fixed drive. Attempting to enable." "Warning"
            Enable-ComputerRestore -Drive "$env:SystemDrive" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1 # Give it a moment to enable
        }
        
        $before = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object SequenceNumber | Select-Object -Last 1).SequenceNumber
        
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        
        # Wait a bit for the restore point to actually appear
        for ($i = 0; $i -lt 10; $i++) { # Try up to 10 seconds
            Start-Sleep -Seconds 1
            $after = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object SequenceNumber | Select-Object -Last 1).SequenceNumber
            if ($after -and $after -ne $before) {
                Write-LogMessage "System restore point created successfully (Sequence Number: $after)" "Success"
                return $true
            }
        }

        Write-LogMessage "Restore point not created (check system restore settings or frequency limit)." "Warning"
        return $false
    } catch {
        Write-LogMessage "Failed to create restore point: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-CategoryFeatures {
    param([Parameter(Mandatory)] [string]$Category)
    
    return $global:Features.GetEnumerator() | Where-Object {
        $_.Value.Category -eq $Category
    } | Sort-Object Name
}

function Execute-Feature {
    param([Parameter(Mandatory)] [string]$FeatureKey)
    
    $feature = $global:Features[$FeatureKey]
    if (!$feature) {
        Write-LogMessage "Feature not found: $FeatureKey" "Error"
        return $false
    }
    
    Write-LogMessage "Executing: $($feature.Name)" "Info"
    
    try {
        & $feature.Script
        $global:AppliedFeatures += $FeatureKey # Keep track of what was applied
        Write-LogMessage "Successfully executed: $($feature.Name)" "Success"
        return $true
    } catch {
        Write-LogMessage "Failed to execute: $($feature.Name) - $($_.Exception.Message)" "Error"
        return $false
    }
}

# ---------- Helpers pour installation d'applications (winget/choco) ----------

function Ensure-WingetOrChoco {
    # Check for winget
    if (Get-Command winget -ErrorAction SilentlyContinue) { 
        Write-LogMessage "winget found." "Verbose"
        return "winget" 
    }

    # Check for choco
    if (Get-Command choco -ErrorAction SilentlyContinue) { 
        Write-LogMessage "Chocolatey found." "Verbose"
        return "choco"  
    }

    Write-LogMessage "winget not found. Attempting to install Chocolatey (fallback)..." "Warning"
    try {
        # Temporarily bypass execution policy for the Chocolatey install script
        $oldExecutionPolicy = Get-ExecutionPolicy -Scope Process
        Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
        
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Restore execution policy
        Set-ExecutionPolicy $oldExecutionPolicy -Scope Process -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-LogMessage "Failed to install Chocolatey: $($_.Exception.Message)" "Error"
        # Restore execution policy even on error if it was changed
        if ($oldExecutionPolicy) {
            Set-ExecutionPolicy $oldExecutionPolicy -Scope Process -Force -ErrorAction SilentlyContinue
        }
        return $null
    }

    if (Get-Command choco -ErrorAction SilentlyContinue) {
		Write-LogMessage "Chocolatey installed successfully." "Success"
		return "choco"
	} else {
		Write-LogMessage "Chocolatey was not successfully installed." "Error"
		return $null
	}
}

function Install-AppBundle {
    param(
        [string[]]$WingetIds,
        [string[]]$ChocoIds
    )
    $pm = Ensure-WingetOrChoco
    if (-not $pm) { Write-LogMessage "No package manager (winget or Chocolatey) available. Cannot install apps." "Error"; return }

    if ($pm -eq "winget") {
        Write-LogMessage "Installing applications using winget..." "Info"
        foreach ($id in $WingetIds) {
            Write-LogMessage "Attempting to install $id with winget." "Info"
            try {
                # Add --source winget if you want to be explicit, but it's default
                # Using -e (exact) for better matching, --silent for no prompts
                winget install --id $id -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
                Write-LogMessage "Successfully installed $id." "Success"
            } catch {
                Write-LogMessage "Failed to install $id with winget: $($_.Exception.Message)" "Warning"
            }
        }
    } else { # $pm -eq "choco"
        Write-LogMessage "Installing applications using Chocolatey..." "Info"
        foreach ($id in $ChocoIds) {
            Write-LogMessage "Attempting to install $id with choco." "Info"
            try {
                # -y for yes to all prompts, --no-progress to suppress progress bar
                choco install $id -y --no-progress -ErrorAction Stop | Out-Null
                Write-LogMessage "Successfully installed $id." "Success"
            } catch {
                Write-LogMessage "Failed to install $id with Chocolatey: $($_.Exception.Message)" "Warning"
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
            $edition = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
            $telemetryLevel = if ($edition -match 'Home') { 1 } else { 0 } # 0=Security, 1=Basic (Home can't go to 0)
            
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
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Feedback\" -TaskName "SqmUpload_MicrosoftEdge" # Added
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Maintenance\" -TaskName "WinSAT" # Often considered telemetry
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
            
            # Also user-specific settings
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0 "DWord"
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Privacy\Experiences" "UserActivity" 0 "DWord"
            }
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
