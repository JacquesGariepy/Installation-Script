# ============================================================================
# WINDOWS 11 ULTIMATE CONFIGURATION TOOL - VERSION 4.4 (Corrected)
# Full Feature Set with All Optimizations, Privacy, Security & Tweaks
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

$global:ScriptVersion = "4.4-Corrected"
$global:ScriptName = "Windows 11 Ultimate Configuration Tool - Complete Edition"

# Ensure log directory exists
if (!(Test-Path $LogPath)) {
    try {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    } catch {
        Write-Warning "Unable to create log directory: $LogPath. Logs may not be saved. Error: $_"
        $LogPath = "$env:TEMP"
    }
}

# Logging FIX: separate transcript and application log to avoid locks
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$global:LogFile       = Join-Path $LogPath "Win11Config_${stamp}.log"
$global:TranscriptFile = Join-Path $LogPath "Win11Config_${stamp}.transcript.txt"

$global:ConfigPath = "$env:LOCALAPPDATA\Win11Config"
$global:BackupPath = Join-Path $global:ConfigPath "Backups"
$global:ProfilesPath = Join-Path $global:ConfigPath "Profiles"
$global:DebloatListPath = Join-Path $global:ConfigPath "DebloatLists"
$global:TempPath = "$env:TEMP\Win11Config"
$global:AppliedFeatures = @()
$global:LogVerbose = $VerboseLogging.IsPresent
$global:OriginalDNS = @{}

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

# Mount HKCR/HKU PS Drives if they don't exist
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

# Start logging with error handling
try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
try { Start-Transcript -Path $global:TranscriptFile -Append -Force | Out-Null } catch { Write-Warning "Unable to start transcript logging: $_" }

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-LogMessage {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with color
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
    
    # Write to application log file
    try { 
        Add-Content -Path $global:LogFile -Value $logEntry -Encoding UTF8 
    } catch {
        Write-Host "[$timestamp] [Error] Failed to write to log file: $global:LogFile - $_" -ForegroundColor Red
    }
    
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

function Invoke-ForEachUserHive {
    param([Parameter(Mandatory)][ScriptBlock]$Script)

    # Current user
    Write-LogMessage "Applying to current user hive: HKCU:" "Verbose"
    & $Script 'HKCU:'

    if ($global:AllUsers) {
        Write-LogMessage "Applying to all user hives..." "Info"
        Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue |
          Where-Object { $_.PSChildName -match 'S-1-5-21-\d+-\d+-\d+-\d+$' -and $_.PSChildName -notmatch '_Classes$' } |
          ForEach-Object {
              $root = "Registry::" + $_.PSPath
              Write-LogMessage "Applying to user hive: $($_.PSChildName)" "Verbose"
              & $Script $root
          }
    }

    if ($global:DefaultUser) {
        $defaultNtuser = "$env:SystemDrive\Users\Default\NTUSER.DAT"
        if (Test-Path $defaultNtuser) {
            Write-LogMessage "Loading default user hive for modifications..." "Info"
            try {
                reg.exe load HKU\DefaultUser "$defaultNtuser" | Out-Null
                Start-Sleep -Milliseconds 500
                
                & $Script 'Registry::HKEY_USERS\DefaultUser'
                Write-LogMessage "Applied to default user profile" "Success"
            } catch {
                Write-LogMessage "Failed to apply settings to default user profile: $($_.Exception.Message)" "Error"
            } finally {
                Start-Sleep -Milliseconds 500
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
        Start-Sleep -Seconds 2
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
            $currentDns = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop
            
            if ($currentDns.ServerAddresses -and $currentDns.ServerAddresses.Count -gt 0) {
                $global:OriginalDNS[$adapterName] = $currentDns.ServerAddresses
                Write-LogMessage "Setting DNS ($($Servers -join ', ')) on adapter: $adapterName" "Info"
                Write-LogMessage "Original DNS backed up for ${adapterName}: $($currentDns.ServerAddresses -join ', ')" "Verbose"
                
                Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $Servers -ErrorAction Stop
                Write-LogMessage "DNS configured successfully on $adapterName" "Success"
            } else {
                Write-LogMessage "Skipping adapter ${adapterName}: No existing DNS configuration detected, assuming DHCP." "Verbose"
            }
        } catch {
            Write-LogMessage "Failed to set DNS on ${adapterName}: $($_.Exception.Message)" "Warning"
        }
    }
}

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
        
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if (!$tpm -or !$tpm.TpmPresent -or !$tpm.TpmReady) {
            Write-LogMessage "TPM not present or not ready - BitLocker may not work properly without TPM protector." "Warning"
        }
        
        $vol = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
        
        if ($vol.VolumeStatus -eq 'FullyDecrypted') {
            Write-LogMessage "Enabling BitLocker on $drive..." "Info"
            
            Enable-BitLocker -MountPoint $drive `
                -EncryptionMethod XtsAes256 `
                -UsedSpaceOnly `
                -TpmProtector `
                -RecoveryPasswordProtector `
                -SkipHardwareTest `
                -ErrorAction Stop
            
            $recoveryKey = (Get-BitLockerVolume -MountPoint $drive).KeyProtector | 
                Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | 
                Select-Object -ExpandProperty RecoveryPassword
            
            Write-LogMessage "BitLocker enabled successfully" "Success"
            Write-LogMessage "IMPORTANT - BitLocker Recovery Key: $recoveryKey" "Important"
            Write-LogMessage "SAVE THIS RECOVERY KEY IN A SECURE LOCATION!" "Important"
            
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
            Write-LogMessage "BitLocker status on ${drive}: $($vol.VolumeStatus). No action taken." "Warning"
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
║                Complete Feature Set - Patched & Hardened Edition             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Create-SystemRestorePoint {
    param([string]$Description = "Windows 11 Configuration Tool v$($global:ScriptVersion)")

    Write-LogMessage "Creating system restore point..." "Info"
    try {
        $systemDriveLetter = $env:SystemDrive.Substring(0,1)
        $isRestoreEnabled = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -First 1)
        
        if (-not (Get-WmiObject -Class Win32_ComputerSystem).IsDomainMember -and -not (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Where-Object {$_.EventType -eq 'ENABLE_SYSTEM_RESTORE'})) {
            Write-LogMessage "System Restore might not be fully enabled or configured. Attempting to enable." "Warning"
            Enable-ComputerRestore -Drive "$systemDriveLetter" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }
        
        $before = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object SequenceNumber | Select-Object -Last 1).SequenceNumber
        
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        
        for ($i = 0; $i -lt 10; $i++) {
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
        if (-not ($global:AppliedFeatures -contains $FeatureKey)) {
             $global:AppliedFeatures += $FeatureKey
        }
        Write-LogMessage "Successfully executed: $($feature.Name)" "Success"
        return $true
    } catch {
        Write-LogMessage "Failed to execute: $($feature.Name) - $($_.Exception.Message)" "Error"
        return $false
    }
}

function Install-Chocolatey {
    try {
        Write-LogMessage "Installing Chocolatey..." "Info"
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent","Win11ConfigTool/4.4 (+powershell)")
        $script = $wc.DownloadString("https://community.chocolatey.org/install.ps1")
        iex $script
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-LogMessage "Chocolatey installed successfully." "Success"
            return $true
        } else {
            throw "choco command not found after install."
        }
    } catch {
        Write-LogMessage "Chocolatey install failed: $($_.Exception.Message)" "Error"
        return $false
    }
}

function global:Ensure-WingetOrChoco {
    # Si déjà défini pour la session, retourner la préférence
    if ($global:PackageManagerPreference) { return $global:PackageManagerPreference }

    # 1) Détection locale
    $hasWinget = Get-Command winget -ErrorAction SilentlyContinue
    $hasChoco  = Get-Command choco  -ErrorAction SilentlyContinue
    if ($hasWinget -and $hasChoco) { $global:PackageManagerPreference = "winget"; return "winget" }
    if ($hasWinget) { $global:PackageManagerPreference = "winget"; return "winget" }
    if ($hasChoco)  { $global:PackageManagerPreference = "choco";  return "choco"  }

    Write-LogMessage "No package manager found." "Important"

    # 2) Tentative d’installation de Winget (Microsoft Store → offline GitHub)
    try {
        # a) Préparer environnement (TLS, Sideloading/Developer Mode)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Force | Out-Null
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps" -Type DWord -Value 1

        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Force | Out-Null
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1

        # b) Via Microsoft Store (officiel)
        if (-not $global:Silent) {
            Write-LogMessage "Opening Microsoft Store page for 'App Installer'… install/update it, then return here." "Info"
            Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"
            Read-Host "After installing/updating 'App Installer', press Enter to continue"
        }

        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-LogMessage "Winget detected after Microsoft Store flow." "Success"
            $global:PackageManagerPreference = "winget"
            return "winget"
        }

        # c) Offline GitHub : VCLibs (aka.ms) + App Installer (.msixbundle)
        Write-LogMessage "Attempting offline install of Winget from GitHub releases..." "Info"
        $UA = @{ "User-Agent" = "Win11ConfigTool/4.4 (+powershell)" }

        # Arch
        $arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        $wantArch = if ($arch -match "ARM64") { "arm64" } else { "x64" }

        # Dossier temp propre
        $tempDir = Join-Path $env:TEMP "Winget-Install"
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
        New-Item $tempDir -ItemType Directory | Out-Null

        # Télécharger VCLibs UWP Desktop depuis aka.ms (lien Microsoft stable)
        $vclibsUrl = if ($wantArch -eq "arm64") {
            "https://aka.ms/Microsoft.VCLibs.140.00.UWPDesktop.arm64"
        } else {
            "https://aka.ms/Microsoft.VCLibs.140.00.UWPDesktop.x64"
        }
        $vclibsPath = Join-Path $tempDir "Microsoft.VCLibs.140.00.UWPDesktop.$wantArch.appx"
        Invoke-WebRequest -Uri $vclibsUrl -OutFile $vclibsPath -UseBasicParsing

        # Vérif taille + signature (évite 0x8007000D)
        if ((Get-Item $vclibsPath).Length -lt 500KB) { throw "Downloaded VCLibs looks too small (<500KB)." }
        $sig = Get-AuthenticodeSignature $vclibsPath
        if ($sig.Status -ne 'Valid') { throw "VCLibs signature invalid: $($sig.Status)" }

        # Installer VCLibs avant App Installer
        Write-LogMessage "Installing dependency VCLibs ($wantArch)..." "Info"
        Add-AppxPackage -Path $vclibsPath -ErrorAction Stop

        # Récupérer dernière release winget-cli
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-cli/releases/latest" -Headers $UA -ErrorAction Stop
        $msix = $release.assets | Where-Object {
            $_.name -match "DesktopAppInstaller.*\.msixbundle$" -or
            $_.name -match "AppInstaller.*\.msixbundle$"      -or
            $_.name -match "Microsoft\.DesktopAppInstaller_.*\.msixbundle$"
        } | Select-Object -First 1
        if (-not $msix) { throw "No .msixbundle found in latest winget-cli release." }

        $msixPath = Join-Path $tempDir $msix.name
        Invoke-WebRequest -Uri $msix.browser_download_url -OutFile $msixPath -UseBasicParsing -Headers $UA

        if ((Get-Item $msixPath).Length -lt 2MB) { throw "Downloaded App Installer bundle looks too small (<2MB)." }
        $sig2 = Get-AuthenticodeSignature $msixPath
        if ($sig2.Status -ne 'Valid') { throw "App Installer signature invalid: $($sig2.Status)" }

        Write-LogMessage "Installing App Installer (.msixbundle)..." "Info"
        Add-AppxPackage -Path $msixPath -ErrorAction Stop

        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-LogMessage "Winget installed successfully (offline path)." "Success"
            $global:PackageManagerPreference = "winget"
            return "winget"
        } else {
            throw "Winget command not available after offline install."
        }
    } catch {
        Write-LogMessage "Winget installation failed: $($_.Exception.Message)" "Error"
    }

    # 3) Fallback → Chocolatey (nécessite la fonction Install-Chocolatey définie ailleurs)
    Write-LogMessage "Falling back to Chocolatey..." "Important"
    try {
        if (Get-Command Install-Chocolatey -ErrorAction SilentlyContinue) {
            if (Install-Chocolatey) {
                $global:PackageManagerPreference = "choco"
                return "choco"
            }
        } else {
            # Fallback inline si la fonction n'est pas définie
            Write-LogMessage "Install-Chocolatey function not found — attempting inline install." "Warning"
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent","Win11ConfigTool/4.4 (+powershell)")
            $script = $wc.DownloadString("https://community.chocolatey.org/install.ps1")
            iex $script
            if (Get-Command choco -ErrorAction SilentlyContinue) {
                $global:PackageManagerPreference = "choco"
                return "choco"
            }
        }
    } catch {
        Write-LogMessage "Chocolatey install failed: $($_.Exception.Message)" "Error"
    }

    Write-LogMessage "No package manager could be configured." "Error"
    return $null
}

function global:Install-AppBundle {
    param(
        [string[]]$WingetIds,
        [string[]]$ChocoIds
    )
    $pm = Ensure-WingetOrChoco
    if (-not $pm) { 
        Write-LogMessage "No package manager (winget or Chocolatey) available. Cannot install apps." "Error"
        # === CORRECTION ICI : Générer une erreur pour arrêter l'exécution ===
        throw "Package manager configuration failed."
        # === FIN DE LA CORRECTION ===
    }

    if ($pm -eq "winget") {
        Write-LogMessage "Installing applications using winget..." "Info"
        foreach ($id in $WingetIds) {
            Write-LogMessage "Attempting to install $id with winget." "Info"
            try {
                winget install --id $id -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
                Write-LogMessage "Successfully installed $id." "Success"
            } catch {
                Write-LogMessage "Failed to install $id with winget: $($_.Exception.Message)" "Warning"
            }
        }
    } else {
        Write-LogMessage "Installing applications using Chocolatey..." "Info"
        foreach ($id in $ChocoIds) {
            Write-LogMessage "Attempting to install $id with choco." "Info"
            try {
                choco install $id -y --no-progress -ErrorAction Stop | Out-Null
                Write-LogMessage "Successfully installed $id." "Success"
            } catch {
                Write-LogMessage "Failed to install $id with Chocolatey: $($_.Exception.Message)" "Warning"
            }
        }
    }
}

function Disable-ServiceSafe {
    param([string]$ServiceName)
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            }
            Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
            Write-LogMessage "Disabled service: $ServiceName" "Success"
            return $true
        } else {
            Write-LogMessage "Service not found: $ServiceName" "Verbose"
            return $false
        }
    } catch {
        Write-LogMessage "Failed to disable service ${ServiceName}: $($_.Exception.Message)" "Warning"
        return $false
    }
}

function Remove-AppxPackageSafe {
    param([string]$PackageName)
    
    try {
        $packages = Get-AppxPackage -Name $PackageName -AllUsers -ErrorAction SilentlyContinue
        if ($packages) {
            foreach ($package in $packages) {
                Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                Write-LogMessage "Removed package: $($package.Name)" "Success"
            }
            
            # Also remove provisioned packages to prevent reinstallation
            $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -like $PackageName }
            foreach ($prov in $provisioned) {
                Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue
                Write-LogMessage "Removed provisioned package: $($prov.DisplayName)" "Success"
            }
            return $true
        } else {
            Write-LogMessage "Package not found: $PackageName" "Verbose"
            return $false
        }
    } catch {
        Write-LogMessage "Failed to remove package ${PackageName}: $($_.Exception.Message)" "Warning"
        return $false
    }
}

function Load-ApplicationManifest {
    param(
        [string]$Path = (Join-Path $PSScriptRoot "apps.json")
    )

    Write-LogMessage "Loading application manifest from: $Path" "Verbose"
    if (-not (Test-Path $Path)) {
        Write-LogMessage "Application manifest 'apps.json' not found at '$Path'. No applications will be available for installation." "Warning"
        return $null
    }

    try {
        $manifest = Get-Content -Path $Path -Raw | ConvertFrom-Json -ErrorAction Stop
        Write-LogMessage "Application manifest loaded successfully." "Success"
        return $manifest
    } catch {
        Write-LogMessage "Failed to load or parse 'apps.json': $($_.Exception.Message)" "Error"
        return $null
    }
}

function Register-ApplicationFeaturesFromManifest {
    param(
        [Parameter(Mandatory)] $AppManifest
    )

    if (-not $AppManifest) { return }

    $bundles = $AppManifest.PSObject.Properties | ForEach-Object { $_.Name }

    foreach ($bundleName in $bundles) {
        $bundle = $AppManifest.$bundleName
        $featureKey = "Apps.Install_$($bundleName)"

        # Use displayName if provided, otherwise generate a name from the key
        $displayName = if ($bundle.displayName) { 
            $bundle.displayName 
        } else { 
            ($bundleName -replace '([A-Z])', ' $1').Trim() 
        }

        $global:Features[$featureKey] = @{
            Name           = "Install $displayName"
            Category       = "Applications"
            Description    = $bundle.description
            Impact         = "Low"
            RebootRequired = $false
            Script         = {
                $wingetIds = $bundle.apps.wingetId | Where-Object { $_ }
                $chocoIds = $bundle.apps.chocoId | Where-Object { $_ }
                Install-AppBundle -WingetIds $wingetIds -ChocoIds $chocoIds
            }.GetNewClosure() # Use GetNewClosure() to capture the current state of $bundle
        }
        Write-LogMessage "Registered application bundle: $bundleName as '$displayName'" "Verbose"
    }
}

# ============================================================================
# COMPREHENSIVE FEATURE DEFINITIONS - COMPLETE SET
# ============================================================================

$global:Features = @{
    
    # ==============================
    # PRIVACY & TELEMETRY FEATURES
    # ==============================
    
    "Privacy.DisableTelemetry" = @{
        Name = "Disable Telemetry"
        Category = "Privacy"
        Description = "Reduce Windows telemetry to minimum level"
        Impact = "High"
        RebootRequired = $false
        Script = {
            $edition = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
            $telemetryLevel = if ($edition -match 'Home') { 1 } else { 0 }
            
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" $telemetryLevel "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" $telemetryLevel "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" $telemetryLevel "DWord"
            
            # Disable telemetry services
            Disable-ServiceSafe -ServiceName "DiagTrack"
            Disable-ServiceSafe -ServiceName "dmwappushservice"
            
            # Disable telemetry scheduled tasks
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
            
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0 "DWord"
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
        Category = "Privacy"
        Description = "Disable all location tracking services"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny" "String"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0 "DWord"
            
            Disable-ServiceSafe -ServiceName "lfsvc"
        }
    }
    
    "Privacy.DisableWebSearch" = @{
        Name = "Disable Web Search in Start Menu"
        Category = "Privacy"
        Description = "Disable Bing web search in Start Menu"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0 "DWord"
            
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "AllowSearchToUseLocation" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0 "DWord"
            }
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
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Siuf\Rules" "PeriodInNanoSeconds" 0 "DWord"
            }
            
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Feedback\Siuf\" -TaskName "DmClient"
            Disable-TaskSafe -TaskPath "\Microsoft\Windows\Feedback\Siuf\" -TaskName "DmClientOnScenarioDownload"
        }
    }
    
    "Privacy.DisableTimeline" = @{
        Name = "Disable Timeline"
        Category = "Privacy"
        Description = "Disable Windows Timeline feature"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0 "DWord"
            
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenEnabled" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenOverlayEnabled" 0 "DWord"
            }
        }
    }
    
    "Privacy.DisableBiometrics" = @{
        Name = "Disable Biometrics"
        Category = "Privacy"
        Description = "Disable Windows Hello biometric features"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" "Enabled" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsHello" "Enabled" 0 "DWord"
            Disable-ServiceSafe -ServiceName "WbioSrvc"
        }
    }
    
    "Privacy.DisableInkAndTyping" = @{
        Name = "Disable Ink & Typing Personalization"
        Category = "Privacy"
        Description = "Disable handwriting and typing data collection"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0 "DWord"
            }
        }
    }
    
    "Privacy.DisableAppDiagnostics" = @{
        Name = "Disable App Diagnostics"
        Category = "Privacy"
        Description = "Prevent apps from accessing diagnostic info"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" "Value" "Deny" "String"
            
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" "Value" "Deny" "String"
            }
        }
    }
    
    # ==============================
    # PERFORMANCE FEATURES
    # ==============================
    
    "Performance.DisableBackgroundApps" = @{
        Name = "Disable Background Apps"
        Category = "Performance"
        Description = "Prevent apps from running in the background"
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
    
    "Performance.DisableStartupDelay" = @{
        Name = "Disable Startup Delay"
        Category = "Performance"
        Description = "Remove artificial startup delay for desktop apps"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" "StartupDelayInMSec" 0 "DWord"
        }
    }
    
    "Performance.DisableSearchIndexing" = @{
        Name = "Disable Search Indexing"
        Category = "Performance"
        Description = "Disable Windows Search indexing for better performance"
        Impact = "High"
        RebootRequired = $false
        Script = {
            Disable-ServiceSafe -ServiceName "WSearch"
        }
    }
    
    "Performance.DisableSuperfetch" = @{
        Name = "Disable Superfetch/SysMain"
        Category = "Performance"
        Description = "Disable Superfetch service (useful for SSDs)"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Disable-ServiceSafe -ServiceName "SysMain"
        }
    }
    
    "Performance.DisablePrefetch" = @{
        Name = "Disable Prefetch"
        Category = "Performance"
        Description = "Disable prefetching (useful for SSDs)"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 0 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 0 "DWord"
        }
    }
    
    "Performance.OptimizeVisualEffects" = @{
        Name = "Optimize Visual Effects"
        Category = "Performance"
        Description = "Adjust for best performance (disable animations)"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Control Panel\Desktop" "UserPreferencesMask" ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) "Binary"
                Set-RegistryValue "$root\Control Panel\Desktop\WindowMetrics" "MinAnimate" "0" "String"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewAlphaSelect" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewShadow" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAnimations" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\DWM" "EnableAeroPeek" 0 "DWord"
            }
        }
    }
    
    "Performance.DisableGameDVR" = @{
        Name = "Disable Game DVR"
        Category = "Performance"
        Description = "Disable Xbox Game DVR for better gaming performance"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" 0 "DWord"
                Set-RegistryValue "$root\System\GameConfigStore" "GameDVR_Enabled" 0 "DWord"
            }
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowgameDVR" 0 "DWord"
        }
    }
    
    "Performance.DisableHibernation" = @{
        Name = "Disable Hibernation"
        Category = "Performance"
        Description = "Disable hibernation and delete hiberfil.sys"
        Impact = "High"
        RebootRequired = $false
        Script = {
            powercfg /h off
            Write-LogMessage "Hibernation disabled and hiberfil.sys removed" "Success"
        }
    }
    
    "Performance.EnableFastStartup" = @{
        Name = "Enable Fast Startup"
        Category = "Performance"
        Description = "Enable fast startup for quicker boot times"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" 1 "DWord"
        }
    }
    
    "Performance.DisableWindowsTips" = @{
        Name = "Disable Windows Tips"
        Category = "Performance"
        Description = "Disable Windows tips and suggestions"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0 "DWord"
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0 "DWord"
            }
        }
    }
    
    "Performance.ClearPageFileAtShutdown" = @{
        Name = "Clear Page File at Shutdown"
        Category = "Performance"
        Description = "Clear virtual memory page file at shutdown (slower shutdown)"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 1 "DWord"
        }
    }
    
    # ==============================
    # SECURITY FEATURES
    # ==============================
    
    "Security.EnableBitLocker" = @{
        Name = "Enable BitLocker Encryption"
        Category = "Security"
        Description = "Enable BitLocker drive encryption on system drive"
        Impact = "High"
        RebootRequired = $true
        Script = {
            Enable-BitLockerSafe
        }
    }
    
    "Security.EnableFirewall" = @{
        Name = "Enable Windows Firewall"
        Category = "Security"
        Description = "Enable Windows Firewall for all profiles"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-NetFirewallProfile -All -Enabled True
            Write-LogMessage "Windows Firewall enabled for all profiles" "Success"
        }
    }
    
    "Security.DisableSMBv1" = @{
        Name = "Disable SMBv1"
        Category = "Security"
        Description = "Disable insecure SMBv1 protocol"
        Impact = "Medium"
        RebootRequired = $true
        Script = {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" 0 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" "DependOnService" @("Bowser","MRxSmb20","NSI") "MultiString"
        }
    }
    
    "Security.SetSecureDNS" = @{
        Name = "Set Secure DNS (Cloudflare)"
        Category = "Security"
        Description = "Configure Cloudflare DNS for better privacy"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-DnsSafe -Servers @("1.1.1.1", "1.0.0.1")
        }
    }
    
    "Security.EnableWindowsDefender" = @{
        Name = "Enable Windows Defender"
        Category = "Security"
        Description = "Ensure Windows Defender is fully enabled"
        Impact = "High"
        RebootRequired = $false
        Script = {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableOnAccessProtection" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableScanOnRealtimeEnable" 0 "DWord"
            
            Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            Write-LogMessage "Windows Defender enabled" "Success"
        }
    }
    
    "Security.EnableUAC" = @{
        Name = "Enable UAC (Maximum)"
        Category = "Security"
        Description = "Set UAC to maximum protection level"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 2 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" 3 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1 "DWord"
        }
    }
    
    "Security.DisableAutoplay" = @{
        Name = "Disable Autoplay"
        Category = "Security"
        Description = "Disable autoplay for all drives"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" 255 "DWord"
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" "DisableAutoplay" 1 "DWord"
            }
        }
    }
    
    "Security.DisableRemoteDesktop" = @{
        Name = "Disable Remote Desktop"
        Category = "Security"
        Description = "Disable Remote Desktop connections"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" 1 "DWord"
            Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        }
    }
    
    "Security.EnableCoreisolation" = @{
        Name = "Enable Core Isolation"
        Category = "Security"
        Description = "Enable memory integrity for core isolation"
        Impact = "Medium"
        RebootRequired = $true
        Script = {
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" 1 "DWord"
        }
    }
    
    "Security.BlockUntrustedFonts" = @{
        Name = "Block Untrusted Fonts"
        Category = "Security"
        Description = "Block untrusted fonts to prevent exploits"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" "MitigationOptions_FontBocking" "1000000000000" "String"
        }
    }
    
    # ==============================
    # BLOATWARE REMOVAL
    # ==============================
    
    "Bloatware.RemoveXboxApps" = @{
        Name = "Remove Xbox Apps"
        Category = "Bloatware"
        Description = "Remove Xbox related apps and services"
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
                Remove-AppxPackageSafe -PackageName $app
            }
            
            Disable-ServiceSafe -ServiceName "XblAuthManager"
            Disable-ServiceSafe -ServiceName "XblGameSave"
            Disable-ServiceSafe -ServiceName "XboxNetApiSvc"
            Disable-ServiceSafe -ServiceName "XboxGipSvc"
        }
    }
    
    "Bloatware.RemoveCortana" = @{
        Name = "Remove Cortana"
        Category = "Bloatware"
        Description = "Remove Cortana assistant"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Remove-AppxPackageSafe -PackageName "Microsoft.549981C3F5F10"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 "DWord"
        }
    }
    
    "Bloatware.RemoveOneDrive" = @{
        Name = "Remove OneDrive"
        Category = "Bloatware"
        Description = "Completely remove Microsoft OneDrive"
        Impact = "High"
        RebootRequired = $true
        Script = {
            Write-LogMessage "Removing OneDrive..." "Info"
            
            Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            
            $oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
            if (!(Test-Path $oneDriveSetup)) {
                $oneDriveSetup = "$env:SystemRoot\System32\OneDriveSetup.exe"
            }
            
            if (Test-Path $oneDriveSetup) {
                Start-Process $oneDriveSetup -ArgumentList "/uninstall" -Wait
            }
            
            Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
            
            Set-RegistryValue "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0 "DWord"
            Set-RegistryValue "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0 "DWord"
        }
    }
    
    "Bloatware.RemoveWindowsStore" = @{
        Name = "Remove Windows Store"
        Category = "Bloatware"
        Description = "Remove Microsoft Store (WARNING: Hard to restore)"
        Impact = "High"
        RebootRequired = $false
        Script = {
            Remove-AppxPackageSafe -PackageName "Microsoft.WindowsStore"
            Remove-AppxPackageSafe -PackageName "Microsoft.StorePurchaseApp"
        }
    }
    
    "Bloatware.RemoveEdge" = @{
        Name = "Disable Edge"
        Category = "Bloatware"
        Description = "Disable Microsoft Edge (cannot fully remove)"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "DefaultBrowserSettingEnabled" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "HideFirstRunExperience" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "DisableLockdownOfStartPages" 1 "DWord"
        }
    }
    
    "Bloatware.RemoveMediaApps" = @{
        Name = "Remove Media Apps"
        Category = "Bloatware"
        Description = "Remove Groove Music, Movies & TV, etc."
        Impact = "Low"
        RebootRequired = $false
        Script = {
            $mediaApps = @(
                "Microsoft.ZuneMusic",
                "Microsoft.ZuneVideo",
                "Microsoft.WindowsSoundRecorder",
                "Microsoft.WindowsCamera",
                "Microsoft.WindowsAlarms",
                "Microsoft.YourPhone"
            )
            
            foreach ($app in $mediaApps) {
                Remove-AppxPackageSafe -PackageName $app
            }
        }
    }
    
    "Bloatware.RemoveOfficeHub" = @{
        Name = "Remove Office Hub"
        Category = "Bloatware"
        Description = "Remove Get Office and Office Hub"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Remove-AppxPackageSafe -PackageName "Microsoft.MicrosoftOfficeHub"
            Remove-AppxPackageSafe -PackageName "Microsoft.Office.OneNote"
        }
    }
    
    "Bloatware.RemoveSkype" = @{
        Name = "Remove Skype"
        Category = "Bloatware"
        Description = "Remove Skype app"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Remove-AppxPackageSafe -PackageName "Microsoft.SkypeApp"
        }
    }
    
    "Bloatware.RemoveMaps" = @{
        Name = "Remove Maps"
        Category = "Bloatware"
        Description = "Remove Windows Maps app"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Remove-AppxPackageSafe -PackageName "Microsoft.WindowsMaps"
            Disable-ServiceSafe -ServiceName "MapsBroker"
        }
    }
    
    "Bloatware.RemoveWeatherNews" = @{
        Name = "Remove Weather & News"
        Category = "Bloatware"
        Description = "Remove Weather, News, and widgets"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Remove-AppxPackageSafe -PackageName "Microsoft.BingWeather"
            Remove-AppxPackageSafe -PackageName "Microsoft.BingNews"
            Remove-AppxPackageSafe -PackageName "Microsoft.BingSports"
            Remove-AppxPackageSafe -PackageName "Microsoft.BingFinance"
            
            # Disable widgets
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarDa" 0 "DWord"
            }
        }
    }
    
    # ==============================
    # UI CUSTOMIZATION
    # ==============================
    
    "UI.ClassicRightClickMenu" = @{
        Name = "Restore Classic Right-Click Menu"
        Category = "UI"
        Description = "Restore Windows 10 style context menu"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" "(Default)" "" "String"
            }
            Restart-Explorer
        }
    }
    
    "UI.TaskbarLeft" = @{
        Name = "Align Taskbar to Left"
        Category = "UI"
        Description = "Move taskbar icons to left side"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAl" 0 "DWord"
            }
            Restart-Explorer
        }
    }
    
    "UI.ShowFileExtensions" = @{
        Name = "Show File Extensions"
        Category = "UI"
        Description = "Always show file extensions in Explorer"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0 "DWord"
            }
        }
    }
    
    "UI.ShowHiddenFiles" = @{
        Name = "Show Hidden Files"
        Category = "UI"
        Description = "Show hidden files and folders"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1 "DWord"
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" 1 "DWord"
            }
        }
    }
    
    "UI.CompactTaskbar" = @{
        Name = "Compact Taskbar"
        Category = "UI"
        Description = "Use small taskbar buttons"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarSi" 0 "DWord"
            }
            Restart-Explorer
        }
    }
    
    "UI.RemoveTaskView" = @{
        Name = "Remove Task View Button"
        Category = "UI"
        Description = "Hide Task View button from taskbar"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowTaskViewButton" 0 "DWord"
            }
            Restart-Explorer
        }
    }
    
    "UI.RemoveSearchBox" = @{
        Name = "Remove Search Box"
        Category = "UI"
        Description = "Remove search box from taskbar"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 0 "DWord"
            }
            Restart-Explorer
        }
    }
    
    "UI.DisableSnapAssist" = @{
        Name = "Disable Snap Assist"
        Category = "UI"
        Description = "Disable Snap Assist suggestions"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SnapAssist" 0 "DWord"
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SnapFill" 0 "DWord"
            }
        }
    }
    
    "UI.DarkMode" = @{
        Name = "Enable Dark Mode"
        Category = "UI"
        Description = "Enable dark mode for Windows and apps"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Invoke-ForEachUserHive {
                param($root)
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" "AppsUseLightTheme" 0 "DWord"
                Set-RegistryValue "$root\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" "SystemUsesLightTheme" 0 "DWord"
            }
        }
    }
    
    "UI.DisableStartupSound" = @{
        Name = "Disable Startup Sound"
        Category = "UI"
        Description = "Disable Windows startup sound"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableStartupSound" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" "DisableStartupSound" 1 "DWord"
        }
    }
    
    # ==============================
    # WINDOWS UPDATE
    # ==============================
    
    "WindowsUpdate.DisableAutoUpdate" = @{
        Name = "Disable Auto Update"
        Category = "WindowsUpdate"
        Description = "Disable automatic Windows Updates"
        Impact = "High"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2 "DWord"
            Disable-ServiceSafe -ServiceName "wuauserv"
        }
    }
    
    "WindowsUpdate.DeferUpdates" = @{
        Name = "Defer Feature Updates"
        Category = "WindowsUpdate"
        Description = "Defer feature updates for 365 days"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdates" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdatesPeriodInDays" 365 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdates" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays" 30 "DWord"
        }
    }
    
    "WindowsUpdate.DisableDriverUpdate" = @{
        Name = "Disable Driver Updates"
        Category = "WindowsUpdate"
        Description = "Prevent Windows Update from installing drivers"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ExcludeWUDriversInQualityUpdate" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0 "DWord"
        }
    }
    
    # ==============================
    # NETWORK OPTIMIZATIONS
    # ==============================
    
    "Network.DisableIPv6" = @{
        Name = "Disable IPv6"
        Category = "Network"
        Description = "Disable IPv6 protocol"
        Impact = "Medium"
        RebootRequired = $true
        Script = {
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 0xff "DWord"
            Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        }
    }
    
    "Network.DisableNetworkDiscovery" = @{
        Name = "Disable Network Discovery"
        Category = "Network"
        Description = "Disable network discovery for security"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            netsh advfirewall firewall set rule group="Network Discovery" new enable=No
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsCache" "NetFailureCacheTime" 0 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsCache" "NegativeSOACacheTime" 0 "DWord"
        }
    }
    
    "Network.OptimizeTCP" = @{
		Name           = "Optimize TCP Settings"
		Category       = "Network"
		Description    = "Optimize TCP settings for better performance"
		Impact         = "Low"
		RebootRequired = $true
		Script         = {
			try {
				# Profil TCP personnalisé (basé sur 'Internet')
				Set-NetTCPSetting -SettingName InternetCustom `
					-AutoTuningLevelLocal Normal `
					-EcnCapability Enabled `
					-Timestamps Disabled `
					-ErrorAction SilentlyContinue

				# Activer offloads globaux
				Set-NetOffloadGlobalSetting `
					-ReceiveSegmentCoalescing Enabled `
					-ReceiveSideScaling Enabled `
					-ErrorAction SilentlyContinue

				# Fallback avec netsh (pour compatibilité)
				netsh int tcp set global autotuninglevel=normal
				netsh int tcp set global ecncapability=enabled
				netsh int tcp set global rsc=enabled
				netsh int tcp set global rss=enabled
				netsh int tcp set global timestamps=disabled

				Write-Host "Optimisations TCP appliquées avec succès." -ForegroundColor Green
			}
			catch {
				Write-Host "Échec de l'application des optimisations TCP : $($_.Exception.Message)" -ForegroundColor Yellow
			}
		}
	}

}

# ============================================================================
# PROFILE DEFINITIONS
# ============================================================================

$global:Profiles = @{
    "Privacy" = @{
        Name = "Maximum Privacy"
        Description = "Apply all privacy-related settings"
        Features = @(
            "Privacy.DisableTelemetry",
            "Privacy.DisableActivityHistory",
            "Privacy.DisableAdvertisingID",
            "Privacy.DisableLocationTracking",
            "Privacy.DisableWebSearch",
            "Privacy.DisableFeedback",
            "Privacy.DisableTimeline",
            "Privacy.DisableInkAndTyping",
            "Privacy.DisableAppDiagnostics"
        )
    }
    
    "Performance" = @{
        Name = "Performance Boost"
        Description = "Optimize system for maximum performance"
        Features = @(
            "Performance.DisableBackgroundApps",
            "Performance.DisableStartupDelay",
            "Performance.DisableSearchIndexing",
            "Performance.DisableSuperfetch",
            "Performance.OptimizeVisualEffects",
            "Performance.DisableGameDVR",
            "Performance.DisableWindowsTips"
        )
    }
    
    "Security" = @{
        Name = "Security Hardening"
        Description = "Apply security best practices"
        Features = @(
            "Security.EnableFirewall",
            "Security.DisableSMBv1",
            "Security.SetSecureDNS",
            "Security.EnableWindowsDefender",
            "Security.EnableUAC",
            "Security.DisableAutoplay",
            "Security.DisableRemoteDesktop",
            "Security.BlockUntrustedFonts"
        )
    }
    
    "Gaming" = @{
        Name = "Gaming Optimizations"
        Description = "Optimize system for gaming"
        Features = @(
            "Performance.DisableBackgroundApps",
            "Performance.DisableSearchIndexing",
            "Performance.DisableGameDVR",
            "Performance.OptimizeVisualEffects",
            "Bloatware.RemoveXboxApps",
            "Network.OptimizeTCP"
        )
    }
    
    "Clean" = @{
        Name = "Clean Install"
        Description = "Remove all bloatware and optimize UI"
        Features = @(
            "Bloatware.RemoveXboxApps",
            "Bloatware.RemoveCortana",
            "Bloatware.RemoveMediaApps",
            "Bloatware.RemoveWeatherNews",
            "UI.ClassicRightClickMenu",
            "UI.TaskbarLeft",
            "UI.ShowFileExtensions",
            "UI.RemoveSearchBox"
        )
    }
    
    "Developer" = @{
        Name = "Developer Workstation"
        Description = "Setup for development work"
        Features = @(
            "Apps.Install_OutilsDeveloppement",
            "Apps.Install_UtilitairesProductivite",
            "UI.ShowFileExtensions",
            "UI.ShowHiddenFiles",
            "UI.DarkMode",
            "Performance.DisableSearchIndexing"
        )
    }
    
    "UltraSecure" = @{
        Name = "Ultra Secure"
        Description = "Maximum security and privacy settings"
        Features = @(
            "Security.EnableBitLocker",
            "Security.EnableFirewall",
            "Security.DisableSMBv1",
            "Security.SetSecureDNS",
            "Security.EnableWindowsDefender",
            "Security.EnableUAC",
            "Security.DisableAutoplay",
            "Security.DisableRemoteDesktop",
            "Security.EnableCoreisolation",
            "Security.BlockUntrustedFonts",
            "Privacy.DisableTelemetry",
            "Privacy.DisableActivityHistory",
            "Privacy.DisableAdvertisingID",
            "Privacy.DisableLocationTracking",
            "Privacy.DisableBiometrics"
        )
    }
    
    "Minimal" = @{
        Name = "Minimal Windows"
        Description = "Strip Windows to essentials only"
        Features = @(
            "Bloatware.RemoveXboxApps",
            "Bloatware.RemoveCortana",
            "Bloatware.RemoveOneDrive",
            "Bloatware.RemoveMediaApps",
            "Bloatware.RemoveOfficeHub",
            "Bloatware.RemoveSkype",
            "Bloatware.RemoveMaps",
            "Bloatware.RemoveWeatherNews",
            "Performance.DisableBackgroundApps",
            "Performance.DisableSearchIndexing",
            "Performance.DisableSuperfetch",
            "Performance.OptimizeVisualEffects",
            "UI.RemoveTaskView",
            "UI.RemoveSearchBox"
        )
    }
}

# ============================================================================
# MENU SYSTEM
# ============================================================================

function Show-MainMenu {
    while ($true) {
        Show-Banner
        Write-Host "`n=== MAIN MENU ===" -ForegroundColor Yellow
        Write-Host "1. Express Configuration (Recommended settings)" -ForegroundColor White
        Write-Host "2. Custom Configuration (Choose features)" -ForegroundColor White
        Write-Host "3. Apply Profile (Pre-configured sets)" -ForegroundColor White
        Write-Host "4. Maintenance Mode (Backup/Restore)" -ForegroundColor White
        Write-Host "5. Export Current Configuration" -ForegroundColor White
        Write-Host "6. View Applied Features" -ForegroundColor White
		Write-Host "  [I] Info & Help    [S] System Info    [L] View Log    [Q] Quit" -ForegroundColor Cyan
        Write-Host "0. Exit" -ForegroundColor Gray
        
        $choice = Read-Host "`nSelect option"
        
        switch ($choice) {
            "1" { Execute-ExpressMode }
            "2" { Show-CustomMenu }
            "3" { Show-ProfileMenu }
            "4" { Show-MaintenanceMenu }
            "5" { Export-CurrentConfiguration; Read-Host "Press Enter to continue" }
			"I" { Show-Information }
            "S" { Show-SystemInfo }
            "L" { Show-LogFile }
            "Q" { Exit-Script }
            "6" { Show-AppliedFeatures }
            "0" { return }
            default { Write-Host "Invalid option!" -ForegroundColor Red }
        }
    }
}

function Show-CustomMenu {
    while ($true) {
        Show-Banner
        Write-Host "`n=== CUSTOM CONFIGURATION ===" -ForegroundColor Yellow
        Write-Host "1. Privacy Settings" -ForegroundColor White
        Write-Host "2. Performance Optimizations" -ForegroundColor White
        Write-Host "3. Security Hardening" -ForegroundColor White
        Write-Host "4. Bloatware Removal" -ForegroundColor White
        Write-Host "5. UI Customization" -ForegroundColor White
        Write-Host "6. Windows Update Settings" -ForegroundColor White
        Write-Host "7. Network Settings" -ForegroundColor White
        Write-Host "8. Install Applications" -ForegroundColor White
        Write-Host "0. Back to Main Menu" -ForegroundColor Gray
        
        $choice = Read-Host "`nSelect category"
        
        switch ($choice) {
            "1" { Show-CategoryMenu "Privacy" }
            "2" { Show-CategoryMenu "Performance" }
            "3" { Show-CategoryMenu "Security" }
            "4" { Show-CategoryMenu "Bloatware" }
            "5" { Show-CategoryMenu "UI" }
            "6" { Show-CategoryMenu "WindowsUpdate" }
            "7" { Show-CategoryMenu "Network" }
            "8" { Show-CategoryMenu "Applications" }
            "0" { return }
            default { Write-Host "Invalid option!" -ForegroundColor Red }
        }
    }
}

function Show-CategoryMenu {
    param([string]$Category)
    
    $features = Get-CategoryFeatures -Category $Category
    
    while ($true) {
        Show-Banner
        Write-Host "`n=== $($Category.ToUpper()) FEATURES ===" -ForegroundColor Yellow
        
        $index = 1
        $featureMap = @{}
        
        foreach ($feature in $features) {
            $applied = if ($global:AppliedFeatures -contains $feature.Key) { "[APPLIED]" } else { "" }
            Write-Host "$index. $($feature.Value.Name) $applied" -ForegroundColor White
            Write-Host "   $($feature.Value.Description)" -ForegroundColor Gray
            $featureMap[$index] = $feature.Key
            $index++
        }
        
        Write-Host "`nA. Apply All" -ForegroundColor Cyan
        Write-Host "0. Back" -ForegroundColor Gray
        
        $choice = Read-Host "`nSelect feature"
        
        if ($choice -eq "0") { return }
        elseif ($choice -eq "A" -or $choice -eq "a") {
            foreach ($feature in $features) {
                Execute-Feature -FeatureKey $feature.Key
            }
            Write-Host "`nAll features in this category have been processed." -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }
        elseif ($featureMap.ContainsKey([int]$choice)) {
            $success = Execute-Feature -FeatureKey $featureMap[[int]$choice]
            if ($success) {
                Write-Host "`nFeature applied successfully!" -ForegroundColor Green
            }
            else {
                Write-Host "`nFeature execution failed. Please check the log for errors." -ForegroundColor Red
            }
            Read-Host "Press Enter to continue"
        }
        else {
            Write-Host "Invalid option!" -ForegroundColor Red
        }
    }
}

function Show-ProfileMenu {
    while ($true) {
        Show-Banner
        Write-Host "`n=== CONFIGURATION PROFILES ===" -ForegroundColor Yellow
        
        $index = 1
        $profileMap = @{}
        
        foreach ($profile in $global:Profiles.GetEnumerator()) {
            Write-Host "$index. $($profile.Value.Name)" -ForegroundColor White
            Write-Host "   $($profile.Value.Description)" -ForegroundColor Gray
            $profileMap[$index] = $profile.Key
            $index++
        }
        
        Write-Host "`n0. Back to Main Menu" -ForegroundColor Gray
        
        $choice = Read-Host "`nSelect profile"
        
        if ($choice -eq "0") { return }
        elseif ($profileMap.ContainsKey([int]$choice)) {
            $profileKey = $profileMap[[int]$choice]
            $profile = $global:Profiles[$profileKey]
            
            Write-Host "`nApplying profile: $($profile.Name)" -ForegroundColor Cyan
            foreach ($featureKey in $profile.Features) {
                Execute-Feature -FeatureKey $featureKey
            }
            
            Write-Host "`nProfile applied successfully!" -ForegroundColor Green
            Read-Host "Press Enter to continue"
        }
        else {
            Write-Host "Invalid option!" -ForegroundColor Red
        }
    }
}

function Show-MaintenanceMenu {
    while ($true) {
        Show-Banner
        Write-Host "`n=== MAINTENANCE MODE ===" -ForegroundColor Yellow
        Write-Host "1. Create System Restore Point" -ForegroundColor White
        Write-Host "2. Export Configuration" -ForegroundColor White
        Write-Host "3. View System Information" -ForegroundColor White
        Write-Host "4. Check for Windows Updates" -ForegroundColor White
        Write-Host "5. Clean Temp Files" -ForegroundColor White
        Write-Host "6. Run System File Checker" -ForegroundColor White
        Write-Host "0. Back to Main Menu" -ForegroundColor Gray
        
        $choice = Read-Host "`nSelect option"
        
        switch ($choice) {
            "1" { 
                Create-SystemRestorePoint
                Read-Host "Press Enter to continue"
            }
            "2" { 
                Export-CurrentConfiguration
                Read-Host "Press Enter to continue"
            }
            "3" { 
                Show-SystemInfo
            }
            "4" {
                Write-Host "Checking for Windows Updates..." -ForegroundColor Yellow
                Start-Process ms-settings:windowsupdate-action
                Read-Host "Press Enter to continue"
            }
            "5" {
                Write-Host "Cleaning temporary files..." -ForegroundColor Yellow
                Remove-Item "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue
                Remove-Item "C:\Windows\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
                Write-Host "Temp files cleaned!" -ForegroundColor Green
                Read-Host "Press Enter to continue"
            }
            "6" {
                Write-Host "Running System File Checker..." -ForegroundColor Yellow
                sfc.exe /scannow
                Write-Host "System File Checker finished." -ForegroundColor Green
                Read-Host "Press Enter to continue"
            }
            "0" { return }
            default { Write-Host "Invalid option!" -ForegroundColor Red }
        }
    }
}

function Show-AppliedFeatures {
    Show-Banner
    Write-Host "`n=== APPLIED FEATURES ===" -ForegroundColor Yellow
    
    if ($global:AppliedFeatures.Count -eq 0) {
        Write-Host "No features have been applied yet." -ForegroundColor Gray
    } else {
        foreach ($featureKey in ($global:AppliedFeatures | Sort-Object -Unique)) {
            $feature = $global:Features[$featureKey]
            if ($feature) {
                Write-Host "• $($feature.Name) ($($feature.Category))" -ForegroundColor Green
            }
        }
    }
    
    Read-Host "`nPress Enter to continue"
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
    while($true) {
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
            "B" { return }
            default { }
        }
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

function Execute-ExpressMode {
    Show-Banner
    Write-Host "`n=== EXPRESS CONFIGURATION ===" -ForegroundColor Yellow
    Write-Host "This will apply recommended settings for:" -ForegroundColor White
    Write-Host "• Enhanced Privacy" -ForegroundColor Gray
    Write-Host "• Better Performance" -ForegroundColor Gray
    Write-Host "• Improved Security" -ForegroundColor Gray
    Write-Host "• Cleaner UI" -ForegroundColor Gray
    
    $confirm = Read-Host "`nContinue? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") { return }
    
    # Apply recommended features
    $expressFeatures = @(
        "Privacy.DisableTelemetry",
        "Privacy.DisableAdvertisingID",
        "Privacy.DisableWebSearch",
        "Performance.DisableBackgroundApps",
        "Performance.OptimizeVisualEffects",
        "Security.EnableFirewall",
        "Security.SetSecureDNS",
        "Security.DisableAutoplay",
        "Bloatware.RemoveCortana",
        "Bloatware.RemoveWeatherNews",
        "UI.ClassicRightClickMenu",
        "UI.ShowFileExtensions"
    )
    
    foreach ($featureKey in $expressFeatures) {
        Execute-Feature -FeatureKey $featureKey
    }
    
    Write-Host "`nExpress configuration completed!" -ForegroundColor Green
    Read-Host "Press Enter to continue"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Check administrator privileges
if (-not (Test-Administrator)) {
    Write-Warning "This script requires Administrator privileges."
    Write-Warning "Please run PowerShell as Administrator and try again."
    Read-Host "Press Enter to exit"
    exit 1
}

# Check Windows 11
if (-not (Test-Windows11)) {
    Read-Host "Press Enter to exit"
    exit 1
}

# Load and register application bundles from the JSON manifest
$global:AppManifest = Load-ApplicationManifest
Register-ApplicationFeaturesFromManifest -AppManifest $global:AppManifest

# Initialize
Show-Banner
Write-LogMessage "Windows 11 Configuration Tool Started" "Info"
Write-LogMessage "Version: $global:ScriptVersion" "Info"
Write-LogMessage "User: $env:USERNAME" "Info"
Write-LogMessage "Computer: $env:COMPUTERNAME" "Info"

# Create restore point if requested
if ($CreateRestorePoint -and -not $SkipRestorePoint) {
    Create-SystemRestorePoint
}

# Handle command-line parameters
if ($ExpressMode) {
    Write-LogMessage "Running in Express Mode" "Info"
    Execute-ExpressMode
}
elseif ($RemoveAllBloatware) {
    Write-LogMessage "Removing all bloatware..." "Info"
    Get-CategoryFeatures -Category "Bloatware" | ForEach-Object {
        Execute-Feature -FeatureKey $_.Key
    }
}
elseif ($ApplyAllPrivacy) {
    Write-LogMessage "Applying all privacy settings..." "Info"
    Get-CategoryFeatures -Category "Privacy" | ForEach-Object {
        Execute-Feature -FeatureKey $_.Key
    }
}
elseif ($ApplyAllSecurity) {
    Write-LogMessage "Applying all security settings..." "Info"
    Get-CategoryFeatures -Category "Security" | ForEach-Object {
        Execute-Feature -FeatureKey $_.Key
    }
}
elseif ($ApplyAllPerformance) {
    Write-LogMessage "Applying all performance optimizations..." "Info"
    Get-CategoryFeatures -Category "Performance" | ForEach-Object {
        Execute-Feature -FeatureKey $_.Key
    }
}
elseif ($ApplyProfile) {
    if ($global:Profiles.ContainsKey($ApplyProfile)) {
        Write-LogMessage "Applying profile: $ApplyProfile" "Info"
        $profile = $global:Profiles[$ApplyProfile]
        foreach ($featureKey in $profile.Features) {
            Execute-Feature -FeatureKey $featureKey
        }
    } else {
        Write-LogMessage "Profile not found: $ApplyProfile" "Error"
    }
}
elseif ($ExportConfig) {
    Export-CurrentConfiguration
}
elseif ($CustomMode -or (-not $Silent)) {
    # Show interactive menu
    Show-MainMenu
}

# Final operations
if ($global:AppliedFeatures.Count -gt 0) {
    Write-Host "`n" -NoNewline
    Write-LogMessage "Configuration completed. $($global:AppliedFeatures.Count) unique features applied." "Success"
    
    # Check if reboot is required
    $rebootRequired = $false
    foreach ($featureKey in $global:AppliedFeatures) {
        if ($global:Features.ContainsKey($featureKey) -and $global:Features[$featureKey].RebootRequired) {
            $rebootRequired = $true
            break
        }
    }
    
    if ($rebootRequired -and -not $NoReboot) {
        Write-Host "`nSome changes require a system restart to take effect." -ForegroundColor Yellow
        if ($ForceReboot) {
            Write-Host "System will restart in 30 seconds..." -ForegroundColor Red
            shutdown /r /t 30 /c "Windows 11 Configuration Tool - Restarting to apply changes"
        } else {
            $restart = Read-Host "Restart now? (Y/N)"
            if ($restart -eq "Y" -or $restart -eq "y") {
                Restart-Computer -Force
            }
        }
    }
}

# Export configuration if specified
if ($ExportConfig) {
    Export-CurrentConfiguration
}

# Cleanup
Write-LogMessage "Script execution completed" "Info"
Write-LogMessage "Log file saved to: $global:LogFile" "Info"

# Stop transcript
try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}

Write-Host "`nConfiguration tool finished. Thank you for using Windows 11 Ultimate Configuration Tool!" -ForegroundColor Green
Read-Host "Press Enter to exit"
