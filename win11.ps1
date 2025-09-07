# ============================================================================
# WINDOWS 11 ULTIMATE CONFIGURATION TOOL - CORRECTED VERSION
# Version: 4.1 - Bug Fixes & Complete Implementation
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

$global:ScriptVersion = "4.1"
$global:ScriptName = "Windows 11 Ultimate Configuration Tool"
$global:LogFile = Join-Path $LogPath "Win11Config_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$global:ConfigPath = "$env:LOCALAPPDATA\Win11Config"
$global:BackupPath = "$global:ConfigPath\Backups"
$global:ProfilesPath = "$global:ConfigPath\Profiles"
$global:DebloatListPath = "$global:ConfigPath\DebloatLists"
$global:TempPath = "$env:TEMP\Win11Config"
$global:AppliedFeatures = @()

# Create necessary directories
@($global:ConfigPath, $global:BackupPath, $global:ProfilesPath, $global:DebloatListPath, $global:TempPath) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# Start logging with error handling
try {
    Stop-Transcript -ErrorAction SilentlyContinue
} catch {}

try {
    Start-Transcript -Path $global:LogFile -Append -Force | Out-Null
} catch {
    Write-Warning "Unable to start transcript logging"
}

# ============================================================================
# COMPREHENSIVE FEATURE DEFINITIONS
# ============================================================================

$global:Features = @{
    # PRIVACY & TELEMETRY
    "Privacy.DisableTelemetry" = @{
        Name = "Disable Telemetry"
        Category = "Privacy"
        Description = "Completely disable Windows telemetry and data collection"
        Impact = "High"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0 "DWord"
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" -ErrorAction SilentlyContinue
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
            Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0 "DWord"
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
            Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1 "DWord"
        }
    }
    
    "Privacy.DisableTimeline" = @{
        Name = "Disable Timeline"
        Category = "Privacy"
        Description = "Disable Windows Timeline feature"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityHistory" 0 "DWord"
        }
    }
    
    "Privacy.DisableDiagnosticData" = @{
        Name = "Disable Diagnostic Data"
        Category = "Privacy"
        Description = "Minimize diagnostic data collection"
        Impact = "High"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "MaxTelemetryAllowed" 0 "DWord"
        }
    }
    
    "Privacy.DisableInkingTyping" = @{
        Name = "Disable Inking & Typing Personalization"
        Category = "Privacy"
        Description = "Stop collection of inking and typing data"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1 "DWord"
            Set-RegistryValue "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1 "DWord"
            Set-RegistryValue "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0 "DWord"
        }
    }
    
    "Privacy.DisableSpeechRecognition" = @{
        Name = "Disable Online Speech Recognition"
        Category = "Privacy"
        Description = "Disable cloud-based speech recognition"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" "HasAccepted" 0 "DWord"
        }
    }
    
    # SECURITY FEATURES
    "Security.EnableWindowsDefender" = @{
        Name = "Configure Windows Defender Maximum Security"
        Category = "Security"
        Description = "Enable all Windows Defender security features"
        Impact = "High"
        RebootRequired = $false
        Script = {
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
                Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
                Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
            } catch {
                Write-LogMessage "Some Windows Defender settings could not be applied: $_" "Warning"
            }
        }
    }
    
    "Security.EnableAllASRRules" = @{
        Name = "Enable All Attack Surface Reduction Rules"
        Category = "Security"
        Description = "Enable all ASR rules for maximum protection"
        Impact = "High"
        RebootRequired = $false
        Script = {
            $asrRules = @{
                "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
                "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
                "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
                "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from lsass.exe"
                "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
                "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files from running unless they meet prevalence/age/trusted list"
                "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
                "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
                "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
                "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
                "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication application from creating child processes"
                "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
                "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands"
                "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes from USB"
                "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
                "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
            }
            
            foreach ($id in $asrRules.Keys) {
                try {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
                    Write-LogMessage "Enabled ASR Rule: $($asrRules[$id])" "Success"
                } catch {
                    Write-LogMessage "Could not enable ASR Rule: $($asrRules[$id])" "Warning"
                }
            }
        }
    }
    
    "Security.EnableBitLocker" = @{
        Name = "Enable BitLocker Encryption"
        Category = "Security"
        Description = "Enable BitLocker drive encryption"
        Impact = "High"
        RebootRequired = $true
        Script = {
            $drive = $env:SystemDrive
            try {
                $bitlockerVolume = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
                if ($bitlockerVolume.VolumeStatus -eq 'FullyDecrypted') {
                    Enable-BitLocker -MountPoint $drive -EncryptionMethod Aes256 -RecoveryPasswordProtector -ErrorAction Stop
                    $recoveryKey = (Get-BitLockerVolume -MountPoint $drive).KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}
                    Write-LogMessage "BitLocker Recovery Key: $($recoveryKey.RecoveryPassword)" "Important"
                    Write-LogMessage "SAVE THIS RECOVERY KEY IN A SECURE LOCATION!" "Warning"
                } else {
                    Write-LogMessage "BitLocker is already enabled on $drive" "Info"
                }
            } catch {
                Write-LogMessage "Could not enable BitLocker: $_" "Error"
            }
        }
    }
    
    "Security.EnableCredentialGuard" = @{
        Name = "Enable Credential Guard"
        Category = "Security"
        Description = "Enable Windows Defender Credential Guard"
        Impact = "High"
        RebootRequired = $true
        Script = {
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" 1 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "RequirePlatformSecurityFeatures" 3 "DWord"
            Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" "Enabled" 1 "DWord"
        }
    }
    
    "Security.EnableSandbox" = @{
        Name = "Enable Windows Sandbox"
        Category = "Security"
        Description = "Enable Windows Sandbox feature"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            try {
                Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online -NoRestart -ErrorAction Stop
                Write-LogMessage "Windows Sandbox enabled successfully" "Success"
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
        Name = "Configure Advanced Firewall"
        Category = "Security"
        Description = "Enable and configure Windows Firewall with strict rules"
        Impact = "High"
        RebootRequired = $false
        Script = {
            try {
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
                Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction Stop
                Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction Stop
                Set-NetFirewallProfile -Profile Public -NotifyOnListen True -ErrorAction Stop
                Set-NetFirewallProfile -Profile Public -AllowUnicastResponseToMulticast False -ErrorAction Stop
                Write-LogMessage "Firewall configured successfully" "Success"
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
        }
    }
    
    "Security.EnableSecureBoot" = @{
        Name = "Verify Secure Boot"
        Category = "Security"
        Description = "Check and enable Secure Boot if possible"
        Impact = "High"
        RebootRequired = $false
        Script = {
            try {
                $secureBootStatus = Confirm-SecureBootUEFI -ErrorAction Stop
                if ($secureBootStatus) {
                    Write-LogMessage "Secure Boot is enabled" "Success"
                } else {
                    Write-LogMessage "Secure Boot is not enabled. Enable it in BIOS/UEFI settings" "Warning"
                }
            } catch {
                Write-LogMessage "Could not verify Secure Boot status (may not be UEFI system)" "Warning"
            }
        }
    }
    
    # PERFORMANCE OPTIMIZATIONS
    "Performance.DisableStartupApps" = @{
        Name = "Disable Startup Applications"
        Category = "Performance"
        Description = "Disable unnecessary startup applications"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                Get-CimInstance Win32_StartupCommand | Where-Object {$_.Caption -notlike "*Windows*" -and $_.Caption -notlike "*Microsoft*"} | ForEach-Object {
                    Write-LogMessage "Disabling startup app: $($_.Caption)" "Info"
                    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
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
            Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2 "DWord"
        }
    }
    
    "Performance.OptimizeSSD" = @{
        Name = "Optimize for SSD"
        Category = "Performance"
        Description = "Apply SSD-specific optimizations"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                fsutil behavior set DisableLastAccess 1
                fsutil behavior set DisableDeleteNotify 0
                Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" -ErrorAction SilentlyContinue
                Write-LogMessage "SSD optimizations applied" "Success"
            } catch {
                Write-LogMessage "Could not apply all SSD optimizations: $_" "Warning"
            }
        }
    }
    
    "Performance.DisableIndexing" = @{
        Name = "Disable Windows Search Indexing"
        Category = "Performance"
        Description = "Disable indexing service for better performance"
        Impact = "High"
        RebootRequired = $false
        Script = {
            try {
                Stop-Service "WSearch" -Force -ErrorAction Stop
                Set-Service "WSearch" -StartupType Disabled -ErrorAction Stop
                Write-LogMessage "Windows Search indexing disabled" "Success"
            } catch {
                Write-LogMessage "Could not disable Windows Search: $_" "Warning"
            }
        }
    }
    
    "Performance.DisableSuperfetch" = @{
        Name = "Disable Superfetch/Prefetch"
        Category = "Performance"
        Description = "Disable application preloading"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                Stop-Service "SysMain" -Force -ErrorAction SilentlyContinue
                Set-Service "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 0 "DWord"
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 0 "DWord"
                Write-LogMessage "Superfetch/Prefetch disabled" "Success"
            } catch {
                Write-LogMessage "Could not disable Superfetch/Prefetch: $_" "Warning"
            }
        }
    }
    
    "Performance.OptimizeVisualEffects" = @{
        Name = "Optimize Visual Effects"
        Category = "Performance"
        Description = "Disable visual effects for better performance"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2 "DWord"
            Set-RegistryValue "HKCU:\Control Panel\Desktop" "UserPreferencesMask" ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) "Binary"
        }
    }
    
    "Performance.SetHighPerformance" = @{
        Name = "Set High Performance Power Plan"
        Category = "Performance"
        Description = "Enable high performance power plan"
        Impact = "Medium"
        RebootRequired = $false
        Script = {
            try {
                powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
                powercfg -change -monitor-timeout-ac 0
                powercfg -change -disk-timeout-ac 0
                powercfg -change -standby-timeout-ac 0
                powercfg -change -hibernate-timeout-ac 0
                Write-LogMessage "High performance power plan activated" "Success"
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
            } catch {
                Write-LogMessage "Could not disable hibernation: $_" "Warning"
            }
        }
    }
    
    "Performance.OptimizeMemory" = @{
        Name = "Optimize Virtual Memory"
        Category = "Performance"
        Description = "Configure virtual memory for optimal performance"
        Impact = "Medium"
        RebootRequired = $true
        Script = {
            try {
                $computerSystem = Get-CimInstance Win32_ComputerSystem
                $totalMemory = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB)
                $pageFileSize = [math]::Round($totalMemory * 1024 * 1.5)
                
                # Disable automatic pagefile management
                $computerSystem | Set-CimInstance -Property @{AutomaticManagedPagefile = $false}
                
                # Configure pagefile
                $pagefileSetting = Get-CimInstance Win32_PageFileSetting -Filter "Name='$env:SystemDrive\\pagefile.sys'" -ErrorAction SilentlyContinue
                if ($pagefileSetting) {
                    $pagefileSetting | Remove-CimInstance
                }
                
                # Create new pagefile configuration using WMI
                $null = Invoke-CimMethod -Namespace "root\cimv2" -ClassName Win32_PageFileSetting -MethodName Create -Arguments @{
                    Name = "$env:SystemDrive\pagefile.sys"
                    InitialSize = $pageFileSize
                    MaximumSize = $pageFileSize
                }
                
                Write-LogMessage "Virtual memory optimized (Pagefile: ${pageFileSize}MB)" "Success"
            } catch {
                Write-LogMessage "Could not optimize virtual memory: $_" "Warning"
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
            Set-RegistryValue "HKCU:\System\GameConfigStore" "GameDVR_Enabled" 0 "DWord"
            Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0 "DWord"
        }
    }
    
    # BLOATWARE REMOVAL
    "Bloatware.RemoveMicrosoft" = @{
        Name = "Remove Microsoft Bloatware"
        Category = "Bloatware"
        Description = "Remove unnecessary Microsoft apps"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            $apps = @(
                "Microsoft.BingNews"
                "Microsoft.BingWeather"
                "Microsoft.GetHelp"
                "Microsoft.Getstarted"
                "Microsoft.Messaging"
                "Microsoft.Microsoft3DViewer"
                "Microsoft.MicrosoftOfficeHub"
                "Microsoft.MicrosoftSolitaireCollection"
                "Microsoft.NetworkSpeedTest"
                "Microsoft.News"
                "Microsoft.Office.Lens"
                "Microsoft.Office.OneNote"
                "Microsoft.Office.Sway"
                "Microsoft.OneConnect"
                "Microsoft.People"
                "Microsoft.Print3D"
                "Microsoft.SkypeApp"
                "Microsoft.StorePurchaseApp"
                "Microsoft.Wallet"
                "Microsoft.Whiteboard"
                "Microsoft.WindowsAlarms"
                "Microsoft.WindowsFeedbackHub"
                "Microsoft.WindowsMaps"
                "Microsoft.WindowsSoundRecorder"
                "Microsoft.ZuneMusic"
                "Microsoft.ZuneVideo"
            )
            
            foreach ($app in $apps) {
                try {
                    Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object DisplayName -like $app | Remove-ProvisionedAppxPackage -Online -ErrorAction SilentlyContinue
                    Write-LogMessage "Removed: $app" "Info"
                } catch {
                    Write-LogMessage "Could not remove $app" "Warning"
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
                "Microsoft.GamingApp"
                "Microsoft.XboxApp"
                "Microsoft.Xbox.TCUI"
                "Microsoft.XboxGameOverlay"
                "Microsoft.XboxGamingOverlay"
                "Microsoft.XboxIdentityProvider"
                "Microsoft.XboxSpeechToTextOverlay"
            )
            
            foreach ($app in $xboxApps) {
                try {
                    Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object DisplayName -like $app | Remove-ProvisionedAppxPackage -Online -ErrorAction SilentlyContinue
                    Write-LogMessage "Removed: $app" "Info"
                } catch {
                    Write-LogMessage "Could not remove $app" "Warning"
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
            $oneDrivePath = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
            if (!(Test-Path $oneDrivePath)) {
                $oneDrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
            }
            
            if (Test-Path $oneDrivePath) {
                try {
                    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
                    Start-Process $oneDrivePath "/uninstall" -NoNewWindow -Wait
                    Remove-Item "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-LogMessage "OneDrive uninstalled" "Success"
                } catch {
                    Write-LogMessage "Could not uninstall OneDrive: $_" "Warning"
                }
            }
        }
    }
    
    "Bloatware.RemoveEdge" = @{
        Name = "Force Uninstall Microsoft Edge"
        Category = "Bloatware"
        Description = "Forcefully remove Microsoft Edge (NOT RECOMMENDED)"
        Impact = "High"
        RebootRequired = $true
        Script = {
            $confirmation = Read-Host "WARNING: This will forcefully remove Edge and may break some Windows features. Continue? (yes/no)"
            if ($confirmation -eq "yes") {
                $edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
                if (Test-Path $edgePath) {
                    try {
                        Get-Process -Name "*edge*" -ErrorAction SilentlyContinue | Stop-Process -Force
                        Get-ChildItem "$edgePath\*\Installer" -ErrorAction SilentlyContinue | ForEach-Object {
                            & "$_\setup.exe" --uninstall --force-uninstall --system-level
                        }
                        Write-LogMessage "Edge removal attempted" "Warning"
                    } catch {
                        Write-LogMessage "Could not remove Edge: $_" "Error"
                    }
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
            Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowCopilotButton" 0 "DWord"
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
            Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "EnableRecall" 0 "DWord"
        }
    }
    
    # INTERFACE CUSTOMIZATION
    "UI.EnableDarkMode" = @{
        Name = "Enable Dark Mode"
        Category = "Interface"
        Description = "Enable dark mode for system and apps"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "AppsUseLightTheme" 0 "DWord"
            Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "SystemUsesLightTheme" 0 "DWord"
        }
    }
    
    "UI.RestoreClassicMenu" = @{
        Name = "Restore Classic Context Menu"
        Category = "Interface"
        Description = "Restore Windows 10 style context menu"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            try {
                New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Force
                New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force
                Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Value "" -Type String
                Write-LogMessage "Classic context menu restored" "Success"
            } catch {
                Write-LogMessage "Could not restore classic menu: $_" "Warning"
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
            Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAl" 0 "DWord"
        }
    }
    
    "UI.ShowFileExtensions" = @{
        Name = "Show File Extensions"
        Category = "Interface"
        Description = "Always show file extensions"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0 "DWord"
        }
    }
    
    "UI.ShowHiddenFiles" = @{
        Name = "Show Hidden Files"
        Category = "Interface"
        Description = "Show hidden files and folders"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1 "DWord"
            Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" 1 "DWord"
        }
    }
    
    # NETWORK CONFIGURATION
    "Network.OptimizeDNS" = @{
        Name = "Optimize DNS Settings"
        Category = "Network"
        Description = "Configure fast and secure DNS servers"
        Impact = "Low"
        RebootRequired = $false
        Script = {
            try {
                $dnsServers = @("1.1.1.1", "1.0.0.1")  # Cloudflare DNS
                Get-NetAdapter | Where-Object Status -eq "Up" | ForEach-Object {
                    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $dnsServers -ErrorAction SilentlyContinue
                }
                Write-LogMessage "DNS servers set to Cloudflare" "Success"
            } catch {
                Write-LogMessage "Could not set DNS servers: $_" "Warning"
            }
        }
    }
    
    "Network.DisableIPv6" = @{
        Name = "Disable IPv6"
        Category = "Network"
        Description = "Disable IPv6 protocol"
        Impact = "Medium"
        RebootRequired = $true
        Script = {
            try {
                Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
                Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 0xff "DWord"
                Write-LogMessage "IPv6 disabled" "Success"
            } catch {
                Write-LogMessage "Could not disable IPv6: $_" "Warning"
            }
        }
    }
    
    # DEVELOPMENT TOOLS
    "Dev.InstallWSL" = @{
        Name = "Install WSL2"
        Category = "Development"
        Description = "Install Windows Subsystem for Linux 2"
        Impact = "Low"
        RebootRequired = $true
        Script = {
            try {
                wsl --install
                wsl --set-default-version 2
                Write-LogMessage "WSL2 installation initiated" "Success"
            } catch {
                Write-LogMessage "Could not install WSL2: $_" "Warning"
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
        }
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Try-catch to avoid errors
    try {
        $logEntry | Out-File -FilePath $global:LogFile -Append -Force
    } catch {
        # Silently continue if can't write to log
    }
    
    # Console output with color
    $color = switch ($Level) {
        "Info" { "White" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Important" { "Cyan" }
        default { "White" }
    }
    
    Write-Host $Message -ForegroundColor $color
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        
        # Auto-detect type for special cases
        if ($Value -is [byte[]]) {
            $Type = "Binary"
        } elseif ($Value -is [string] -and $Type -eq "DWord") {
            # Check if it's actually a string value
            if (![int]::TryParse($Value, [ref]$null)) {
                $Type = "String"
            }
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        return $true
    } catch {
        Write-LogMessage "Failed to set registry value: $Path\$Name - $_" "Error"
        return $false
    }
}

function Show-Banner {
    Clear-Host
    $banner = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║              WINDOWS 11 ULTIMATE CONFIGURATION TOOL v$($global:ScriptVersion)                ║
║                     Complete Feature Set - Interactive Mode                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Windows11 {
    $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
    if ($osVersion -notlike "10.0.22*") {
        Write-Warning "This script is designed for Windows 11. Current OS version: $osVersion"
        Write-Warning "Some features may not work correctly on other Windows versions."
        $continue = Read-Host "Continue anyway? (Y/N)"
        return ($continue -eq "Y")
    }
    return $true
}

function Create-SystemRestorePoint {
    param([string]$Description = "Windows 11 Configuration Tool")
    
    Write-LogMessage "Creating system restore point..." "Info"
    
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive" -ErrorAction Stop
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-LogMessage "System restore point created successfully" "Success"
        return $true
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

# ============================================================================
# MISSING FUNCTIONS IMPLEMENTATION
# ============================================================================

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
        Write-Host "`n Found $($results.Count) matching features:" -ForegroundColor Cyan
        $i = 1
        foreach ($result in $results) {
            Write-Host "`n [$i] $($result.Value.Name)" -ForegroundColor White
            Write-Host "     Category: $($result.Value.Category)" -ForegroundColor Gray
            Write-Host "     $($result.Value.Description)" -ForegroundColor Gray
            $i++
        }
        
        Write-Host ""
        $selection = Read-Host " Select features to apply (e.g., 1,3,5) or 'none'"
        
        if ($selection -ne "none" -and $selection -ne "") {
            $indices = $selection -split ',' | ForEach-Object { [int]$_.Trim() - 1 }
            
            foreach ($index in $indices) {
                if ($index -ge 0 -and $index -lt $results.Count) {
                    Execute-Feature -FeatureKey $results[$index].Key
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
                Remove-Item -Path "$global:ProfilesPath\$profileName.json" -Force -ErrorAction SilentlyContinue
                Write-LogMessage "Profile deleted: $profileName" "Success"
            }
        }
        "4" {
            $profiles = Get-ChildItem -Path $global:ProfilesPath -Filter "*.json" -ErrorAction SilentlyContinue
            if ($profiles) {
                Write-Host "`n Saved profiles:" -ForegroundColor Cyan
                foreach ($profile in $profiles) {
                    $data = Get-Content $profile.FullName | ConvertFrom-Json
                    Write-Host " - $($profile.BaseName) (Created: $($data.Created), Features: $($data.Features.Count))" -ForegroundColor White
                }
            } else {
                Write-Host " No saved profiles found" -ForegroundColor Yellow
            }
        }
        "5" {
            $profileName = Read-Host " Enter profile name to export"
            $exportPath = Read-Host " Enter export path (default: Desktop)"
            if (!$exportPath) { $exportPath = "$env:USERPROFILE\Desktop" }
            Export-Profile -Name $profileName -Path $exportPath
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
        }
    }
    
    $profilePath = Join-Path $global:ProfilesPath "$Name.json"
    $profile | ConvertTo-Json -Depth 10 | Out-File -FilePath $profilePath -Force
    Write-LogMessage "Profile saved: $Name" "Success"
}

function Load-Profile {
    param([string]$Name)
    
    $profilePath = Join-Path $global:ProfilesPath "$Name.json"
    if (Test-Path $profilePath) {
        $profile = Get-Content $profilePath | ConvertFrom-Json
        
        Write-Host "`n Loading profile: $Name" -ForegroundColor Cyan
        Write-Host " Features to apply: $($profile.Features.Count)" -ForegroundColor White
        
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
    } else {
        Write-LogMessage "Profile not found: $Name" "Error"
    }
}

function Export-Profile {
    param(
        [string]$Name,
        [string]$Path
    )
    
    $sourcePath = Join-Path $global:ProfilesPath "$Name.json"
    if (Test-Path $sourcePath) {
        $destPath = Join-Path $Path "$Name.json"
        Copy-Item -Path $sourcePath -Destination $destPath -Force
        Write-LogMessage "Profile exported to: $destPath" "Success"
    } else {
        Write-LogMessage "Profile not found: $Name" "Error"
    }
}

function Import-Profile {
    param([string]$Path)
    
    if (Test-Path $Path) {
        $fileName = Split-Path $Path -Leaf
        $destPath = Join-Path $global:ProfilesPath $fileName
        Copy-Item -Path $Path -Destination $destPath -Force
        Write-LogMessage "Profile imported: $fileName" "Success"
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
    Write-Host " [7] Defragment Drives" -ForegroundColor White
    Write-Host " [8] Check Disk Errors" -ForegroundColor White
    Write-Host ""
    Write-Host " [B] Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host " Enter your choice"
    
    switch ($choice) {
        "1" {
            Write-Host " Cleaning temporary files..." -ForegroundColor Yellow
            Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
            RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
            RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2
            Write-LogMessage "Temporary files cleaned" "Success"
        }
        "2" {
            Write-Host " Running System File Checker..." -ForegroundColor Yellow
            sfc /scannow
        }
        "3" {
            Write-Host " Running DISM Health Check..." -ForegroundColor Yellow
            DISM /Online /Cleanup-Image /RestoreHealth
        }
        "4" {
            Write-Host " Clearing Windows Update cache..." -ForegroundColor Yellow
            Stop-Service wuauserv -Force
            Remove-Item "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Service wuauserv
            Write-LogMessage "Windows Update cache cleared" "Success"
        }
        "5" {
            Write-Host " Resetting network settings..." -ForegroundColor Yellow
            netsh winsock reset
            netsh int ip reset
            ipconfig /release
            ipconfig /renew
            ipconfig /flushdns
            Write-LogMessage "Network settings reset" "Success"
        }
        "6" {
            Write-Host " Clearing DNS cache..." -ForegroundColor Yellow
            ipconfig /flushdns
            Write-LogMessage "DNS cache cleared" "Success"
        }
        "7" {
            Write-Host " Starting drive defragmentation..." -ForegroundColor Yellow
            defrag C: /O
        }
        "8" {
            Write-Host " Checking disk for errors..." -ForegroundColor Yellow
            chkdsk C: /f /r
        }
        "B" { return }
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
    Write-Host " [5] Create Full System Backup" -ForegroundColor White
    Write-Host " [6] List Restore Points" -ForegroundColor White
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
            $backupFile = "$global:BackupPath\Registry_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
            reg export HKLM $backupFile /y
            reg export HKCU "$global:BackupPath\HKCU_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg" /y
            Write-LogMessage "Registry backed up to: $backupFile" "Success"
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
                    $confirm = Read-Host " Are you sure? This will modify the registry. (yes/no)"
                    if ($confirm -eq "yes") {
                        reg import $backups[$index].FullName
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
            Write-Host " Starting Windows Backup..." -ForegroundColor Yellow
            wbadmin start backup -backupTarget:$global:BackupPath -include:C: -allCritical -quiet
        }
        "6" {
            Write-Host "`n Available restore points:" -ForegroundColor Cyan
            Get-ComputerRestorePoint | Format-Table -AutoSize
        }
        "B" { return }
    }
    
    Read-Host "`n Press Enter to continue"
}

function Export-CurrentConfiguration {
    $exportData = @{
        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        SystemInfo = @{
            ComputerName = $env:COMPUTERNAME
            Username = $env:USERNAME
            OS = (Get-CimInstance Win32_OperatingSystem).Caption
            Version = (Get-CimInstance Win32_OperatingSystem).Version
        }
        AppliedFeatures = $global:AppliedFeatures
        Features = $global:Features
    }
    
    $exportPath = "$env:USERPROFILE\Desktop\Win11Config_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportPath -Force
    Write-LogMessage "Configuration exported to: $exportPath" "Success"
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
    Write-Host ""
    Write-Host " IMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host " - Always create a restore point before making changes" -ForegroundColor Gray
    Write-Host " - Some features require a system restart" -ForegroundColor Gray
    Write-Host " - Run this tool as Administrator" -ForegroundColor Gray
    Write-Host " - Review each feature's impact before applying" -ForegroundColor Gray
    Write-Host ""
    Write-Host " Log file location: $($global:LogFile)" -ForegroundColor Cyan
    Write-Host " Configuration path: $($global:ConfigPath)" -ForegroundColor Cyan
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

function Show-ProfileMixer {
    Show-Banner
    Write-Host "`n PROFILE MIXER - Combine Multiple Profiles" -ForegroundColor Yellow
    Write-Host " ════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    
    $availableProfiles = @{
        "1" = @{
            Name = "Privacy Focused"
            Features = @("Privacy.DisableTelemetry", "Privacy.DisableActivityHistory", "Privacy.DisableAdvertisingID", "Privacy.DisableLocationTracking")
        }
        "2" = @{
            Name = "Security Hardened"
            Features = @("Security.EnableWindowsDefender", "Security.EnableAllASRRules", "Security.EnableFirewall", "Security.EnableUAC")
        }
        "3" = @{
            Name = "Performance Optimized"
            Features = @("Performance.DisableStartupApps", "Performance.DisableBackgroundApps", "Performance.OptimizeSSD", "Performance.SetHighPerformance")
        }
        "4" = @{
            Name = "Debloated"
            Features = @("Bloatware.RemoveMicrosoft", "Bloatware.RemoveXbox", "AI.DisableCopilot", "AI.DisableRecall")
        }
    }
    
    Write-Host " Available profiles to combine:" -ForegroundColor Cyan
    foreach ($key in $availableProfiles.Keys | Sort-Object) {
        Write-Host " [$key] $($availableProfiles[$key].Name)" -ForegroundColor White
    }
    
    Write-Host ""
    $selections = Read-Host " Select profiles to combine (e.g., 1,3,4)"
    
    $combinedFeatures = @()
    $profileNames = @()
    
    $indices = $selections -split ',' | ForEach-Object { $_.Trim() }
    foreach ($index in $indices) {
        if ($availableProfiles.ContainsKey($index)) {
            $combinedFeatures += $availableProfiles[$index].Features
            $profileNames += $availableProfiles[$index].Name
        }
    }
    
    if ($combinedFeatures.Count -gt 0) {
        # Remove duplicates
        $combinedFeatures = $combinedFeatures | Select-Object -Unique
        
        Write-Host "`n Combined profile includes:" -ForegroundColor Cyan
        Write-Host " Profiles: $($profileNames -join ', ')" -ForegroundColor White
        Write-Host " Total features: $($combinedFeatures.Count)" -ForegroundColor White
        
        $confirm = Read-Host "`n Apply combined profile? (Y/N)"
        if ($confirm -eq "Y") {
            if (!$SkipRestorePoint) {
                Create-SystemRestorePoint -Description "Combined Profile Application"
            }
            
            foreach ($feature in $combinedFeatures) {
                Execute-Feature -FeatureKey $feature
            }
            
            Write-LogMessage "Combined profile applied successfully" "Success"
        }
    }
    
    Read-Host "`n Press Enter to continue"
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
            "8" { Export-CurrentConfiguration; Read-Host "`n Press Enter to continue" }
            "I" { Show-Information }
            "S" { Show-SystemInfo }
            "L" { Show-LogFile }
            "Q" { Exit-Script }
            default { Write-Host " Invalid option. Please try again." -ForegroundColor Red; Start-Sleep -Seconds 2 }
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
    Write-Host " [3] Performance Optimized - Best performance tweaks" -ForegroundColor White
    Write-Host " [4] Debloated - Remove all unnecessary apps" -ForegroundColor White
    Write-Host " [5] Developer - Development tools and settings" -ForegroundColor White
    Write-Host " [6] Gaming - Gaming optimizations" -ForegroundColor White
    Write-Host " [7] Minimal - Essential tweaks only" -ForegroundColor White
    Write-Host " [8] Ultimate - All recommended tweaks" -ForegroundColor White
    Write-Host " [9] Custom Mix - Combine multiple profiles" -ForegroundColor White
    Write-Host ""
    Write-Host " [B] Back to Main Menu" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host " Enter your choice"
    
    $profiles = @{
        "1" = @("Privacy.DisableTelemetry", "Privacy.DisableActivityHistory", "Privacy.DisableAdvertisingID", "Privacy.DisableLocationTracking")
        "2" = @("Security.EnableWindowsDefender", "Security.EnableAllASRRules", "Security.EnableFirewall", "Security.EnableUAC")
        "3" = @("Performance.DisableStartupApps", "Performance.DisableBackgroundApps", "Performance.OptimizeSSD", "Performance.SetHighPerformance")
        "4" = @("Bloatware.RemoveMicrosoft", "Bloatware.RemoveXbox", "AI.DisableCopilot", "AI.DisableRecall")
        "5" = @("Dev.InstallWSL", "Dev.EnableDevMode")
        "6" = @("Performance.DisableGameDVR", "Performance.SetHighPerformance", "Performance.OptimizeVisualEffects")
        "7" = @("Privacy.DisableTelemetry", "Bloatware.RemoveMicrosoft", "UI.ShowFileExtensions")
        "8" = @("Privacy.DisableTelemetry", "Security.EnableWindowsDefender", "Performance.OptimizeSSD", "Bloatware.RemoveMicrosoft")
    }
    
    if ($choice -eq "B" -or $choice -eq "b") {
        return
    }
    
    if ($choice -eq "9") {
        Show-ProfileMixer
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
        
        $categoryFeatures = Get-CategoryFeatures -Category $category
        $i = 1
        
        foreach ($feature in $categoryFeatures) {
            Write-Host "  [$i] $($feature.Value.Name)" -ForegroundColor White
            Write-Host "      $($feature.Value.Description)" -ForegroundColor Gray
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
                    $selectedFeatures += @($categoryFeatures)[$index].Key
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
        Write-Host "     $($feature.Value.Description)" -ForegroundColor Gray
        Write-Host "     Impact: $($feature.Value.Impact) | Reboot Required: $($feature.Value.RebootRequired)" -ForegroundColor DarkGray
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

function Exit-Script {
    Write-Host "`n Exiting Windows 11 Configuration Tool..." -ForegroundColor Yellow
    
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
            Restart-Computer -Force
        }
    }
    
    try {
        Stop-Transcript -ErrorAction SilentlyContinue
    } catch {}
    
    exit 0
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Check administrator privileges
if (!(Test-Administrator)) {
    Write-Host "This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please run as Administrator." -ForegroundColor Yellow
    
    if (!$Silent) {
        Read-Host "Press Enter to exit"
    }
    exit 1
}

# Check Windows 11 compatibility
if (!(Test-Windows11)) {
    exit 1
}

# Handle command-line parameters
if ($PSBoundParameters.Count -gt 0) {
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
        # Load and apply saved profile
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
} else {
    # Interactive mode
    Show-MainMenu
}

try {
    Stop-Transcript -ErrorAction SilentlyContinue
} catch {}
