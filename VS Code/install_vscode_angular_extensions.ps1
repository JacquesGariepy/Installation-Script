[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("64-bit", "32-bit")]
    [string]$Architecture = "64-bit",

    [Parameter()]
    [ValidateSet("stable", "insider")]
    [string]$BuildEdition = "insider",

    [Parameter()]
    [ValidateNotNull()]
    [string[]]$AdditionalExtensions = @(
        "aaron-bond.better-comments",
        "Angular.ng-template",
        "johnpapa.angular-essentials",
        "johnpapa.Angular2"
    ),

    [Parameter()]
    [switch]$LaunchWhenDone
)

# Installation path for VSCode
$codePath = "C:\Users\jgariepy\AppData\Local\Programs\"

# Determine bit version based on architecture
$bitVersion = if ($Architecture -eq "64-bit") { "win32-x64" } else { "win32-x86" }

try {
    $ProgressPreference = 'SilentlyContinue'

    switch ($BuildEdition) {
        "stable" {
            $codeCmdPath = "$codePath\Microsoft VS Code\bin\code.cmd"
            $appName = "Visual Studio Code ($Architecture)"
        }
        "insider" {
            $codeCmdPath = "$codePath\Microsoft VS Code Insiders\bin\code-insiders.cmd"
            $appName = "Visual Studio Code - Insiders Edition ($Architecture)"
        }
    }

    Write-Host "`nInstalling for $BuildEdition..." -ForegroundColor Green

    # Combine default and additional extensions
    $extensions = @("ms-vscode.PowerShell") + $AdditionalExtensions

    foreach ($extension in $extensions) {
        Write-Host "`nInstalling extension $extension" -ForegroundColor Yellow
        & $codeCmdPath --install-extension $extension
    }

    if ($LaunchWhenDone) {
        Write-Host "`nInstallation complete, starting $appName...`n`n" -ForegroundColor Green
        & $codeCmdPath
    }
    else {
        Write-Host "`nInstallation complete!`n`n" -ForegroundColor Green
    }
}
finally {
    $ProgressPreference = 'Continue'
}
