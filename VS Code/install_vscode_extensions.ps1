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
        "anteprimorac.html-end-tag-labels",
        "DavidAnson.vscode-markdownlint",
        "dbaeumer.vscode-eslint",
        "eamodio.gitlens-insiders",
        "EditorConfig.EditorConfig",
        "eg2.vscode-npm-script",
        "esbenp.prettier-vscode",
        "formulahendry.auto-rename-tag",
        "GitHub.copilot",
        "GitHub.vscode-pull-request-github",
        "johnpapa.vscode-peacock",
        "johnpapa.winteriscoming",
        "ms-dotnettools.csharp",
        "ms-playwright.playwright",
        "naumovs.color-highlight",
        "PKief.material-icon-theme",
        "rangav.vscode-thunder-client",
        "VisualStudioExptTeam.vscodeintellicode",
        "yzhang.markdown-all-in-one",
        "ms-mssql.mssql",
        "ms-vscode.powershell",
        "ms-vscode.live-server"
    ),

    [switch]$LaunchWhenDone
)

# Define the installation path for VSCode
$codePath = "C:\Users\jgariepy\AppData\Local\Programs\"

try {
    $ProgressPreference = 'SilentlyContinue'

    # Determine the appropriate build edition and command path
    switch ($BuildEdition) {
        "stable" {
            $codeCmdPath = Join-Path $codePath "Microsoft VS Code\bin\code.cmd"
            $appName = "Visual Studio Code ($Architecture)"
        }
        "insider" {
            $codeCmdPath = Join-Path $codePath "Microsoft VS Code Insiders\bin\code-insiders.cmd"
            $appName = "Visual Studio Code - Insiders Edition ($Architecture)"
        }
    }

    Write-Host "`nInstalling for $BuildEdition..." -ForegroundColor Green

    # Install extensions
    foreach ($extension in $AdditionalExtensions) {
        Write-Host "`nInstalling extension $extension" -ForegroundColor Yellow
        & $codeCmdPath --install-extension $extension
    }

    # Launch VSCode if specified
    if ($LaunchWhenDone) {
        Write-Host "`nInstallation complete, starting $appName...`n`n" -ForegroundColor Green
        & $codeCmdPath
    }
    else {
        Write-Host "`nInstallation complete!`n`n" -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    $ProgressPreference = 'Continue'
}
