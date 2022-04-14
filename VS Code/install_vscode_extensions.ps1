[CmdletBinding()]
param(
    [parameter()]
    [ValidateSet(,"64-bit","32-bit")]
    [string]$Architecture = "64-bit",

    [parameter()]
    [ValidateSet("stable","insider")]
    
    #stable ou insider
    [string]$BuildEdition = "insider",
    
    [Parameter()]
    [ValidateNotNull()]
    [string[]]$AdditionalExtensions = @(
    "aaron-bond.better-comments",
	"Angular.ng-template",
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
	"johnpapa.angular-essentials",
	"johnpapa.Angular2",
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
    	"esbenp.prettier-vscode",
    	"ms-vscode.powershell",
    	"ms-vscode.live-server"),

    [switch]$LaunchWhenDone
)
	#path d'installation de vscode
    $codePath = "C:\Users\jgariepy\AppData\Local\Programs\"
    $bitVersion = "win32-x64"

    try {
        $ProgressPreference = 'SilentlyContinue'

        #version des vscode
		$buildEditions = @("stable", "insider")

        foreach ($buildEdition in $buildEditions) {

            switch ($buildEdition) {
                "Stable" {
                    $codeCmdPath = "$codePath\Microsoft VS Code\bin\code.cmd"
                    $appName = "Visual Studio Code ($($Architecture))"

                    break;
                }
                "Insider" {
                    $codeCmdPath = "$codePath\Microsoft VS Code Insiders\bin\code-insiders.cmd"
                    $appName = "Visual Studio Code - Insiders Edition ($($Architecture))"
                    break;
                }
            }
            Write-Host "`nInstalling for $buildEdition..." -ForegroundColor Green
            
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
    }
    finally {
        $ProgressPreference = 'Continue'
    }
