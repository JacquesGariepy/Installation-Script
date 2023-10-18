if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Output "winget is already installed."
} else {
    Write-Output "winget is not installed. Installing now..."
    # Get the current Windows version
    $WindowsVersion = [System.Environment]::OSVersion.Version
    
    # Check if the major version is 10 for Windows 10
    if ($WindowsVersion.Major -eq 10) {
        Write-Output "Detected Windows 10. Registering winget..."
    
        # Register winget
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
    
        Write-Output "winget registration attempted."
    } else {
        Start-Process "ms-windows-store://pdp/?PFN=Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
    }
}

# Terminal
winget install -e -h --id Microsoft.PowerShell.Preview --force --accept-source-agreements
winget install -e -h --id Microsoft.WindowsTerminal.Preview --force --accept-source-agreements
winget install -e -h --id JanDeDobbeleer.OhMyPosh --force --accept-source-agreements

# Browsers
winget install -e -h --id Google.Chrome --force --accept-source-agreements
winget install -e -h --id Google.Chrome.Dev --force --accept-source-agreements
winget install -e -h --id Google.Chrome.Beta --force --accept-source-agreements
winget install -e -h --id Mozilla.Firefox --force --accept-source-agreements
winget install -e -h --id Mozilla.Firefox.DeveloperEdition --force --accept-source-agreements
winget install -e -h --id Microsoft.Edge.Beta --force --accept-source-agreements
winget install -e -h --id BraveSoftware.BraveBrowser --force --accept-source-agreements  # Additional: Brave Browser
winget install -e -h --id Brave.Brave.Nightly --force --accept-source-agreements 
winget install -e -h --id TorProject.TorBrowser --force --accept-source-agreements

# IDEs
winget install -e -i --id Microsoft.VisualStudio.2022.Enterprise-Preview --force --accept-source-agreements
# winget install -e -i --id Microsoft.VisualStudio.2022.Enterprise --force --accept-source-agreements
winget install -e -h --id Microsoft.VisualStudioCode --force --accept-source-agreements
winget install -e -h --id Microsoft.VisualStudioCode.Insiders --force --accept-source-agreements
winget install -e -h --id Notepad++.Notepad++ --force --accept-source-agreements
winget install -e -h --id JetBrains.PyCharm --force --accept-source-agreements  # Additional: PyCharm for Python Development
winget install -e -h --id WinMerge.WinMerge --force --accept-source-agreements 

# Frameworks
winget install -e -h --id Microsoft.dotnet --force --accept-source-agreements
winget install -e -h --id OpenJS.NodeJS --force --accept-source-agreements
winget install -e -h --id Yarn.Yarn --force --accept-source-agreements

# Development
winget install -e -h --id Python.Python.3 --force --accept-source-agreements
winget install -e -h --id Anaconda.Anaconda3 --force --accept-source-agreements
# winget install -e -h --id Anaconda.Miniconda3 --force --accept-source-agreements #miniconda or anaconda
winget install -e -h --id Microsoft.WindowsTerminal --force --accept-source-agreements
winget install -e -h --id Microsoft.WingetCreate --force --accept-source-agreements
winget install -e -h --id GitTools.GitVersion --force --accept-source-agreements
winget install -e -h --id Chocolatey.Chocolatey --force --accept-source-agreements
winget install -e -h --id JetBrains.ReSharper --force --accept-source-agreements
winget install -e -h --id JetBrains.Rider --force --accept-source-agreements
winget install -e -h --id JetBrains.WebStorm --force --accept-source-agreements
winget install -e -h --id JetBrains.DataGrip --force --accept-source-agreements

# Git
winget install -e -i --id Git.Git --force --accept-source-agreements
winget install -e -h --id GitHub.GitLFS --force --accept-source-agreements
winget install -e -h --id GitHub.cli --force --accept-source-agreements
winget install -e -h --id GitHub.GitHubDesktop.Beta  --force --accept-source-agreements 
winget install -e -h --id Axosoft.GitKraken --force --accept-source-agreements
winget install -e -h --id StefHeyenrath.GitHubReleaseNotes --force --accept-source-agreements
winget install -e -h --id GitHub.ClassroomAssistant --force --accept-source-agreements #for course
# winget install -e -h --id=GitHub.GitLFS  --force --accept-source-agreements #for course

# Database
winget install -e -i --id Microsoft.AzureDataStudio.Insiders --force --accept-source-agreements
winget install -e -i --id Microsoft.SQLServer.2019.Developer --force --accept-source-agreements
winget install -e -i --id Microsoft.SQLServerManagementStudio --force --accept-source-agreements
winget install -e -h --id MongoDB.MongoDB --force --accept-source-agreements  # Additional: MongoDB
winget install -e -h --id AllroundAutomations.PLSQLDeveloper -force --accept-source-agreements
winget install -e -h --id PostgreSQL.PostgreSQL -force --accept-source-agreements

# call
winget install -e -h --id Telerik.Fiddler --force --accept-source-agreements
winget install -e -h --id Postman.Postman --force --accept-source-agreements  # Additional: Postman for API Testing
winget install -e -h --id SmartBear.SoapUI --force --accept-source-agreements

# Tools
winget install -e -h --id Docker.DockerDesktop --force --accept-source-agreements
winget install -e -h --id Microsoft.PowerBI  --force --accept-source-agreements
winget install -e -h --id PuTTY.PuTTY --force --accept-source-agreements
winget install -e -h --id RARLab.WinRAR --force --accept-source-agreements
winget install -e -h --id M2Team.NanaZip --force --accept-source-agreements
winget install -e -h --id TorProject.TorBrowser --force --accept-source-agreements
winget install -e -h --id Obsidian.Obsidian --force --accept-source-agreements
winget install -e -h --id SomePythonThings.WingetUIStore --force --accept-source-agreements
winget install -e -h --id HandyOrg.HandyWinget-GUI --force --accept-source-agreements
winget install -e -h --id Microsoft.PowerToys --force --accept-source-agreements
winget install -e -h --id Microsoft.PCManager --force --accept-source-agreements
winget install -e -h --id Google.NearbyShare --force --accept-source-agreements
winget install  -e -h --id Adobe.Acrobat.Reader.64-bit --force --accept-source-agreements

# Azure
winget install -e -h --id Microsoft.AzureDataStudio --force --accept-source-agreements
winget install -e -h --id Microsoft.AzureStorageExplorer --force --accept-source-agreements
winget install -e -h --id Microsoft.AzureCLI --force --accept-source-agreements

#VM
winget install -e -h --id Oracle.VirtualBox --force --accept-source-agreements 

#Organisation
winget install -e -h --id Notion.Notion --force --accept-source-agreements 
winget install -e -h --id Discord.Discord --force --accept-source-agreements 

#Video
winget install -e -h --id OBSProject.OBSStudio.Pre-release --force --accept-source-agreements
winget install -e -h --id VideoLAN.VLC --force --accept-source-agreements

#hardware
winget install -e -h --id CPUID.CPU-Z --force --accept-source-agreements

#secure
winget install -e -h --id Bitwarden.Bitwarden --force --accept-source-agreements
winget install -e -h --id PrestonN.FreeTube --force --accept-source-agreements

#teams
winget install -e -h --id Discord.Discord --force --accept-source-agreements

#ui
winget install -e -h --id SlackTechnologies.Slack --force --accept-source-agreements
