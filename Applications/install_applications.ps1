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

# IDEs
winget install -e -i --id Microsoft.VisualStudio.2022.Enterprise-Preview --force --accept-source-agreements
winget install -e -h --id Microsoft.VisualStudioCode --force --accept-source-agreements
winget install -e -h --id Microsoft.VisualStudioCode.Insiders --force --accept-source-agreements
winget install -e -h --id Notepad++.Notepad++ --force --accept-source-agreements
winget install -e -h --id JetBrains.PyCharm --force --accept-source-agreements  # Additional: PyCharm for Python Development

# Frameworks
winget install -e -h --id Microsoft.dotnet --force --accept-source-agreements
winget install -e -h --id OpenJS.NodeJS --force --accept-source-agreements
winget install -e -h --id Yarn.Yarn --force --accept-source-agreements

# Development
winget install -e -h --id Python.Python.3 --force --accept-source-agreements
winget install -e -h --id Anaconda.Anaconda3 --force --accept-source-agreements  # Additional: Anaconda for Data Science

# Git
winget install -e -i --id Git.Git --force --accept-source-agreements
winget install -e -h --id GitHub.GitLFS --force --accept-source-agreements
winget install -e -h --id GitHub.cli --force --accept-source-agreements
winget install -e -h --id Axosoft.GitKraken --force --accept-source-agreements

# Database
winget install -e -i --id Microsoft.AzureDataStudio.Insiders --force --accept-source-agreements
winget install -e -i --id Microsoft.SQLServer.2019.Developer --force --accept-source-agreements
winget install -e -i --id Microsoft.SQLServerManagementStudio --force --accept-source-agreements
winget install -e -h --id MongoDB.MongoDB --force --accept-source-agreements  # Additional: MongoDB

# Tools
winget install -e -h --id Docker.DockerDesktop --force --accept-source-agreements
winget install -e -h --id Microsoft.PowerBI  --force --accept-source-agreements
winget install -e -h --id Telerik.Fiddler --force --accept-source-agreements
winget install -e -h --id JetBrains.ReSharper --force --accept-source-agreements
winget install -e -h --id JetBrains.Rider --force --accept-source-agreements
winget install -e -h --id JetBrains.WebStorm --force --accept-source-agreements
winget install -e -h --id JetBrains.DataGrip --force --accept-source-agreements
winget install -e -h --id Postman.Postman --force --accept-source-agreements  # Additional: Postman for API Testing
winget install -e -h --id SmartBear.SoapUI --force --accept-source-agreements

# Azure
winget install -e -h --id Microsoft.AzureDataStudio --force --accept-source-agreements
winget install -e -h --id Microsoft.AzureStorageExplorer --force --accept-source-agreements
winget install -e -h --id Microsoft.AzureCLI --force --accept-source-agreements

winget install -e -h --id Oracle.VirtualBox --force --accept-source-agreements 

winget install -e -h --id AllroundAutomations.PLSQLDeveloper -force --accept-source-agreements
