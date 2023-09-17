# Constants
$WINGET_OPTIONS="-e -h --force --accept-source-agreements"

# Terminal
winget install $WINGET_OPTIONS --id Microsoft.PowerShell.Preview
winget install $WINGET_OPTIONS --id Microsoft.WindowsTerminal.Preview
winget install $WINGET_OPTIONS --id JanDeDobbeleer.OhMyPosh

# Browsers
winget install $WINGET_OPTIONS --id Google.Chrome
winget install $WINGET_OPTIONS --id Google.Chrome.Dev
winget install $WINGET_OPTIONS --id Google.Chrome.Beta
winget install $WINGET_OPTIONS --id Mozilla.Firefox
winget install $WINGET_OPTIONS --id Mozilla.Firefox.DeveloperEdition
winget install $WINGET_OPTIONS --id Microsoft.Edge.Beta
winget install $WINGET_OPTIONS --id BraveSoftware.BraveBrowser

# IDEs
winget install $WINGET_OPTIONS -i --id Microsoft.VisualStudio.2022.Enterprise-Preview
winget install $WINGET_OPTIONS --id Microsoft.VisualStudioCode
winget install $WINGET_OPTIONS --id Microsoft.VisualStudioCode.Insiders
winget install $WINGET_OPTIONS --id Notepad++.Notepad++
winget install $WINGET_OPTIONS --id JetBrains.PyCharm

# Frameworks
winget install $WINGET_OPTIONS --id Microsoft.dotnet
winget install $WINGET_OPTIONS --id OpenJS.NodeJS
winget install $WINGET_OPTIONS --id Yarn.Yarn

# Development
winget install $WINGET_OPTIONS --id Python.Python.3
winget install $WINGET_OPTIONS --id Anaconda.Anaconda3

# Git
winget install $WINGET_OPTIONS -i --id Git.Git
winget install $WINGET_OPTIONS --id GitHub.GitLFS
winget install $WINGET_OPTIONS --id GitHub.cli
winget install $WINGET_OPTIONS --id Axosoft.GitKraken

# Database
winget install $WINGET_OPTIONS -i --id Microsoft.AzureDataStudio.Insiders
winget install $WINGET_OPTIONS -i --id Microsoft.SQLServer.2019.Developer
winget install $WINGET_OPTIONS -i --id Microsoft.SQLServerManagementStudio
winget install $WINGET_OPTIONS --id MongoDB.MongoDB

# Tools
winget install $WINGET_OPTIONS --id Docker.DockerDesktop
winget install $WINGET_OPTIONS --id Microsoft.PowerBI
winget install $WINGET_OPTIONS --id Telerik.Fiddler
winget install $WINGET_OPTIONS --id JetBrains.ReSharper
winget install $WINGET_OPTIONS --id JetBrains.Rider
winget install $WINGET_OPTIONS --id JetBrains.WebStorm
winget install $WINGET_OPTIONS --id JetBrains.DataGrip
winget install $WINGET_OPTIONS --id Postman.Postman

# Azure
winget install $WINGET_OPTIONS --id Microsoft.AzureDataStudio
winget install $WINGET_OPTIONS --id Microsoft.AzureStorageExplorer
winget install $WINGET_OPTIONS --id Microsoft.AzureCLI
