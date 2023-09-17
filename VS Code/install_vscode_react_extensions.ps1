<#
.SYNOPSIS
This script installs the necessary tools for React development based on best practices and updated installation recommendations for 2023.

.DESCRIPTION
The script installs Node.js, Yarn (a popular package manager for React), and creates a new React application using Create React App (CRA). It also installs some recommended extensions for Visual Studio Code that are beneficial for React development.

.NOTES
Make sure to run this script with administrative privileges.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReactAppName = "my-react-app",

    [Parameter()]
    [switch]$UseYarn
)

try {
    $ProgressPreference = 'SilentlyContinue'

    # Install Node.js
    Write-Host "Installing Node.js..." -ForegroundColor Green
    Invoke-Expression "iex ((New-Object System.Net.WebClient).DownloadString('https://install-node.now.sh/latest'))"

    # Check if Node and npm were installed successfully
    node -v
    npm -v

    # Install Yarn package manager if the switch is provided
    if ($UseYarn) {
        Write-Host "Installing Yarn package manager..." -ForegroundColor Green
        npm install -g yarn

        # Check if Yarn was installed successfully
        yarn -v
    }

    # Install Create React App (CRA) globally
    Write-Host "Installing Create React App (CRA)..." -ForegroundColor Green
    npm install -g create-react-app

    # Create a new React application using CRA
    Write-Host "Creating a new React application named $ReactAppName..." -ForegroundColor Green
    if ($UseYarn) {
        create-react-app $ReactAppName --use-yarn
    } else {
        create-react-app $ReactAppName
    }

    # Install recommended extensions for Visual Studio Code
    $vsCodeExtensions = @(
        "esbenp.prettier-vscode",          # Prettier - Code formatter
        "dbaeumer.vscode-eslint",          # ESLint
        "dsznajder.es7-react-js-snippets", # ES7 React/Redux/GraphQL/React-Native snippets
        "ms-vscode.vscode-typescript-tslint-plugin" # TSLint (deprecated, but some projects might still use it)
    )

    $codeCmdPath = "C:\Users\$env:USERNAME\AppData\Local\Programs\Microsoft VS Code\bin\code.cmd"
    foreach ($extension in $vsCodeExtensions) {
        Write-Host "Installing VS Code extension: $extension" -ForegroundColor Yellow
        & $codeCmdPath --install-extension $extension
    }

    Write-Host "React development environment setup is complete!" -ForegroundColor Green

} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
} finally {
    $ProgressPreference = 'Continue'
}

