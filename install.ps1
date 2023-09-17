# Set the execution policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Write-Host "Autoriser l’exécution de scripts PowerShell. Si PowerShell avait une restriction préalable, veuillez relancer ce script." -ForegroundColor Yellow

# Function to prompt and run scripts
function RunScript($promptMessage, $scriptPath) {
    $confirmation = Read-Host $promptMessage
    if ($confirmation -eq 'y') {
        &"$PSScriptRoot\$scriptPath"
    }
}

# Call the function for each script
RunScript "Installation applications (y/n)" "Applications\install_applications.ps1"
RunScript "Installation Visual Studio 2022 Extensions (y/n)" "VisualStudio2022\install_visualstudio_extensions.ps1"
RunScript "Installation VSCode Extensions (y/n)" "VS Code\install_vscode_extensions.ps1"
RunScript "Installation VSCode Angular Extensions (y/n)" "VS Code\install_vscode_angular_extensions.ps1"
RunScript "Installation VSCode React & React Native Extensions (y/n)" "VS Code\install_vscode_react_extensions.ps1"
RunScript "Installation Chrome Extensions (y/n)" "Chrome\install_chrome_extensions.ps1"

Write-Host "Fin de l'installation" -ForegroundColor Yellow
