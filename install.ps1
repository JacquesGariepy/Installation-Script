set-executionpolicy unrestricted
Write-Host "Autoriser l’exécution de scripts PowerShell. Si powershell avait une restriction préalable, veuillez relancer ce script." -ForegroundColor Yellow

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
Write-Host "Installation" -ForegroundColor Yellow

$confirmation = Read-Host "Installation applications (y/n)"
if ($confirmation -eq 'y') {
  &"$PSScriptRoot\Applications\install_applications.ps1"  
}

$confirmation = Read-Host "Installation Visual Studio 2022 Extensions (y/n)"
if ($confirmation -eq 'y') {
  &"$PSScriptRoot\VisualStudio2022\install_visualstudio_extensions.ps1"  
}

$confirmation = Read-Host "Installation VSCode Angular Extensions (y/n)"
if ($confirmation -eq 'y') {
  &"$PSScriptRoot\VS Code\install_vscode_angular_extensions.ps1"
}

$confirmation = Read-Host "Installation VSCode React & React Native Extensions (y/n)"
if ($confirmation -eq 'y') {
  &"$PSScriptRoot\VS Code\install_vscode_react_extensions.ps1"
}

$confirmation = Read-Host "Installation Chrome Extensions (y/n)"
if ($confirmation -eq 'y') {
  &"$PSScriptRoot\Chrome\install_chrome_extensions.ps1"
}

Write-Host "Fin de l'nstallation" -ForegroundColor Yellow
