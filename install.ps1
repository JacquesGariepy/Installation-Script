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

$confirmation = Read-Host "Installation VSCode Extensions (y/n)"
if ($confirmation -eq 'y') {
  &"$PSScriptRoot\VS Code\install_vscode_extensions.ps1"
}

$confirmation = Read-Host "Installation Chrome Extensions (y/n)"
if ($confirmation -eq 'y') {
  &"$PSScriptRoot\Chrome\install_chrome_extensions.ps1"
}

Write-Host "Fin de l'nstallation" -ForegroundColor Yellow