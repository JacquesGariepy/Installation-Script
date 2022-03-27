param([String] $PackageName, $Arguments)
 
$ErrorActionPreference = "Stop"
 
$baseProtocol = "https:"
$baseHostName = "marketplace.visualstudio.com"
 
$Uri = "$($baseProtocol)//$($baseHostName)/items?itemName=$($PackageName)"
$VsixLocation = "$($env:Temp)\$([guid]::NewGuid()).vsix"
 
$VSInstallDir = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service"
 
if (-Not $VSInstallDir) {
  Write-Error "Visual Studio InstallDir registry key missing"
  Exit 1
}
 
Write-Host "Installation VSIX extension $($PackageName)" -ForegroundColor Yellow
$HTML = Invoke-WebRequest -Uri $Uri -UseBasicParsing -SessionVariable session
 
Write-Host "Attempting to download"
$anchor = $HTML.Links |
Where-Object { $_.class -eq 'install-button-container' } |
Select-Object -ExpandProperty href

if (-Not $anchor) {
  Write-Error "Could not find download anchor tag on the Visual Studio Extensions page"
  Exit 1
}
$href = "$($baseProtocol)//$($baseHostName)$($anchor)"
Invoke-WebRequest $href -OutFile $VsixLocation -WebSession $session
 
if (-Not (Test-Path $VsixLocation)) {
  Write-Error "Downloaded VSIX file could not be located"
  Exit 1
}

Write-Host "Installing extensions..."
Start-Process -Filepath "$($VSInstallDir)\VSIXInstaller" -ArgumentList "$($Arguments) $($VsixLocation)" -Wait
 
rm $VsixLocation
 
Write-Host "Installation of $($PackageName) complete! `n`n" -ForegroundColor Green