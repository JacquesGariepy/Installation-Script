[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$PackageName,

    [Parameter(Mandatory=$false)]
    [string]$Arguments
)

# Set constants
$baseProtocol = "https:"
$baseHostName = "marketplace.visualstudio.com"
$VSInstallDir = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service"

# Set error action preference
$ErrorActionPreference = "Stop"

function Download-VSIX {
    $Uri = "$baseProtocol//$baseHostName/items?itemName=$PackageName"
    $VsixLocation = Join-Path $env:Temp "$([guid]::NewGuid()).vsix"

    Write-Verbose "Fetching VSIX extension from $Uri"
    $HTML = Invoke-WebRequest -Uri $Uri -UseBasicParsing -SessionVariable session

    $anchor = $HTML.Links | Where-Object { $_.class -eq 'install-button-container' } | Select-Object -ExpandProperty href

    if (-not $anchor) {
        throw "Could not find download anchor tag on the Visual Studio Extensions page"
    }

    $href = "$baseProtocol//$baseHostName$anchor"
    Invoke-WebRequest $href -OutFile $VsixLocation -WebSession $session

    if (-not (Test-Path $VsixLocation)) {
        throw "Downloaded VSIX file could not be located"
    }

    return $VsixLocation
}

function Install-VSIX {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VsixLocation
    )

    if (-not (Test-Path $VSInstallDir)) {
        throw "Visual Studio InstallDir does not exist"
    }

    Write-Verbose "Installing extensions..."
    Start-Process -Filepath (Join-Path $VSInstallDir "VSIXInstaller") -ArgumentList "$Arguments $VsixLocation" -Wait

    Remove-Item $VsixLocation -Force
}

try {
    Write-Host "Starting installation of VSIX extension $PackageName" -ForegroundColor Yellow
    $VsixLocation = Download-VSIX
    Install-VSIX -VsixLocation $VsixLocation
    Write-Host "Installation of $PackageName complete!" -ForegroundColor Green
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
