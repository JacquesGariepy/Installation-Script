$DownloadAndInstall = Join-Path $PSScriptRoot "_install_script.ps1"

$packages = @(
    @{ Name="MadsKristensen.NpmTaskRunner64"; Args="/q /a" },
    @{ Name="ErikEJ.SQLServerCompactSQLiteToolbox"; Args="/q /a" },
    @{ Name="VisualStudioPlatformTeam.ProductivityPowerPack2022"; Args="/q /a" },
    @{ Name="ErikEJ.EFCorePowerTools"; Args="/q /a" },
    @{ Name="ProBITools.MicrosoftReportProjectsforVisualStudio2022"; Args="/q /a" },
    @{ Name="ProBITools.MicrosoftAnalysisServicesModelingProjects2022"; Args="/q /a" }
    # ... Add other packages similarly
)

foreach ($package in $packages) {
    try {
        & $DownloadAndInstall -PackageName $package.Name -Arguments $package.Args
        Write-Verbose "Installed $($package.Name) successfully."
    } catch {
        Write-Error "Failed to install $($package.Name). Error: $($_.Exception.Message)"
    }
}

Write-Host "Installing dotnet nuget package" -ForegroundColor Yellow
dotnet tool install --global Microsoft.Tye
