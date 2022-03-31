           
$DownloadAndInstall= $PSScriptRoot+"\_install_script.ps1"

& $DownloadAndInstall -PackageName "MadsKristensen.NpmTaskRunner64" "/q /a"
& $DownloadAndInstall -PackageName "ErikEJ.SQLServerCompactSQLiteToolbox" "/q /a"
& $DownloadAndInstall -PackageName "ErikEJ.EFCorePowerTools" "/q /a"
& $DownloadAndInstall -PackageName "SteveCadwallader.CodeMaidVS2022" "/q /a"
& $DownloadAndInstall -PackageName "Mojtabakaviani.SqlTools" "/q /a"
& $DownloadAndInstall -PackageName "EWoodruff.VisualStudioSpellCheckerVS2022andLater" "/q /a"
& $DownloadAndInstall -PackageName "WixToolset.WixToolsetVisualStudio2022Extension" "/a"
& $DownloadAndInstall -PackageName "ProBITools.MicrosoftReportProjectsforVisualStudio2022" "/q /a"
& $DownloadAndInstall -PackageName "DevartSoftware.CodeCompare" "/q /a"
& $DownloadAndInstall -PackageName "VisualStudioPlatformTeam.ProductivityPowerPack2022" "/q /a"

Write-Host "Installation dotnet nuget package" -ForegroundColor Yellow
dotnet tool install --global Microsoft.Tye --version 0.11.0-alpha.22111.1
