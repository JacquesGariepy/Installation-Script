# Define the source location and destination paths
$location = Split-Path -Parent $PSCommandPath
$destination = Get-ChildItem -Path 'HKCU:\Software\Microsoft\Office\' -Recurse |
               Where-Object { $_.PSChildName -eq 'Application' } |
               Get-ItemProperty -Name 'MyShapesPath' |
               Select-Object -ExpandProperty 'MyShapesPath'

# Define the file extensions to search for
$fileExtensions = @('*.vssx', '*.vstx')

# Loop through each file extension and copy the files
foreach ($extension in $fileExtensions) {
    Get-ChildItem -Path $location -Recurse -Force -Filter $extension |
    Where-Object { $_.PSPath -notcontains 'Previous Versions' } |
    ForEach-Object {
        Copy-Item -Path $_.PSPath -Destination $destination -Force
    }
}
