param(
    [switch]$RemoveData
)

$ServiceName = "CANA"
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
}

$StartMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\CANA"
if (Test-Path $StartMenu) {
    Remove-Item -Recurse -Force $StartMenu -ErrorAction SilentlyContinue
}

if ($RemoveData) {
    $confirm = Read-Host "Delete CANA historical data under $env:ProgramData\CANA? Type YES to confirm"
    if ($confirm -eq "YES") {
        Remove-Item -Recurse -Force (Join-Path $env:ProgramData "CANA") -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "User data under $env:ProgramData\CANA was preserved."
}

Write-Host "CANA service unregistered."
