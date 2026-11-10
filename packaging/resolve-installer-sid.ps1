param(
    [string]$OutFile = "",
    [string]$Explicit = ""
)

$ErrorActionPreference = "Stop"

function Get-CanaInstallerSid {
    param([string]$ExplicitSid)
    if ($ExplicitSid) {
        $trimmed = $ExplicitSid.Trim()
        if ($trimmed -in @("S-1-5-18", "S-1-5-19", "S-1-5-20")) {
            throw "Installer SID resolved to a privileged service account."
        }
        if ($trimmed -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
            throw "Installer SID is not a valid unelevated user SID."
        }
        return $trimmed
    }
    $sessionId = (Get-Process -Id $PID).SessionId
    $proc = Get-CimInstance Win32_Process -Filter "Name = 'explorer.exe'" |
        Where-Object { $_.SessionId -eq $sessionId } |
        Select-Object -First 1
    if (-not $proc) {
        throw "Could not determine the installing user's unelevated SID."
    }
    $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid
    if (-not $owner.Sid) {
        throw "Could not determine the installing user's unelevated SID."
    }
    $sid = [string]$owner.Sid
    if ($sid -in @("S-1-5-18", "S-1-5-19", "S-1-5-20")) {
        throw "Installer SID resolved to a privileged service account."
    }
    if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
        throw "Installer SID is not a valid unelevated user SID."
    }
    return $sid
}

$sid = Get-CanaInstallerSid -ExplicitSid $Explicit
if ($OutFile) {
    $dir = Split-Path -Parent $OutFile
    if ($dir) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    Set-Content -Path $OutFile -Value $sid -Encoding ASCII
}
Write-Output $sid
