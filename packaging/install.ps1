param(
    [string]$InstallDir = $PSScriptRoot,
    [string]$InstallerSid = ""
)

$ErrorActionPreference = "Stop"
$ServiceName = "CANA"
$Exe = Join-Path $InstallDir "CANA.exe"
$DataRoot = Join-Path $env:ProgramData "CANA"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run CANA setup as Administrator. Installation aborted."
}
if (-not (Test-Path $Exe)) {
    $Exe = Join-Path $InstallDir "dist\CANA\CANA.exe"
}
if (-not (Test-Path $Exe -PathType Leaf)) {
    throw "CANA.exe was not found. Build CANA-Setup.exe first. Installation aborted."
}
New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataRoot "logs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataRoot "sessions") | Out-Null
Start-Transcript -Path (Join-Path $DataRoot "logs\install.log") -Append | Out-Null
try {

function Get-CanaInstallerSid {
    param([string]$Explicit)
    $resolver = Join-Path $PSScriptRoot "resolve-installer-sid.ps1"
    if (-not (Test-Path $resolver)) {
        $resolver = Join-Path $InstallDir "resolve-installer-sid.ps1"
    }
    if (Test-Path $resolver) {
        $sid = & $resolver -Explicit $Explicit
        if ($sid) {
            return [string]$sid.Trim()
        }
    }
    if ($Explicit) {
        $trimmed = $Explicit.Trim()
        if ($trimmed -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
            throw "Installer SID is not a valid unelevated user SID. Installation aborted."
        }
        return $trimmed
    }
    throw "Could not determine the installing user's unelevated SID. Installation aborted."
}

function Invoke-CanaChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE. Installation aborted."
    }
}

function Protect-CanaDataRoot {
    param(
        [string]$Path,
        [string]$UserSid
    )
    Invoke-CanaChecked icacls $Path /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*${UserSid}:(OI)(CI)RX"
    Invoke-CanaChecked icacls $Path /inheritance:r
    Invoke-CanaChecked icacls $Path /remove:g "*S-1-1-0" "*S-1-5-32-545"
}

$ConfigPath = Join-Path $DataRoot "config.json"
$SidPath = Join-Path $DataRoot "installer-user.sid"
$InstallerSid = Get-CanaInstallerSid -Explicit $InstallerSid
if ($InstallerSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
    throw "Installer SID is not a valid unelevated user SID. Installation aborted."
}
if ($InstallerSid -in @("S-1-5-18", "S-1-5-19", "S-1-5-20")) {
    throw "Installer SID resolved to a privileged service account. Installation aborted."
}
Set-Content -Path $SidPath -Value $InstallerSid -Encoding ASCII
Protect-CanaDataRoot -Path $DataRoot -UserSid $InstallerSid
if (-not (Test-Path $ConfigPath)) {
    $config = @{
        automatic_startup = $true
        capture_interface = ""
        database_path = (Join-Path $DataRoot "cana.db")
        logging_level = "INFO"
        logs_dir = (Join-Path $DataRoot "logs")
        monitoring_enabled = $true
        packet_filter = "ALL"
        persist = $true
        sessions_dir = (Join-Path $DataRoot "sessions")
        notify = $false
    }
    $configJson = $config | ConvertTo-Json
    # Write UTF-8 without a BOM so json.load() cannot choke on it.
    [System.IO.File]::WriteAllText(
        $ConfigPath,
        $configJson,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    try {
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    } finally {
        $existing.Dispose()
    }
}

if (-not (Test-Path $Exe)) {
    $DistExe = Join-Path $InstallDir "dist\CANA\CANA.exe"
    if (Test-Path $DistExe) {
        $Exe = $DistExe
    }
}
if (-not (Test-Path $Exe)) {
    throw "CANA.exe was not found at $Exe. The production installer requires the frozen CANA.exe. Installation aborted."
}
$BinPath = "`"$Exe`""

$StartType = "auto"
if (Test-Path $ConfigPath) {
    try {
        $existingConfig = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        if ($null -ne $existingConfig.automatic_startup -and -not [bool]$existingConfig.automatic_startup) {
            $StartType = "demand"
        }
    } catch {
        $StartType = "auto"
    }
}

if ($existing) {
    Invoke-CanaChecked sc.exe config $ServiceName binPath= $BinPath start= $StartType DisplayName= "CANA Network Monitor" obj= LocalSystem
} else {
    Invoke-CanaChecked sc.exe create $ServiceName binPath= $BinPath start= $StartType DisplayName= "CANA Network Monitor" obj= LocalSystem
}

$registered = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $registered) {
    throw "Service '$ServiceName' was not registered by sc.exe create. Installation aborted."
}

Invoke-CanaChecked sc.exe description $ServiceName "Context-Aware Network Behavior Analyzer. Captures and analyzes local network traffic in the background."
Invoke-CanaChecked sc.exe config $ServiceName start= $StartType
Invoke-CanaChecked sc.exe failure $ServiceName reset= 86400 actions= restart/15000/restart/15000/restart/15000
Invoke-CanaChecked sc.exe failureflag $ServiceName 1
sc.exe start $ServiceName
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) {
    throw "sc.exe start failed with exit code $LASTEXITCODE. Installation aborted."
}
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    throw "Service '$ServiceName' is not visible to the Service Control Manager. Installation aborted."
}
$running = Get-Service -Name $ServiceName
try {
    $running.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
} finally {
    $running.Dispose()
}
Write-Host "CANA service installed and started."
} catch {
    Write-Host "CANA installation failed: $_"
    exit 1
} finally {
    Stop-Transcript | Out-Null
}
