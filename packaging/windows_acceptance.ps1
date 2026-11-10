$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$env:CANA_ACCEPTANCE = "1"
python -m pytest tests/test_windows_acceptance.py tests/test_windows_packaging.py -q
if ($LASTEXITCODE -ne 0) {
    throw "Windows acceptance suite failed"
}
Write-Host "Windows acceptance suite passed."
