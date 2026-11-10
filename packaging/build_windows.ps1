param([string]$Python = "python", [string]$ISCC = "")

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

& $Python -m pip install -e '.[windows,ui]' pyinstaller
if ($LASTEXITCODE -ne 0) { throw "Build dependency installation failed." }
& $Python -m PyInstaller packaging/cana.spec --noconfirm --distpath packaging/dist --workpath packaging/build
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

Write-Host "Built packaging/dist/CANA/CANA.exe"
Write-Host "Compile packaging/CANA.iss with Inno Setup to produce CANA-Setup.exe"
if ($ISCC) {
    & $ISCC packaging/CANA.iss
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }
}
