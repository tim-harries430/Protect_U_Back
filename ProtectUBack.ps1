$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$launcher = Join-Path $PSScriptRoot "project\protect_launcher.py"
if (-not (Test-Path -LiteralPath $launcher)) {
    $launcher = Join-Path $PSScriptRoot "protect_launcher.py"
}
python $launcher menu
