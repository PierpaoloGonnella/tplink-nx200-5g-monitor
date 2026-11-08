param([string]$Database = "nx200_prod.db")
$ErrorActionPreference = "Stop"
$dashboardPython = @(".venv-review", ".venv") | ForEach-Object { Join-Path $PSScriptRoot "$_\Scripts\python.exe" } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $dashboardPython) { throw "Ambiente mancante: consulta README.md per l'installazione." }
$env:NX200_DASHBOARD_DB = if ([IO.Path]::IsPathRooted($Database)) { $Database } else { Join-Path $PSScriptRoot $Database }
Push-Location $PSScriptRoot
try {
    Write-Host "Dashboard: http://localhost:8501 - lascia aperto questo terminale. Ctrl+C per chiudere."
    & $dashboardPython -m streamlit run (Join-Path $PSScriptRoot "nx200_dashboard.py") --server.port 8501
} finally { Pop-Location }
