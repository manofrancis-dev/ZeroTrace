param(
  [string]$Old = (Join-Path $PSScriptRoot "backend\.env.old")
)

$new = Join-Path $PSScriptRoot "backend\.env"
if (-not (Test-Path -LiteralPath $Old)) {
  Write-Host "Old .env not found: $Old" -ForegroundColor Yellow
  Write-Host "Pass the old file path explicitly, e.g. .\USE_OLD_ENV.ps1 -Old 'C:\path\to\old\.env'"
  exit 1
}
Copy-Item -LiteralPath $Old -Destination $new -Force
Write-Host "Existing Zero Trace .env copied without changing its values." -ForegroundColor Green
