$old = "C:\Users\Manoj\OneDrive\Desktop\ZeroTrace\backend\.env"
$new = Join-Path $PSScriptRoot "backend\.env"
if (-not (Test-Path -LiteralPath $old)) {
  Write-Host "Old .env not found:" -ForegroundColor Yellow
  Write-Host $old
  exit 1
}
Copy-Item -LiteralPath $old -Destination $new -Force
Write-Host "Existing Zero Trace .env copied without changing its values." -ForegroundColor Green
