# Multi-Tier Verification Script for SOC/DFIR & CTF Unified Workspace Platform
$ErrorActionPreference = "Stop"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "1. Running Rust IPC Protocol Unit Tests..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
cargo test -p ipc-protocol
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "2. Running SQLite Storage Integration Tests..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
cargo test --test ctf_storage_test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "3. Running Engine Server E2E Lifecycle Tests..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
cargo test -p engine-server --test ctf_e2e_integration_test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "4. Running Desktop UI Syntax and E2E Tests..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
npm test --prefix apps/desktop-ui
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host ">>> ALL MULTI-TIER TESTS PASSED SUCCESSFULLY! <<<" -ForegroundColor Green
