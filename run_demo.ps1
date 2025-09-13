# MCP Security Framework - PowerShell Demo Script

Write-Host "🚀 MCP Security Framework - PowerShell Demo" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""

Write-Host "Running framework demo..." -ForegroundColor Yellow
python demo_framework.py

Write-Host ""
Write-Host "Demo completed! Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
