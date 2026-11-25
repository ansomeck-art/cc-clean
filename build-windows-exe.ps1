<#
.SYNOPSIS
  Build a portable single-file Windows executable: dist\RegionGuard.exe
  Target Windows PCs do NOT need Python installed to run RegionGuard.exe!
#>
$ErrorActionPreference = "Stop"
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Dir

# Locate Python 3.9+
$pyExe = $null
$pyPrefix = @()
foreach ($pair in @(@("py", @("-3")), @("python", @()), @("python3", @()))) {
    try {
        if (-not (Get-Command $pair[0] -ErrorAction SilentlyContinue)) { continue }
        & $pair[0] @($pair[1] + @("-c", "import sys; assert sys.version_info >= (3, 9)")) 2>$null
        if ($LASTEXITCODE -eq 0) {
            $pyExe = $pair[0]
            $pyPrefix = $pair[1]
            break
        }
    } catch {}
}

if (-not $pyExe) {
    Write-Error "Python 3.9+ not found. Please install Python 3 first."
    exit 1
}

Write-Host "[1/3] Checking PyInstaller..." -ForegroundColor Cyan
& $pyExe @($pyPrefix + @("-m", "PyInstaller", "--version")) 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller not installed. Installing via pip..." -ForegroundColor Yellow
    & $pyExe @($pyPrefix + @("-m", "pip", "install", "--upgrade", "pyinstaller"))
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install PyInstaller. Check your network or run: py -3 -m pip install pyinstaller"
        exit 1
    }
}

Write-Host "[2/3] Building portable single-file RegionGuard.exe..." -ForegroundColor Cyan
& $pyExe @($pyPrefix + @("-m", "PyInstaller", "--clean", "--noconfirm", "RegionGuard.spec"))
if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller build failed."
    exit 1
}

$exePath = Join-Path $Dir "dist\RegionGuard.exe"
if (Test-Path $exePath) {
    $szMb = [math]::Round((Get-Item $exePath).Length / 1MB, 2)
    Write-Host "[3/3] Build succeeded! Output: $exePath ($szMb MB)" -ForegroundColor Green
    Write-Host "Tip: Copy RegionGuard.exe to any Windows 10/11 PC and run: RegionGuard.exe --open" -ForegroundColor Cyan
} else {
    Write-Error "Expected output not found at $exePath"
    exit 1
}
