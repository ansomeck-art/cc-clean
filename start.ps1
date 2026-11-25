param(
    [int]$Port = 8765,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerPy = Join-Path $Dir "server.py"

function Find-Python39 {
    $candidates = @(
        @("py", @("-3")),
        @("python", @()),
        @("python3", @())
    )
    foreach ($pair in $candidates) {
        $exe = $pair[0]
        $prefix = $pair[1]
        try {
            $cmd = Get-Command $exe -ErrorAction SilentlyContinue
            if (-not $cmd) { continue }
            & $exe @($prefix + @("-c", "import sys; assert sys.version_info >= (3, 9)")) 2>$null
            if ($LASTEXITCODE -eq 0) {
                return @{ Exe = $exe; Prefix = $prefix }
            }
        } catch {}
    }

    $dirs = @()
    foreach ($pattern in @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python3*"),
        "C:\Program Files\Python3*",
        "C:\Python3*"
    )) {
        $dirs += Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue
    }
    foreach ($d in ($dirs | Sort-Object Name -Descending)) {
        $pyExe = Join-Path $d.FullName "python.exe"
        if (Test-Path $pyExe) {
            try {
                & $pyExe -c "import sys; assert sys.version_info >= (3, 9)" 2>$null
                if ($LASTEXITCODE -eq 0) {
                    return @{ Exe = $pyExe; Prefix = @() }
                }
            } catch {}
        }
    }
    return $null
}

$py = Find-Python39
if (-not $py) {
    Write-Error "Python 3.9+ not found. Please install Python 3 from https://www.python.org/downloads/"
    exit 1
}

Write-Host "Starting Region Guard on http://127.0.0.1:$Port ..." -ForegroundColor Cyan
$pyArgs = @($py.Prefix) + @($ServerPy, "--host", "127.0.0.1", "--port", "$Port")
if (-not $NoBrowser) {
    $pyArgs += "--open"
}
& $py.Exe @pyArgs
