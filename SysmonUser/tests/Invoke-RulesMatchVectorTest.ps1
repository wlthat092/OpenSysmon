param()

$ErrorActionPreference = "Stop"

function Initialize-VsBuildEnvironment {
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
        return
    }

    $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswherePath)) {
        throw "vswhere.exe not found."
    }

    $vsInstallPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if (-not $vsInstallPath) {
        throw "Visual Studio C++ tools not found."
    }

    $vcvarsall = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvarsall.bat"
    if (-not (Test-Path $vcvarsall)) {
        throw "vcvarsall.bat not found."
    }

    $envOutput = & cmd /c "`"$vcvarsall`" x64 >nul 2>&1 && set"
    foreach ($line in $envOutput) {
        if ($line -match '^([^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path $scriptDir -Parent
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sysmon-rules-tests-" + [Guid]::NewGuid().ToString("N"))
$testSource = Join-Path $scriptDir "rules_match_vectors.cpp"
$objectDir = Join-Path $tempRoot "obj"
$outputExe = Join-Path $tempRoot "rules_match_vectors.exe"

$includeArgs = @("/I", (Join-Path $projectDir "include"))
$linkArgs = @("kernel32.lib", "user32.lib", "advapi32.lib")

Initialize-VsBuildEnvironment
try {
    New-Item -ItemType Directory -Path $objectDir -Force | Out-Null

    $compileArgs = @(
        "/nologo",
        "/EHsc",
        "/std:c++17",
        "/W3",
        "/MD",
        "/DUNICODE",
        "/D_UNICODE",
        "/Fe:$outputExe",
        "/Fo$objectDir\"
    )

    & cl.exe @compileArgs @includeArgs $testSource @linkArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cl.exe failed with exit code $LASTEXITCODE"
    }

    & $outputExe
    if ($LASTEXITCODE -ne 0) {
        throw "rules_match_vectors.exe failed with exit code $LASTEXITCODE"
    }
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Host "OK: rules match vector tests passed" -ForegroundColor Green
