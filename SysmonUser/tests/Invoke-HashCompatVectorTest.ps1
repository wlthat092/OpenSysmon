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

function Invoke-HashCompatTestBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Sources,

        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [string[]]$IncludeArgs,

        [Parameter(Mandatory = $true)]
        [string[]]$LinkArgs
    )

    $testOutputDir = Join-Path $OutputRoot $Name
    $objectDir = Join-Path $testOutputDir "obj"
    $outputExe = Join-Path $testOutputDir "$Name.exe"
    $pdbPath = Join-Path $testOutputDir "$Name.pdb"
    $compileArgs = @(
        "/nologo",
        "/EHsc",
        "/std:c++17",
        "/W3",
        "/MD",
        "/DUNICODE",
        "/D_UNICODE",
        "/Fe:$outputExe",
        "/Fo$objectDir\",
        "/Fd$pdbPath"
    )

    New-Item -ItemType Directory -Path $objectDir -Force | Out-Null

    & cl.exe @compileArgs @IncludeArgs @Sources @LinkArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cl.exe failed for $Name with exit code $LASTEXITCODE"
    }

    & $outputExe
    if ($LASTEXITCODE -ne 0) {
        throw "$Name.exe failed with exit code $LASTEXITCODE"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path $scriptDir -Parent
$repoRoot = Split-Path $projectDir -Parent
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sysmon-hash-tests-" + [Guid]::NewGuid().ToString("N"))
$symCryptIncludeDir = Join-Path $repoRoot "third_party\SymCrypt\inc"
$symCryptLibDir = Join-Path $repoRoot "third_party\SymCrypt\build\bin\amd64fre\lib"
$hashCompatSource = Join-Path $projectDir "src\hash_compat.cpp"
$legacyBackendSource = Join-Path $projectDir "src\symcrypt_backend.cpp"
$vectorTestSource = Join-Path $scriptDir "hash_compat_vectors.cpp"
$incrementalTestSource = Join-Path $scriptDir "hash_compat_incremental_vectors.cpp"
$includeArgs = @(
    "/I", (Join-Path $projectDir "include")
)
$linkArgs = @(
    "kernel32.lib",
    "user32.lib",
    "bcrypt.lib"
)

if (Test-Path $legacyBackendSource) {
    throw "symcrypt_backend.cpp should be merged into hash_compat.cpp"
}

if (Test-Path $symCryptIncludeDir) {
    $includeArgs += @("/I", $symCryptIncludeDir)
}

if (Test-Path (Join-Path $symCryptLibDir "symcrypt_static.lib")) {
    $linkArgs += @("/link", "/LTCG", "/LIBPATH:$symCryptLibDir", "symcrypt_static.lib")
}

Initialize-VsBuildEnvironment
try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    Invoke-HashCompatTestBuild `
        -Name "hash_compat_vectors" `
        -Sources @($vectorTestSource, $hashCompatSource) `
        -OutputRoot $tempRoot `
        -IncludeArgs $includeArgs `
        -LinkArgs $linkArgs

    Invoke-HashCompatTestBuild `
        -Name "hash_compat_incremental_vectors" `
        -Sources @($incrementalTestSource) `
        -OutputRoot $tempRoot `
        -IncludeArgs $includeArgs `
        -LinkArgs $linkArgs
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Host "OK: hash vector tests passed" -ForegroundColor Green
