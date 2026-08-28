# build.ps1 - SysmonUser build script
# Builds the SysmonUser project using MSBuild

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectFile = Join-Path $scriptDir "SysmonUser.vcxproj"
$resourcesDir = Join-Path $scriptDir "resources"
$manifestFile = Join-Path $resourcesDir "sysmon_provider.man"

function Find-WindowsKitMessageCompiler {
    $kitsBinDir = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (-not (Test-Path $kitsBinDir)) {
        return $null
    }

    $versionDirs = Get-ChildItem -Path $kitsBinDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending

    foreach ($versionDir in $versionDirs) {
        $candidate = Join-Path $versionDir.FullName "x64\mc.exe"
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    $fallback = Join-Path $kitsBinDir "x64\mc.exe"
    if (Test-Path $fallback) {
        return $fallback
    }

    return $null
}

# Find MSBuild (VS2022)
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath 2>$null
    if ($vsPath) {
        $msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
    }
}

if (-not (Test-Path $msbuild)) {
    # Try older path
    $msbuild = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (-not (Test-Path $msbuild)) {
        Write-Error "MSBuild not found. Please install Visual Studio 2022 Build Tools."
        exit 1
    }
}

if (-not (Test-Path $manifestFile)) {
    Write-Error "Manifest not found: $manifestFile"
    exit 1
}

$mc = Find-WindowsKitMessageCompiler
if (-not $mc) {
    Write-Error "mc.exe not found under Windows Kits 10. Install the Windows 10 SDK Message Compiler."
    exit 1
}

Write-Host "Generating message compiler artifacts..." -ForegroundColor Cyan
Write-Host "MC: $mc"
& $mc -h $resourcesDir -r $resourcesDir $manifestFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "mc.exe failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# Find MIDL compiler
$kitsBinDir = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
$versionDirs = Get-ChildItem -Path $kitsBinDir -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
    Sort-Object { [version]$_.Name } -Descending

$midl = $null
foreach ($versionDir in $versionDirs) {
    $candidate = Join-Path $versionDir.FullName "x64\midl.exe"
    if (Test-Path $candidate) {
        $midl = $candidate
        break
    }
}

if (-not $midl) {
    Write-Error "midl.exe not found under Windows Kits 10."
    exit 1
}

# Compile RPC IDL
$idlFile = Join-Path $scriptDir "SysmonClipboard.idl"
$buildDir = Join-Path $scriptDir "build"
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
}

Write-Host "Generating RPC stubs..." -ForegroundColor Cyan
Write-Host "MIDL: $midl"

# MIDL needs cl.exe in PATH. Set up VS environment if not already available.
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswherePath) {
        $vsInstallPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vsInstallPath) {
            $vcvarsall = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvarsall.bat"
            if (Test-Path $vcvarsall) {
                Write-Host "Setting up VS environment via vcvarsall.bat x64..."
                $envOutput = & cmd /c "`"$vcvarsall`" x64 >nul 2>&1 && set"
                foreach ($line in $envOutput) {
                    if ($line -match '^([^=]+)=(.*)$') {
                        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
                    }
                }
            }
        }
    }
}

& $midl /out $buildDir /h SysmonClipboard_h.h $idlFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "midl.exe failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Building SysmonUser ($Configuration|$Platform)..." -ForegroundColor Cyan
Write-Host "MSBuild: $msbuild"
Write-Host "Project: $projectFile"

# Build
& $msbuild $projectFile /p:Configuration=$Configuration /p:Platform=$Platform /t:Rebuild /m /v:minimal

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBUILD SUCCESSFUL" -ForegroundColor Green
    $outputDir = Join-Path $scriptDir "..\x64\$Configuration"
    Write-Host "Output: $outputDir\Sysmon.exe"
} else {
    Write-Host "`nBUILD FAILED" -ForegroundColor Red
    exit $LASTEXITCODE
}
