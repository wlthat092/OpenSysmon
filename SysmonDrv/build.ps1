param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$Release,
    [switch]$Rebuild,
    [switch]$Clean,
    [string]$SdkRoot = "C:\Program Files (x86)\Windows Kits\10",
    [string]$WdkRoot = "C:\Program Files (x86)\Windows Kits\10"
)

$ErrorActionPreference = "Continue"

# Kernel-mode (WDK) headers/libs and shared/ucrt (SDK) headers. Both default to
# the standard Windows Kits layout; CI or non-standard installs can override via
# -SdkRoot / -WdkRoot.
$sdkInclude = Join-Path $SdkRoot "Include\10.0.26100.0"
$wdkInclude = Join-Path $WdkRoot "Include\10.0.26100.0"
$wdkLib = Join-Path $WdkRoot "Lib\10.0.26100.0\km\x64"
$ucrtInc = Join-Path $sdkInclude "ucrt"

# Resolve the MSVC toolset via vswhere so the build is not tied to a single VS
# install layout; fall back to the canonical VS2022 Professional path when
# vswhere is unavailable.
$msvcToolsRoot = $null
$vswhereExe = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhereExe) {
    $vsInstallPath = & $vswhereExe -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsInstallPath) {
        $vsInstallPath = $vsInstallPath.Trim()
        $candidateRoot = Join-Path $vsInstallPath "VC\Tools\MSVC"
        if (Test-Path $candidateRoot) {
            $msvcToolsRoot = $candidateRoot
        }
    }
}
if (-not $msvcToolsRoot) {
    $msvcToolsRoot = "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC"
}
$msvcVersion = Get-ChildItem $msvcToolsRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name
if (-not $msvcVersion) {
    Write-Host "MSVC toolset not found under $msvcToolsRoot" -ForegroundColor Red
    exit 1
}
$msvcInc = Join-Path $msvcToolsRoot "$msvcVersion\include"
$msvcBin = Join-Path $msvcToolsRoot "$msvcVersion\bin\Hostx64\x64"
$clExe = Join-Path $msvcBin "CL.exe"
$linkExe = Join-Path $msvcBin "link.exe"

$srcDir = Join-Path $PSScriptRoot "src"
$symCryptRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "third_party\SymCrypt"
$symCryptInc = Join-Path $symCryptRoot "inc"
$symCryptLib = Join-Path $symCryptRoot "build\bin\amd64fre\lib\symcrypt_static.lib"
if ($Release -and -not $PSBoundParameters.ContainsKey('Configuration')) {
    $Configuration = 'Release'
}

$objDir = Join-Path $PSScriptRoot ("x64\{0}" -f $Configuration)
$outDir = $objDir

if ($Clean) {
    Remove-Item (Join-Path $PSScriptRoot "x64") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Cleaned." -ForegroundColor Green
    exit 0
}

if ($Rebuild) {
    Remove-Item (Join-Path $PSScriptRoot "x64") -Recurse -Force -ErrorAction SilentlyContinue
}

New-Item -Path $objDir -ItemType Directory -Force | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath 2>$null
    if ($vsPath) {
        $msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
    }
}

if (-not (Test-Path $msbuild)) {
    Write-Host "MSBuild not found. Please install Visual Studio 2022 Build Tools." -ForegroundColor Red
    exit 1
}

$srcFiles = @(
    "driver.c","minifilter.c","process.c","thread.c","image.c",
    "registry.c","communication.c","event.c","queue.c","hash.c",
    "fileinfo.c","processinfo.c","utils.c","registry_data.c","rules.c","obcallback.c","tampering.c",
    "network.c","pipe.c","wmi.c","dns.c","clipboard.c"
)

$incDirs = "/I`"$PSScriptRoot\include`" /I`"$symCryptInc`" /I`"$wdkInclude\km`" /I`"$sdkInclude\shared`" /I`"$msvcInc`" /I`"$ucrtInc`""
$commonDefines = "/D _KERNEL_MODE /D NTDDI_VERSION=0x0A000000 /D _AMD64_ /D AMD64 /D _WIN64 /D POOL_NX_OPTIN=1"
if ($Configuration -eq 'Release') {
    $defines = "$commonDefines /D NDEBUG"
    $compFlags = "/c /nologo /O2 /Ob2 /Oi /Ot /W3 /GS $defines /Gd /TC /EHsc"
} else {
    $defines = "$commonDefines /D DBG=1"
    $compFlags = "/c /nologo /Od /W3 /GS $defines /Gd /TC /EHsc"
}

$failed = $false
foreach ($src in $srcFiles) {
    $srcPath = Join-Path $srcDir $src
    $objName = [System.IO.Path]::GetFileNameWithoutExtension($src) + ".obj"
    $objPath = Join-Path $objDir $objName

    $cmdLine = "`"$clExe`" $compFlags /Fo`"$objPath`" $incDirs `"$srcPath`""
    $output = cmd /c $cmdLine 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $src" -ForegroundColor Red
        $output | ForEach-Object { Write-Host "  $_" }
        $failed = $true
    } else {
        Write-Host "OK: $src" -ForegroundColor Green
    }
}

if ($failed) {
    Write-Host "`nCompilation failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`nLinking..." -ForegroundColor Cyan

$objFiles = (Get-ChildItem $objDir -Filter "*.obj" | ForEach-Object { "`"$($_.FullName)`"" }) -join " "

$linkCmd = "`"$linkExe`" /OUT:`"$outDir\SysmonDrv.sys`" /INCREMENTAL:NO /NOLOGO /NXCOMPAT /DYNAMICBASE /INTEGRITYCHECK /NODEFAULTLIB /ENTRY:GsDriverEntry /SUBSYSTEM:NATIVE /DRIVER /MACHINE:X64 /OPT:REF /OPT:ICF $objFiles /LIBPATH:`"$wdkLib`" ntoskrnl.lib hal.lib wmilib.lib fltMgr.lib BufferOverflowK.lib cng.lib wdmsec.lib `"$symCryptLib`""

$output = cmd /c $linkCmd 2>&1
$output | ForEach-Object { Write-Host "  $_" }

if ($LASTEXITCODE -eq 0) {
    $sysFile = Get-Item "$outDir\SysmonDrv.sys"
    Write-Host "`nBUILD SUCCESSFUL: $($sysFile.FullName) ($($sysFile.Length) bytes)" -ForegroundColor Green
} else {
    Write-Host "`nLink FAILED!" -ForegroundColor Red
    exit 1
}
