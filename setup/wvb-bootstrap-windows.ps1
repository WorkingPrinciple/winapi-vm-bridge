param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('setup', 'update', 'rollback', 'uninstall', 'doctor')]
    [string]$Operation,
    [Parameter(Position = 1)]
    [string]$PackageOrVersion,
    [string]$InstallRoot = "$env:ProgramData\WinApiVmBridge\runtime"
)

$ErrorActionPreference = 'Stop'

function Verify-Release([string]$Manifest) {
    if ($env:WVB_ALLOW_UNSIGNED -eq '1') {
        Write-Warning 'Unsigned development package explicitly allowed.'
        return
    }
    if (-not $env:WVB_SIGNATURE_VERIFIER) {
        throw 'WVB_SIGNATURE_VERIFIER is required for release packages.'
    }
    & $env:WVB_SIGNATURE_VERIFIER $Manifest
    if ($LASTEXITCODE -ne 0) {
        throw 'Release signature verification failed.'
    }
}

function Package-Cli([string]$PackageDirectory) {
    $cli = Join-Path $PackageDirectory 'bin\wvb-package.exe'
    if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
        throw "Package lifecycle binary is missing: $cli"
    }
    return $cli
}

switch ($Operation) {
    { $_ -in @('setup', 'update') } {
        if (-not $PackageOrVersion) {
            throw 'A package directory is required.'
        }
        $manifest = Join-Path $PackageOrVersion 'runtime-package.json'
        $payload = Join-Path $PackageOrVersion 'payload'
        Verify-Release $manifest
        $cli = Package-Cli $PackageOrVersion
        & $cli verify --source $payload --manifest $manifest
        & $cli stage --root $InstallRoot --source $payload --manifest $manifest
        $version = (Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json).package_version
        $runtime = Join-Path $InstallRoot "versions\$version\bin\wvb-runtime.exe"
        if (-not (Test-Path -LiteralPath $runtime -PathType Leaf)) {
            throw "Staged runtime is missing: $runtime"
        }
        $health = Join-Path $env:TEMP "wvb-health-$PID.txt"
        try {
            & $runtime doctor `
                --state (Join-Path $InstallRoot 'state.db') `
                --package-root (Join-Path $InstallRoot "versions\$version") `
                --receipt $health
            & $cli activate --root $InstallRoot --manifest $manifest --health-receipt $health
        } finally {
            Remove-Item -LiteralPath $health -Force -ErrorAction SilentlyContinue
        }
    }
    'rollback' {
        if (-not $PackageOrVersion) {
            throw 'A package directory containing wvb-package.exe is required.'
        }
        & (Package-Cli $PackageOrVersion) rollback --root $InstallRoot
    }
    'uninstall' {
        if (-not $PackageOrVersion) {
            throw 'A package version is required.'
        }
        $cli = $env:WVB_PACKAGE_CLI
        if (-not $cli) {
            $cli = Join-Path $InstallRoot 'bin\wvb-package.exe'
        }
        & $cli uninstall-preflight --root $InstallRoot --version $PackageOrVersion
        if ($env:WVB_CONFIRM_UNINSTALL -ne '1') {
            throw 'Set WVB_CONFIRM_UNINSTALL=1 after reviewing the preflight.'
        }
        & $cli uninstall --root $InstallRoot --version $PackageOrVersion
    }
    'doctor' {
        $active = Join-Path $InstallRoot 'active.jcs'
        if (-not (Test-Path -LiteralPath $active -PathType Leaf)) {
            throw 'Runtime is not active.'
        }
        $version = (Get-Content -Raw -LiteralPath $active | ConvertFrom-Json).package_version
        & (Join-Path $InstallRoot "versions\$version\bin\wvb-runtime.exe") doctor `
            --state (Join-Path $InstallRoot 'state.db') `
            --package-root (Join-Path $InstallRoot "versions\$version")
    }
}
