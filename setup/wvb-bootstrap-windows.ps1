param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('setup', 'update', 'rollback', 'uninstall', 'doctor')]
    [string]$Operation,
    [Parameter(Position = 1)]
    [string]$PackageOrVersion,
    [string]$InstallRoot = "$env:ProgramData\WinApiVmBridge\runtime"
)

$ErrorActionPreference = 'Stop'

function Invoke-Native([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed: $FilePath exit=$LASTEXITCODE"
    }
}

function Verify-Release([string]$Manifest) {
    if ($env:WVB_ALLOW_UNSIGNED -eq '1') {
        Write-Warning 'Unsigned development package explicitly allowed.'
        return
    }
    if (-not $env:WVB_SIGNATURE_VERIFIER) {
        throw 'WVB_SIGNATURE_VERIFIER is required for release packages.'
    }
    Invoke-Native $env:WVB_SIGNATURE_VERIFIER @($Manifest)
}

function Package-Cli([string]$PackageDirectory) {
    $cli = Join-Path $PackageDirectory 'bin\wvb-package.exe'
    if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
        throw "Package lifecycle binary is missing: $cli"
    }
    return $cli
}

function Verify-Envelope([string]$PackageDirectory, [string]$Manifest) {
    $root = (Resolve-Path -LiteralPath $PackageDirectory).Path
    $document = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
    if ($document.schema -ne 'winapi-vm-bridge.release-envelope.v1') {
        throw 'Invalid release envelope.'
    }
    foreach ($entry in $document.files) {
        $relative = [string]$entry.path
        if ([IO.Path]::IsPathRooted($relative) -or
            $relative.Contains('\') -or
            $relative.Split('/') -contains '..' -or
            $relative.Split('/') -contains '.') {
            throw "Invalid release path: $relative"
        }
        $path = Join-Path $root ($relative.Replace('/', '\'))
        $resolved = (Resolve-Path -LiteralPath $path).Path
        if (-not $resolved.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Release path escaped: $relative"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved).Hash.ToLowerInvariant()
        if ($actual -ne $entry.sha256) {
            throw "Release hash mismatch: $relative"
        }
    }
}

switch ($Operation) {
    { $_ -in @('setup', 'update') } {
        if (-not $PackageOrVersion) {
            throw 'A package directory is required.'
        }
        $releaseManifest = Join-Path $PackageOrVersion 'release-manifest.json'
        $manifest = Join-Path $PackageOrVersion 'runtime-package.json'
        $payload = Join-Path $PackageOrVersion 'payload'
        Verify-Release $releaseManifest
        Verify-Envelope $PackageOrVersion $releaseManifest
        $cli = Package-Cli $PackageOrVersion
        $installedCli = Join-Path $InstallRoot 'bin\wvb-package.exe'
        New-Item -ItemType Directory -Force (Split-Path $installedCli) | Out-Null
        Copy-Item -LiteralPath $cli -Destination $installedCli -Force
        Invoke-Native $cli @('verify', '--source', $payload, '--manifest', $manifest)
        Invoke-Native $cli @(
            'stage', '--root', $InstallRoot, '--source', $payload, '--manifest', $manifest
        )
        $version = (Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json).package_version
        $runtime = Join-Path $InstallRoot "versions\$version\bin\wvb-runtime.exe"
        if (-not (Test-Path -LiteralPath $runtime -PathType Leaf)) {
            throw "Staged runtime is missing: $runtime"
        }
        $health = Join-Path $env:TEMP "wvb-health-$PID.txt"
        try {
            Invoke-Native $runtime @(
                'init-state', '--state', (Join-Path $InstallRoot 'state.db')
            )
            Invoke-Native $runtime @(
                'doctor',
                '--state', (Join-Path $InstallRoot 'state.db'),
                '--package-root', (Join-Path $InstallRoot "versions\$version"),
                '--receipt', $health
            )
            Invoke-Native $cli @(
                'activate', '--root', $InstallRoot, '--manifest', $manifest,
                '--health-receipt', $health
            )
        } finally {
            Remove-Item -LiteralPath $health -Force -ErrorAction SilentlyContinue
        }
    }
    'rollback' {
        if (-not $PackageOrVersion) {
            throw 'A package directory containing wvb-package.exe is required.'
        }
        Invoke-Native (Package-Cli $PackageOrVersion) @('rollback', '--root', $InstallRoot)
    }
    'uninstall' {
        if (-not $PackageOrVersion) {
            throw 'A package version is required.'
        }
        $cli = $env:WVB_PACKAGE_CLI
        if (-not $cli) {
            $cli = Join-Path $InstallRoot 'bin\wvb-package.exe'
        }
        Invoke-Native $cli @(
            'uninstall-preflight', '--root', $InstallRoot, '--version', $PackageOrVersion
        )
        if ($env:WVB_CONFIRM_UNINSTALL -ne '1') {
            throw 'Set WVB_CONFIRM_UNINSTALL=1 after reviewing the preflight.'
        }
        Invoke-Native $cli @(
            'deactivate', '--root', $InstallRoot, '--version', $PackageOrVersion
        )
        Invoke-Native $cli @(
            'uninstall', '--root', $InstallRoot, '--version', $PackageOrVersion
        )
    }
    'doctor' {
        $active = Join-Path $InstallRoot 'active.jcs'
        if (-not (Test-Path -LiteralPath $active -PathType Leaf)) {
            throw 'Runtime is not active.'
        }
        $version = (Get-Content -Raw -LiteralPath $active | ConvertFrom-Json).package_version
        Invoke-Native (Join-Path $InstallRoot "versions\$version\bin\wvb-runtime.exe") @(
            'doctor',
            '--state', (Join-Path $InstallRoot 'state.db'),
            '--package-root', (Join-Path $InstallRoot "versions\$version")
        )
    }
}
