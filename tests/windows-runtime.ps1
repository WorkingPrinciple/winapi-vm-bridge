$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $repo
try {
    cargo test --workspace --all-features --locked
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows runtime workspace tests failed.'
    }
    $pins = @{
        'external\whiny\v0.3.0\frozen-bundles\native-scalar\bundle.json' =
            '67330e6444fdb8876d8c162692b544a891cc47d15d8140c3bd92f0ab6e51d828'
        'external\whiny\v0.3.0\frozen-bundles\managed-scalar\bundle.json' =
            '0086d567312afc118e0e4b31dad37ac108af7428c0b718bf329b6115ed773678'
    }
    foreach ($entry in $pins.GetEnumerator()) {
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $entry.Key).Hash.ToLowerInvariant()
        if ($actual -ne $entry.Value) {
            throw "Whiny bundle hash mismatch: $($entry.Key)"
        }
    }
    $bootstrap = Get-Content -Raw setup\wvb-bootstrap-windows.ps1
    [void][scriptblock]::Create($bootstrap)
    if ($bootstrap -notmatch 'Copy-Item -LiteralPath \$cli -Destination \$installedCli' -or
        $bootstrap -notmatch "'deactivate'") {
        throw 'Windows bootstrap is missing durable lifecycle CLI uninstall support.'
    }
    Write-Output 'windows-runtime=ok frozen-bundles=pinned'
} finally {
    Pop-Location
}
