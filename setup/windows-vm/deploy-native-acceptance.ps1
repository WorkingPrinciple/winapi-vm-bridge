param(
    [string]$Root = 'C:\WvbAcceptance\native-scalar',
    [string]$PayloadZip = 'C:\Users\Public\wvb-native-payload.zip',
    [string]$Manifest = 'C:\Users\Public\wvb-acceptance-package.json',
    [string]$ListenAddress = '192.168.64.4:47960',
    [string]$DeploymentId = 'manual'
)

$ErrorActionPreference = 'Stop'
trap {
    ($_ | Out-String) |
        Set-Content -Encoding UTF8 'C:\Users\Public\wvb-native-deploy-error.txt'
    exit 1
}
Remove-Item 'C:\Users\Public\wvb-native-deploy-error.txt' -Force -ErrorAction SilentlyContinue
$donePath = Join-Path $Root ("deploy-{0}.done" -f $DeploymentId)
Remove-Item $donePath -Force -ErrorAction SilentlyContinue

if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    throw "acceptance manifest is missing: $Manifest"
}
$document = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
if ($document.schema -ne 'wvb.windows-vm-scalar-package.v1' -or
    $document.native.profile -ne 'native-scalar') {
    throw 'invalid native acceptance manifest'
}
$native = $document.native

function Require-Hash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "hash mismatch: $Path expected=$Expected actual=$actual"
    }
}

function Require-Entry([string]$Key) {
    $entry = @($native.files | Where-Object { $_.key -eq $Key })
    if ($entry.Count -ne 1) {
        throw "missing or duplicate native manifest entry: $Key"
    }
    return $entry[0]
}

Require-Hash $PayloadZip $native.payloadZipSha256
New-Item -ItemType Directory -Force -Path $Root | Out-Null
$payload = Join-Path $Root 'payload'
$priorBroker = Join-Path $payload 'wvb-native-e2e.exe'
$stoppedPids = @()
Get-CimInstance Win32_Process |
    Where-Object { $_.ExecutablePath -eq $priorBroker } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force
        $stoppedPids += $_.ProcessId
    }
Remove-Item -Recurse -Force $payload -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $payload | Out-Null
Expand-Archive -LiteralPath $PayloadZip -DestinationPath $payload -Force

$files = [ordered]@{}
foreach ($key in @('Broker', 'Dispatcher', 'Target', 'Contract')) {
    $entry = Require-Entry $key
    $files[$key] = [ordered]@{
        Path = Join-Path $payload ([string]$entry.relativePath)
        Hash = [string]$entry.sha256
    }
}
foreach ($entry in $files.Values) {
    Require-Hash $entry.Path $entry.Hash
}

$config = [ordered]@{
    address = $ListenAddress
    adapterHash = [string]$native.contractSha256
    dispatcherPath = $files.Dispatcher.Path
    dispatcherSha256 = $files.Dispatcher.Hash
}
$configPath = Join-Path $Root 'e2e-config.json'
[IO.File]::WriteAllBytes(
    $configPath,
    [Text.Encoding]::UTF8.GetBytes(($config | ConvertTo-Json))
)
$runner = @"
@echo off
"$($files.Broker.Path)" server "$configPath" > "$Root\server.log" 2>&1
echo %ERRORLEVEL% > "$Root\server.exit"
"@
[IO.File]::WriteAllText(
    (Join-Path $Root 'run-server.cmd'),
    $runner,
    [Text.Encoding]::ASCII
)

$rule = 'WvbAcceptance-native-scalar'
Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
New-NetFirewallRule `
    -DisplayName $rule `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort ([int]($ListenAddress.Split(':')[-1])) `
    -Program $files.Broker.Path `
    -Profile Any | Out-Null

$identity = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    User = $env:USERNAME
    Os = [System.Environment]::OSVersion.VersionString
    Arch = $env:PROCESSOR_ARCHITECTURE
    IpAddresses = @(
        Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -ne '127.0.0.1' } |
            Select-Object -ExpandProperty IPAddress
    )
    Utc = (Get-Date).ToUniversalTime().ToString('o')
    Root = $Root
    FirewallRule = $rule
    DeploymentId = $DeploymentId
    StoppedPriorBrokerPids = $stoppedPids
    Files = $files
}
$identity | ConvertTo-Json -Depth 6 |
    Set-Content -Encoding UTF8 (Join-Path $Root 'deployment.json')
[IO.File]::WriteAllText(
    $donePath,
    'PASS',
    [Text.Encoding]::ASCII
)
