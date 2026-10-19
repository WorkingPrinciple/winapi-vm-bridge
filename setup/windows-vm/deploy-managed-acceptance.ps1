param(
    [string]$Root = 'C:\WvbAcceptance\canonical-runtime',
    [string]$RuntimeZip = 'C:\Users\Public\wvb-dotnet-runtime.zip',
    [string]$NethostPackage = 'C:\Users\Public\wvb-nethost.nupkg',
    [string]$PayloadZip = 'C:\Users\Public\wvb-managed-payload.zip',
    [string]$Manifest = 'C:\Users\Public\wvb-acceptance-package.json',
    [string]$ListenAddress = '192.168.64.4:47961',
    [string]$DeploymentId = 'manual'
)

$ErrorActionPreference = 'Stop'
trap {
    ($_ | Out-String) |
        Set-Content -Encoding UTF8 'C:\Users\Public\wvb-deploy-error.txt'
    exit 1
}
Remove-Item 'C:\Users\Public\wvb-deploy-error.txt' -Force -ErrorAction SilentlyContinue
$donePath = Join-Path $Root ("deploy-{0}.done" -f $DeploymentId)
Remove-Item $donePath -Force -ErrorAction SilentlyContinue

if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    throw "acceptance manifest is missing: $Manifest"
}
$document = Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
if ($document.schema -ne 'wvb.windows-vm-scalar-package.v1' -or
    $document.managed.profile -ne 'managed-scalar') {
    throw 'invalid managed acceptance manifest'
}
$managed = $document.managed

function Require-Hash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "hash mismatch: $Path expected=$Expected actual=$actual"
    }
}

function Require-Entry([string]$Key) {
    $entry = @($managed.files | Where-Object { $_.key -eq $Key })
    if ($entry.Count -ne 1) {
        throw "missing or duplicate managed manifest entry: $Key"
    }
    return $entry[0]
}

Require-Hash $RuntimeZip $managed.runtimePackageSha256
Require-Hash $NethostPackage $managed.nethostPackageSha256
Require-Hash $PayloadZip $managed.payloadZipSha256

New-Item -ItemType Directory -Force -Path $Root | Out-Null
$runtime = Join-Path $Root 'runtime'
$payload = Join-Path $Root 'payload'
$priorBroker = Join-Path $payload 'wvb-managed-e2e.exe'
$stoppedPids = @()
Get-CimInstance Win32_Process |
    Where-Object { $_.ExecutablePath -eq $priorBroker } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force
        $stoppedPids += $_.ProcessId
    }
Remove-Item -Recurse -Force $runtime, $payload -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path `
    (Join-Path $runtime 'dotnet'), (Join-Path $runtime 'host'), $payload | Out-Null

Expand-Archive -LiteralPath $RuntimeZip -DestinationPath (Join-Path $runtime 'dotnet') -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
$nethostExpanded = Join-Path $runtime 'nethost-package'
[System.IO.Compression.ZipFile]::ExtractToDirectory($NethostPackage, $nethostExpanded)
Copy-Item `
    (Join-Path $nethostExpanded 'runtimes\win-x64\native\nethost.dll') `
    (Join-Path $runtime 'host\nethost.dll') -Force
Copy-Item `
    (Join-Path $nethostExpanded 'LICENSE.TXT') `
    (Join-Path $runtime 'host\LICENSE.TXT') -Force
Expand-Archive -LiteralPath $PayloadZip -DestinationPath $payload -Force

$entries = [ordered]@{
    Broker = Require-Entry 'Broker'
    NativeHost = Require-Entry 'NativeHost'
    Dispatcher = Require-Entry 'Dispatcher'
    RuntimeConfig = Require-Entry 'RuntimeConfig'
    Target = Require-Entry 'Target'
    Contract = Require-Entry 'Contract'
}
$files = [ordered]@{
    HostFxr = [ordered]@{
        Path = Join-Path $runtime 'dotnet\host\fxr\8.0.32\hostfxr.dll'
        Hash = $managed.hostfxrSha256
    }
    NetHost = [ordered]@{
        Path = Join-Path $runtime 'host\nethost.dll'
        Hash = $managed.nethostSha256
    }
}
foreach ($key in $entries.Keys) {
    $files[$key] = [ordered]@{
        Path = Join-Path $payload ([string]$entries[$key].relativePath)
        Hash = [string]$entries[$key].sha256
    }
}
foreach ($entry in $files.Values) {
    Require-Hash $entry.Path $entry.Hash
}

$config = [ordered]@{
    address = $ListenAddress
    adapterHash = [string]$managed.contractSha256
    hostDll = $files.NativeHost.Path
    hostDllSha256 = $files.NativeHost.Hash
    dotnetRoot = Join-Path $runtime 'dotnet'
    nethostPath = $files.NetHost.Path
    nethostSha256 = $files.NetHost.Hash
    hostfxrSha256 = $files.HostFxr.Hash
    runtimeConfigPath = $files.RuntimeConfig.Path
    runtimeConfigSha256 = $files.RuntimeConfig.Hash
    dispatcherAssemblyPath = $files.Dispatcher.Path
    dispatcherAssemblySha256 = $files.Dispatcher.Hash
    targetAssemblyPath = $files.Target.Path
    targetAssemblySha256 = $files.Target.Hash
}
$configPath = Join-Path $Root 'e2e-config.json'
$configJson = $config | ConvertTo-Json
[IO.File]::WriteAllBytes(
    $configPath,
    [Text.Encoding]::UTF8.GetBytes($configJson)
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

$rule = 'WvbAcceptance-canonical-runtime'
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
