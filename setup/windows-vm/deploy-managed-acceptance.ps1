param(
    [string]$Root = 'C:\WvbAcceptance\canonical-runtime',
    [string]$RuntimeZip = 'C:\Users\Public\wvb-dotnet-runtime.zip',
    [string]$NethostPackage = 'C:\Users\Public\wvb-nethost.nupkg',
    [string]$PayloadZip = 'C:\Users\Public\wvb-managed-payload.zip',
    [string]$ListenAddress = '192.168.64.3:47961',
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

$pins = [ordered]@{
    RuntimePackage = '0132501a735fc584adff29d28084150083f6ba320f5ae52beb7c49f52ba793f7'
    NethostPackage = '32d48bdbce29ec3c57917ca2aae2aa5fc71302702780c099b9f122842bccd789'
    PayloadPackage = '1d8924284a811f1045f1253226799956d3a3fcc1c6899de579c78aa3bb99f80d'
    HostFxr = 'd579c8d05dd7456be1551ab0cc3a86bd298b5cd5675936332cc4c8e56e59984d'
    NetHost = 'b7ebee5df9d8e27aca714db5be487aba5f00a24687e2e920b385444ae4f085d0'
    Broker = 'aa8d3ae816dd2bb70d85bf487696c851d91ea68d7d84787bae3bcd45d8852ef3'
    NativeHost = '2f8b176b05dad63c5a7488a3f6a4c17ce81eedab9d449c1a3734bcf8bcc7aa60'
    Dispatcher = '489a2d3f4a4331fcd6befb372b19130c7483e7add66e71a85bef2808f15a66f7'
    RuntimeConfig = 'ca8666237d92cc378ef2cf0e34c09ec9f64ce3ed0b0e82d3333b83594da4cab0'
    Target = '49df01adbcd5d578cc950bd7daf448eba6cebe3741eb0b0ffc874e6d64b46be6'
    Contract = '8f91443299fb2e54e13d129ceea7bd864e9e82259721d854753421e516e303d8'
}

function Require-Hash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "hash mismatch: $Path expected=$Expected actual=$actual"
    }
}

Require-Hash $RuntimeZip $pins.RuntimePackage
Require-Hash $NethostPackage $pins.NethostPackage
Require-Hash $PayloadZip $pins.PayloadPackage

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

$files = [ordered]@{
    HostFxr = @{
        Path = Join-Path $runtime 'dotnet\host\fxr\8.0.32\hostfxr.dll'
        Hash = $pins.HostFxr
    }
    NetHost = @{
        Path = Join-Path $runtime 'host\nethost.dll'
        Hash = $pins.NetHost
    }
    Broker = @{
        Path = Join-Path $payload 'wvb-managed-e2e.exe'
        Hash = $pins.Broker
    }
    NativeHost = @{
        Path = Join-Path $payload 'wvb_managed_host.dll'
        Hash = $pins.NativeHost
    }
    Dispatcher = @{
        Path = Join-Path $payload 'Example.ManagedMath.WvbDispatcher.dll'
        Hash = $pins.Dispatcher
    }
    RuntimeConfig = @{
        Path = Join-Path $payload 'Example.ManagedMath.WvbDispatcher.runtimeconfig.json'
        Hash = $pins.RuntimeConfig
    }
    Target = @{
        Path = Join-Path $payload 'Example.ManagedMath.dll'
        Hash = $pins.Target
    }
    Contract = @{
        Path = Join-Path $payload 'contract.canonical.json'
        Hash = $pins.Contract
    }
}
foreach ($entry in $files.Values) {
    Require-Hash $entry.Path $entry.Hash
}

$config = [ordered]@{
    address = $ListenAddress
    adapterHash = $files.Contract.Hash
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
