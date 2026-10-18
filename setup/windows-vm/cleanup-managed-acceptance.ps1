param(
    [string]$Root = 'C:\WvbAcceptance\canonical-runtime'
)

$ErrorActionPreference = 'Stop'
$rule = 'WvbAcceptance-canonical-runtime'
$broker = Join-Path $Root 'payload\wvb-managed-e2e.exe'
$stoppedPids = @()
Get-CimInstance Win32_Process |
    Where-Object { $_.ExecutablePath -eq $broker } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force
        $stoppedPids += $_.ProcessId
    }
Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
if (Test-Path $Root) {
    Remove-Item -Recurse -Force $Root
}
Remove-Item `
    'C:\Users\Public\wvb-dotnet-runtime.zip', `
    'C:\Users\Public\wvb-nethost.nupkg', `
    'C:\Users\Public\wvb-managed-payload.zip', `
    'C:\Users\Public\wvb-deploy.ps1', `
    'C:\Users\Public\wvb-identity.ps1', `
    'C:\Users\Public\wvb-exec-test.txt' `
    -Force -ErrorAction SilentlyContinue
$receipt = [ordered]@{
    RootRemoved = -not (Test-Path $Root)
    FirewallRuleRemoved = $null -eq (
        Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    )
    StoppedPids = $stoppedPids
    Utc = (Get-Date).ToUniversalTime().ToString('o')
}
[IO.File]::WriteAllBytes(
    'C:\Users\Public\wvb-cleanup.json',
    [Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json))
)
