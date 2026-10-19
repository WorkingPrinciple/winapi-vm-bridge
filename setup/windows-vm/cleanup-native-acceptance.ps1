param(
    [string]$Root = 'C:\WvbAcceptance\native-scalar'
)

$ErrorActionPreference = 'Stop'
$rule = 'WvbAcceptance-native-scalar'
$broker = Join-Path $Root 'payload\wvb-native-e2e.exe'
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
    'C:\Users\Public\wvb-native-payload.zip', `
    'C:\Users\Public\wvb-native-deploy.ps1', `
    'C:\Users\Public\wvb-native-deploy-error.txt' `
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
    'C:\Users\Public\wvb-native-cleanup.json',
    [Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json))
)
