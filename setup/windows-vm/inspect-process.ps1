param(
    [Parameter(Mandatory = $true)]
    [int]$TargetPid,
    [string]$Output = 'C:\Users\Public\wvb-process.json'
)

$process = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid"
$json = if ($null -eq $process) {
    @{ ProcessId = $TargetPid; State = 'not-found' } | ConvertTo-Json
}
else {
    $process |
        Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate |
        ConvertTo-Json
}
[IO.File]::WriteAllBytes(
    $Output,
    [Text.Encoding]::UTF8.GetBytes($json)
)
