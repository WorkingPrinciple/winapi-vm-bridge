$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
$capability = Join-Path $env:TEMP 'winapi-vm-bridge-ci-capability'
Set-Content -NoNewline -Path $capability -Value ('a' * 64)
$env:PYTHONPATH = $repo
$server = Start-Process py -ArgumentList @(
    '-3', '-m', 'winapi_vm_bridge.server',
    '--host', '127.0.0.1',
    '--port', '47891',
    '--capability-file', $capability
) -WorkingDirectory $repo -PassThru -WindowStyle Hidden
try {
    Start-Sleep -Seconds 2
    $script = @'
from winapi_vm_bridge.client import call
r = call("127.0.0.1", 47891, "a" * 64, "windows.kernel32", "GetTickCount64", {})
assert r["ok"] is True
assert r["resultType"] == "u64"
assert isinstance(r["result"], int) and r["result"] > 0
print("real kernel32.dll GetTickCount64 round trip passed")
'@
    $script | py -3 -
    if ($LASTEXITCODE -ne 0) { throw "Windows round-trip test failed" }
}
finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Remove-Item $capability -Force -ErrorAction SilentlyContinue
}
