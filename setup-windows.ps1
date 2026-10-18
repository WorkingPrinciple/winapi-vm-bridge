$ErrorActionPreference = 'Stop'
$repo = Join-Path $env:LOCALAPPDATA 'WinApiVmBridge'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is required. Install Git for Windows, then rerun this command.'
}
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python 3 is required. Install it from python.org or winget, then rerun.'
}
if (Test-Path (Join-Path $repo '.git')) {
    git -C $repo fetch --quiet origin main
    git -C $repo reset --hard origin/main
} else {
    git clone --depth 1 https://github.com/dragoshont/winapi-vm-bridge.git $repo
}
& (Join-Path $repo 'windows\doctor.ps1')
$state = Join-Path $env:LOCALAPPDATA 'WinApiVmBridge'
$capability = Join-Path $state 'capability'
New-Item -ItemType Directory -Force -Path $state | Out-Null
if (-not (Test-Path $capability)) {
    $value = & py -3 -c "import secrets; print(secrets.token_hex(32))"
    [IO.File]::WriteAllText($capability, $value)
}
$task = 'WinApiVmBridge'
$command = 'py'
$arguments = "-3 -m winapi_vm_bridge.server --port 47801 --capability-file `"$capability`""
$action = New-ScheduledTaskAction -Execute $command -Argument $arguments -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Force | Out-Null
Start-ScheduledTask -TaskName $task
Write-Output 'Windows broker ready on TCP 47801.'
Write-Output 'PAIRING CODE (paste into the Mac setup prompt):'
Write-Output ([IO.File]::ReadAllText($capability))
Write-Output 'The Xbox/GDK adapter additionally requires an authorized local GDK installation and title config.'
Write-Output ('Rollback: Remove-Item -Recurse -Force "' + $repo + '"')
