$ErrorActionPreference = 'Stop'
$repo = Join-Path $env:LOCALAPPDATA 'WinApiVmBridge'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'git is required. Install Git for Windows, then rerun this command.'
}
if (Test-Path (Join-Path $repo '.git')) {
    git -C $repo fetch --quiet origin main
    git -C $repo reset --hard origin/main
} else {
    git clone --depth 1 https://github.com/dragoshont/winapi-vm-bridge.git $repo
}
& (Join-Path $repo 'windows\doctor.ps1')
Write-Output 'Windows setup ready. Core mock mode is available.'
Write-Output 'The Xbox/GDK adapter additionally requires an authorized local GDK installation and title config.'
Write-Output ('Rollback: Remove-Item -Recurse -Force "' + $repo + '"')

