$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitOperatingSystem) { throw '64-bit Windows is required' }
Write-Output ('windows=' + [Environment]::OSVersion.VersionString)
Write-Output 'coreMock=true'
Write-Output 'doctor=ok'

