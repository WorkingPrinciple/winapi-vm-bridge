param(
    [Parameter(Mandatory=$true)][string]$Stage,
    [switch]$Worker
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# WTS state, not a guessed console username or the service's session-0 identity.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class WvbObserverSession {
    [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool WTSQuerySessionInformationW(IntPtr server, int session,
        int info, out IntPtr buffer, out int count);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr buffer);
    static IntPtr Query(int info) {
        IntPtr p; int count;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, 1, info, out p, out count))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return p;
    }
    public static string Text(int info) {
        IntPtr p=Query(info);
        try { return Marshal.PtrToStringUni(p); } finally { WTSFreeMemory(p); }
    }
    public static bool Active() {
        IntPtr p=Query(8);
        try { return Marshal.ReadInt32(p)==0; } finally { WTSFreeMemory(p); }
    }
}
'@

function Get-SessionOneSid {
    if (-not [WvbObserverSession]::Active()) {
        throw 'Session 1 is not active; human console sign-in required. No task started.'
    }
    $user = [WvbObserverSession]::Text(5)
    $domain = [WvbObserverSession]::Text(7)
    if ([string]::IsNullOrWhiteSpace($user)) {
        throw 'No interactive session-1 user; human console sign-in required.'
    }
    $account = New-Object System.Security.Principal.NTAccount($domain, $user)
    return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Test-MutationRights {
    param([System.Security.AccessControl.FileSystemRights]$Rights)
    $write = [System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        [System.Security.AccessControl.FileSystemRights]::Delete
    return ($Rights -band $write) -ne 0
}

function Assert-PrivateRoot([string]$Path) {
    $allowed = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-18', 'S-1-5-32-544'
    )
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and
            (Test-MutationRights $rule.FileSystemRights) -and $sid -notin $allowed) {
            throw 'run_root must be writable only by the operator, SYSTEM and Administrators.'
        }
    }
}

function Get-WorkerFailure {
    param([string]$OutputDir)
    $path = Join-Path $OutputDir 'worker-error.json'
    if (-not (Test-Path -LiteralPath $path)) {
        return 'Worker did not publish diagnostics; reconcile the retained task.'
    }
    $file = Get-Item -LiteralPath $path
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $file.Length -gt 32768) {
        return 'Worker diagnostics are oversized or a reparse point; reconcile the retained task.'
    }
    $diagnostic = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    return ('worker step=' + $diagnostic.step + ': ' + $diagnostic.reason)
}

function Set-StageAccess([string]$Path, [string]$Sid, [bool]$Writable) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($owner in @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-18', 'S-1-5-32-544'
    ) | Select-Object -Unique) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($owner)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', $inherit, $propagate, $allow)
        $acl.AddAccessRule($rule)
    }
    $rights = if ($Writable) { 'Modify' } else { 'ReadAndExecute' }
    $identity = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity, $rights, $inherit, $propagate, $allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

$plan = Get-Content -LiteralPath (Join-Path $Stage 'plan.json') -Raw | ConvertFrom-Json
$output = Join-Path $Stage 'output\observations.json'
$observer = Join-Path $Stage 'observer.exe'

if ($Worker) {
    $step = 'session-check'
    try {
        if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -ne 1) {
            throw 'Scheduled task is not in session 1; refusing package execution.'
        }
        $sid = Get-SessionOneSid
        if ($sid -ne [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
            throw 'Interactive task identity no longer matches session 1.'
        }
        $step = 'observer-hash-check'
        if ((Get-FileHash -LiteralPath $observer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $plan.observer_sha256) {
            throw 'Staged observer SHA256 mismatch.'
        }
        if (Test-Path -LiteralPath $output) { throw 'Observer output already exists; no replay.' }
        # Names are restricted by the Rust plan parser; paths use Windows argv quoting.
        $arguments = '--context ' + $plan.context + ' --out "' + $output + '"'
        $step = 'desktop-package-launch'
        $activation = @{
            chain = 'interactive-session-1-task -> Invoke-CommandInDesktopPackage -> observer'
            worker_session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
            worker_pid = $PID
            package_family_name = $plan.package_family_name
            app_id = $plan.app_id
            prevent_breakaway = $plan.prevent_breakaway
            source = 'wrapper-declared launch parameters, not native claim-bit attestation'
        }
        [IO.File]::WriteAllText((Join-Path $Stage 'output\activation-control.json'),
            ($activation | ConvertTo-Json -Compress))
        $launch = @{
            PackageFamilyName = $plan.package_family_name
            AppId = $plan.app_id
            Command = $observer
            Args = $arguments
        }
        if ($plan.prevent_breakaway) { $launch.PreventBreakaway = $true }
        Invoke-CommandInDesktopPackage @launch | Out-Null
        $step = 'observer-output-wait'
        $deadline = [DateTime]::UtcNow.AddMilliseconds($plan.timeout_ms)
        while (-not (Test-Path -LiteralPath $output)) {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw 'Observer deadline expired; native completion/quiescence unknown. No replay.'
            }
            Start-Sleep -Milliseconds 100
        }
        $step = 'observer-output-size'
        if ((Get-Item -LiteralPath $output).Length -gt $plan.max_output_bytes) {
            throw 'Observer output exceeds configured bound.'
        }
        exit 0
    } catch {
        $reason = $_.Exception.Message
        $reason = $reason.Substring(0, [Math]::Min(4096, $reason.Length))
        $diagnostic = @{ step = $step; reason = $reason } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $Stage 'output\worker-error.json'), $diagnostic)
        throw
    }
}

Assert-PrivateRoot (Split-Path -Parent $Stage)
$sid = Get-SessionOneSid
Set-StageAccess $Stage $sid $false
$outputDir = Join-Path $Stage 'output'
New-Item -ItemType Directory -Path $outputDir -ErrorAction Stop | Out-Null
Set-StageAccess $outputDir $sid $true
$taskName = Split-Path -Leaf $Stage
$runner = Join-Path $Stage 'runner.ps1'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$workerSource = '& { ' + [IO.File]::ReadAllText($runner) + ' } -Stage ''' +
    $Stage.Replace("'", "''") + ''' -Worker'
$workerEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerSource))
$action = New-ScheduledTaskAction -Execute $powershell `
    -Argument ('-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $workerEncoded)
$principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::FromMilliseconds($plan.timeout_ms + 5000))
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'Owned task name already exists; no replacement or replay.'
}
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
# No -Force, password, session creation, credential acquisition or sign-in.
$started = [DateTime]::Now
Start-ScheduledTask -TaskName $taskName
$deadline = [DateTime]::UtcNow.AddMilliseconds($plan.timeout_ms + 5000)
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
$taskFolder = $scheduler.GetFolder('\')
while ($true) {
    $task = $taskFolder.GetTask($taskName)
    if ($task.LastRunTime -ge $started.AddSeconds(-1) -and $task.State -ne 4 -and
        $task.GetInstances(0).Count -eq 0 -and $task.LastTaskResult -ne 267009) {
        if ($task.LastTaskResult -ne 0) {
            $detail = Get-WorkerFailure $outputDir
            throw "Owned task failed ($($task.LastTaskResult)): $detail; retain task and run directory; no replay."
        }
        if (-not (Test-Path -LiteralPath $output)) { throw 'Task exited without observer output.' }
        # Retain even terminal tasks: proof validation happens in the broker afterward.
        exit 0
    }
    if ([DateTime]::UtcNow -ge $deadline) {
        throw "Task deadline expired; retain $taskName and run directory. Completion unknown; no replay."
    }
    Start-Sleep -Milliseconds 100
}
