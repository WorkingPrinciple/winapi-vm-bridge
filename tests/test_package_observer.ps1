# Host-only tests: parse the real runner; replace only the native WTS query.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$source = Join-Path $PSScriptRoot '../setup/windows-vm/run-package-observer.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }

Add-Type @'
public static class WvbObserverSession {
    public static bool IsActive = false;
    public static string User = "";
    public static bool Active() { return IsActive; }
    public static string Text(int info) { return info == 5 ? User : "TEST"; }
}
'@

$function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-SessionOneSid'
}, $true)
if ($null -eq $function) { throw 'Missing session prerequisite function.' }
$sessionCheck = $function.Body.GetScriptBlock()

function Assert-Refusal([scriptblock]$Action, [string]$Message) {
    $failure = $null
    try { & $Action | Out-Null } catch { $failure = $_.Exception.Message }
    if ($null -eq $failure -or -not $failure.Contains($Message)) {
        throw "Expected refusal '$Message', got '$failure'."
    }
}

[WvbObserverSession]::IsActive = $false
[WvbObserverSession]::User = 'signed-in-but-disconnected'
Assert-Refusal $sessionCheck 'Session 1 is not active'
[WvbObserverSession]::IsActive = $true
[WvbObserverSession]::User = ''
Assert-Refusal $sessionCheck 'No interactive session-1 user'
[WvbObserverSession]::User = '   '
Assert-Refusal $sessionCheck 'No interactive session-1 user'

function Get-SourceFunction([string]$Name) {
    $definition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $Name
    }.GetNewClosure(), $true)
    if ($null -eq $definition) { throw "Missing function $Name." }
    return $definition.Body.GetScriptBlock()
}

$mutationCheck = Get-SourceFunction 'Test-MutationRights'
foreach ($rights in @('Read', 'ReadAndExecute', 'ReadPermissions', 'Synchronize')) {
    if (& $mutationCheck $rights) { throw "Read-only ACL rights rejected: $rights" }
}
foreach ($rights in @('Write', 'WriteData', 'AppendData', 'WriteAttributes',
    'WriteExtendedAttributes', 'Delete', 'DeleteSubdirectoriesAndFiles',
    'ChangePermissions', 'TakeOwnership', 'Modify', 'FullControl')) {
    if (-not (& $mutationCheck $rights)) { throw "Mutation ACL rights accepted: $rights" }
}

$Stage = Join-Path ([IO.Path]::GetTempPath()) ('wvb-observer-host-test-' + [Guid]::NewGuid().ToString('N'))
$outputDir = Join-Path $Stage 'output'
New-Item -ItemType Directory -Path $outputDir | Out-Null
try {
    $diagnosticCheck = Get-SourceFunction 'Get-WorkerFailure'
    if (-not (& $diagnosticCheck $outputDir).Contains('did not publish diagnostics')) {
        throw 'Missing worker diagnostics silently accepted.'
    }
    foreach ($step in @('session-check', 'observer-hash-check', 'desktop-package-launch', 'observer-output-wait')) {
        $message = @{ step = $step; reason = 'specific refusal' } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $outputDir 'worker-error.json'), $message)
        $detail = & $diagnosticCheck $outputDir
        if (-not $detail.Contains($step) -or -not $detail.Contains('specific refusal')) {
            throw "Worker diagnostic lost its step/reason: $step"
        }
    }
    [IO.File]::WriteAllText((Join-Path $outputDir 'worker-error.json'), ('x' * 32769))
    if (-not (& $diagnosticCheck $outputDir).Contains('oversized')) {
        throw 'Oversized worker diagnostics accepted.'
    }
    if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -ne 1) {
    $worker = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.IfStatementAst] -and
            $node.Extent.Text.StartsWith('if ($Worker)')
    }, $true)
    if ($null -eq $worker) { throw 'Missing worker gate.' }
    $workerBody = [scriptblock]::Create('& ' + $worker.Clauses[0].Item2.Extent.Text)
        Assert-Refusal $workerBody 'not in session 1'
        $detail = & $diagnosticCheck $outputDir
        if (-not $detail.Contains('session-check') -or -not $detail.Contains('not in session 1')) {
            throw 'Real worker refusal did not retain its specific reason.'
        }
    }
} finally {
    Remove-Item -LiteralPath (Join-Path $outputDir 'worker-error.json') -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $outputDir
    Remove-Item -LiteralPath $Stage
}
if ($ast.Extent.Text.Contains('Unregister-ScheduledTask')) {
    throw 'Tasks must remain available until broker proof validation and explicit reconciliation.'
}
Write-Output 'PowerShell syntax, session refusals, ACL mutation rights, worker diagnostics and task retention passed (host-only).'
