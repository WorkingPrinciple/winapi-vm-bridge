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

if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -ne 1) {
    $worker = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.IfStatementAst] -and
            $node.Extent.Text.StartsWith('if ($Worker)')
    }, $true)
    if ($null -eq $worker) { throw 'Missing worker gate.' }
    $workerBody = [scriptblock]::Create('& ' + $worker.Clauses[0].Item2.Extent.Text)
    Assert-Refusal $workerBody 'not in session 1'
}
Write-Output 'PowerShell runner syntax and four host-only session refusal checks passed.'
