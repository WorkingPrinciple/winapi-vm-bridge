# WX-12 package-context observer execution

| ID | Requirement | Testable acceptance | Owner | Status |
| --- | --- | --- | --- | --- |
| REQ-WX12-01 | Execute only an operator-pinned WX-07 observer in a named package through the existing authenticated CALL transport, with an independent exact capability grant. No caller-selected commands or paths. | Host tests reject missing, wildcard, expired and wrong-scope grants, changed artifacts, invalid requests and oversized output; existing call behavior is preserved. | Bridge | accepted |
| REQ-WX12-02 | Require a human-signed-in, active interactive session 1; execute through an interactive scheduled task and Invoke-CommandInDesktopPackage. Return exact output, SHA256, session ID and in-process GetCurrentPackageFamilyName proof. Fail closed on wrong/missing identity and uncertain execution; never retry automatically. | Host tests exercise fail-closed proof/result validation and the generated task boundary. Windows compilation succeeds. Native behavior remains unclaimed until resumed live acceptance. | Bridge | accepted |
| REQ-WX12-03 | Reproduce historical r9 only after the owner's explicit resume of VM/screen control. | On the authorized guest, pin the generated observer and package, run once in session 1, verify native identity proof and compare the retained exact output to the full historical SHA256 beginning 0a5fee77. Reconcile task/process cleanup. | Owner + Bridge | blocked |

## Corrections

| Date | Type | Requirement | Direction |
| --- | --- | --- | --- |
| 2026-10-25 | add | REQ-WX12-01, REQ-WX12-02, REQ-WX12-03 | Source-only: no VM start/control/snapshot/exec or screen/input actions. Host build/tests only. Console sign-in is a human prerequisite; no credentials, account changes or sign-in automation. |
| 2026-10-25 | add | REQ-WX12-01, REQ-WX12-02 | Commit after each implementation step. |
| 2026-10-25 | revise | REQ-WX12-01, REQ-WX12-02 | Local game-development use, not a public library: keep one bounded capability and reuse the existing transport; no SDK or generic command-execution framework. |
| 2026-10-25 | revise | REQ-WX12-02 | PR #16 follow-up: diagnostics read failures/oversize must preserve the observer failure and run path; always check worker-gate structure and explicitly report session-1 runtime-check skips. Host regression checks and same-branch push only; VM/screen STOP unchanged. |

## Source acceptance evidence (2026-10-25)

REQ-WX12-01 and REQ-WX12-02 are accepted **only to their source/host-test
criteria**, not native Windows execution. Implementation commits `7bd8982`
and `48466a3` consume the WX-07 interface agreed with its Whiny owner:
EXE `--context NAME --out PATH`, `whiny.observations.v1`, context-prefixed
`observed_on` identity strings and independent observer/contract/shapes/module
pins. There is no external VM action or claimed r9 observation.

- `cargo fmt --all -- --check`: passed.
- `cargo test --workspace --all-features --locked`: 161 passed, zero failures.
  This includes ten `wvb` binary tests and durable role expiry/revocation tests.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  passed.
- Windows x64 GNU `wvb` CLI executable build and target clippy: passed.
- PowerShell 7 host checks: real runner/Windows test-entry syntax, inactive
  session/no-user/wrong-session refusal, mutation-vs-read ACL rights, bounded
  worker step/reason diagnostics and retained tasks passed. No real WTS query,
  task creation, desktop-package activation or observer execution occurred.
- Independent read-only review found ACL-right classification, lost worker
  error detail and premature task deletion defects. `48466a3` fixes all three
  with host regressions. No subsequent native/independent PASS is claimed.

REQ-WX12-03 stays blocked by the owner STOP. The full resume procedure is in
[docs/package-observer.md](docs/package-observer.md#source-checks-and-pending-native-acceptance).
The full historical SHA256/output must be recovered; a prefix is not a pin.
Generated provenance changes output bytes, so literal historical hash equality
must not be inferred from matching r9 cells or silently replaced by that weaker
criterion. This oracle discrepancy remains explicit for resumed acceptance.

## PR #16 follow-up (2026-10-25)

Both minor review findings reproduced against the current source. Launcher
diagnostics now read at most 16 KiB without displacing the observer-failure
message, retained run path or no-replay warning when the file is oversized,
missing or unreadable. Read errors are included as diagnostic detail.
Host regressions cover those cases and normal stderr.

The PowerShell test always extracts/checks the worker gate before the
session-specific runtime branch; session 1 explicitly warns about skipped
runtime refusal checks. A source regression guards that ordering/warning.
An isolated host-only session-1 simulation also verified the warning and
rejected a missing-worker-gate mutant without native WTS/task/VM execution.

Final checks: 163 workspace tests passed (12 CLI binary tests), workspace fmt
and all-targets/all-features clippy passed, Windows x64 GNU CLI build and
target clippy passed, PowerShell host regressions passed. Native acceptance
and the owner STOP remain unchanged.
