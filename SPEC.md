# WX-12 package-context observer execution

| ID | Requirement | Testable acceptance | Owner | Status |
| --- | --- | --- | --- | --- |
| REQ-WX12-01 | Execute only an operator-pinned WX-07 observer in a named package through the existing authenticated CALL transport, with an independent exact capability grant. No caller-selected commands or paths. | Host tests reject missing, wildcard, expired and wrong-scope grants, changed artifacts, invalid requests and oversized output; existing call behavior is preserved. | Bridge | in-progress |
| REQ-WX12-02 | Require a human-signed-in, active interactive session 1; execute through an interactive scheduled task and Invoke-CommandInDesktopPackage. Return exact output, SHA256, session ID and in-process GetCurrentPackageFamilyName proof. Fail closed on wrong/missing identity and uncertain execution; never retry automatically. | Host tests exercise fail-closed proof/result validation and the generated task boundary. Windows compilation succeeds. Native behavior remains unclaimed until resumed live acceptance. | Bridge | in-progress |
| REQ-WX12-03 | Reproduce historical r9 only after the owner's explicit resume of VM/screen control. | On the authorized guest, pin the generated observer and package, run once in session 1, verify native identity proof and compare the retained exact output to the full historical SHA256 beginning 0a5fee77. Reconcile task/process cleanup. | Owner + Bridge | blocked |

## Corrections

| Date | Type | Requirement | Direction |
| --- | --- | --- | --- |
| 2026-10-25 | add | REQ-WX12-01, REQ-WX12-02, REQ-WX12-03 | Source-only: no VM start/control/snapshot/exec or screen/input actions. Host build/tests only. Console sign-in is a human prerequisite; no credentials, account changes or sign-in automation. |
| 2026-10-25 | add | REQ-WX12-01, REQ-WX12-02 | Commit after each implementation step. |
| 2026-10-25 | revise | REQ-WX12-01, REQ-WX12-02 | Local game-development use, not a public library: keep one bounded capability and reuse the existing transport; no SDK or generic command-execution framework. |
