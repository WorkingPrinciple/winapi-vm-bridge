# WX-12: local package-context observer

This is a narrow local game-development capability, not a public execution SDK.
`wvb serve-observer --config FILE` consumes a pinned WX-07 observer EXE and runs
one named compiled context, once, over the existing authenticated Noise,
HELLO and CALL/RESULT path. It does not deploy/start/control a VM, create a
login session, obtain credentials or change accounts. Console sign-in is human.
The owner explicitly resumed bounded live acceptance at 15:42 on 2026-10-25.
The resumed run observed real package-context output but failed the exact r9
Flags comparison and authenticated result-return criterion; see below.

## Operator configuration

Keep the observer plan and EXE in an operator-controlled directory. The plan
uses this exact shape; substitute verified lowercase SHA256 values, not prefixes:

```json
{
  "observer": "RtlQueryPackageClaims.observer.exe",
  "observer_sha256": "<64 lowercase hex>",
  "contract_sha256": "<WX-07 replace contract SHA256>",
  "shapes_sha256": "<WX-07 shapes SHA256>",
  "module_sha256": "<expected native ntdll.dll SHA256>",
  "context": "packaged-gamingapp-signed",
  "package_family_name": "Microsoft.GamingApp_8wekyb3d8bbwe",
  "app_id": "Microsoft.Xbox.App",
  "timeout_ms": 30000,
  "max_output_bytes": 262144
}
```

`observer` is relative to the plan's directory, with the existing controlled-path
rules (no absolute/drive/UNC, traversal, symlink/reparse or reserved paths).
The executable's bytes are checked at startup and again before staging. There
are no caller-supplied arguments, scripts, paths or package selectors.
The plan's exact file bytes, not canonicalized JSON, determine its SHA256.
The contract/shapes/module pins are independent from that execution-plan hash.

The private server config has `listen`, `private_key_path`, `actors` in the
existing `serve` format, `plan_path`, `plan_sha256` (32 JSON bytes),
`run_root`, and `lifetime_ms` (maximum 600000). Unknown configuration and plan
fields are rejected. `run_root` must already exist and be writable only by
the operator, SYSTEM and Administrators. The script checks its ACL before
creating a task. Use a short local Windows path; no shared writable directories.
The server budget must be at least `timeout_ms + 10000`.
The result must fit the existing logical-payload bound, including worst-case
JSON escaping; output itself is capped at 1 MiB.

An authenticated actor needs **both** unexpired grants, scoped to the exact plan
hash and operation 1:

```json
{
  "role": "PackageObserver",
  "adapter_hash": ["<32 verified plan-hash bytes>"],
  "operation_id": 1,
  "expires_at_unix_ms": "<operator-selected finite Unix ms deadline>"
}
```

The second grant has the same scope with `"role": "Invoke"`. The placeholder
arrays/deadline above are explanatory, not executable configuration.
Wildcard grants, Operator, ServiceAdmin and AdapterAdmin do not grant this
capability. `PackageObserver` is role 7 in persisted role records. Grants are
rechecked on every call, including expiry and revocation. Possession of an
observer grant does not admit an adapter bundle; the normal `serve` bundle
admission path is unchanged. This separate local capability does not introduce
or claim a new Whiny adapter contract/dispatcher ABI.

## Authenticated invocation and output

Use the existing `wvb call --config FILE --request EMPTY_FILE --response NEW_FILE`.
The client config's `contract_path` points to the **execution plan**, and
`contract_sha256` is the plan hash. Operation, request schema and response schema
IDs are all 1. The request is zero bytes. Deduplication/idempotency keys and
automatic retries are not supported. Size the client's response capacity for
up to `6 * max_output_bytes + 8192`; a small response capacity can lose the
result after execution, and is not permission to rerun.

The guest stages a fresh, nonce-named `wvb-observer-*` directory and copies the
verified EXE, plan and embedded runner into it. It requires active WTS session 1
with a signed-in user, then creates one limited interactive-token scheduled task
for that user's SID. The worker independently verifies its own process is in
session 1 and still belongs to the active session's user before calling:

```text
Invoke-CommandInDesktopPackage -PackageFamilyName PFN -AppId APP
    -Command STAGED_OBSERVER -Args '--context NAME --out PATH' -PreventBreakaway
```

Those are WX-07's exact arguments. The interactive user receives read/execute
access to the staged inputs and modify access to the separate output directory.
No password, logon automation, session-0 fallback or headless package claim exists.
At the PowerShell boundary, Rust's canonical `\\?\C:\...` form is converted
to a local drive path; UNC/non-drive staging is rejected. The scheduled worker
uses the pinned staged script source as an encoded inline command, not `-File`;
no user/machine execution-policy setting is changed.
The script waits for the atomically published output and task completion.
It retains its exact task and run directory on success as well as failure.
In particular, a task exit 0 does not delete the task before the broker has
validated the observation proof. Worker failures retain bounded step/reason
diagnostics in `output/worker-error.json`, surfaced by the launcher as errors,
never as accepted observations.
Launcher stderr is capped at 16 KiB when returned in an error; oversized or
unavailable diagnostics never replace the observer-failure message and retained
run-directory path.
The host launcher is separately deadline-bounded; terminating it does not
terminate or prove quiescence of the task/observer. Nothing retries automatically.

Before returning success, Bridge checks `whiny.observations.v1`, nonempty cells
all in the selected context, and WX-07's actual `observed_on` proof:

- `observer_mode=native` and exact observer/contract/shapes/module SHA256 pins;
- `os_build` and `<context>.module_path`;
- `<context>.session_id="1"`;
- `<context>.package_identity="GetCurrentPackageFamilyName=0"`;
- `<context>.package_family_name` matching the selected PFN.

A refusal file, session 0/2, absent proof, mismatched package/hash, malformed
JSON, mixed contexts or oversized output produces an explicit error, not
packaged evidence. This is in-process proof from a pinned observer, not remote
attestation against a malicious signed-in user or a compromised guest.
Bridge validates execution/provenance; Whiny remains the owner of cell semantics
and the complete replace-observations schema validation.

The response is JSON with `observations_utf8` (the unchanged output file as a
UTF-8 string), `output_sha256`, `output_bytes`, context/AppId, observer hash,
`proof`, `run_directory`, `task_completed=true`, `task_retained=true` and
`observer_process_quiescence="not-attested"`. Re-encode the string as UTF-8
without newline translation/BOM and verify the hash before saving it for
`whiny replace --observations`. Task completion plus published output is **not**
a retained-handle OS exit/cleanup proof for the native observer.
Errors/disconnects can leave execution uncertain; retain the run/task identity
and reconcile rather than replay. Successful evidence directories are retained
for the developer; cleanup is deliberate, not broad directory removal.

## Source checks and pending native acceptance

Host tests cover independent/exact/expired/revoked grants, request rejection,
artifact mutations, one-shot consumption, raw-output hash round trips, wrong
session/package/refusal/missing proof and output bounds. The PowerShell host
check parses the real runner and tests session prerequisite refusals with only
the native WTS query replaced, ACL mutation-right classification, bounded
worker diagnostics and task retention. It does not touch a VM or create a real
task. The existing Windows CI entry point also runs it under PowerShell 5.1;
that hosted run has not been observed here:

```sh
cargo test -p wvb-client-ffi --features cli --bin wvb --locked
cargo build -p wvb-client-ffi --features cli --bin wvb --target x86_64-pc-windows-gnu --locked
pwsh -NoLogo -NoProfile -File tests/test_package_observer.ps1
```

The original acceptance procedure (now authorized, but not fully passed):

1. Have the owner sign into guest session 1. Verify the exact guest/OS build,
   native DLL hash, package version/PFN/AppId and WX-07 source/build identity.
   Recover the full historical r9 output and SHA256 beginning `0a5fee77`;
   a prefix is not an acceptance pin.
2. Build/pin the WX-07 r9 matrix (TokenHandle -6: Site B claim+attributes,
   claim-only, all-NULL), observer, shapes and contract. Stage only those
   reviewed artifacts, private existing transport keys/config and explicit,
   short-lived Invoke + PackageObserver grants on the resumed guest.
3. Start `wvb serve-observer`, invoke one empty operation-1 call and retain the
   server/task diagnostics plus exact response/output. Check session 1 and the
   real package-family proof, all pins, output length and SHA256 independently.
4. Attempt the literal r9 byte/hash comparison. **Do not claim it from cell
   parity:** WX-07 adds provenance metadata and a generated-observer hash, so
   identical raw SHA256 to the hand-written r9 observer is not established and
   may be impossible. Retain that discrepancy for an explicit owner decision;
   never rewrite/normalize output to fabricate the historical hash.
   Separately compare the three r9 native cells (status 0; claim Flags 5,
   Origin 3; Site B AttributesPresent 3).
5. Under resumed authorization, test signed-out/disconnected session 1, wrong
   package, wrong pins and deadline failure; confirm no session-0 output is
   accepted. Reconcile each retained exact task and native process before any
   retry; check exact-owned task removal and evidence retention, not a blanket
   process kill or presumed VM quiescence. Only after proof validation and native
   process reconciliation, manually unregister the exact `wvb-observer-<nonce>`
   task (no wildcard/Force), retaining its evidence directory.

Windows compilation and host mocks do not qualify scheduled-task execution,
desktop-package activation, session identity, r9 parity or native cleanup.

## Resumed native r02 result

**Not accepted as r9 parity or successful authenticated output delivery.**
The explicit owner resume sidecar SHA256 was
`0494ca577f87491f5a6df940c6aa8b95bc13d470e19c69dd71024ecf4aff8c44`.
The pinned UTM wrapper and step runner were verified before use:
`f3c11beec8737b8b2e2c0df705a83ddccedbc901f5d36faa6ae85ccf0a934559`
and `dd181f65fec68384242380a6fa123a1cb07a354adf4056c82748780d01bbc9fe`.
The guest was `Whiny-Windows11-x64`,
UUID `F659FCF2-AC83-4072-86A6-F7538781A1FC`, computer `WHINY`, x64,
OS `10.0.26300.0`; a session-1 Explorer process was already signed in.
GamingApp was `2610.1001.20.0`, PFN/AppId as above. No credentials,
account changes, sign-in automation, snapshots or VM lifecycle changes occurred.

The installed Whiny was `0.4.0+dev.663438d`, reported by its owner as the
content squashed into main `b13d02a`. Its unedited generated EXE observed the
three explicit TokenHandle -6 shapes in one named package context. Pins:

| Input/evidence | SHA256 |
| --- | --- |
| Replace contract | `cb1f4e1363e017aaae3dec48367f1b837af2ce7133cb9f652135498e9b8b375b` |
| Shapes | `a775d955687f4af0d49dae5a49cc217f1124ed79425339018811f4936d566c1a` |
| Generated C source | `e85a6f0bcf8d0f8fd16cbe2aa4a6ec91b559d87721872d247efa8422c63b8d5f` |
| Generated observer EXE | `111591c19b6069dc2ca3243a8fb28adab7f99d249a08503ac51de2f2dc30624d` |
| Native ntdll.dll | `651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c` |
| Execution plan | `e5dc5bef360289d385c38efe050ff019a04b1b4f1214241ff344e951772b3bfb` |
| r02 guest broker EXE | `73501cd662d9b675df73e820427e502500384a2479e14857db3d9518c911aa7d` |
| Recovered observations.json (2800 bytes) | `5d194d8f568db5539d90e81ba5619513de87d9b8b1f18973790df56c6fcb7e15` |

The first connected r01 reached authenticated HELLO/backend activation but
failed before task creation: PowerShell 5 `Join-Path` rejected Rust's verbatim
canonical path. After reconciling no observer launch, `a512b95` fixed the local
drive-path boundary and switched the worker to inline source without changing
the guest's restricted file-execution policy. No raw-output success was
fabricated for r01.

Fresh r02 used separate ephemeral Noise identities and both exact, ten-minute
Invoke/PackageObserver grants. Guest broker PID1176 reached authenticated,
backend-ready and activated stages. Its single operation created task
`wvb-observer-3599e101917115acddd72b1428cfee72` under
`C:\WhinyLane\wvb-wx12-r02`. The task's observed LastRunTime was
`2026-10-25T13:57:08Z`; LastResult was 0, terminal state Ready and instances 0.
Its output records `observer_mode=native`, session `"1"`,
`GetCurrentPackageFamilyName=0` and the exact expected PFN and input/module pins.

| Shape | Native result | Native effects | r9 comparison |
| --- | --- | --- | --- |
| Site B: claim + attributes | `0` | Flags `0x25`, Origin `3`, AttributesPresent `3` | **FAIL**: Flags expected `0x5` |
| Claim only | `0` | Flags `0x25`, Origin `3` | **FAIL**: Flags expected `0x5` |
| All NULL | `0` | Supplied-pointer effects unchanged | Match |

Do not mask off `0x20`, reinterpret Flags `0x25` as `0x5`, modify frozen
replacement cells, or attribute the difference to a cause not yet demonstrated.
The generated EXE and historical DLL harness are distinct; the output is
evidence of this run, not parity with the historical observer.

The task output was published, but the broker's 68000ms launcher deadline
expired; its retained process handle observed broker exit2. The authenticated
client received failure and no result body. The exact output was subsequently
recovered read-only through UTM file pull, with matching guest/host SHA256.
This is **not** a successful CALL result, and recovery is not an automatic
retry. Native task setup/polling timing remains unresolved; no new unobserved
deadline workaround is represented as a fix.

Cleanup exported the exact terminal task XML, checked zero task instances and
no exact-path broker/observer processes, deleted that task only, deleted both
exact r01/r02 program/IP/port-bound firewall rules, and removed guest
`server.key`/`serve.json` plus ephemeral host keys. A separate read-only check
verified task/rule/key/config absence, no exact-path owned processes and
unchanged output hash. Evidence directories remain. The observer had no
retained OS process handle; process absence is a snapshot, not an exit-code
attestation.

Full raw output, source inputs and source-pinned wrapper receipts are retained
in session artifacts:
`/Users/dragoshont/.copilot/session-state/df48ff55-d4bc-4780-9ba0-1212a667e723/files/`
(`wx12-r02/observations.json`, `wx12-*-observed.jsonl`).
REQ-WX12-03 remains blocked by the observed Flags mismatch and missing
authenticated result delivery, not by a missing human sign-in.

Final source checks on the path/worker fix passed: 163 workspace tests,
workspace formatting and all-targets/all-features clippy, Windows x64 GNU
release executable build/target clippy, and PowerShell host refusal/ACL/
diagnostic tests. Official installed `whiny replace --observations` accepted
the recovered file as three cells in the selected context and bound the same
output hash. That roundtrip generated scratch files only; no frozen fixture,
replacement cell or deployed application was changed.
