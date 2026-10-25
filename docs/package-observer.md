# WX-12: local package-context observer

This is a narrow local game-development capability, not a public execution SDK.
`wvb serve-observer --config FILE` consumes a pinned WX-07 observer EXE and runs
one named compiled context, once, over the existing authenticated Noise,
HELLO and CALL/RESULT path. It does not deploy/start/control a VM, create a
login session, obtain credentials or change accounts. Console sign-in is human.
**Live acceptance is on hold until the owner explicitly resumes VM control.**

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
The script waits for the atomically published output and task completion.
It retains its exact task and run directory on success as well as failure.
In particular, a task exit 0 does not delete the task before the broker has
validated the observation proof. Worker failures retain bounded step/reason
diagnostics in `output/worker-error.json`, surfaced by the launcher as errors,
never as accepted observations.
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

**REQ-WX12-03 remains blocked.** After explicit owner resume, and not before:

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
