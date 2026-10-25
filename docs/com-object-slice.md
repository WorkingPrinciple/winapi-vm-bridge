# One-object COM slice (supporting REQ-A04 work)

Additive design, version `com-u32-v1`. Existing transport, CALL/RESULT,
adapter-contract v3, scalar adapters and `whiny_dispatch_v1` stay unchanged.
Whiny owns validation/generation; Bridge owns authenticated object leases.

**Contract.** Optional top-level `object_slice` contains `abi: "com-u32-v1"`,
`activation: {kind: "com-local-server", clsid: GUID}`, `interface_iid: GUID`,
`interface_kind: "iunknown"`, `handle_type: nonzero-u32`, `method_slot: 3`,
`activation_operation_id`, `method_operation_id`, `close_operation_id`, and
`max_objects` (1..64). Distinct operation/schema IDs reference the existing
operation table and exact admission grants; class/IID/slot cannot come from
untrusted request bytes. The one method is `HRESULT M(UINT32, UINT32*)`.
Target/dependency hashes include the owned local-server EXE. No aggregation,
callbacks, async, arbitrary QI or custom marshaling. WinRT is not silently
covered: runtime class, factory IID versus instance IID, HSTRING/IInspectable
and an optional ActivateInstance operation require a separately agreed additive
variant once cell007 identifies the target.
The quoted LocalServer32 executable must resolve to the admitted target path/hash.
Runtime config `com_registration_scope` defaults to `current-user`; the explicitly
owner-approved SYSTEM harness uses `local-machine` (64-bit), rejecting any HKCU
CLSID shadow rather than falling back between hives.
That check is not atomic activation attestation or packaged-service support.

**Typed bodies.** All integers little-endian; GUID contract strings use canonical
text. Activation: empty request; response `HRESULT:i32` + token (32 bytes total).
Token: broker epoch[16], slot:u32, generation:u32, handle_type:u32 (28 bytes).
Method: token + input:u32 (32 bytes); response HRESULT:i32 + output:u32 (8 bytes).
Failed target HRESULT: zero token/output on wire; never publish a local interface.
The COM method declares `native_error.output_validity: "zero-on-failure"` and
writes caller output zero after validating a failed typed response, matching
native OOP Automation marshaling observed in r03
(`com-r03-s7-system-collect-observed.jsonl`,
SHA256 `12b87b94fab9c126e696c293257b2cd37bd76de4fa44b1b7dcac8bad6b8e0a8f`).
Serve rejects missing/old output policies and mismatched or duplicate
operation/schema bindings before starting the native host.
Transport/protocol failures remain distinct; E_POINTER is local/no CALL.
Preserve every HRESULT bit,
including successful S_FALSE. Dispatcher success is zero even on target failure;
target HRESULT lives in the body. Malformed input is rejected before native
execution. Transport failure is reported distinctly, with no retry.

**Guest generated ABI.** Three additive `extern "system"` exports:
`int32_t whiny_object_activate_v1(void **out_interface)`,
`int32_t whiny_object_invoke_v1(void *interface, uint32_t input, uint32_t *out)`,
`uint32_t whiny_object_release_v1(void *interface)`.
These native pointers never leave the guest. Activation uses the contract-pinned
CLSID/IID and CLSCTX_LOCAL_SERVER, no aggregation. Bridge calls all three only
on its dedicated CoInitializeEx(MTA) thread, serially, and releases all stored
references before CoUninitialize and dispatcher unload.

**Ownership/close.** One HandleTable per authenticated connection, bound also to
adapter and IID; actor is trusted session context, never caller authority.
Check the full 128-bit epoch before the table's internal u64 epoch. Reject stale,
wrong-type/IID/adapter and cross-session tokens. No reconnect/resume or durable
native pointers. Local QI admits only IUnknown and the one contract IID, returns
one controlling local identity, and AddRef/Release use a local atomic count.
One owned guest reference backs that façade; final Release sends existing
HANDLE_CLOSE and waits for HANDLE_STATUS. Additive C API:
`wvb_client_handle_close(const uint8_t token[28], int32_t *native_status)`;
the configured authenticated actor supplies owner_actor_id. Server checks the
contract's close-operation grant. HANDLE_STATUS disposition zero means closed;
nonzero means rejected, with native_status containing i32 HRESULT when present.
Disconnect retires every lease on the owner thread, including after failed close.
Concurrent invoke/close are serialized; unknown completion is never replayed.

**Evidence.** Harness: owned test local-server `WvbScalarObject`, method
`Transform(x, &y)` returning x+1 (UINT32_MAX returns E_INVALIDARG). It is not a
Windows/Xbox service. Compare native oracle with generated façade on Calimocho,
then test HRESULT/output rules, QI/refcounts, bad/stale/cross-session/type tokens,
release and disconnect cleanup. Scope guest registration/staging through de639,
restore prior state, retain receipts. This is supporting evidence, not A04.

## Supporting runtime evidence

The one-shot SYSTEM r04 generated run used Whiny `f02d2be`, Calimocho Wine
11.20, the actual Bridge builtin/Unixlib pair and the retained r03 native target.
It compared the hash-pinned native oracle stdout
(`06079b9ec0aa4144bc3a42db333754bc973e1b694da3ccf61e26590eab682d19`)
cell by cell:

| Cell | Native oracle | Generated through Bridge |
| --- | ---: | ---: |
| Success HRESULT | 0 | 0 |
| Success output | 42 | 42 |
| Failed HRESULT | -2147024809 (E_INVALIDARG) | -2147024809 |
| Failed output | 0 | 0 |

The native oracle's exit2 was its superseded unchanged-sentinel assertion,
not an activation failure. The generated caller exited0, checked local
QI/refcounts/NULL-out, rejected wrong epoch/generation/type and stale close,
verified the surviving lease, and closed it exactly once. Its complete generated
trace contains activation, local invalid input, successful method, failed native
method and release with outcomes `ok`, `invalid_input`, `ok`, `call_failed`, `ok`.
The private wineserver drained without forced process termination.

Retained artifacts are under `out/com-object-system-r04/runtime-once/`:
`result.json` SHA256
`b0364eff8f398d36d368a696fb4c191249808c8c6beae7aba8f62ccb3e99f098`,
`response.jsonl` SHA256
`99873f1db0008ec9373b4cd52f25e2e55ec7c3ab239224654428d7d5fab1be8e`,
and `trace.jsonl` SHA256
`982d852e29feb67c0e73b2098b7aac2d82783e21744b6f916d44b96776d607bf`.
Contract SHA256:
`f02c4067e3011e3bc5eeb9303a68da27f99fc9b5b70e0407e76eea7855a2b61c`;
generated proxy SHA256:
`a61c65ea9de82120837601a3c6a21e85bdc28127aa20b87c20c7254208b47968`.
The independently collected guest monitor (`com-r04-r04-monitor.json`,
SHA256 `c068f8b24ec9843381fefa6a5b2fc6d263e10b94cc4049416ea6a0feb84663b3`)
observed broker PID3296 and actual OOP server PID5048 in SYSTEM/session0,
the admitted server image path/hash, and both OS exit codes0 via retained process
handles. The appended native log (`com-r04-generated-server-append.jsonl`,
SHA256 `6482681572be29dd0a9c740f60f9c066fa8a46485fb228078f4478fdab4fddbb`)
contains two activations, three invocations, two releases and completion.
The rollback receipt (`com-r04-rollback.json`, SHA256
`fb05d61f6fe477547b1a5feff5a3b5c9f100fcc99c2c7c462cd87af342e72e3a`)
verifies prior subtree/value names/types/values, removes the three exact-owned
HKLM64 GUID roots and exact scoped firewall rule, and verifies registration,
rule and listener absence. No r04 task was created. Older r01/r02 artifacts and
the unloaded user's hive were left untouched; this is r04 cleanup, not a claim
that earlier user-context registration has been removed.
