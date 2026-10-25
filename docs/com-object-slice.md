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
This first harness additionally requires the current user's quoted
LocalServer32 executable to resolve to the admitted target path and hash.
That check is not atomic activation attestation or packaged-service support.

**Typed bodies.** All integers little-endian; GUID contract strings use canonical
text. Activation: empty request; response `HRESULT:i32` + token (32 bytes total).
Token: broker epoch[16], slot:u32, generation:u32, handle_type:u32 (28 bytes).
Method: token + input:u32 (32 bytes); response HRESULT:i32 + output:u32 (8 bytes).
Failed HRESULT: zero token/output on wire; never publish a local interface and
never write the caller's scalar output on failure. Preserve every HRESULT bit,
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
