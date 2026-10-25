# Runtime architecture and limitations

Whiny exclusively owns inspection, adapter-contract v3, code generation and
freezing. Bridge consumes the resulting exact contract and generated dispatcher.
Historical plans and acceptance narratives are available in Git history; they
are not a second runtime implementation or a requirement to launch a call.

## Product path

`wvb serve --config FILE` runs on Windows. It verifies the approved frozen
contract, bundle descriptor, dispatcher, target and dependencies through the
existing admission engine, including controlled paths, hashes and file identity.
An explicit AdapterAdmin grant is required to admit that contract. A Noise
session key identifies a separately registered caller; every call needs an
exact, unexpired Invoke grant for its adapter hash and operation.

The scalar server loads only `whiny_dispatch_v1` from the admitted native dispatcher.
The bounded COM variant instead loads the three declared object exports.
It serves one authenticated connection with one concurrent invocation. Readiness
prints the server PID, endpoint and lifetime, never keys. A natural successful
exit requires a completed result and no incomplete/pending calls at EOF.

`wvb call --config FILE --request FILE --response NEW_FILE` uses the existing
configure, bind-operation and call-ex C ABI. It sends one exact operation and
never retries. The response is the generated contract's typed body, not a
generic success value. Transport, dispatch and target-native errors remain
different channels. The caller validates the operation-specific body.

## Stable boundaries

- `whiny.adapter-contract.v3`, `whiny.dispatch.v1`, the process specification and
  frozen test vectors are unchanged.
- Existing client signatures, record layouts, framing, Noise and HELLO activation
  are unchanged. No pointer crosses the wire.
- Local serve/call configuration expresses existing operator approval and actor
  grants; it is not a new contract, registry or pairing protocol.
- Test-authority/correlated-handoff support is opt-in through the admission
  crate's `test-authority` feature. Core bundle/path/hash/role checks remain on.
- The old state/doctor/receipt CLI requires `wvb-runtime/legacy-admin`.
  It is not the product call launcher.
- `setup/run_generated_call.py` is the one current call driver. It neither
  deploys nor starts a VM, and does not retry an uncertain operation.

## Honest limitations

The server's asynchronous lifetime cannot preempt a stuck synchronous native
function or DLL unload. A timeout or disconnect with pending work is not a
terminal guest result, process join or proof of quiescence. Retain the observed
process identity and reconcile through its owner; never infer guest exit from
the host wrapper's exit or automatically repeat the operation.

Only executable generated native profiles are usable. The additive
`object_slice` branch implements the narrow `com-u32-v1` guest host:
one authenticated session, a dedicated MTA owner thread, actor/adapter-bound
typed leases, invocation over CALL/RESULT and close over existing HANDLE_CLOSE.
It loads generated activate/invoke/release exports instead of treating
metadata-only COM declarations as executable dispatch. Native pointers stay in
the owner thread; disconnect retires references before apartment/module teardown.
Explicit current-user or owner-approved machine64 LocalServer32 path/hash checks constrain the owned test fixture,
not arbitrary packaged-service activation. See [the bounded spec](com-object-slice.md).
The generated SYSTEM r05 supporting run matched all four native HRESULT/output
cells, including observed Automation zero-on-failure writeback, and passed the
actual official `whiny trace` command with five calls/twelve events, complete and
without dropped events. R04's pairing checks alone did not catch invalid GUID
braces in trace targets; its trace is not schema-valid recorder evidence. This is bounded
owned-fixture evidence, not generic COM/WinRT, callbacks, async, or unchanged-app
A04 support.

The additive WinRT owner composes the product's existing admission and control
paths with a pinned WinMD/manifest and thread-scoped RoGetActivationFactory.
Separate factory/instance roles, independent close and same-thread cleanup are
source-tested. Its real registration-free native SYSTEM r01 oracle observes
S_OK/output42 and E_INVALIDARG/unchanged A5A5A5A5, with actual native module paths
and OS exit0. The generated r03 Calimocho client matched all six native
factory/Create/HRESULT/output cells and passed the official recorder gate:
seven calls/sixteen events, complete and without drops. A retained guest handle
proves broker OS exit0, and exact-owned rule/key cleanup is reconciled. External
DLL sampling missed the run; module identity relies on the in-process backend
gate, not an independently sampled loaded-image hash. See
[the bounded WinRT slice](winrt-object-slice.md).
The process crate is a codec, not a process executor.
No general Windows service installer, pairing command or automatic key
provisioner is implied by these two commands.

A real generated DLL call can support transport acceptance. It does not prove
unchanged-app consumption, GamingServices compatibility or a behavioral
replacement. Retained scalar/managed receipts and fixture artifacts retain
their original qualifications. The source-matched Calimocho builtin/Unixlib
closure was selected only in the private pinned PID/COM/WinRT supporting runs;
source/build success alone is not native runtime acceptance or engine-wide
qualification.
