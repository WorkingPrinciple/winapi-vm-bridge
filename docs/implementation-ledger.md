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

The server loads only `whiny_dispatch_v1` from the admitted native dispatcher.
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

Only executable generated native profiles are usable. Handle, callback,
transfer and asynchronous lifecycle primitives are not proof of generated
COM/WinRT/object support. The process crate is a codec, not a process executor.
No general Windows service installer, pairing command or automatic key
provisioner is implied by these two commands.

A real generated DLL call can support transport acceptance. It does not prove
unchanged-app consumption, GamingServices compatibility or a behavioral
replacement. Retained scalar/managed receipts and fixture artifacts retain
their original qualifications. The Calimocho-source builtin/Unixlib closure is
built but unselected; source/build success is not native runtime acceptance.
