# Bounded WinRT factory and instance slice

`winrt-u32-v1` reuses the authenticated COM object owner, existing CALL/RESULT
and HANDLE_CLOSE/STATUS paths. A dedicated MTA thread owns every native pointer,
factory and instance lease, and their cleanup. This is an owned supporting
fixture, not Xbox/GamingServices, arbitrary WinRT or unchanged-app acceptance.

## Frozen ABI

| Operation | Request | Typed response |
| --- | --- | --- |
| Factory activation | empty | HRESULT:i32 + factory token28 |
| Create (factory slot7) | factory token28 | HRESULT:i32 + instance token28 |
| Transform (instance slot8) | instance token28 + UINT32 | HRESULT:i32 + UINT32 |
| Close | existing HANDLE_CLOSE token | existing HANDLE_STATUS |

Factory and instance have distinct nonzero handle types. Full epoch, actor,
generation and type checks apply before native execution. Closing a factory does
not invalidate an instance. Failed creation publishes a zero token; capacity
failures release unpublished native references. Disconnect releases all live
references on the owner thread before apartment/context destruction.

The WinRT method requires `output_validity: unchanged-on-failure`; activation,
creation and close require `success-only`. Failed typed responses normalize
their wire output to zero, but the generated facade leaves its caller's UINT32
untouched. COM's observed OOP zero-on-failure policy does not apply to WinRT.
Transport/dispatch/protocol failures are separate from native HRESULTs.

## Registration-free native composition

The product `wvb serve` selects the WinRT backend for the admitted WinRT object
slice and validates its profile, class, both IIDs and operation/schema bindings.
`winrt_activation_manifest` explicitly selects a relative path from the existing
admitted dependency list; the profile's WinMD path/hash must match another
admitted dependency. This adds no contract, registry or bundle schema.

The backend verifies target, dispatcher, manifest and WinMD hashes; initializes
`RoInitialize(RO_INIT_MULTITHREADED)` (value1); creates a thread-scoped activation
context with the admitted target's assembly directory; and loads the exact
generated factory/create/invoke/release exports. The generated factory export
calls real `RoGetActivationFactory` with the pinned class HSTRING and factory
IID. There is no global registration, process-default context, direct factory
fallback, cross-thread context or remote string/pointer.

Before publishing either native object, its actual vtable module path and
on-disk hash must match the admitted component. These checks are not atomic
loaded-image attestation. All references retire before RoUninitialize and
activation-context teardown; cleanup failures are reported explicitly.

## Owned native fixture

`native/fixtures/winrt-scalar/build.sh` builds
`Wvb.Test.WvbScalarRuntimeClass.dll`, a native console oracle, and a genuine
`Wvb.Test.winmd`. Its package-free .NET metadata emitter writes a WindowsRuntime
1.4 metadata PE, WindowsRuntime assembly/type flags, both custom interface GUID
attributes, the runtime class/default interface/factory metadata, and the real
reserved methods accounting for factory slot7 and instance slot8. It reopens
the emitted PE and checks its header, tables, flags, method bodies and slot order.
No TLB renaming, copied external metadata or downloaded package is involved.

Build in a new output directory:

```sh
WVB_WINRT_OUT="$PWD/out/winrt-scalar-new" \
WVB_WINRT_IMPORT_LIBRARY="/absolute/path/to/matched/libwvb_autoconfig.dll.a" \
  sh native/fixtures/winrt-scalar/build.sh
```

The oracle accepts absolute manifest, assembly-directory and log paths. It
activates only its thread's context, calls real RoGetActivationFactory, records
actual factory/instance module paths, releases the factory before using the
instance, and records success/failure HRESULT/output cells. The fixture log
contains actual process/thread identities and reference lifecycle events.

Native Windows observation, generated Calimocho comparison, official
`whiny trace` validation and exact-owned cleanup remain acceptance gates.
Compilation and mock-owner tests are source evidence only, not runtime parity.

## Native r01 observation

The real Windows oracle ran once in SYSTEM/session0 (PID2088/thread2928), with
retained-handle OS exit0. Factory and instance vtable module paths were both
`C:\WhinyLane\wvb-winrt-r01\Wvb.Test.WvbScalarRuntimeClass.dll`, SHA256
`06352f3363f16415589815641b3866b10bfcfb09f69298d0aeb613175881bc03`.
Factory activation and Create returned S_OK; Transform41 returned S_OK/output42;
TransformMAX returned E_INVALIDARG with caller output2779096485 (`A5A5A5A5`)
unchanged. The factory was released before the instance's three native calls.
No registry, task, firewall, broker, protocol key, display or input changes.

Oracle stdout SHA256
`726aa5b6cbae70684f8b54889a3256b5af231dfc78ccd7690d6e698e60ca7e40`;
native log `122a7a3472c8f09607a45de798c4a044bd2a36d7c34fa544904015f89dfcb7fe`;
guest collection `4b3ca4adfacb2a96a53c64c2541857b98b0e213bd6cec8df8faf4eacaa7a4d42`.
This observed result is the WinRT `unchanged-on-failure` baseline adopted by
Whiny `dfea21e`, not an inference from COM's different Automation behavior.
Generated end-to-end parity and recorder acceptance are still pending.

## Generated comparison gate

Whiny `dfea21e` emits the unchanged-on-failure method policy and brace-free
recorder targets. Object slices emit sources only: do not select the generator's
`--input-root` adapter-bundle packaging mode, which does not describe these object
exports. The operator-reviewed descriptor/admission remains the existing bounded
composition, not generalized Whiny object-bundle packaging.

The owned caller checks IUnknown/IInspectable/custom-IID identity, exactly the
admitted GetIids result, unsupported class-name/trust queries, reserved slots,
NULL-out rejection, factory close before instance use and independent final
release. Raw lease probes test epoch/generation/type and swapped-role close
rejection plus surviving instance use and stale-close rejection. Method/create
wrong-role CALLs are source-tested; the broker terminates such invalid CALLs,
so they must not be presented as live nonterminal dispatch-error responses.

`--demo-winrt` reuses the private-prefix/wineserver lifecycle. It requires the
pinned native stdout and actual pinned `whiny trace` executable. The original
proxy-written recording must contain seven paired outcomes (factory, Create,
factory close, local NULL-out, success method, failed method, instance close),
bound to this process/contract/proxy. Official validation must report complete,
seven calls, sixteen events and zero drops. Only then are all six native
factory/Create/HRESULT/output cells compared. Post-call failures retain evidence
and never retry the native operation.

## Generated r02 setup failure

R02 stopped at `wvb_client_configure=-3`, before proxy loading, recording or any
target CALL. Configure includes TCP, Noise authentication and HELLO/HELLO_ACK;
it is not a local-only initializer. The guest broker PID2740 exited2 with
Windows transport error10053. Its monitor saw no target module, and no native
fixture log was created. This does not establish a WinRT method failure or
parity. Monitor SHA256
`8292c67d4c4533e71625dcb2f600e96d09cf18bfb09d6230803b26fdc821eb80`;
broker stderr `8430a03a89fae8865668282508af912d8b7663b7892ce9c3b7f12079f25680da`.

The original cleanup operation reconciled exit0: exact program/Public/TCP47965/
local192.168.64.4/remote192.168.64.1 rule removed after prior-filter verification,
listener and disposable key absent, no task or registration created. Receipt
SHA256 `d761542420cbff51ef81aa3d5fbdfde0b8c35fb0aa6622eee1d404b212c7fb85`.
Native r01 and r02 public evidence remain untouched; local disposable r02 keys
were removed. Two private Calimocho loopback-only controls subsequently proved
the same WinRT caller can complete configuration with both the original builtin
pair and the diagnostic pair. These synthetic controls are not native parity.
Setup diagnostics now preserve the original connection error and emit flushed
connected/authenticated/backend-ready/activated phase timings, without keys or
call payloads. R02 is terminal and must not be replayed.
