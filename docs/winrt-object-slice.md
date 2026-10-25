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
The generated r03 comparison below uses this exact native baseline.

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

## Generated r03 host observation

After actual listener readiness was observed, the prewarmed private Calimocho
prefix admitted exactly one generated client. Its console process (Windows
PID32) exited0 and its private wineserver drained. All six native baseline cells
matched: factory and Create S_OK, method S_OK/output42, and E_INVALIDARG with
unchanged caller output2779096485. Factory release returned0 while its separate
instance remained live (`DllCanUnloadNow=S_FALSE`); final instance release
returned0 and `DllCanUnloadNow=S_OK`. Epoch/generation/type/swapped-role close
rejections, surviving instance use and stale-close rejection were observed.

The proxy's original recording passed the actual pinned Whiny `dfea21e`
`whiny trace` command without incomplete-mode allowances: complete, seven calls,
sixteen events, zero drops, one thread. The NULL-out method outcome was
`invalid_input`, native E_INVALIDARG was `call_failed`, and the remaining five
outcomes were `ok`. Contract and proxy bindings matched the actual artifacts.
The persistent copy was independently re-read by the same official validator.

| Public host artifact | SHA256 |
| --- | --- |
| Native comparison result | `b5d524cf95cc03cbfe4aa735d90fd74cde1f795fc00bdcd7eb095afcf1b22a76` |
| Caller stdout | `8757f939fb873f6195526606281ab20600ef89882848bcf8567e8062dc19454c` |
| Original proxy trace | `7f813219d0f84bf2c320e443d30a51bdcb129434b9c855c0a15e7e460723d886` |
| Official validation result | `84a766a734e8b551a46eacdecb98abac22b9f4d68ec09a28742492cadd100daf` |
| Generated contract | `a28d2e624d6466df30fc35238c5afe295f249a65e36b30779fe1fd5c11c6b9fb` |
| Generated proxy DLL | `2948aaec5bd14d9c142642a11c5fcecc6678c4cd0cfb917558e17d438cf1036c` |

The engine remains the exact selected Calimocho Wine
`f6d0546fad2d0dafaa09a9fe6cabe75bb070567df6b0933ecd3622dcb6349194`.
The PE builtin remains `b0b4464fa8851ea078227b302698dd4e14d9dc2ba00c08fa36fc104e5612c308`;
the diagnostic Unixlib is `789fe9d0328cf0ef2f0358ccf670cfa2620d6d88181bf4fd8da51282dcdc55cd`.
No display/input, CrossOver, global registration or global Wine state was used.
R03 does not establish the cause of r02's transport failure. The separately
collected guest terminal and cleanup receipts follow; host success does not
stand in for them.

## Generated r03 guest terminal and cleanup

The retained SYSTEM/session0 broker handle proved PID5276 OS exit0. Its flushed
phase sequence was connected0ms, authenticated21ms, backend-ready186ms,
activated190ms, completed; stderr was empty. The fresh native log contains
fifteen lifecycle rows, all PID5276/thread1352: two factory creations, two
instance creations, three invokes and all four releases. This is an in-process
DLL fixture, not an out-of-process target server.

| Public guest artifact | SHA256 |
| --- | --- |
| Retained-handle monitor | `09151a67e76113696629813c5904bdb4752b7d8f772bc8bffd9d8b3c20f63f7e` |
| Broker phase stdout | `1a0867f373a036765055b73090777a389193a4615b2734aaa6510497791ff976` |
| Native lifecycle log | `005afff6d8fa6362510e7980a66df840a884d5631b62f3a3b2f0430c940003b7` |
| Exact-owned cleanup receipt | `d761542420cbff51ef81aa3d5fbdfde0b8c35fb0aa6622eee1d404b212c7fb85` |

The operator verified the broker file pin
`606e48a89b207bb562e902bb2f3cca66c604d70b21ee732b9af69e1762e9c8e7`
immediately before launching its exact configured path. No live process-image
path/hash receipt was collected. The external DLL sampler also missed the short
run: its `modules` array is empty. Do not claim an independently sampled loaded
image or DLL module path/hash for r03. Object identity instead relies on the
source-bound backend's mandatory actual-vtable-module path/hash check before
publishing each factory/instance lease. Native r01 separately observed both
actual module paths. Neither mechanism is atomic loaded-image attestation.

The delayed start and cleanup operations were reconciled through their original
handles, without replay. Cleanup handle1620 exited0 after verifying the exact
prior program/Public/TCP47965/local192.168.64.4/remote192.168.64.1 filters, then
removing only that rule and the disposable key. Rule/listener/key absence was
verified; no task or registry change was created. Exact local r03 disposable
keys were also removed. Public r01/r02/r03 evidence is retained, with the original
host recording and terminal guest receipts copied into persistent session
artifacts. This qualifies the owned supporting fixture only, not generic WinRT,
GamingServices, behavioral replacement parity or unchanged-app A04.

## R02 investigation and readiness hardening

R02's host caller began at03:23:33.38Z and returned its configure failure
at03:23:39.04Z, approximately5.66s later, with a configured whole-setup budget of
5000ms. Listening had already been observed by03:22:40Z. A subsequent read-only
metadata query found the guest monitor wrote its terminal outputs around
03:23:43Z; those are collection times, not native start/exit timestamps, and the
guest/host clock offset was not measured. Receipt SHA256
`eafee6e4d99f590fb781c621f258650afae6eafb0a86713f8b3136fc8581932c`.
The retained receipts do not support claiming a listener-bind race or a
180-second broker lifetime expiry. The host's prefix warm log overlapped the
attempt, unlike prewarmed r03; that does not prove prefix initialization caused
the failure.

The strongest supported hypothesis is expiration of the client's five-second
setup budget. The old runtime collapsed TCP, Noise authentication and
HELLO_ACK/backend-readiness timeouts into the same error and C status-3. R02
captured neither that error detail nor per-stage timings, and guest key transfer
verified length/ACL rather than byte or derived-public-key equality. Its exact
historical failing stage and underlying delay therefore remain unproven.
R03's190ms setup is not retroactive evidence of a specific r02 cause.

Local loopback regressions reproduce configure-3 after an authenticated peer
delays readiness beyond the configured budget, before any target CALL. A
sufficient explicitly configured setup budget succeeds. Tests also exposed a
separate real bug: configuration previously accepted an authenticated
HELLO_ACK whose readiness status was not ready.

The client now admits only the product's ready status1 and rejects other
statuses before publishing a configured client. TCP, Noise and HELLO_ACK retain
the same single absolute deadline, but timeout diagnostics name the pending
stage. The broker's pre-connection `ready` event preserves its existing name
for consumers while explicitly reporting `readiness: listener-only` and
`backend_ready: false`; only the authenticated HELLO_ACK sent after backend
initialization establishes backend readiness. This setup covers pin checking,
owner/context initialization and dispatcher loading, not a target activation
CALL. C ABI layouts, exports, wire format and configured timeout values are
unchanged. No speculative global timeout increase, sleep, readiness TCP probe
or automatic retry was added. The regression tests use local synthetic peers;
no further native VM comparison was needed or performed.
