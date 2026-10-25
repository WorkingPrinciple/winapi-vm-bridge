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

All WinRT operations require `output_validity: success-only`. Failed typed
responses normalize their wire output to zero, but the generated facade must
leave its caller's UINT32 untouched. COM's observed OOP zero-on-failure policy
does not apply to WinRT. Transport/dispatch/protocol failures are separate from
native HRESULTs.

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
