# Owned COM local-server fixture

`WvbScalarObject` is a test class, not a Windows/Xbox service or A04 acceptance.
Its one `IUnknown`-derived interface has slot 3:
`HRESULT Transform(UINT32 input, UINT32 *output)`.
Input 41 returns S_OK/42; UINT32_MAX returns E_INVALIDARG without writing output.
The IDL's Automation-compatible interface uses the Windows universal marshaler.

| Identity | GUID |
|---|---|
| Class | BA9A4DA2-79FE-4B31-8DB4-201AF0266C11 |
| Interface | BA9A4DA2-79FE-4B31-8DB4-201AF0266C12 |
| Type library, version 1.0 | BA9A4DA2-79FE-4B31-8DB4-201AF0266C13 |

Build only (no Wine, COM registration or VM launch):

```sh
WVB_WIDL=/absolute/path/calimocho/install/bin/widl \
WVB_COM_IMPORT_LIBRARY=/absolute/path/updated/libwvb_autoconfig.dll.a \
sh native/fixtures/com-scalar/build.sh
```

The sole guest operator stages and verifies the EXE/TLB in an owned root,
refuses existing class/interface/type-library GUID registrations, and creates
only the corresponding session user's HKCU `Software\Classes` entries.
`CLSID\{class}\LocalServer32` contains the quoted owned EXE plus
`--server "absolute-owned-log.jsonl"`.
`Interface\{interface}\ProxyStubClsid32` is
`{00020424-0000-0000-C000-000000000046}`; its `TypeLib` subkey has the library GUID
as default value and `Version=1.0`.
`TypeLib\{library}\1.0\0\win64` contains the absolute owned TLB path.
Do not register these under SYSTEM's HKCU, overwrite existing keys, or install a
system service. Final rollback removes just those three new GUID roots and the
temporary task/firewall rule, verifies their absence, and retains receipts.

Native oracle: `com_scalar.exe --oracle`. It activates the registered OOP class,
records both method results, releases, and returns nonzero on a mismatch.
The COM server writes PID/thread-bound events and ends on last object release
or a 120-second idle limit. Its actual PID/path/hash must be independently
observed; caller output alone does not prove target identity or quiescence.

`proxy_call.exe` loads the Whiny-generated DLL and its actual
`whiny_object_create_v1`, exercises local QI identity, E_POINTER, successful and
failing method calls, and final release over the real builtin/FFI.
Its explicit arguments are proxy path, private key path, broker address,
broker-public-key hex, actor hex, client-instance hex, build-fingerprint hex,
trace path, proxy hash. Keys are never command-line values or logs.
Only Calimocho is an active runtime. Use a fresh isolated prefix and the
source-matched builtin pair, reconcile unknown operations without replay, and
confirm native oracle, generated results, lease cleanup and guest rollback
before describing this slice as runtime evidence.
