# Owned COM local-server fixture

`WvbScalarObject` is a test class, not a Windows/Xbox service or A04 acceptance.
Its one `IUnknown`-derived interface has slot 3:
`HRESULT Transform(UINT32 input, UINT32 *output)`.
Input 41 returns S_OK/42; UINT32_MAX returns E_INVALIDARG.
The implementation leaves its server-side output untouched on failure, but
the observed native OOP Automation marshaler writes zero to the caller's
`[out]` UINT32 (r03 receipt `12b87b94...`). The oracle and generated façade
therefore require zero, not an unchanged sentinel.
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
system service. An explicit owner-approved alternative uses the exact same
three previously absent HKLM roots in the 64-bit view and SYSTEM context.
Bridge then requires `com_registration_scope: "local-machine"` and refuses
per-user CLSID shadows; default `current-user` does not silently fall back.
Final rollback removes just those three new GUID roots in the used hive and the
temporary task/firewall rule, verifies their absence, and retains receipts.

Native oracle: `com_scalar.exe --oracle`. It activates the registered OOP class,
records both method results, releases, and returns nonzero on a mismatch.
The COM server writes PID/thread-bound events and ends on last object release
or a 120-second idle limit. Its actual PID/path/hash must be independently
observed; caller output alone does not prove target identity or quiescence.
The quoted LocalServer32 command includes `--server LOG_FILE`; COM
[appends `-Embedding`](https://learn.microsoft.com/en-us/windows/win32/com/localserver32).
The fixture accepts that optional trailing flag (or `/Embedding`), writes a
`starting` event before COM initialization, and reports initialization,
class-registration and event-creation errors explicitly. Rejecting the extra
argument used to exit before registration and caused `CO_E_SERVER_EXEC_FAILURE`.

`proxy_call.exe` loads the Whiny-generated DLL and its actual
`whiny_object_create_v1`, exercises local QI identity, E_POINTER, successful and
failing method calls, and final release over the real builtin/FFI.
Its explicit arguments are proxy path, private key path, broker address,
broker-public-key hex, actor hex, client-instance hex, build-fingerprint hex,
trace path, proxy hash. Keys are never command-line values or logs.
The final argument is the canonical contract hash. A second, explicitly bound
FFI lease holds the owned server alive while the genuine generated façade runs.
After its final Release, control probes reject altered epoch, generation and
IID/type tokens, verify that the valid lease still works, close it once, and
confirm stale-close rejection. These are real FFI/control probes, not generated
method trace entries; their separate `control-negatives` row must pass.
Only Calimocho is an active runtime. Use a fresh isolated prefix and the
source-matched builtin pair, reconcile unknown operations without replay, and
confirm native oracle, generated results, lease cleanup and guest rollback
before describing this slice as runtime evidence.

After the sole guest operator has prepared a fresh scoped `wvb serve` session,
the host driver runs this caller exactly once:

```sh
python3 setup/run_generated_call.py --demo-com \
  --wine /absolute/calimocho/install/bin/wine \
  --wine-sha256 "$WINE_SHA256" --wineserver-sha256 "$WINESERVER_SHA256" \
  --proxy-caller out/com-scalar/proxy_call.exe \
  --proxy /absolute/generated/proxy.dll \
  --builtin-root /absolute/matched/lib/wine \
  --config /absolute/private/call.json \
  --runtime-root /absolute/new-private-runtime \
  --oracle-stdout /absolute/pinned/native-oracle.stdout.txt \
  --oracle-sha256 "$ORACLE_STDOUT_SHA256"
```

The config uses the existing product call fields with 5000ms connect and
10000ms call budgets. The driver validates the pinned fixture class/IID and
contract hash, retains raw caller stdout/stderr even on failure, and checks
the successful output, failed HRESULT with zero output, and final release.
It reuses the PID demo's private-prefix initialization and bounded owned-server
drain. Never reuse a runtime root or retry after an unknown completion.
`generated_recording=false` explicitly means the generated recorder was absent;
no trace is fabricated. When present, a complete artifact/contract/process-bound
paired trace is required. The paired oracle path/hash options validate the
native baseline before launching Wine, then compare successful HRESULT/output
and failed HRESULT/output in four explicit cells. Only equal cells set
`native_oracle_compared=true`; without these options it remains false.
The result always says `supporting_only=true`: independently verify the native
context/target identity and guest cleanup before claiming supporting
acceptance, never A04. The original r03 oracle's exit2 was a stale sentinel
assertion; its recorded HRESULT/zero-output cells remain the accepted baseline.
