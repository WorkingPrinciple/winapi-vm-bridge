# WinAPI VM Bridge

![WinAPI VM Bridge: a missing DLL on Mac is represented by a proxy that calls the real DLL in a Windows VM](docs/assets/bridge-overview.svg)

Use a DLL that exists in Windows from an app running under Wine on macOS. The
app stays on the Mac. A generated proxy DLL exposes the missing exports, sends
selected calls to the real DLL inside a Windows VM, and returns the native
result.

## Try the bridge

**Windows PowerShell**

```powershell
irm https://raw.githubusercontent.com/dragoshont/winapi-vm-bridge/main/setup-windows.ps1 | iex
```

**Mac**

```bash
curl -fsSL https://raw.githubusercontent.com/dragoshont/winapi-vm-bridge/main/setup-mac.sh | bash
```

**Round trip**

```bash
winapi-vm-bridge call core.ping --json
```

Windows prints a pairing code once. Paste it into the Mac setup prompt. The
third command then performs a real private Mac → VM → Mac RPC call.

Here, **paired** means the Mac client and Windows broker prove they share the
same random capability. It prevents an unrelated local process from using the
broker. It is not user, Microsoft, application, or account authentication.

## How it works

```text
app.exe → shim.dll → private RPC → Windows broker → vendor.dll
app.exe ← shim.dll ← private RPC ← Windows broker ← vendor.dll
```

1. Describe the DLL exports in a strict adapter manifest.
2. Generate a Wine-side shim and Windows dispatcher review bundle.
3. Implement custom marshalling only where the ABI needs it.
4. Validate one complete operation in the real application.

## Build an adapter

```bash
winapi-vm-bridge init vendor.library
winapi-vm-bridge generate adapter.json --out generated
cat generated/vendor-library/IMPLEMENTATION_TASK.md
```

The generated task is designed for either a developer or a coding agent. It
includes the contract, unresolved marshalling work, tests, and stop conditions.

## Where it fits

Best for coarse request/result calls:

- account and public-profile APIs;
- store, catalogue, entitlement, and licensing checks;
- achievements, presence, and cloud saves;
- Windows-only HTTP/signing SDK clients;
- proprietary codecs, conversion, and document processing;
- scientific, industrial, and device-management SDK queries that do not need a
  kernel driver.

### Works well

- scalar arguments and fixed-layout structs;
- bounded input/output buffers;
- UTF-8 and UTF-16 strings;
- opaque remote handles;
- coarse synchronous or async request/result APIs.

### Needs custom marshalling

- nested pointers and allocator ownership;
- callbacks, COM, thread affinity, and window messages;
- shared memory and process-local handles;
- bespoke cancellation or async lifecycles.

### Out of scope

- kernel drivers and anti-cheat;
- per-frame graphics calls;
- undocumented ABIs;
- arbitrary client-selected DLL paths or exports.

## What is included

- capability-paired, versioned RPC core;
- Windows broker and Mac client;
- adapter JSON schema and generator;
- generated shim/dispatcher skeletons;
- AI-ready implementation prompt;
- bounds, pairing, and round-trip tests;
- three-command setup and rollback guidance.

## Status

| Capability | Status |
|---|---|
| Paired Mac ↔ Windows VM RPC | Working |
| Portable `core.ping` round trip | Working |
| Adapter schema and patch generator | Working |
| Generated review/test bundle | Working |
| Compilable scalar shim/dispatcher generation | [Planned](https://github.com/dragoshont/winapi-vm-bridge/issues/1) |
| Complex API adapters | Per library |
| Transparent arbitrary-DLL remoting | Not supported |

## Read next

- [Architecture](docs/architecture.md)
- [Generic adapter model](docs/generic-adapters.md)
- [Adapter guide](docs/adapter-guide.md)
- [Evidence method](docs/evidence.md)
- [SDK](sdk/README.md)
- [Security](SECURITY.md)

Independent research. The project does not ship third-party SDKs, DLLs,
credentials, application files, or private configuration. Use only libraries
and systems you are authorized to use.
