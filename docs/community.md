# Community note

## Publication status

Community promotion should describe **WinAPI VM Bridge only**: a generic SDK
for purpose-built Windows DLL/API calls from Wine-hosted applications through a
Windows VM. Do not bundle it with a particular game, store, vendor, SDK, X Ode,
or Xodus announcement. No Reddit post has been published from this work.

Short reusable introduction:

> I built a small bridge for a concrete problem: an app under Wine needs
> `vendor.dll`, but that DLL only works in Windows.
>
> The Mac gets a generated proxy `vendor.dll`. Calls go through a paired private
> RPC link to the real DLL inside a Windows VM, then the native result comes
> back to the app.
>
> **The demo calls a real Windows DLL—not a ping or mock.**
> `kernel32.dll!GetTickCount64` runs inside Windows and its native 64-bit result
> returns to the Mac. Windows CI executes the same round trip.
>
> Try the core round trip:
>
> ```powershell
> irm https://raw.githubusercontent.com/dragoshont/winapi-vm-bridge/main/setup-windows.ps1 | iex
> ```
>
> ```bash
> curl -fsSL https://raw.githubusercontent.com/dragoshont/winapi-vm-bridge/main/setup-mac.sh | bash
> winapi-vm-bridge call windows.kernel32.GetTickCount64 --json
> ```
>
> The public repo includes the paired transport, adapter schema/generator,
> diagrams, tests, and an AI-ready implementation task:
> https://github.com/dragoshont/winapi-vm-bridge
>
> Good candidates are coarse request/result APIs:
>
> - account and public-profile calls;
> - store, catalogue, entitlement, and licensing checks;
> - achievements, presence, and cloud-save operations;
> - Windows-only HTTP/signing SDK clients;
> - proprietary codecs, file conversion, and document processing;
> - scientific, industrial, or device-management SDK queries that do not need a
>   kernel driver.
>
> The third command calls the real `kernel32.dll!GetTickCount64` export in the
> Windows VM and returns its native 64-bit result. Each additional DLL still
> needs a documented ABI and adapter. Simple C functions are straightforward;
> pointers, callbacks, COM,
> handles, and async APIs need explicit marshalling. Kernel drivers, anti-cheat,
> and per-frame graphics are the wrong fit.
>
> Pairing happens once per Mac ↔ Windows VM pair. New DLL adapters reuse the
> same transport and do not need another pairing code.

Only post this where it directly answers the thread. Adjust it to the user's
problem and avoid cross-posting identical promotional text.

Keep X Ode and any adapter-specific case studies for their own announcements.
