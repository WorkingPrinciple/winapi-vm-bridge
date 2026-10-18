# Community note

## Publication status

Community promotion should describe **WinAPI VM Bridge only**: a generic SDK
for purpose-built Windows DLL/API calls from Wine-hosted applications through a
Windows VM. Do not bundle it with a particular game, store, vendor, SDK, X Ode,
or Xodus announcement. No Reddit post has been published from this work.

Short reusable introduction:

> I built a small generic bridge for calling an adapted Windows DLL from an app
> running under Wine on macOS. The app stays on the Mac; selected calls go to
> the real DLL inside a Windows VM and the native result comes back. The public
> repo includes the paired private transport, three-command setup, adapter
> schema/generator, diagrams, tests, and an AI-ready implementation task:
> https://github.com/dragoshont/winapi-vm-bridge
>
> It is not magic arbitrary-DLL remoting. Simple C ABIs are straightforward;
> pointers, callbacks, COM, handles, and async APIs need explicit marshalling.

Only post this where it directly answers the thread. Adjust it to the user's
problem and avoid cross-posting identical promotional text.

Keep X Ode and any adapter-specific case studies for their own announcements.
