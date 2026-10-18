# Community note

Short reusable introduction:

> I have my own use cases, but I've been working on a proof of concept for
> purpose-built Windows API calls from Wine/CrossOver on macOS through a Windows
> VM. A real game `XUserAddAsync` call completed Mac → VM → Mac and the game's
> own result handler received `S_OK` in about 13 ms on a warm path. This is not
> arbitrary DLL remoting, graphics virtualization, anti-cheat support, or proof
> of gameplay improvement; each API needs an exact adapter. I’m sharing the
> transport, evidence, and limitations in case it helps similar Windows-only SDK
> gaps.

Only post this where it directly answers the thread. Adjust it to the user's
problem and avoid cross-posting identical promotional text.

