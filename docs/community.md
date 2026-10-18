# Community note

## Publication status

Reddit publication is intentionally deferred until X Ode's public presentation
is ready. The technical bridge and X Ode should be introduced together in
threads specifically asking about Game Pass/Xbox titles under CrossOver.
No Reddit post has been published from this repository work.

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

Suggested combined version for later:

> I have my own use cases, but I've been working on X Ode, a Mac-side runtime
> project for legitimately owned Windows/Xbox PC titles, plus a generic VM bridge
> for the Windows-only SDK calls Wine cannot perform itself. In a real Abiotic
> Factor test, the game's own user-add call completed Mac → Windows VM → Mac in
> about 13 ms on a warm path, and corrected adapters returned the genuine user
> ID and profile result. This does not make the full Game Pass catalogue work
> yet—each API and title still needs exact compatibility work—but the transport,
> adapter SDK, evidence, and limitations are public:
> https://github.com/dragoshont/winapi-vm-bridge
