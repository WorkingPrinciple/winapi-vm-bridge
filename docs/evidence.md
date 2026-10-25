# Evidence

## Historical precursor: 2026-10-18

The AF Add/GetId/GetGamertag roundtrip recorded here used the Exp2 lab broker
and rescued Xodus/private shim. It did **not** use this VM Bridge implementation
or the Whiny-generated proxy/dispatcher path. These historical observations
are precursor evidence only, not acceptance evidence for either current path.

## Verified historical observations

- The caller was the real owned game process, not a fixture.
- The game entered `XUserAddAsync`.
- The runtime sent a version negotiation and user-add request to Windows.
- The Windows broker returned `S_OK` and an opaque user session.
- The game consumed `XUserAddResult(S_OK)`.
- Process-local elapsed time was approximately 13 ms on a warm path.
- Independent broker logs contained exactly one new negotiation, add, and close
  during the capture interval.
- A later corrected game run consumed the genuine remote XUID successfully.

## Not verified by this precursor

- Fresh Windows sign-in versus cached signed-in-user reuse.
- Gameplay or online-service improvement.
- Cloud saves, achievements, presence, or multiplayer.
- Anti-cheat, graphics, or kernel-driver support.
- General arbitrary-library remoting.
- This VM Bridge implementation or the Whiny-generated proxy/dispatcher path.

## Evidence hygiene

Receipts retain only operation types, HRESULTs, timings, output lengths, binary
hashes, and presence booleans. They exclude account identifiers, gamertags,
tokens, signatures, capabilities, headers, bodies, licenses, and full URLs.

## Correction history

The experiment initially prohibited all identity export. That was an
experimental design choice, not a user requirement or technical law. It caused
the first remote `XUserGetId` implementation to fail deliberately. The contract
was corrected to return the genuine remote identifier while preserving
credential safeguards. Adapter outputs should be classified by sensitivity and
API semantics, not blanket-redacted.
