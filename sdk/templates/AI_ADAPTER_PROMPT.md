# Implement one WinAPI VM Bridge adapter

Use `contract.json` and the authoritative header/documentation named by the
maintainer. Do not infer undocumented behavior.

## Required work

1. Preserve export names, calling conventions, structure packing, HRESULTs,
   buffer-size/result calls, async completion, cancellation, and handle lifetime.
2. Implement only operations listed in the contract.
3. Reject malformed/oversized input before Windows invocation.
4. Never transfer raw process pointers or OS handles. Model remote handles as
   connection-owned opaque IDs.
5. Classify outputs by sensitivity. Never log credentials, capabilities,
   identifiers, profile values, headers, bodies, tokens, signatures, or licenses.
6. Add mock parity tests, malformed/bounds tests, disconnect/restart tests, and
   one real application operation receipt.
7. Document what is not implemented. Never fabricate success.

## Stop conditions

Stop and report an exact blocker if the ABI lacks pointer ownership, allocator,
callback threading, packing, or lifetime information. Do not broaden the
adapter, search for another application, or introduce an arbitrary-export API.

