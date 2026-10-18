# Generic adapter system

## Goal

Make Windows DLL remoting repeatable:

```text
authoritative header + adapter manifest
  → generated Wine shim DLL
  → generated validated RPC schema
  → generated Windows dispatch table
  → tests and three-command setup
```

## Supported type model

Initial portable types:

- signed/unsigned integers and floats;
- booleans and HRESULT-style status codes;
- enums and bit flags;
- fixed-layout packed/aligned structs;
- UTF-8/UTF-16 strings with explicit maximum lengths;
- bounded byte arrays with in/out/inout directions;
- opaque remote handles with close and restart invalidation.

Extension plugins:

- nested structures and pointer graphs;
- asynchronous callback/result APIs;
- COM interfaces;
- shared buffers;
- thread-affine calls.

Explicitly out of scope:

- kernel drivers;
- injecting anti-cheat;
- arbitrary raw pointer transfer;
- invoking client-supplied DLL paths or export names;
- bypassing licensing, authentication, DRM, or application policy.

## Manifest sketch

```yaml
schemaVersion: 1
adapter: vendor.library
windows:
  dll: vendor.dll
  sha256: REQUIRED_AT_INSTALL
operations:
  Query:
    export: VendorQueryW
    callingConvention: stdcall
    timeoutMs: 15000
    parameters:
      - name: request
        type: utf16
        direction: in
        maxBytes: 4096
      - name: output
        type: bytes
        direction: out
        maxBytes: 65536
    returns: hresult
```

The installed manifest is part of the trusted configuration. The RPC request
selects `vendor.library.Query`; it cannot override `vendor.dll`, its hash,
calling convention, or buffer bounds.

## Generated shim

The shim exports the same function name/calling convention expected by the
application. It validates local pointers and lengths, serializes values, waits
or completes asynchronously according to the contract, copies output into the
caller's buffers, and returns the native-style error.

## Generated broker dispatcher

The broker validates the request schema, resolves only the allowlisted DLL and
export, invokes it with bounded broker-owned memory, serializes the result, and
wipes sensitive temporary buffers.

## Test generation

Generated tests cover:

- minimum/maximum values and sizes;
- null pointers and insufficient output buffers;
- malformed RPC and unknown fields;
- timeout, cancellation, disconnect and broker restart;
- remote handle ownership and stale handles;
- structure packing/calling-convention compatibility;
- deterministic local mock versus remote result parity.

