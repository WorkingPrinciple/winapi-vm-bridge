# Adapter guide

## Generic workflow

1. Obtain an authoritative C header or ABI description for the Windows DLL.
2. Create an adapter manifest.
3. Generate the Wine-side shim and Windows dispatcher.
4. Implement custom marshalling only for types the manifest cannot express.
5. Run generated contract, buffer, cancellation, disconnect and fuzz tests.
6. Validate one complete real application operation.

## Start with one complete operation

Before building infrastructure, trace one real call from application entry to
result consumption. Record the exact input/output/async contract. Do not infer
product value from a standalone broker test.

## Preserve semantics

- Return native HRESULTs/errors.
- Preserve result-size/result calls and insufficient-buffer behavior.
- Model handles as connection-owned opaque sessions.
- Bind handles to broker epoch and invalidate on restart/sign-out/disconnect.
- Implement cancellation and close without leaking remote state.
- Bound every string, body, array, and wait.
- Never silently fall back to a different identity or execution mode.

## Sensitive outputs

Do not treat all output as either public or forbidden:

| Output | Typical handling |
|---|---|
| Public identifier/profile | Return when required; avoid logs |
| Token/signature | Exact scope/lifetime, authenticated channel, memory only |
| Password/private key | Never export |
| API body | Return only fields/body required by the adapter contract |

## Acceptance

An adapter is accepted only when a real application call crosses the bridge,
the real native API runs, and the application consumes the exact result.
Helper tests remain necessary but are not product acceptance.

## Why a binary path is insufficient

`LoadLibrary` and `GetProcAddress` can locate an export, but they do not reveal
how to safely move its arguments between processes. Generic remoting therefore
requires a contract. Simple C functions can be fully generated; complex APIs
need plugins. Claiming every DLL works without this metadata would be unsafe and
incorrect.

