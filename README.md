# WinAPI VM Bridge

WinAPI VM Bridge is the runtime and execution plane for invoking approved
Windows APIs from software running under Wine on macOS. It does not inspect
targets or generate adapters. Those source-plane responsibilities belong to
[Whiny](https://github.com/dragoshont/whiny).

```text
Whiny inspection/review/freezing
  -> immutable contract and adapter bundle
  -> VM Bridge operator admission
  -> Wine client / encrypted RPC / Windows broker
  -> exact admitted dispatcher, target and dependencies
  -> result, lifecycle events and runtime receipt
```

## Ownership boundary

Whiny exclusively owns:

- inspection and semantic investigation;
- canonical contract/IR and dependency placement;
- review and freezing;
- proxy, dispatcher, project and package generation;
- immutable adapter bundles.

VM Bridge exclusively owns:

- bundle admission, controlled paths and hash verification;
- pairing, encrypted transport and multiplexing;
- actor, role and operation authorization;
- calls, transfers, handles, callbacks, cancellation and process lifecycle;
- native, CLR and process execution hosts for the declared dispatcher ABI;
- durable operations, receipts, audit and diagnostics;
- setup, service operation, update, rollback, uninstall and acceptance.

The dependency direction is one-way. VM Bridge consumes pinned frozen Whiny
artifacts; it does not infer or regenerate their contract.

## Frozen boundary

The selected unreleased boundary is:

| Artifact | Identifier |
|---|---|
| Contract | `whiny.adapter-contract.v3` |
| Bundle | `whiny.adapter-bundle.v1` |
| Dispatcher ABI | `whiny.dispatch.v1` |
| Runtime receipt | `whiny.runtime-receipt.v1` |

There is no compatibility mode for the old Whiny contract or `wvb-ir` schema 2.
Existing inspection/generation code remains temporarily to preserve the proven
vertical paths. It will be removed atomically after Whiny publishes its
validator package and frozen native and managed bundle vectors and the runtime
consumer tests pass.

## Runtime security model

- Generated bundle contents are untrusted data.
- An existing `AdapterAdmin` grant scoped to the exact contract hash is required
  to admit a bundle.
- Admission pins exact contract, bundle descriptor, dispatcher, target and
  dependency hashes.
- Paths are controlled relative paths. Absolute, drive, UNC, traversal,
  case-colliding, symlink and reparse-point paths are rejected.
- File identity is re-verified before load.
- Admission never grants invocation. Each caller still needs an exact `Invoke`
  grant for the contract hash and operation ID.
- Arbitrary caller-selected paths, DLLs, exports, assemblies and commands are
  rejected.

## Verified runtime baseline

The `canonical-runtime` baseline through `d5b8e89` includes:

- protocol framing, fragmentation, flow control and Noise transport;
- TCP bootstrap and HELLO activation;
- canonical chunked CALL/RESULT streaming;
- multiplexed client and broker;
- Windows-loadable C ABI client runtime;
- durable state, actor grants and audit hash chain;
- handle, callback and asynchronous lifecycle primitives;
- CLR hosting and encrypted native/managed CrossOver round trips.

This branch additionally contains reviewed bundle admission, durable admission
and operation state, transfer lifecycle, bounded native process codecs and a
deterministic CrossOver Job Object oracle.

## Build and test

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
./tests/test-portable.sh
```

The portable gate intentionally keeps the legacy generator/inspection path
green until the atomic Whiny cutover.

## Current holds

- Whiny bundle v1 and dispatcher ABI vectors are not yet published, so the
  source-plane cutover and target-profile activation remain blocked.
- The preferred isolated `Whiny-Windows11-x64` acceptance VM is booted, but its
  QEMU guest agent is unavailable. No guest mutation or forwarding change is
  made until target readiness and reversible control are established.
- The previous CrossOver by-name unixlib experiment failed with
  `STATUS_INVALID_INFO_CLASS` and is not retried unchanged. The supported
  direction is a Wine loader-initialized builtin DLL/unixlib pair, not a private
  memory-information-class load.
- Signing identities and publication remain external human-controlled holds.

## Documentation

- [Canonical runtime ledger and ADR](docs/implementation-ledger.md)
- [Architecture](docs/architecture.md)
- [Security](SECURITY.md)
- [Evidence](docs/evidence.md)
- [Research sources](docs/research-sources.md)

The project does not ship third-party SDKs, DLLs, credentials, application
files or private configuration. Use only systems and software you are
authorized to operate.
