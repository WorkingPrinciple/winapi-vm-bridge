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
The old VM-owned inspection/generation code has been removed. Runtime consumer
tests use the immutable Whiny v0.3.0 artifacts pinned under
`external/whiny/v0.3.0/`.

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
deterministic CrossOver Job Object oracle. It also builds byte-reproducible
unsigned macOS and Windows runtime archives with embedded SPDX and external
artifact-bound provenance.

Bootstrap launchers are separate platform-authenticated distribution artifacts;
they are deliberately not embedded in the unsigned archive they verify.

## Build and test

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
./tests/test-portable.sh
```

The portable gate validates the runtime-only workspace and the pinned frozen
Whiny consumer boundary after the completed atomic cutover.

## Current holds

- The native and managed frozen scalar bundles are admitted and execute through
  their generic runtime hosts under CrossOver and the exact Windows x64 UTM VM,
  including encrypted native and managed RPC.
- `Whiny-Windows11-x64` readiness, one-reboot persistence, clean package
  setup/update/rollback/uninstall, three-run scalar topology benchmarks,
  authenticated Runtime Owner receipts and owned-resource cleanup are verified.
- Shell-hook, NT wait-completion, ALPC and other unfrozen profiles remain
  explicitly unsupported until Whiny supplies reviewed exact identities and
  commands.
- The previous CrossOver by-name unixlib experiment failed with
  `STATUS_INVALID_INFO_CLASS` and is not retried unchanged. The supported
  direction is a Wine loader-initialized builtin DLL/unixlib pair, not a private
  memory-information-class load.
- Signing identities, notarization, hosted CI billing and publication remain
  external human-controlled release holds.

## Documentation

- [Canonical runtime ledger and ADR](docs/implementation-ledger.md)
- [Architecture](docs/architecture.md)
- [Security](SECURITY.md)
- [Evidence](docs/evidence.md)
- [Research sources](docs/research-sources.md)

The project does not ship third-party SDKs, DLLs, credentials, application
files or private configuration. Use only systems and software you are
authorized to operate.
