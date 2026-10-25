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
  -> exact typed result and separate native-error semantics
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

The product has two commands. Build for the host, and cross-build the same
executable for the Windows guest:

```bash
cargo build --release --locked -p wvb-client-ffi --features cli --bin wvb
cargo build --release --locked -p wvb-client-ffi --features cli --bin wvb \
  --target x86_64-pc-windows-gnu
```

## Serve/call quick start

Use a reviewed Whiny-generated contract and compiled dispatcher, not an
arbitrary DLL/export supplied by a caller. The operator stages their approved
bundle and private configuration on the guest. No VM installer, firewall
change, discovery, pairing or key generation happens implicitly.

```powershell
# Windows: one authenticated connection; stdout includes the real server PID.
.\wvb.exe serve --config C:\Bridge\serve.json > C:\Bridge\serve.jsonl
```

```bash
# macOS: one invocation; response.bin must not already exist.
./target/release/wvb call --config call.json \
  --request request.bin --response response.bin
# Optional single current driver; a u32 comparison is specific to that contract.
python3 setup/run_generated_call.py --wvb "$PWD/target/release/wvb" \
  --config call.json --request request.bin --response next-response.bin \
  --expected-u32 "$OBSERVED_GUEST_PID"
```

`serve.json` has `listen` (a specific interface/nonzero port), `private_key_path`,
`actors` (each explicit `id`, `public_key`, existing `grants`), `operator_actor`,
`bundle_root`, relative `contract_path`/`descriptor_path`, existing
`OperatorAdmission` as `approval`, `response_capacity`, and `lifetime_ms`
(1..600000). Approval uses the existing compatibility, contract/descriptor
SHA-256, file-kind/path/hash and operation/schema records. An exact
`AdapterAdmin` grant admits the bundle; an independent exact `Invoke` grant
authorizes each operation. Grant expiry is honored. Unknown keys are rejected
before session activation.

`call.json` has `address`, `private_key_path`, `broker_public_key`, `actor_id`,
`client_instance`, `build_fingerprint`, `contract_path`, `contract_sha256`,
`operation` (`operation_id`, `request_schema_id`, `response_schema_id`),
`response_capacity`, `connect_timeout_ms`, and `call_timeout_ms`. Byte arrays
are JSON arrays of integers. Private keys are separate exact 32-byte binary
files, owner-only on Unix; on Windows restrict their inherited ACL to the
operator/server identity. Never put keys in argv, logs, Git, or a shared file.
There are no built-in identities or grants.

The request and result are the operation's exact generated bytes. An empty
request is a zero-byte file. The CLI reports dispatch status/length, writes the
typed result separately, and never guesses a target HRESULT or retries a call.
Its configuration selects an approved operation, not a new wire schema.
Readiness and natural completion are different events. Deadline/error exit 2
does not prove guest cancellation or quiescence; reconcile the retained PID.
A synchronous native function/unload can outlast the asynchronous deadline.

`native/fixtures/kernel32-pid/contract.json` describes one real Windows DLL
operation for supporting transport acceptance: zero request bytes, one u32 PID.
Its target hash is specific to the observed guest and must not be replaced by
an unverified file. `RemoteGetCurrentProcessId` is the diagnostic operation
name; the actual DLL entry is `GetCurrentProcessId`. A raw product `call`
through its generated dispatcher is not evidence that the generated PE proxy
was executed. That proxy is generated separately by the unchanged Whiny tool.
Use a Whiny generator that emits internal proxy symbols, aliases the original
exports in its `.def`, and imports recorder APIs from kernel32. The original
generator's Windows-header symbol collision is not grounds to hand-edit its
output or weaken the contract.

The same driver can invoke the actual generated PE proxy through an explicitly
prepared, private Wine prefix and the existing builtin/native FFI pair:

```bash
python3 setup/run_generated_call.py \
  --proxy-caller /absolute/path/proxy_call.exe \
  --wine /absolute/path/wine --wine-sha256 EXACT_ENGINE_SHA256 \
  --proxy /absolute/path/proxy.dll \
  --config /absolute/path/call.json --response /absolute/path/new-result.bin \
  --trace /absolute/path/new-trace.jsonl --expected-u32 GUEST_READY_PID
```

The existing `native/wine-unixlib/build-and-test.sh` SDK build also compiles
`native/fixtures/kernel32-pid/proxy_call.c` as `pid_proxy_call.exe` against the
real builtin import library, not a mock transport. Set `WINEPREFIX` to the already initialized owned
prefix and `WINEDLLPATH` to the pinned builtin pair. This mode never initializes
a prefix or enables automatic Keychain/bootstrap configuration; it uses the
same private key file and public configuration as `wvb call`. Its explicit
connect/call budgets are both 5000ms. The caller loads the real named export,
records exactly one call, compares its returned PID, resets and unloads.
The driver requires a complete, paired remote call trace bound to the proxy
and contract hashes. Neither this owner probe nor the raw call is unchanged-app
or GamingServices acceptance.

### One-command real PID demo

After the guest owner starts `wvb serve` and supplies its ready PID, the same
driver can prepare a **new private host prefix**, call the generated export once,
record its result/trace, and shut down its owned host runtime:

```bash
python3 setup/run_generated_call.py --demo-pid \
  --proxy-caller /absolute/path/pid_proxy_call.exe \
  --proxy /absolute/path/generated-proxy.dll \
  --wine /absolute/path/calimocho/install/bin/wine \
  --wine-sha256 EXACT_ENGINE_SHA256 \
  --wineserver-sha256 EXACT_SERVER_SHA256 \
  --builtin-root /absolute/path/source-matched-pair/lib/wine \
  --config /absolute/path/call.json \
  --runtime-root /absolute/path/new-demo-directory \
  --expected-u32 GUEST_READY_PID
```

The Wine install must include `bin/wineserver` and its matching `lib/wine`;
the builtin root contains `x86_64-windows/wvb_autoconfig.dll` and
`x86_64-unix/wvb_autoconfig.so`. Build the proxy with the current Whiny generator
and link it against that pair's import library. The command verifies the
engine/server pins, stages the public binaries, initializes only the new
prefix, and derives new response, trace and diagnostic paths inside it.
The private key is read from the existing private file, never copied, printed
or hashed. An existing demo directory is rejected, and no retry is automatic.
Cleanup ends and kills Windows processes only in that new private prefix, then
waits for its owned server to drain naturally. Forced server termination is
reported as unknown prefix quiescence, not successful cleanup; evidence remains.

**CrossOver is excluded from active acceptance.** Both direct proxy mode and
the demo reject CrossOver paths (including resolved aliases and inherited
environment paths). Use an explicitly selected, hash-pinned Calimocho/Xodus
engine and its source-matched builtin pair. Historical CrossOver observations
remain historical, not current acceptance.
The demo does not connect to the VM control plane, start the guest service,
change its firewall or grant authority. Those stay with the guest owner.

### Bounded COM object slice

The additive `com-u32-v1` object host keeps native COM interfaces on a dedicated
guest MTA thread and returns only connection-bound typed leases. Activation and
one synchronous `HRESULT M(UINT32, UINT32*)` use existing CALL/RESULT; final
release uses existing HANDLE_CLOSE. Target HRESULTs remain typed response data,
not transport/dispatcher errors. Disconnect drains owned references.
See the [bounded contract/ABI](docs/com-object-slice.md) and
[owned local-server fixture](native/fixtures/com-scalar/README.md).
Its explicit `--demo-com` host driver reuses the PID demo's private-prefix
lifecycle and retains one-shot caller evidence without inferring native-oracle
parity or inventing an unavailable generated trace.
With a hash-pinned native oracle, the driver compares all four HRESULT/output
cells before reporting native parity. The owned SYSTEM r05 run matched the r03
Automation baseline, including zero output on E_INVALIDARG, and passed the
actual official `whiny trace` schema/completeness gate; see the
[bounded evidence](docs/com-object-slice.md#supporting-runtime-evidence).
Source tests and fixture builds alone do not prove this. This is not
general WinRT, GamingServices or unchanged-app A04 support.

### Bounded WinRT factory and instance slice

`winrt-u32-v1` adds separate factory/instance leases through a pinned,
thread-scoped registration-free context and real RoGetActivationFactory.
The native SYSTEM r01 oracle observes unchanged caller output on E_INVALIDARG,
distinct from COM Automation's zero writeback. The `--demo-winrt` driver requires
that hash-pinned native baseline and official trace validation before reporting
six-cell parity. Generated live acceptance is pending; see
[the scope, metadata and evidence](docs/winrt-object-slice.md).

The admission crate's historical scalar/correlated test-authority machinery is
behind `test-authority`; it is not compiled into this product by default. Core
bundle, path, hash, actor and operation checks remain mandatory. The previous
state/doctor/receipt CLI requires `wvb-runtime/legacy-admin`. The old synthetic
UTM/CrossOver call/benchmark launchers were replaced by the single explicit
generated-call driver; historical artifacts remain unchanged.

## Source checks

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
- Historical `Whiny-Windows11-x64` readiness, package lifecycle and scalar
  topology evidence is retained but explicitly unqualified. Its post-hoc
  receipts are invalid, and current-build pre-authorized Windows acceptance is
  pending a stable target. The source-only scalar test-authority handoff is now
  consumed exactly, but remains `development-only`, `support_claim: none` and
  `runtime_support: false`; it does not qualify the historical guest evidence.
- Shell-hook, NT wait-completion, ALPC and other unfrozen profiles remain
  explicitly unsupported until Whiny supplies reviewed exact identities and
  commands.
- The previous CrossOver by-name unixlib experiment failed with
  `STATUS_INVALID_INFO_CLASS` and is not retried unchanged. The supported
  source composition now uses a Wine loader-initialized builtin DLL/unixlib
  pair, not a private memory-information-class load. Source tests and the PE
  caller build do not qualify the pair. An isolated SDK subset and x64 pair
  have now been built from CodeWeavers' official 26.3.0 source archive;
  compatibility with installed build 39832, per-bottle activation and the
  real-app receipt remain outstanding.
- Scalar client calls require exact frozen operation-schema bindings.
  Dispatcher execution errors are rejected before body copies; target API
  error values in valid typed results remain distinct. See the
  [client FFI contract](docs/architecture.md#client-ffi-operation-and-error-contract).
  Bounded-memory wire/typed-dispatch integration and protected resident-target
  composition remain incomplete; no new admission schema is introduced.
- Signing identities, notarization, hosted CI billing and publication remain
  external human-controlled release holds.

## Documentation

- [Runtime path and limitations](docs/implementation-ledger.md)
- [Architecture](docs/architecture.md)
- [Security](SECURITY.md)
- [Evidence](docs/evidence.md)
- [Research sources](docs/research-sources.md)

The project does not ship third-party SDKs, DLLs, credentials, application
files or private configuration. Use only systems and software you are
authorized to operate.
