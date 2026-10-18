# WinAPI VM Bridge — Canonical Implementation Ledger

> **Repository:** `dragoshont/winapi-vm-bridge`  
> **Observed checkout:** `canonical-runtime` at `e6ce707b6fd6152f50d5ff0256f5e94d757dcace`  
> **Public `main` observed at:** `21d1d484b964965afe44397c6e99d170237cd17e`  
> **Ledger date:** 2026-10-18  
> **Disposition:** advisory/read-only; no repository changes, builds, agents, posts, deployments, or runtime mutations were performed.  
> **Normative sources:** live canonical-status canvas; current repository; external transport report; Architrave rubric and backend/operations packs. The repository has no `architrave.config.json`; therefore no repository-specific Architrave backend/IaC commands or contracts could be loaded.  
> **Notation:** **[D]** is a binding decision. **[AC]** requires confirmation by the independent adversarial review before implementation begins. **[STOP]** is a hard implementation stop, not permission to improvise.

---

## 0. Plan tournament

Scores are `1` best and `5` worst.

| Candidate | Description | Contract drift | Blast radius | Migration / rollback | Test burden | Operator approval | Verdict |
|---|---|---:|---:|---:|---:|---:|---|
| A. Minimal scalar slice | Replace JSON with protocol v2, generate scalar native C DLL and dispatcher, prove one real call; defer handles, callbacks, COM, managed and EXE support | 4 | 2 | 3 | 2 | 2 | Rejected: useful as an internal checkpoint but violates “100% canonical implementation” if merged or presented as completion |
| B. Fuller canonical sequence | Freeze protocol/security/adapter contracts, implement shared runtime, then all six target families and complete marshalling/lifecycle/setup/release gates on one integration branch | 1 | 4 | 3 | 5 | 4 | **Selected**: only option matching the requested final support matrix without temporary public protocols |
| C. ADR/research-first deferral | Write ADRs and benchmarks, defer implementation until later approvals | 2 | 1 | 1 | 2 | 5 | Rejected: transport evidence is sufficient to select framed TCP; the user explicitly requested a complete executable ledger followed by implementation |
| D. gRPC/Protobuf primary | Replace transport with gRPC and generated protobuf services | 3 | 4 | 4 | 4 | 4 | Rejected: no topology-specific evidence, extra HTTP/2/channel/allocation complexity, and no demonstrated advantage for tiny ABI calls |
| E. FlatBuffers primary | Use FlatBuffers for every message from the outset | 2 | 3 | 3 | 4 | 3 | Rejected as primary: available benchmark is stale and not cross-VM; verifier/runtime/dependency costs are unjustified before project-local measurement |
| F. Preserve JSON/v1 alongside v2 | Add v2 and maintain compatibility negotiation with current JSON/v1 | 5 | 5 | 4 | 5 | 2 | Rejected: creates the prohibited parallel temporary protocol and doubles security/testing surface |

### Recommended sequence

**[D] Select Candidate B: contract-first canonical replacement on `canonical-runtime`, retained off `main` until the complete vertical path passes.**

It wins because it:

1. Defines one protocol and one adapter model before generators or UI/CLI claims bind to them.
2. Uses internal vertical checkpoints without treating them as releasable support.
3. replaces JSON/v1 atomically at final integration instead of maintaining two data planes;
4. lands operation state, diagnostics, audit receipts, preflight and rollback before setup/status claims;
5. covers all requested target families and marshalling classes;
6. preserves hard manual gates where ABI semantics cannot be proved;
7. permits autonomous implementation after one program-level sign-off and independent adversarial PASS, while retaining mandatory stop gates for identity, secrets, signing, destructive migration, and unproved ABI behavior.

---

# 1. Outcome, non-goals and terms

## 1.1 Outcome

The final release shall provide:

- A macOS/Wine client runtime and a Windows broker connected by one persistent, custom-framed, encrypted TCP protocol v2 with `TCP_NODELAY`.
- Deterministically generated unsigned proxy artifacts and matching Windows dispatchers from a normalized, hashed adapter contract.
- Supported generation/runtime backends for:
  1. native C DLL;
  2. native C++ DLL;
  3. COM/WinRT;
  4. .NET assembly;
  5. native EXE;
  6. .NET EXE.
- Contract-preserving handling for scalar values, records, strings, buffers, handles, callbacks, async operations, errors, COM identity, and explicitly modeled file/bulk transfer.
- Authorized static inspection and optional authorized dynamic tracing on Windows and macOS/Wine.
- Explicit confidence and evidence. Observation never silently becomes contract truth.
- A contract-specific AI implementation packet whenever generation cannot prove semantics.
- Append-only receipts, durable long-running-operation state, specific diagnostics, benchmark evidence, immutable held-out assessments, clean-machine packaging tests, and deterministic unsigned build hashes.
- No scaffold, TODO, fake result, mock-only behavior, or generated-but-unimplemented path counted as support.

## 1.2 Non-goals

The final product shall not claim or implement:

- arbitrary caller-selected DLL paths, exports, commands, CLSIDs, assemblies, methods, or environment variables;
- raw process pointer or OS-handle transfer;
- kernel drivers, anti-cheat bypass, DRM/licensing bypass, injected GUI remoting, arbitrary desktop interaction, or per-frame graphics remoting;
- transparent remoting of undocumented C++ ABIs, custom COM marshaling, mixed-mode C++/CLI, process-local IPC, window-message contracts, or shared memory without an explicit reviewed adapter;
- OpenCode or another subprocess/polling protocol as the transport;
- gRPC as the primary data plane;
- QEMU macOS vhost-vsock, ivshmem, ALPC, named pipes, or Unix-domain sockets as a cross-VM transport;
- externally published benchmark numbers as acceptance thresholds;
- deterministic signed bytes. Only unsigned payloads are reproducible; signing is separate and receipted.

## 1.3 Terms

- **Adapter contract:** normalized, immutable description of target identity, ABI/API, semantics, limits, permissions and tests.
- **Proxy:** Mac/Wine-side DLL, assembly or executable exposing the caller-facing contract.
- **Dispatcher:** generated Windows-side operation table and marshalling code.
- **Broker:** Windows service hosting dispatchers and invoking allowlisted targets.
- **Operation:** durable, inspectable unit for long-running work such as generation, tracing, EXE execution, async calls, update or uninstall.
- **Call:** potentially short-lived RPC invocation. Every call receives an audit receipt; only long-running/recoverable calls become durable operations.
- **Receipt:** immutable JSON/CBOR record containing hashes, state transitions and redacted evidence.
- **Broker epoch:** random 128-bit value regenerated at broker start; scopes handles and non-resumable callbacks.
- **Contract hash:** SHA-256 of canonical UTF-8 JSON with sorted keys, NFC strings, no insignificant whitespace and integers represented in decimal.
- **Support:** all family-specific acceptance tests, fresh-process differential tests, clean-machine E2E, and held-out assessment pass with no unresolved semantics.
- **AI completion packet:** frozen contract-specific task containing exact unknowns, files, symbols, tests and stop conditions. It is not support by itself.

---

# 2. Current-state inventory and disposition

## 2.1 Branch state

- `main` ends at `21d1d48…`.
- `canonical-runtime` adds:
  - `83973ec…`: static ABI inspection;
  - `e6ce707…`: contract-specific AI completion tasks.
- **[D]** Continue only on an integration branch derived from `canonical-runtime`. Public `main` remains unchanged until final integration.
- Git internals are not product files and are excluded from source-tree migration.

## 2.2 Existing files

| Existing path | Current role/status | Final disposition |
|---|---|---|
| `.github/workflows/ci.yml` | macOS portable tests plus Windows Python `kernel32` round trip | **Replace** with pinned lint/unit/fuzz/build/reproducibility/Windows/macOS/Wine/package/clean-machine/held-out matrix |
| `.gitignore` | ignores caches/build/log/token/secret/local config | **Keep and extend** for Rust/CMake/.NET/build receipts/traces/corpora/private pairing state |
| `CONTRIBUTING.md` | basic adapter contribution rules | **Migrate** to contract-first evidence, family support gates and no-support-with-unresolved-fields policy |
| `LICENSE` | Apache-2.0 | **Keep** |
| `NOTICE` | trademark and third-party disclaimer | **Keep; update provenance references** |
| `README.md` | describes Python proof as working core and generation as next step | **Replace at release** with canonical v2 truth; remove premature “included/working” claims until gates pass |
| `SECURITY.md` | short allowlist and secret guidance | **Replace** with full threat/reporting/rotation/supported-version policy |
| `config.example.yml` | v1 host/port/capability-file YAML | **Delete after migration**; replace with versioned TOML containing references, never secrets |
| `setup-mac.sh` | git clone/reset, plaintext capability prompt/file, symlink | **Replace** with signed package installer/bootstrap; no direct `curl | sh` as canonical setup |
| `setup-windows.ps1` | Git/Python requirement, scheduled task, plaintext capability display | **Replace** with signed MSI/service installer and explicit pairing window |
| `adapters/example-math.yaml` | duplicate YAML v1 example | **Delete**; JSON is the sole canonical contract form |
| `bin/winapi-vm-bridge` | shell CLI routing to Python scripts | **Replace** with native `wvb` CLI |
| `docs/adapter-guide.md` | high-level adapter workflow | **Migrate** |
| `docs/adapter-inference.md` | static/trace concept; trace marked future | **Replace** with exact evidence/confidence/redaction contract |
| `docs/architecture.md` | proof architecture and historical game evidence | **Migrate**; separate historical evidence from canonical architecture |
| `docs/community.md` | promotional copy | **Delete from canonical implementation branch** or move to non-normative website; it is not product architecture |
| `docs/evidence.md` | historical experiment evidence | **Keep as historical, immutable appendix**; label non-release evidence |
| `docs/generic-adapters.md` | intended type model | **Replace** with generated schema reference and support matrix |
| `docs/assets/bridge-overview.svg` | conceptual diagram | **Replace/update** to show encrypted persistent TCP, broker service and generated runtime |
| `examples/example-math/adapter.json` | schema-v1 scalar example with placeholder hash | **Migrate** to v2 fixture with a deterministic built test DLL hash |
| `examples/inspection/vendor.h` | scalar/pointer/callback inspection fixture | **Keep and expand** into family fixtures |
| `mac/doctor.sh` | prints unconditional `pairedCore=true` and `doctor=ok` | **Delete/replace**; current output is not evidence-backed |
| `sdk/README.md` | skeleton generator documentation | **Replace** |
| `sdk/__init__.py` | empty Python package marker | **Delete** after Python generator migration |
| `sdk/abi_inspect.py` | useful Clang AST/header/DLL hashing proof; limited C parsing | **Migrate behavior** into canonical inspector; retain fixture parity tests, then delete Python implementation |
| `sdk/adapter.schema.json` | schema v1, DLL-only, limited types | **Replace atomically** with schema v2 |
| `sdk/generate.py` | emits review skeleton/TODO comments, not compilable support | **Delete after generator parity**; no skeleton generator remains |
| `sdk/templates/adapter.json` | v1 DLL template | **Replace** with family-specific v2 examples |
| `sdk/templates/AI_ADAPTER_PROMPT.md` | generic prompt | **Replace** with generated contract-specific packet schema/template |
| `tests/test-portable.sh` | shell checks and broad regex secret scan | **Replace** with canonical test orchestration |
| `tests/test_sdk.py` | proof tests for v1 generator/transport/inspection | **Migrate behavior**, then delete Python tests |
| `tests/windows-roundtrip.ps1` | Python `kernel32` loopback round trip | **Replace** with real packaged broker/proxy E2E |
| `winapi_vm_bridge/__init__.py` | Python proof package | **Delete after v2 E2E parity** |
| `winapi_vm_bridge/cli.py` | v1 CLI | **Delete** |
| `winapi_vm_bridge/client.py` | one connection per JSON call, plaintext capability auth | **Delete** |
| `winapi_vm_bridge/protocol.py` | custom 8-byte header, JSON, 65,535-byte limit | **Replace entirely**; must not coexist in final tree |
| `winapi_vm_bridge/server.py` | single-threaded Python broker with hard-coded operations | **Delete** |
| `windows/doctor.ps1` | unconditional doctor output | **Delete/replace** |
| `sdk/__pycache__/**`, `tests/__pycache__/**`, `winapi_vm_bridge/__pycache__/**` | generated local bytecode, including stale `inspect.cpython-314.pyc` | **Delete from working tree; never track/package** |

---

# 3. Final architecture and complete source tree

## 3.1 Binding architecture

**[D]**

```text
Application under Wine
  → generated proxy DLL / managed assembly / proxy EXE
  → libwvb_client (persistent multiplexed connection)
  → Noise-encrypted framed TCP v2, TCP_NODELAY
  → Windows service wvb-broker
  → generated dispatcher loaded by contract hash
  → pinned DLL / COM class / managed assembly / EXE
  → result, callback, operation state and receipt over same session
```

- Core runtime language: **Rust stable**, pinned in `rust-toolchain.toml`.
- Native generated ABI surfaces: C11 or target-pinned C++ with MSVC/Clang compatibility as declared by the contract.
- Managed generated surfaces: C# with pinned .NET SDK; NativeAOT is optional per target, not assumed.
- Build orchestration: CMake presets for generated native targets, Cargo workspace for runtime/tooling, `dotnet` for managed targets.
- Durable broker state: SQLite in WAL mode with bounded busy timeout and `BEGIN IMMEDIATE` for state transitions.
- Shared schema/code generation: Rust generator emits Rust/C/C++/C# codecs from the one contract IR.
- No public HTTP/admin dashboard is required. CLI status commands expose setup, inventory, operations, diagnostics and audit truth.

## 3.2 Final tree

```text
/
├── .github/workflows/
│   ├── ci.yml
│   ├── fuzz.yml
│   ├── reproducible.yml
│   └── release.yml
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml
├── CMakeLists.txt
├── CMakePresets.json
├── Directory.Build.props
├── global.json
├── schemas/
│   ├── adapter-v2.schema.json
│   ├── protocol-v2.schema.json
│   ├── evidence-v1.schema.json
│   ├── operation-v1.schema.json
│   └── receipt-v1.schema.json
├── crates/
│   ├── wvb-protocol/
│   │   └── src/{lib.rs,envelope.rs,codec.rs,messages.rs,limits.rs,error.rs,state.rs}
│   ├── wvb-crypto/
│   │   └── src/{lib.rs,noise.rs,identity.rs,pairing.rs,storage.rs}
│   ├── wvb-client/
│   │   └── src/{lib.rs,connection.rs,multiplex.rs,callbacks.rs,handles.rs,operations.rs}
│   ├── wvb-broker/
│   │   └── src/{main.rs,service.rs,listener.rs,session.rs,dispatch.rs,policy.rs,limits.rs}
│   ├── wvb-state/
│   │   ├── src/{lib.rs,db.rs,event.rs,operation.rs,receipt.rs,audit.rs}
│   │   └── migrations/{0001_expand.sql,0002_import_v1.sql}
│   ├── wvb-inspect/
│   │   └── src/{main.rs,pe.rs,clang.rs,pdb.rs,clr.rs,typelib.rs,evidence.rs,confidence.rs}
│   ├── wvb-trace/
│   │   └── src/{main.rs,authorize.rs,detours.rs,frida.rs,shape.rs,redact.rs,merge.rs}
│   ├── wvb-ir/
│   │   └── src/{lib.rs,adapter.rs,types.rs,semantics.rs,normalize.rs,validate.rs}
│   ├── wvb-generate/
│   │   └── src/{main.rs,receipt.rs,ai_packet.rs,native_c.rs,native_cpp.rs,com.rs,dotnet.rs,exe.rs}
│   ├── wvb-cli/
│   │   └── src/{main.rs,setup.rs,doctor.rs,pair.rs,inspect.rs,generate.rs,operation.rs,audit.rs,benchmark.rs}
│   └── wvb-bench/
│       └── src/{main.rs,matrix.rs,metrics.rs,report.rs}
├── native/
│   ├── include/wvb_client.h
│   ├── client-ffi/src/lib.rs
│   ├── broker-host/include/wvb_dispatcher.h
│   ├── trace-detours/
│   └── fixtures/{c-dll,cpp-dll,com-server,native-exe}
├── managed/
│   ├── Wvb.Client/
│   ├── Wvb.DispatchHost/
│   ├── Wvb.Generator/
│   └── fixtures/{ManagedLibrary,ManagedExe,WinRtComponent}
├── generator/templates/
│   ├── native-c/
│   ├── native-cpp/
│   ├── com/
│   ├── dotnet-library/
│   ├── native-exe/
│   ├── dotnet-exe/
│   └── AI_IMPLEMENTATION_PACKET.md
├── protocol/
│   ├── v2.md
│   ├── message-ids.csv
│   ├── golden/
│   └── fuzz-corpus/
├── adapters/
│   └── fixtures/*.adapter.json
├── packaging/
│   ├── macos/{pkg,launchd,entitlements}
│   ├── windows/{msi,service,firewall}
│   └── manifests/
├── benchmarks/
│   ├── topology.toml
│   └── baselines/.gitkeep
├── tests/
│   ├── unit/
│   ├── property/
│   ├── contract/
│   ├── differential/
│   ├── compatibility/
│   ├── chaos/
│   ├── e2e/
│   ├── clean-machine/
│   ├── held-out/
│   └── scripts/
├── docs/
│   ├── architecture.md
│   ├── protocol-v2.md
│   ├── adapter-contract.md
│   ├── inspection-and-tracing.md
│   ├── security.md
│   ├── operations.md
│   ├── setup-macos.md
│   ├── setup-windows.md
│   ├── rollback-uninstall.md
│   ├── support-matrix.md
│   ├── reproducible-builds.md
│   ├── performance.md
│   ├── release.md
│   ├── examples/
│   └── historical/evidence.md
├── examples/
│   ├── native-c/
│   ├── native-cpp/
│   ├── com/
│   ├── dotnet-library/
│   ├── native-exe/
│   └── dotnet-exe/
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── NOTICE
```

---

# 4. Canonical protocol v2

## 4.1 Transport and codec decision

- **[D] Transport:** persistent bidirectional TCP over the VM virtual NIC/explicit loopback forwarding, with `TCP_NODELAY`, keepalive, bounded reconnect backoff and one multiplexed connection per broker identity.
- **[D] Encryption/authentication:** Noise `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`.
- **[D] Primary codec:** generated deterministic packed tagged fields, not JSON, Protobuf, gRPC or FlatBuffers.
- Packed encoding is selected because the contract is closed and generated, tiny calls matter, deterministic byte representations are required, and applicable evidence does not establish a FlatBuffers advantage across this topology.
- FlatBuffers may replace the packed payload codec only through a future protocol-major decision after the benchmark gate in §14. It is not an optional parallel codec in v2.

## 4.2 Wire envelope

Every decrypted Noise transport record contains one 80-byte little-endian header followed by `payloadLength` bytes.

| Offset | Field | Type | Rule |
|---:|---|---|---|
| 0 | `magic` | `[u8;4]` | ASCII `WVB2` |
| 4 | `headerBytes` | `u16` | exactly `80` |
| 6 | `major` | `u8` | exactly `2` |
| 7 | `minor` | `u8` | negotiated, initially `0` |
| 8 | `messageType` | `u16` | registry value |
| 10 | `flags` | `u16` | only negotiated bits accepted |
| 12 | `connectionEpoch` | `u64` | random per connection, echoed by peer |
| 20 | `streamId` | `u32` | `0` control; nonzero call/callback/transfer stream |
| 24 | `sequence` | `u32` | starts at zero per stream; strictly increments |
| 28 | `messageId` | `[u8;16]` | UUIDv7 bytes; unique per sender identity |
| 44 | `correlationId` | `[u8;16]` | request ID or all zero when not a response |
| 60 | `deadlineUnixMs` | `u64` | zero only for allowed control messages |
| 68 | `payloadLength` | `u32` | at most 1,048,576 |
| 72 | `uncompressedLength` | `u32` | initially equal to payload length; compression flag forbidden in minor 0 |
| 76 | `reserved` | `u32` | zero on send; nonzero rejected in v2.0 |

Noise record length is a big-endian `u32` outside the ciphertext and may not exceed `1,048,672` bytes including header and authentication overhead. The receiver validates record length before allocation.

## 4.3 Packed payload encoding

Payload prefix:

```text
schemaId:u32 | schemaVersion:u16 | fieldCount:u16
repeated fieldCount times:
  tag:u16 | wireType:u8 | fieldFlags:u8 | length:u32 | value:length
```

Rules:

- Fields are emitted in ascending tag order.
- Duplicate known scalar tags are malformed.
- Unknown tags and unknown message types are ignored only when the envelope marks them `OPTIONAL`; required unknown control messages close the connection with `UNSUPPORTED_REQUIRED_FEATURE`.
- Wire types: `1=u8`, `2=u16`, `3=u32`, `4=u64`, `5=i32`, `6=i64`, `7=f32`, `8=f64`, `9=bool`, `10=bytes`, `11=utf8`, `12=uuid128`, `13=nested`, `14=repeated`.
- Integers are little-endian; booleans are exactly `0` or `1`; floats preserve IEEE bits.
- UTF-8 must be well formed; contract-specific UTF-16 values use bytes plus explicit code-unit count and permit contract-declared unpaired-surrogate behavior.
- Required fields missing or malformed fail that message with a specific protocol error.
- Canonical re-encoding must be byte-identical.

## 4.4 Message registry

| ID | Symbol | Direction / purpose |
|---:|---|---|
| `0x0001` | `HELLO` | negotiate minor, limits, features, identity and broker epoch |
| `0x0002` | `HELLO_ACK` | selected values or incompatibility |
| `0x0003` | `PING` | liveness with monotonic sender timestamp |
| `0x0004` | `PONG` | liveness response |
| `0x0005` | `GOAWAY` | graceful drain reason and last accepted stream |
| `0x0006` | `WINDOW_UPDATE` | add connection/stream receive credit |
| `0x0007` | `ERROR` | protocol/session-level error |
| `0x0100` | `CALL_BEGIN` | adapter hash, operation ID, request schema, idempotency key |
| `0x0101` | `CALL_DATA` | one bounded argument/body chunk |
| `0x0102` | `CALL_END` | request complete |
| `0x0110` | `CALL_RESULT_BEGIN` | native status and output schema |
| `0x0111` | `CALL_RESULT_DATA` | output chunk |
| `0x0112` | `CALL_RESULT_END` | terminal receipt hash |
| `0x0120` | `CANCEL` | cancel target message/operation with reason |
| `0x0121` | `CANCEL_ACK` | accepted, too-late, unsupported or unknown |
| `0x0200` | `CALLBACK_REGISTER` | callback contract, lease and threading mode |
| `0x0201` | `CALLBACK_INVOKE` | reverse call |
| `0x0202` | `CALLBACK_RESULT` | reverse-call result |
| `0x0203` | `CALLBACK_UNREGISTER` | revoke callback lease |
| `0x0300` | `HANDLE_CLOSE` | close opaque handle |
| `0x0301` | `HANDLE_STATUS` | close result/stale status |
| `0x0400` | `OPERATION_QUERY` | query durable operation |
| `0x0401` | `OPERATION_STATE` | operation snapshot plus event cursor |
| `0x0402` | `RECEIPT_QUERY` | query idempotency/receipt outcome |
| `0x0403` | `RECEIPT_RESULT` | immutable receipt or unknown |
| `0x0500` | `PAIR_CLIENT` | accepted only inside explicit pairing window |
| `0x0501` | `PAIR_RESULT` | client identity registration outcome |

## 4.5 Call state machine

```text
IDLE
 → CALL_BEGIN
 → RECEIVING_REQUEST (zero or more CALL_DATA)
 → CALL_END
 → QUEUED
 → RUNNING
 → RESULT_BEGIN
 → SENDING_RESULT (zero or more RESULT_DATA)
 → RESULT_END
 → TERMINAL
```

Alternative transitions:

- `RECEIVING_REQUEST|QUEUED|RUNNING → CANCEL_REQUESTED`.
- `CANCEL_REQUESTED → CANCELED` only after dispatcher confirms no further target mutation.
- `CANCEL_REQUESTED → COMPLETED_TOO_LATE` if the native call already completed.
- Disconnect invalidates connection-scoped handles/callbacks. Durable operations continue only when the adapter declares `disconnectPolicy=continue`; otherwise cancellation is attempted and final state is recorded.
- The client may not infer success from disconnect, timeout or `CANCEL_ACK`.

## 4.6 Callback state machine

```text
UNREGISTERED → REGISTERED → INVOKING(n) → REGISTERED → UNREGISTERING → CLOSED
```

- Each registration has `callbackId`, contract hash, lease deadline, maximum concurrent invocations, ordering mode and reentrancy mode.
- `serial` ordering permits one invocation at a time. `parallel` requires an explicit maximum.
- Reentrant calls are rejected unless `reentrant=true`.
- Callback invocation uses a distinct stream and deadline.
- Disconnect closes all non-durable callback registrations. Late invocations return `CALLBACK_GONE`.
- Native callback thread evidence is preserved. If the original API requires an exact thread/apartment and the proxy cannot reproduce it, generation stops.

## 4.7 Limits and backpressure

| Limit | Canonical value |
|---|---:|
| frame payload | 1,048,576 bytes |
| ordinary logical call request/result | 16 MiB each unless lower contract bound |
| explicit bulk/file stream | 1 GiB |
| concurrent streams per connection | 128 |
| queued calls per client | 256 |
| callbacks per session | 1,024 |
| handles per session | 65,536 |
| nesting depth | 32 |
| fields per payload | 4,096 |
| string bytes | contract bound, hard maximum 16 MiB |
| call deadline | 1 ms–300 s; EXE contract may allow 24 h |
| handshake timeout | 10 s |
| idle timeout | 120 s; PING after 30 s inactivity |
| replay-receipt retention | 24 h or contract-declared longer |
| pairing attempts | 5 per 10 minutes per source and 20 globally |
| authentication failures | connection closed without detailed oracle |

- Initial connection credit: 8 MiB; initial stream credit: 2 MiB.
- Sender may not exceed granted credit. `WINDOW_UPDATE` is sent after consumption, not receipt.
- Bounded broker queues reject with `RESOURCE_EXHAUSTED`, `retryAfterMs`, queue depth and limit.
- No unbounded per-client task spawning.

## 4.8 Chunking

- Payload chunks are at most 1 MiB and carry `chunkIndex`, `offset`, `logicalLength`, `chunkHash`, and `final`.
- Offsets must be contiguous unless the contract explicitly allows sparse file transfer.
- Final logical SHA-256 is supplied in `CALL_END`/`RESULT_END`.
- Duplicate chunks with the same index and hash are idempotently ignored; conflicting duplicates terminate the stream.
- Reassembly writes large bodies to broker-owned temporary files, not one contiguous allocation.
- Temporary files are owner-only, quota-bounded and removed on terminal state/startup reconciliation.

## 4.9 Deadlines, cancellation, reconnect and idempotency

- Deadlines are absolute UTC milliseconds plus receiver-side monotonic budget derived at receipt. Clock skew greater than five minutes is diagnostic, not a reason to extend work.
- Cancellation is cooperative unless the target family has a proven safe cancellation primitive. Forced thread termination is forbidden.
- Each effecting call requires a 128-bit idempotency key scoped to `(clientIdentity, adapterHash, operationId)`.
- Repeated keys return the prior receipt or current operation; different request hashes with the same key return `IDEMPOTENCY_CONFLICT`.
- Automatic replay after reconnect is allowed only for `idempotency=read-only|exactly-once-receipted`.
- Non-idempotent unknown outcomes return `OUTCOME_UNKNOWN`; they are never blindly retried.
- Reconnect uses full-jitter delays of 100 ms, 200 ms, 400 ms, 800 ms, 1.6 s, capped at 30 s.
- Handles include `brokerEpoch`, `ownerSessionId`, `slot`, and `generation`; broker restart makes old epochs stale.
- Durable operation queries survive reconnect; raw streams, callbacks and handles do not.

## 4.10 Error model

`WvbError` fields:

```text
domain, code, message, stage, retryClass, nativeDomain, nativeCode,
correlationId, operationId?, remediation?, evidenceIds[], details{}
```

Domains include `protocol`, `auth`, `policy`, `contract`, `transport`, `marshal`, `native`, `com`, `managed`, `process`, `storage`, `resource`, `timeout`, `canceled`, `internal`.

- Native errors preserve `HRESULT`, Win32 `GetLastError`, NTSTATUS, C++/SEH classification, managed exception type/HResult, and process exit status separately.
- User-facing messages are redacted. Exact internal evidence is available only through authorized diagnostic receipts.
- Unknown fields are ignored; malformed required fields are rejected specifically.
- Catch-all “pipeline failed” errors are prohibited.

## 4.11 Pairing, crypto and threat model

- Broker generates a static X25519 identity at installation and stores the private key with Windows DPAPI machine protection and service ACL.
- Mac client static identity is stored in Keychain; no plaintext capability file remains.
- Pairing requires an explicit ten-minute local pairing window opened by an administrator. The broker displays a 256-bit random PSK once through the local setup UI/console.
- Noise XXpsk3 proves PSK possession and exchanges static identities. Successful pairing stores the client public key, display label, creation time and revocation state.
- Subsequent sessions use the stored peer identity and a fresh one-time handshake PSK derived from the pairing secret via HKDF; transport nonces prevent record replay.
- Pairing secrets, private keys, payloads, identifiers and tokens never enter logs or receipts.
- Capability revocation is by client public-key fingerprint.
- Threats addressed: unauthenticated LAN callers, malicious/malformed clients, replay, oversized allocation, queue exhaustion, path/export substitution, DLL preloading, downgrade, stale handles, callback floods, secret leakage and update rollback.
- Out of scope: compromised Mac user account, compromised Windows administrator/kernel, malicious allowlisted target code, physical memory extraction.
- **[AC]** Cryptographic construction, DPAPI/Keychain access boundaries, pairing UX, firewall scope and update signing require adversarial security approval before implementation proceeds past the security gate.

---

# 5. Adapter contract and deterministic build receipts

## 5.1 Schema v2 top-level fields

`schemas/adapter-v2.schema.json` shall require:

```json
{
  "schemaVersion": 2,
  "adapterId": "vendor.product",
  "adapterVersion": "1.2.3",
  "family": "native-c-dll",
  "architectures": ["x86_64"],
  "target": {},
  "sources": [],
  "types": {},
  "operations": [],
  "security": {},
  "runtime": {},
  "tests": {},
  "evidence": {},
  "support": {}
}
```

Required target identities by family:

- Native DLL: basename, PE machine, timestamp policy, SHA-256, export name/ordinal, loaded-path policy.
- COM/WinRT: CLSID/runtime class, IID set, typelib/WinMD hashes, server path hash and threading model.
- .NET: assembly name/version/culture/public-key token/MVID/SHA-256/target framework.
- EXE: basename, SHA-256, architecture, argv grammar, working-directory policy and child-process policy.

Every operation shall define:

- stable numeric `operationId`;
- source symbol and caller-visible signature;
- calling convention and architecture;
- parameter/return type references;
- ownership, nullability, direction, lengths, alias groups and allocator pair;
- timeout, idempotency, disconnect and cancellation policy;
- sensitivity labels;
- required role/capability;
- native errors and last-error behavior;
- callback/async/handle effects;
- exact local-oracle, remote-parity and adversarial tests.

`replace-at-install` is forbidden in release contracts. Fixture contracts may reference a build receipt that resolves the exact hash.

## 5.2 Deterministic receipt

`BuildReceiptV1` includes:

- receipt schema/version and generator Git commit;
- canonical contract hash;
- every input relative path, media type and SHA-256;
- normalized Clang/PDB/TLB/WinMD/CLR inspection evidence hashes;
- generator, Rust, Clang/LLVM, MSVC, Windows SDK, CMake, Ninja and .NET versions;
- target triple, architecture, language mode, ABI, compiler/linker flags;
- environment allowlist and normalized source root;
- generated-file hashes;
- object and unsigned final artifact hashes;
- export table, PE section/layout and managed public API hashes;
- test vector and test-result receipt hashes;
- unresolved list, which must be empty for support;
- signature metadata in a separate `SigningReceiptV1`.

Determinism rules:

- `SOURCE_DATE_EPOCH` fixed to the contract commit time;
- `/Brepro`, deterministic managed build, stable GUID/MVID strategy, sorted operations/exports, normalized paths and no absolute debug paths;
- two clean builds in distinct directories must produce identical unsigned hashes;
- Authenticode/notarization timestamps and signatures are not part of the unsigned equality check.

---

# 6. Static inspection and evidence confidence

## 6.1 Inspection inputs

- C/C++ headers through pinned Clang AST and target-specific flags.
- PE export/import/resource/load-config data.
- PDB type and symbol records where authorized.
- CLR ECMA-335 metadata, assembly references, P/Invoke, generic constraints, nullable annotations and PDBs.
- IDL/MIDL source, TLB through `ITypeLib/ITypeInfo`, and WinRT `.winmd`.
- Target hashes and architecture for every evidence source.

## 6.2 Confidence model

Each semantic claim records:

```text
claimId, subject, property, value, confidence, evidenceIds[],
contradictingEvidenceIds[], reviewer, reviewedAt, expiresOnTargetHashChange
```

Confidence values:

- `authoritative`: declared by signed vendor IDL/header/docs plus matching binary.
- `structural`: mechanically present in PE/PDB/CLR/TLB/WinMD.
- `observed`: seen in authorized traces.
- `inferred`: correlation supported by multiple traces but not authoritative.
- `unknown`: unresolved.

Only `authoritative` or `structural` claims may generate ABI layout automatically. Ownership, allocator, callback thread, COM apartment, aliasing and cancellation require authoritative evidence or explicit human-reviewed contract annotations. Observed/inferred evidence may propose annotations but cannot silently approve them.

## 6.3 Required output

`wvb inspect` emits:

- normalized IR candidate;
- exact evidence records;
- conflicts and unknowns;
- static loaded-target expectations;
- generated test vectors;
- a supportability classification;
- no generated proxy when ABI-affecting unknowns remain.

---

# 7. Authorized dynamic tracing and inference

- Tracing is opt-in, target-hash-bound and local to systems the operator is authorized to inspect.
- Windows native tracing uses Microsoft Detours in a purpose-built signed/explicitly loaded probe.
- Frida may be used on Windows or macOS/Wine only when explicitly enabled and recorded; it is never bundled as a hidden/background component.
- Traces collect shapes and lifecycle evidence, not unrestricted payloads:
  - pointer identity token, null/non-null, region size, protection and alias group;
  - before/after hash and changed byte ranges;
  - explicit length arguments;
  - allocation/free pairing and module;
  - thread/apartment ID class;
  - callback ordering, nesting and timing;
  - handle create/use/close sequence;
  - async begin/completion/result/cancel sequence;
  - loaded module canonical path and SHA-256.
- Default redaction excludes string/body contents, credentials, account IDs, capabilities, tokens, signatures and private keys.
- Sensitive bytes may not be retained merely because tracing can see them.
- Each trace has authorization scope, target hash, probe hash, start/end, redaction policy and destruction deadline.
- Three or more varied traces may raise a hypothesis from `unknown` to `inferred`; they cannot make it `authoritative`.
- Contradictory traces lower confidence and block generation.
- **[STOP]** Rare callback behavior, allocator ownership, custom `IMarshal`, apartment affinity, nested aliasing or destructive side effects that remain unproved produce an AI packet and manual gate.

---

# 8. Generation and runtime by target family

| Family | Generated caller artifact | Windows dispatcher | Mandatory proof |
|---|---|---|---|
| Native C DLL | PE DLL with exact exports, calling convention, ordinals and ABI | typed function-pointer invocation from pinned DLL | export-table equality, struct layout, local-vs-remote fresh-process differential |
| Native C++ DLL | compiler/architecture-specific shim preserving decorated names and declared ABI | same compiler ABI dispatcher | compiler version pin, name/vtable/layout proof; C++ exception crossing prohibited unless exact proof exists |
| COM/WinRT | in-process COM proxy implementing declared IIDs / WinRT projection | apartment-aware COM activator and interface table | QI identity, AddRef/Release, apartment/reentrancy, VARIANT/SAFEARRAY/BSTR parity |
| .NET assembly | assembly matching public API and strong-name policy | isolated managed dispatch host | public API hash, overload/generic/async/exception parity, load-context and dependency hash gate |
| Native EXE | proxy EXE preserving approved argv/env/stdin/stdout/stderr/exit semantics | owned process-tree runner in a Windows Job Object | argument quoting, streaming I/O, timeout/cancel, child cleanup, exact exit status |
| .NET EXE | managed proxy EXE or native launcher as contract declares | managed process runner / assembly entry host | same process contract plus runtime/assembly identity |

- Side-by-side placement is canonical. PE import-table patching is not.
- Native C++ support is per pinned compiler ABI, never a universal claim.
- COM local servers, UI/message pumps and custom marshaling require explicit contracts.
- EXE environment is default-deny allowlist. Interactive desktop access is off.
- Windows Job Object uses kill-on-close, process-count/memory/CPU limits and complete child-tree accounting.
- Managed dispatch runs in a fresh process where unload/isolation cannot be proved in-process.

---

# 9. Marshalling matrix

| Category | Canonical representation and requirement | Unsupported/stop condition |
|---|---|---|
| Integers/floats/bool | fixed-width wire values; explicit native width/sign; IEEE bit preservation | ABI-dependent `long`, `size_t`, `wchar_t` without target architecture |
| Enum/flags | underlying width plus allowed/unknown-value policy | generator must not reject unknown bit flags when contract permits forward compatibility |
| Records | field offsets, total size, alignment, packing, endianness and padding policy | missing authoritative layout |
| Unions | discriminator plus active arm; raw union only with exact size and arm contract | unknown active arm |
| Bitfields | compiler/architecture layout explicitly recorded and tested | portable inference from source spelling alone |
| UTF-8/ANSI | byte count, terminator policy, code page and invalid-sequence behavior | unspecified code page |
| UTF-16/BSTR/HSTRING | code-unit length, terminator/embedded-null rules, allocator semantics | conflation of BSTR/HSTRING/plain buffer |
| Buffers | in/out/inout, capacity, produced/required length, maximum and insufficient-buffer behavior | unbounded pointer |
| Pointer graph | object IDs, node/edge limits, alias groups, nullability and ownership | cycles/aliasing without reviewed graph contract |
| Allocators | named allocator/deallocator pair and ownership transfer | unknown freeing side |
| Opaque handles | broker epoch, owner, slot, generation, type and close operation | raw HANDLE/pointer on wire |
| Transferable OS resources | broker-side use only or copied semantic data | arbitrary duplicated OS handle across VM |
| Callbacks | callback ID, signature, lease, thread/apartment, order, concurrency, reentrancy and unregister | unknown callback lifetime/thread |
| Async | begin/completion/result/cancel state machine and durable operation when needed | completion inferred from timeout or disconnect |
| COM identity | stable remote object ID, IID, QI table, distributed lease/ref accounting | custom `IMarshal` without reviewed adapter |
| COM refcount | local proxy refcount batched to remote with final release receipt | claiming exact instantaneous distributed refcount |
| Apartments | STA executor/message pump or MTA pool as contract declares | unknown threading model |
| Exceptions | native exception/SEH never crosses directly; mapped to declared error preserving code | arbitrary C++ exception ABI |
| `GetLastError` | capture immediately after target call and set caller thread’s last error before return | another API call between target return and capture |
| HRESULT/NTSTATUS | preserved separately from transport status | collapsing native failure into generic RPC error |
| Files | content-addressed chunk stream plus metadata and explicit path policy | transmitting arbitrary host paths |
| Shared buffers | copy/chunk semantics in v2; no cross-VM shared-memory claim | zero-copy/shared-memory claim on QEMU/macOS |
| Sensitive outputs | contract sensitivity and memory/log policy | password/private-key export |

---

# 10. Mac/Wine shim and Windows broker runtime

## 10.1 Mac/Wine

- `libwvb_client` owns one process-wide connection pool keyed by broker identity.
- Generated proxies validate caller pointers before serialization, but guarded copying must convert invalid caller memory into the declared native failure rather than crash the broker.
- Thread-local last-error state is restored before returning.
- Callback dispatch uses contract-declared worker, caller-thread rendezvous, STA or explicit event-loop strategy.
- Client queues are bounded and expose `BUSY`/native equivalent rather than blocking indefinitely.
- At-fork/process-exit hooks close sessions without unsafe network work in loader-lock contexts.
- DLL entry points perform no network connection or blocking work under loader lock.

## 10.2 Windows broker

- Runs as a least-privileged Windows service account, not administrator.
- Loads dispatchers from an administrator-writable, service-readable store.
- Before load, resolves canonical path, rejects reparse traversal, opens with no-follow semantics where available, verifies hash/signing policy and verifies the loaded module path/hash again after load.
- Dispatchers receive typed broker-owned buffers, not the raw socket.
- Dangerous targets may run in per-adapter worker processes with Job Object, token and resource limits.
- SQLite stores operations/events/receipts; dispatch threads never hold database locks during native calls.
- Startup reconciliation marks abandoned non-resumable work `unknown`/`failed` with evidence; it never fabricates completion.
- Broker exposes readiness separately from health:
  - readiness: listener, identity, database, dispatcher catalog and queue capacity;
  - health: dependency checks, stale operations, disk quota, update state and recent failures.

---

# 11. Setup, doctor, networking, update, rollback and uninstall

## 11.1 Setup sequence

1. Install signed Windows MSI.
2. MSI installs service, data directories, ACLs and a firewall rule scoped to the VM/private profile and configured broker port.
3. Service generates identity and remains unpaired.
4. Administrator runs `wvb pair open`; preflight shows listener address, firewall scope, ten-minute expiry and current clients.
5. Install signed/notarized macOS package containing `wvb` and Wine runtime.
6. `wvb pair <host>` performs Noise pairing and stores identity in Keychain.
7. `wvb doctor` verifies route, peer fingerprint, protocol, readiness, catalog, clock skew and a real fixture call.
8. Adapter installation performs preflight, hash verification, deterministic receipt verification and atomic catalog activation.

## 11.2 Doctor output

Every check contains:

```text
checkId, scope, status, source, checkedAt, reason, remediation, evidenceId
```

Statuses: `pass`, `warning`, `blocked`, `fail`, `unknown`. No unconditional `doctor=ok` or `pairedCore=true`.

## 11.3 Update and rollback

- Packages use signed manifests with version, content hashes, minimum compatible schema and rollback eligibility.
- Update stages: download → signature verify → preflight → quiesce → backup state/catalog → install inactive version → health probe → atomic activate.
- Failure restores the prior binary/catalog and records an operation receipt.
- Database migrations use expand → import/backfill → contract. Destructive contract migrations require a separately approved release and verified backup restoration.
- Protocol v1 is not run in parallel. Rollback restores the complete prior v1 package and state backup; it does not make v1 and v2 simultaneously reachable.

## 11.4 Uninstall

- Preflight lists service, firewall rule, paired clients, adapters, operation history and retained receipts.
- Stop service, cancel/mark operations according to policy, remove package/firewall/service.
- Secrets are deleted from DPAPI/Keychain only after explicit confirmation.
- Audit export is optional and redacted.
- Uninstall receipt states what was removed and what data was retained.

---

# 12. Observability, receipts, privacy and logging

## 12.1 Durable operation schema

Fields include:

- `operationId`, `type`, `actorFingerprint`, `targetIds`;
- `createdAt`, `startedAt`, `updatedAt`, `completedAt`;
- `status`: `queued|waiting|running|blocked|canceling|canceled|succeeded|failed|partial|expired|unknown`;
- ordered stages with timestamps, status, redacted message/error and evidence IDs;
- progress only when measurable;
- attempt, idempotency key hash, retry/cancel/rerun capabilities;
- artifact hashes, trace ID and receipt hash.

## 12.2 Event model

- Append-only `events` table with monotonic sequence per operation.
- Operation snapshots are derived under `BEGIN IMMEDIATE`.
- Receipt/event insertion and terminal-state transition are atomic.
- A bounded writer queue applies backpressure; audit is not silently dropped.
- Crash recovery reconciles running operations against worker/process state.

## 12.3 Log policy

Allowed by default:

- protocol/message type, adapter/operation numeric ID;
- durations, byte counts, queue depth;
- redacted error codes;
- target/build/receipt hashes;
- peer public-key fingerprint prefix.

Forbidden:

- pairing code or derived secrets;
- private keys;
- raw payloads;
- credentials, tokens, signatures, licenses;
- account/profile identifiers;
- unrestricted file paths, command lines or environment;
- callback/context pointer values.

Retention is configurable, bounded and documented. Diagnostic bundles show a manifest before export and use explicit redaction.

---

# 13. Security, fuzzing, dependencies and signing

- Default-deny operation capability tokens are bound to client identity, adapter hash, operation IDs, expiry and rate limits.
- Authorization occurs for every call, callback registration, trace, adapter install, pairing mutation, update and audit export.
- Per-client and per-operation token buckets bound calls, bytes, callbacks and failed auth.
- Fuzz targets cover the Noise record boundary, envelope, packed codec, all generated decoders, adapter validation, PE/CLR/PDB/TLB parsing, chunk reassembly and receipt import.
- Corpus includes truncation, duplicate tags, integer overflow, decompression flags, alias bombs, deep nesting, stale handles, callback storms and conflicting chunks.
- Dependency policy:
  - lockfiles committed;
  - `cargo deny` license/advisory/source policy;
  - NuGet locked mode;
  - pinned GitHub Actions by commit before release;
  - SBOM in SPDX JSON;
  - provenance attestation and source/archive hashes.
- Unsigned artifacts are reproduced first. Signing runs in a separate protected release job using referenced secret-store keys; keys never materialize in repository/logs.
- Release verifies signature, timestamp, certificate chain, unsigned hash linkage and loaded binary hash.
- **Mandatory human approval:** pairing/identity design, firewall scope, signing configuration, any PII-sensitive adapter, and any destructive data migration.

---

# 14. Performance tiers and decision gates

## 14.1 Required benchmark matrix

Actual Mac host + QEMU/UTM Windows VM:

- payloads: tiny, 4 KiB, 64 KiB, 1 MiB;
- cold and warm connection;
- sequential and bounded concurrency;
- p50/p95/p99 wall latency;
- client/broker CPU, allocations and bytes on wire;
- callback invocation and cancellation propagation;
- chunk count and reassembly cost;
- at least 1,000 measured iterations after warmup, raw samples retained;
- machine, VM, networking, power and build metadata recorded.

Fixtures:

- `core.ping`;
- real `kernel32!GetTickCount64`;
- deterministic native echo fixture;
- callback fixture;
- cancellable long operation;
- native and managed EXE stream fixtures.

## 14.2 Acceptance

- Every matrix cell completes without corruption, leak, protocol error or unbounded memory growth.
- 1 MiB request and result both pass with verified whole-message hashes.
- Cold and warm results are reported separately.
- No external number is a pass threshold.
- The release publishes measured results without implying universal performance.
- The candidate is blocked if its warm p99, CPU or allocations regress by more than 20% from the immediately preceding canonical v2 baseline without an approved correctness/security justification.
- A codec replacement requires same-machine paired A/B evidence showing either:
  - at least 15% lower total CPU with no p99 or allocation regression over 5%; or
  - at least 10% lower p99 with no CPU or allocation regression over 5%.
- **[D]** Packed generated codecs remain canonical unless this gate is met through a protocol-major review. gRPC does not become primary through this gate; it requires a separate architectural decision.

---

# 15. Complete test strategy and exact acceptance

| Layer | Required coverage | Acceptance |
|---|---|---|
| Unit | envelope, codec, IDs, deadlines, limits, errors, normalization, hashes, state transitions | all pass on macOS/Windows; no ignored release tests |
| Property | canonical encode/decode, unknown-field leniency, state-machine invariants, chunk reassembly | at least 100,000 generated cases per release seed set |
| Contract | JSON schema, IR, generated API/export tables, error mapping | every fixture and released adapter validates; no unresolved fields |
| Fuzz | protocol, parser, metadata readers, generated decoders | sanitizer-clean; each target runs at least 8 CPU-hours before release and continuous CI smoke |
| Differential | local native/managed oracle versus bridged call in fresh processes | exact value/error/output/last-error parity for every supported operation |
| Compatibility | current client/current broker, previous supported minor/current peer | all advertised minor combinations pass; no v1 compatibility claim |
| Chaos | disconnect, half-close, delay, reorder at application streams, restart, disk full, queue full, worker crash | truthful terminal/unknown states; no duplicate effect; recovery receipt exists |
| Security | auth failure, replay, downgrade, path substitution, DLL swap, callback flood, parser bombs | all rejected before side effect; specific redacted evidence |
| E2E | generated proxy loaded by real Wine process; real Windows target result consumed | complete six-family fixture suite passes |
| Clean-machine | fresh supported macOS and Windows VM from packages | setup, pair, generate/install, invoke, doctor, update rollback and uninstall pass |
| Reproducibility | two isolated unsigned builds | byte-identical artifacts and receipts |
| Held-out | frozen unseen headers/TLB/assemblies/EXEs and adversarial contracts | generator either produces passing artifact or exact AI packet; never false support |
| Packaging smoke | install/upgrade/uninstall, service, firewall, Keychain/DPAPI | no orphan service/rule/secret unless retention explicitly selected |

Mandatory adversarial cases include:

1. 1 MiB final chunk truncated after receipt.
2. Same idempotency key with a different request hash.
3. Broker restart while a handle and callback are active.
4. DLL replaced between preflight and load.
5. Cancel races with native completion.
6. COM `Release` during callback reentrancy.
7. EXE spawns a child and parent exits.
8. Managed target throws an exception containing sensitive text.
9. PDB/header disagree about packing.
10. Trace observations contradict an ownership annotation.

---

# 16. Packaging, release, support matrix, docs and examples

- macOS package: universal where practical; supported macOS versions listed explicitly; notarized release package.
- Windows package: x64 MSI initially; ARM64 only after native fixture and packaging gates pass.
- Wine support is version-bounded and tested; unsupported versions receive an honest doctor result.
- Release contains broker, CLI, client runtime, generator, schemas, docs, fixture contracts, SBOM, provenance and checksums.
- Third-party DLLs/SDKs are never redistributed without license authorization.
- Every target-family example must build a real fixture, generate a proxy, execute through the VM, and show the corresponding receipt.
- Documentation must include architecture, exact protocol, adapter authoring, evidence/confidence, tracing authorization, setup/pairing, operations/diagnostics, security, reproducibility, rollback/uninstall, limitations and support matrix.
- Status claims derive from test receipts. “Generated,” “experimental,” and “supported” are distinct.
- A target family is `supported` only after its complete family acceptance passes; otherwise it is `unsupported` or `requires-contract-specific-completion`.

---

# 17. Phase ledger and ordered dependency-safe task graph

## 17.1 Program approval model

The user explicitly requests implementation of all phases after this ledger receives independent adversarial review. Therefore this is an **approved-program** ledger rather than a one-phase roadmap.

- **Immediate phase:** P0 independent review and contract freeze.
- P1–P16 remain `not-started` until P0 passes.
- After P0 PASS and owner sign-off, P1–P16 become `approved-for-this-run` and may continue autonomously in dependency order.
- Separate ordinary approval is not required between phases.
- Mandatory human checkpoints remain for identity/secret/signing/PII/destructive-migration decisions; the P0 sign-off may satisfy them only if it explicitly approves those listed decisions without requested changes.
- Any `[STOP]`, destructive migration, scope expansion, contract change, cryptographic redesign or hidden unknown returns to adversarial review.

## 17.2 Phase ledger

| Phase | Status now | Scope | Out of scope | Exit gate | Autonomous continuation |
|---|---|---|---|---|---|
| P0 Contract/adversarial freeze | `approved-for-this-run` | review this ledger, resolve ACs, freeze protocol/schema/security | product implementation | independent PASS plus owner sign-off | yes, into P1 |
| P1 Repository/build foundation | `not-started` | pinned toolchains, workspace, gates, receipts | runtime features | clean portable build/test and reproducible fixture | yes after P0 |
| P2 Protocol/security/state | `not-started` | protocol v2, Noise, SQLite operations/audit | target invocation | protocol/security/fuzz gates | yes |
| P3 Inspection and IR | `not-started` | PE/Clang/PDB/CLR/TLB/WinMD and confidence | dynamic inference | held-out static classification gate | yes |
| P4 Scalar native vertical path | `not-started` | compilable native C proxy and dispatcher | public merge/support claim | real Wine→VM DLL result | yes |
| P5 Compound marshalling | `not-started` | records/strings/buffers/unions/errors | handles/callbacks | differential/bounds gate | yes |
| P6 Handles/resources | `not-started` | opaque handles, generations, restart behavior | callbacks/COM | stale/owner/restart gate | yes |
| P7 Callbacks/async/cancel | `not-started` | reverse RPC, leases, reentrancy, async | COM-specific identity | callback/cancel chaos gate | yes |
| P8 COM/WinRT | `not-started` | typelib/WinMD proxies and apartments | custom IMarshal without contract | COM identity/apartment suite | yes |
| P9 Managed DLL | `not-started` | .NET assembly proxy/dispatcher | C++/CLI | managed differential suite | yes |
| P10 EXE families | `not-started` | native and .NET EXE process contracts | interactive GUI remoting | Job Object/process-tree suite | yes |
| P11 Dynamic tracing/AI packets | `not-started` | authorized probes, inference, exact packets | automatic promotion of inference | redaction/conflict/held-out gate | yes |
| P12 Setup/operations/update | `not-started` | packages, service, pairing, doctor, inventory, operations, diagnostics, rollback/uninstall | public release | clean-machine lifecycle | yes |
| P13 Security/performance hardening | `not-started` | fuzz, rate limits, provenance, benchmark decision | new transport | security and benchmark gates | yes |
| P14 Full compatibility/E2E | `not-started` | six-family matrix, chaos, held-out, real DLL path | docs-only completion | all test classes green | yes |
| P15 Migration and cleanup | `not-started` | import secrets, remove v1/scaffolds/docs drift | main merge | no superseded path or false claim | yes |
| P16 Release/final integration | `not-started` | signed packages, final receipts, atomic main merge | partial release | definition of done | no further phase |

## 17.3 Ordered tasks

Each task status is `not-started` unless noted.

| ID | Files | Dependencies | Implementation and deterministic tests | Acceptance | Rollback / risk |
|---|---|---|---|---|---|
| T000 | this ledger/review artifact | none | independent reviewer checks all ACs, schemas, limits, threats and task dependencies | PASS; no unresolved architectural decision | revise ledger only; **R4 identity/security** |
| T010 | `Cargo.*`, toolchain, CMake, `global.json`, CI | T000 | create pinned workspaces and minimal real fixture builds; lock dependencies | macOS/Windows clean builds; two fixture builds identical | delete new foundation; medium dependency risk |
| T011 | `schemas/*`, `wvb-ir` | T010 | encode adapter/evidence/operation/receipt schemas and canonical normalization | golden hashes stable; invalid/unknown contracts rejected specifically | schema unshipped; high drift risk |
| T020 | `wvb-protocol`, `protocol/v2.md`, goldens | T011 | implement exact envelope, codec, limits, flow control and state machines | golden vectors cross-language identical; property tests pass | revert whole v2 crate; high caller impact |
| T021 | `wvb-crypto`, pairing tests | T020 | implement Noise, identity storage interfaces, replay/downgrade rejection | official Noise vectors plus cross-platform handshake pass | no plaintext fallback; **R4 secrets/identity** |
| T022 | `wvb-state/migrations`, state/receipt modules | T011 | create append-only events, snapshots, idempotency and reconciliation | crash/lock/duplicate tests pass; database invariant checker clean | restore backup/drop unactivated DB; data risk |
| T023 | `wvb-client`, `wvb-broker` core | T020–T022 | persistent multiplexing, bounded queues, operation status and readiness | loopback call/cancel/reconnect/queue tests pass | revert both peers atomically |
| T030 | `wvb-inspect/{pe,clang,pdb}` | T011 | migrate existing Clang behavior; add target ABI/export/layout evidence | existing fixtures plus conflicting PDB/header test pass | retain old inspector only on integration branch |
| T031 | `wvb-inspect/{clr,typelib}` | T030 | add CLR/TLB/WinMD metadata and identity extraction | deterministic evidence on managed/COM fixtures | isolate readers; malformed metadata risk |
| T032 | `evidence.rs`, `confidence.rs`, held-out static tests | T030–T031 | implement claim graph/conflict/expiry and supportability | no inferred claim becomes authoritative | rollback evidence DB schema before activation |
| T040 | `wvb-generate`, native C templates, C fixture | T023,T030 | generate exact scalar proxy/dispatcher/codecs/exports | proxy compiles; export table exact; real DLL result consumed under Wine | delete generated artifact; ABI crash risk |
| T041 | deterministic receipt/repro tests | T040 | normalize builds and emit `BuildReceiptV1` | two clean unsigned artifacts byte-identical | keep generation blocked if nondeterministic |
| T050 | IR types and C/C++ templates | T040 | add enum/flags/records/packing/unions/bitfields | local/remote differential vectors exact | per-type feature remains unsupported |
| T051 | string/buffer/file marshallers | T050,T020 | add UTF-8/16, BSTR/HSTRING forms, in/out/inout, 1 MiB chunking | null/embedded-null/insufficient/truncated/1 MiB pass | feature-gated contract rejection |
| T052 | error bridge | T050 | preserve HRESULT/Win32/NTSTATUS/SEH/exception classification and last error | fresh-process parity for each domain | do not map to generic success/error |
| T060 | handle table/client proxy | T023,T052 | implement owner/epoch/slot/generation/close/lease | wrong owner, double close, restart stale tests pass | invalidate all handles; external resource risk |
| T070 | callback registry/reverse RPC | T060 | implement leases, ordering, concurrency, reentrancy and unregister | nested, storm, late callback and disconnect tests pass | unregister/close session |
| T071 | async/cancel state machines | T070,T022 | implement begin/completion/result/cancel and durable states | cancel race never invents success; exact terminal receipt | reconcile to unknown; side-effect risk |
| T080 | COM generator/runtime | T031,T070 | QI, identity, ref batching, STA/MTA execution, VARIANT/SAFEARRAY/BSTR | COM fixture passes identity/ref/apartment/reentrant tests | COM family remains unsupported; **R4 identity/data** |
| T081 | WinRT projection | T080 | WinMD interfaces, HSTRING, async projection | WinRT fixture differential suite passes | disable family |
| T090 | managed client/dispatch host/generator | T023,T031,T071 | generate public API, overloads, async, exceptions; isolate load contexts | API hash and fresh-process differential pass | managed family unsupported |
| T100 | native EXE proxy/runner | T023,T022 | argv/env/stdin/out/err/exit plus Job Object process tree | quoting, streaming, timeout, child cleanup pass | terminate Job and mark receipt |
| T101 | managed EXE proxy/runner | T090,T100 | managed entry/process contract | same plus managed exception/runtime identity | disable managed EXE family |
| T110 | `wvb-trace` Detours/Frida | T032,T071 | authorization, probes, shape/lifecycle collection and redaction | target hash gate and zero forbidden fields in fixtures | uninstall probes/delete traces; privacy risk |
| T111 | inference merger | T110 | correlate traces, preserve contradictions/unknowns | inferred claims never auto-approve ABI | discard inference output |
| T112 | AI packet generator/template | T032,T111 | emit exact target, unknowns, files/symbols/tests/stops/build command | held-out unprovable targets yield complete packet, no TODO-only output | regenerate packet; no runtime risk |
| T120 | Windows MSI/service/firewall | T021,T023,T022 | package least-privileged service, ACLs, private-profile rule | clean VM install/readiness/uninstall pass | MSI rollback removes service/rule; **R4 network** |
| T121 | macOS package/Keychain/Wine client | T021,T023 | package CLI/runtime; Keychain identity | clean Mac install/pair/uninstall pass | package rollback removes binaries/key reference |
| T122 | CLI setup/doctor/inventory/catalog | T120,T121 | preflight, pairing, adapter install/list, sourced/timestamped checks | no unconditional status; blocked/stale states truthful | no mutation without operation receipt |
| T123 | operations/diagnostics/audit CLI | T022,T122 | list/show/watch/cancel/rerun/export with evidence | operation fields and append-only audit exposed | read-only commands safe; export privacy risk |
| T124 | update/rollback/uninstall | T120–T123 | atomic inactive install, health activate, restore, impact summary | injected update failure restores prior version/state | backup restore; destructive action approval |
| T130 | fuzz/security/rate-limit suite | T020–T124 | fuzz all boundaries; abuse and substitution tests | §15 security/fuzz gates pass | block release |
| T131 | benchmark harness and packed-codec report | T023,T051,T071 | execute exact topology matrix | complete raw/report artifacts; regression rule passes | performance does not override correctness |
| T132 | SBOM/provenance/signing pipeline | T010,T041,T124 | deterministic unsigned build then separate signing receipt | unsigned reproducibility and signature linkage pass | revoke/rebuild; **R4 signing secrets** |
| T140 | six-family E2E/compat/chaos | all family tasks,T130 | run complete matrix on actual topology | every §15 gate green | no partial support claim |
| T141 | held-out assessment | T140,T112 | immutable unseen inputs and false-support audit | compile/run or exact packet; zero false positives | revise generator and rerun all affected gates |
| T150 | migration importer and backup | T124,T140 | import plaintext v1 capability into secure stores after re-pair confirmation; backup old state | new v2 pair works before old secret deletion | restore old package/config backup |
| T151 | delete superseded source/docs | T150 | remove Python v1, YAML duplicate, skeleton/TODO docs, fake doctors and caches | repository search finds no v1 wire path or unsupported working claim | revert cleanup commit before merge |
| T152 | final docs/support matrix/examples | T151,T141 | bind every claim to receipt; publish limitations and rollback | docs and generated schemas match code | documentation-only revert |
| T160 | clean-machine release candidate | T132,T152 | install/pair/all-family examples/update rollback/uninstall | all clean-machine receipts pass | discard RC |
| T161 | final independent review | T160 | adversarial rubric, security and capability-honesty review | PASS; zero blockers/majors | return to owning task |
| T162 | atomic main integration | T161 | merge complete canonical tree only; tag signed release | main CI/release reality checks green; no partial merge | revert merge/tag/package to prior release |

---

# 18. Migration from public main and `canonical-runtime`

## 18.1 Expand

1. Branch from `canonical-runtime`; record `main` and branch hashes.
2. Add v2 workspace, schemas, tests and packages without changing public `main`.
3. Add v2 database and secure identity stores under versioned paths.
4. Preserve v1 files only as reference while v2 is incomplete; do not expose both protocols from one installed broker.

## 18.2 Migrate

1. Build the v2 vertical path and all family gates entirely on integration.
2. On upgrade, back up v1 config and capability with owner-only permissions.
3. Require explicit v2 pairing/identity confirmation.
4. Import only non-secret preferences automatically.
5. After v2 E2E succeeds, delete plaintext capability files from Mac and Windows and record presence-only deletion receipts.
6. Move historical evidence to `docs/historical/`; do not rewrite it as v2 evidence.

## 18.3 Contract

Before final merge delete:

- `winapi_vm_bridge/`;
- Python `sdk` generator/inspector after parity;
- `config.example.yml`;
- `adapters/example-math.yaml`;
- shell `bin/winapi-vm-bridge`;
- old setup scripts and fake doctor scripts;
- scaffold templates and generic TODO prompt;
- stale public claims and `__pycache__`.

No destructive data step occurs until:

- backup restoration has been tested;
- v2 pairing and core/family E2E have passed;
- uninstall/rollback receipts are verified;
- adversarial review approves secret deletion.

## 18.4 Rollback

- Before activation: remove v2 inactive package/state.
- After activation but before old-secret deletion: restore v1 package/config backup and firewall/task state.
- After old-secret deletion: rollback requires re-pairing v1; this consequence must appear in preflight and requires explicit confirmation.
- Never downgrade the v2 database in place. Restore the pre-upgrade snapshot.
- No v1/v2 dual listener is permitted.

---

# 19. Release gates and final definition of done

The project is done only when all are true:

1. Protocol v2 is the only runtime protocol.
2. JSON/v1 and its plaintext capability exchange are absent.
3. Packed codec golden/property/fuzz tests pass.
4. Noise pairing, identity storage, replay/downgrade and revocation tests pass.
5. Unsigned proxy and dispatcher artifacts reproduce byte-for-byte.
6. The loaded target path/hash equals the contract.
7. Native C, native C++, COM/WinRT, .NET assembly, native EXE and .NET EXE family fixture suites pass.
8. All marshalling matrix rows are implemented or cause explicit contract rejection/AI packets; no silent partial support exists.
9. A real Wine process loads a generated proxy and consumes a real Windows DLL result.
10. Handles, callbacks, cancellation, disconnect and broker restart behave according to their state machines.
11. 1 MiB request and result transfers pass end-to-end.
12. Setup, pairing reuse, doctor, catalog, operations, diagnostics, audit, update rollback and uninstall pass on clean machines.
13. Operations have durable state; action submission is never represented as completion.
14. Secret/PII scans, fuzzing, dependency policy, SBOM and provenance pass.
15. Benchmark matrix is published from the actual topology without external thresholds.
16. Held-out assessment has zero false support claims.
17. No mock, scaffold, TODO, fake result or unimplemented generated path is labeled supported.
18. Every public capability claim maps to a test and receipt.
19. Independent adversarial review passes with zero Blockers/Majors.
20. Only then may the complete integration branch merge atomically to `main`.

---

# 20. Do-not-build and rejected alternatives

| Rejected alternative | Evidence/reason |
|---|---|
| QEMU `vhost-vsock` on macOS | depends on Linux vhost facilities; unavailable for the target QEMU/UTM topology |
| `ivshmem`/cross-VM shared-memory ring | documented Linux-host orientation and unavailable canonical macOS path |
| Apple Virtualization.framework Windows vsock | Windows/UTM support and host interaction remain unverified; not a release dependency |
| Named pipes, ALPC or UDS as cross-VM transport | scoped to one kernel/host unless another bridge is added |
| DCOM/MIDL RPC as primary transport | no supported custom protocol-sequence plug-in for this data plane; custom marshaling remains necessary |
| gRPC primary | no topology-specific advantage; channel/HTTP2/allocation complexity; not selected without project benchmark and new ADR |
| FlatBuffers primary | stale non-topology benchmark; verifier/runtime dependency not justified; packed generated codec selected |
| Protobuf/MessagePack/Cap’n Proto parallel codecs | violate one canonical protocol and add negotiation/test surface |
| JSON/v1 compatibility listener | prohibited temporary parallel protocol and 65,535-byte hard gap |
| OpenCode/subprocess polling | Whiny provides process/evidence patterns, not a suitable low-latency transport |
| SPICE WebDAV primary bulk path | HTTP/WebDAV overhead and path/security semantics; files use canonical chunk streams |
| PE import-table patching | side-by-side generated proxy placement is safer and deterministic |
| Arbitrary `LoadLibrary`/`GetProcAddress` API | binary exports do not encode pointer ownership, bounds, callbacks or lifetime |
| Automatic ownership inference | impossible to prove from C ABI/TLB alone; dynamic observations preserve uncertainty |
| Custom `IMarshal` automatic support | wire semantics are invisible to TLB and require an explicit adapter |
| Forced thread termination for cancellation | can corrupt target state and cannot prove rollback |
| Interactive GUI/desktop EXE remoting | message loops, desktop identity and process-local IPC require explicit application-specific work |
| Shared-memory/zero-copy support claim | not available across the selected topology; v2 uses bounded copy/chunk semantics |
| Deterministic signed hash claim | signing timestamps/signatures are intentionally separate from deterministic unsigned payloads |
| Partial merge after scalar success | scalar is an internal checkpoint, not the requested canonical completion |

---

# Human-approval checklist

The owner and independent reviewer shall record explicit `GO` or `NO-GO` for each item:

- [ ] **GO:** Outcome, non-goals, terminology and six target families are complete.
- [ ] **GO:** Candidate B and the ordered P0–P16 sequence are approved.
- [ ] **GO:** Protocol v2 envelope, packed codec, limits, state machines and error model are frozen.
- [ ] **GO:** Persistent framed TCP with `TCP_NODELAY` is approved as the canonical transport.
- [ ] **GO:** Noise XXpsk3, Keychain, DPAPI, pairing window, client revocation and firewall scope are approved.
- [ ] **GO:** Packed generated codecs are approved over FlatBuffers; replacement requires the stated measured gate and protocol-major review.
- [ ] **GO:** Adapter schema, confidence model and AI packet stop behavior are approved.
- [ ] **GO:** Dynamic tracing is opt-in, authorized, hash-bound and redacted as specified.
- [ ] **GO:** Durable operation/event/receipt storage precedes setup and action-completion claims.
- [ ] **GO:** Expand → migrate → contract and complete-package rollback are approved.
- [ ] **GO:** Deletion of plaintext v1 secrets requires successful v2 pairing, backup validation and explicit destructive preflight.
- [ ] **GO:** Signing remains separate from deterministic unsigned builds.
- [ ] **GO:** PII-, identity-, secret-, firewall- and signing-sensitive slices receive the mandatory review described above.
- [ ] **GO:** No v1/v2 dual listener, partial main merge, mock support claim or TODO-backed capability is permitted.
- [ ] **GO:** P0 is the immediate approved phase.
- [ ] **GO:** After independent P0 PASS and this owner sign-off, P1–P16 are approved for autonomous dependency-ordered execution without ordinary phase-by-phase approval.
- [ ] **GO:** Any contract change, destructive migration not described here, cryptographic redesign, new transport, scope expansion or `[STOP]` condition returns to independent review.
- [ ] **GO:** Final merge is authorized only after T161 PASS and every definition-of-done item is evidenced.

**Program decision:** `GO / NO-GO`  
**Approved by:** ____________________  
**Independent review receipt:** ____________________  
**Date:** ____________________
