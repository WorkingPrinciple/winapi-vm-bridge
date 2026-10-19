# WinAPI VM Bridge — Canonical Runtime Ledger and ADR, Revision 5

> **Repository:** `dragoshont/winapi-vm-bridge`  
> **Public product branch:** `main`, observed at `21d1d484b964965afe44397c6e99d170237cd17e` before ledger publication  
> **Integration baseline:** `canonical-runtime` at `d5b8e89`; active implementation branch `dragoshont-vm-bridge-runtime-split`
> **Canonical Run ID:** `wvb-canonical-v2`  
> **Public ledger destination:** the owner has authorized the ledger-only T002 publication to `main`; product integration remains gated by T161 and the clean-machine hold
> **Public ledger publication:** commit `5f315391d3501c24ea941138f7db82a893369da9`, blob `9b09c1e3e8c0f480a8fe7331546954f2cc5b9603`, published-byte SHA-256 `ede93391ff0e4c9b17d6cc833099603ed4bbe255d761cdb0aeaa5e2e2a30b124`
> **Implementation destination:** reviewable checkpoints on the active branch until the complete release path passes
> **Revision date:** 2026-10-18  
> **Owner authorization:** the user explicitly approves the full corrected canonical program and autonomous implementation; three adversarial revise loops were completed, their consolidated findings are binding, and the owner directed implementation to continue after those findings were corrected  
> **Current state:** frozen Whiny v0.3.0 native and managed scalar bundles are independently verified, pinned, separately execution-admitted and exercised under CrossOver; exact JCS runtime receipts and atomic terminal Runtime Owner persistence are verified; duplicate VM-owned inspection/IR/generation source has been removed atomically; deterministic/security gates pass; T161 remains held behind Windows clean-machine acceptance, missing non-scalar Whiny profiles, canonical Run reconciliation and external signing
> **Execution mode:** approved repository edit/build/test/package and local branch-integration program; no signing-secret access, production deployment or unrelated infrastructure mutation is authorized
> **Notation:** **[D]** binding decision; **[GATE]** deterministic acceptance; **[STOP]** no inference or implementation beyond this point; **[CONDITIONAL]** implemented only after its specified evidence trigger

> **Revision 5 authority:** this file is the one canonical VM Bridge runtime
> ledger and architecture decision record. It supersedes the earlier full-stack
> ownership model without creating a second roadmap. Historical task identifiers
> remain only where they identify already-proven runtime work or migration
> provenance.

---

## 0. Source reconciliation and governing records

### 0.1 Normative inputs

This ledger reconciles:

1. the current public repository and local `canonical-runtime` state;
2. the live canonical-status document;
3. the independent review-loop findings;
4. the external transport research;
5. Whiny evidence patterns at the reviewed commit;
6. the Architrave rubric, backend guidance and operations guidance;
7. the user’s binding requirements in this conversation.
8. the user-directed product split assigning all inspection, inference,
   canonical contract/IR, dependency-description, review/freezing and generation
   work to Whiny;
9. the Whiny handoff selecting `whiny.adapter-contract.v3`,
   `whiny.adapter-bundle.v1`, `whiny.dispatch.v1` and
   `whiny.runtime-receipt.v1`.

### 0.2 Binding ownership ADR

**[D] Whiny is the source plane.** Whiny exclusively owns inspection, semantic
investigation/evidence, canonical contract/IR, dependency-placement
description, review/freezing, all proxy/dispatcher/project/package generation
and immutable adapter bundle production.

**[D] VM Bridge is the execution plane.** VM Bridge owns admission of frozen
Whiny artifacts, transport/session security, authorization, controlled loading,
broker/client execution, transfer/callback/handle/process lifecycle, operation
state and receipts, setup/service operations, diagnostics, resilience,
packaging and topology acceptance.

**[D] Dependency direction is one-way.** VM Bridge may depend on a pinned,
versioned Whiny validator/package and immutable bundle. Whiny contracts and
bundles never depend on VM Bridge implementation types, and VM Bridge does not
fork, infer or regenerate Whiny-owned contract data.

**[D] No compatibility layer is required.** Neither product is released.
`whiny.adapter-contract.v3` replaces both the old Whiny 1.0 contract and
`wvb-ir` schema 2. Cutover is atomic after Whiny publishes validator/package
coordinates plus frozen native and managed bundle/dispatcher vectors and the
runtime consumer tests pass.

### 0.3 Canonical hash and commit rules

This response is a candidate ledger document and has no repository commit or final file hash yet. No fabricated hash is assigned.

Task T000 shall:

1. write this exact approved text to the Run’s candidate ledger artifact;
2. compute `SHA-256` over the UTF-8 bytes with LF line endings;
3. record that candidate hash in `architrave.run.v2.json`;
4. record the independent follow-up verdict and its source hash;
5. reconcile the live canonical-status document by recording:
   - its pre-reconciliation SHA-256;
   - the branch and commits it described;
   - any stale phase/status claims;
   - the final reconciled SHA-256 after the status artifact is corrected outside this ledger;
6. after the third review's consolidated architectural findings are corrected
   and T000 records deterministic closure plus the owner continuation decision,
   publish the redacted public ledger alone to `main`;
7. record the resulting public ledger commit and blob hash;
8. update the Run to distinguish:
   - candidate ledger hash;
   - independently approved ledger hash;
   - public ledger blob hash;
   - integration implementation commits.

No implementation source may accompany the ledger-only public commit.

### 0.4 Runtime handoff evidence

The T037/T038/T040 handoff is frozen under
`runtime-artifacts/whiny-v0.3.0/acceptance/runtime-receipts-v1/`.
The source plane is Whiny commit
`870da868f3d3d48f1da1a36123a9aaf1a6435e53`, validator package SHA-256
`e95244e9056997a1887052744c1e235403f8e560cc2fa80d23ad14a4094c7a6f`,
and handoff manifest SHA-256
`11dd56f11e9f46b5099fd8b842a3b4455298698d570706fb267f329598da2731`.

The corrected canonical receipts are:

- native receipt SHA-256
  `eb02139899a73b93f11bd273ee9a27c9d599b7e0723c0a2695eb91d39ce422cd`;
- managed receipt SHA-256
  `bcbb3a8086fca5aa705e9577bdc93e875ea51e76aca514314d54867814e458b6`;
- strict trust-policy SHA-256
  `fedfc843772405c0dd799ba83e6a108f56e2c98ea06a1935efd61f114fa292e9`;
- acceptance index SHA-256
  `b57ad845e28054a969705f1f3c1cc8f60478f6d07242693a9e9f4af8f9cb357c`.

The policy binds the exact signing domain, keys, host list and bundle hashes.
Every signer is `acceptance-only` with `production_runtime_identity: false`.
The original native and managed receipts, SHA-256
`f1a6b46da911033d5aef97570ead963fc9b6819d7c4051782db6a666ca8abad8`
and
`f2f3c804a25af272ad62bffaead6746f91730e21b33611147ec9cb09734f4380`,
are retained only as historical evidence invalid for the corrected ingestor.
The native receipt binds dispatcher SHA-256
`af0df10d005a149c10dc3134e22e63a2e2962990d0aa5c164a5742dd57e10cdf`
and both corrected receipts bind response SHA-256
`e8a4b2ee7ede79a3afb332b5b6cc3d952a65fd8cffb897f5d18016577c33d7cc`.
The runtime handoff reported native and managed result `42`, but the imported
receipts authenticate the response hash rather than embedding the decoded
scalar. This evidence is a scalar runtime checkpoint. It does not establish
production runtime identity, Windows clean-machine acceptance or T162
completion.

T16, T26 and T32 remain **UNVERIFIED source-plane dependencies**, not VM
Bridge runtime defects and not failed runtime executions. Exact frozen Whiny
package `870da868f3d3d48f1da1a36123a9aaf1a6435e53` /
`e95244e9056997a1887052744c1e235403f8e560cc2fa80d23ad14a4094c7a6f` /
`11dd56f11e9f46b5099fd8b842a3b4455298698d570706fb267f329598da2731`
contains only the native-scalar and managed-scalar profiles. It does not
contain frozen shell-hook, `NtWait*` or ALPC contracts, dispatchers, provider
identities, operations or acceptance commands. No side-effecting execution was
attempted and no retry is authorized from this absence. The dependent tasks
remain held until Whiny supplies exact frozen bundles and dispatchers,
provider/candidate hashes, operation IDs, cleanup/challenge policy and
acceptance commands, or an independent review records an unsupported decision.
VM Bridge shall not invent `loaded_files`, runtime receipts or provider
identity for these missing source-plane profiles.

Whiny authoritative checkpoint
`afa7604` records reviewed development-plane native C++, COM, WinRT, bounded
managed DLL and .NET EXE profiles, but they are not frozen runtime-acceptance
packages. Its
`spec/test-vectors/windows-adapter-package-v1/unsupported-decisions.json`
marks `shell_hook`, `nt_wait_completion` and `alpc` as
`unsupported-until-frozen-identities`. The exact release conditions are:

| Scenario | Required frozen inputs before VM execution |
|---|---|
| T16 shell hook | provider/candidate paths and SHA-256; native calibration references; admitted interactive-desktop helper |
| T26 NT wait completion | provider/candidate paths and SHA-256; exact admitted declarations/statuses; admitted generated helper |
| T32 ALPC | provider/candidate paths and SHA-256; exact admitted declarations/statuses/flags/attributes; admitted generated helper |

No Xbox sign-in or game launch is required. Until Whiny supplies a reviewed
bundle with these identities plus its exact acceptance command, all three
scenarios remain `UNVERIFIED`; VM Bridge must not execute them or emit a
runtime receipt.

Whiny's final repository-wide independent review is `PASS` at clean pushed
checkpoint `fde7bc0` (`89b29f1` code plus final ledger verdict). Its complete
Rust/Python/lint/evidence/audit gates passed. The source plane now additionally
requires exact named PE export equality and fails closed when CLR
nullable-default context is unresolved. These guarantees constrain future
frozen bundles; they do not change the existing scalar pins or authorize
T16/T26/T32 execution.

### 0.5 Public redaction boundary

The public ledger may contain:

- architecture and protocol specifications;
- public source URLs;
- public repository commit IDs;
- logical filenames and source-tree paths;
- limits, tests and support policy.

It must not contain:

- local filesystem paths;
- credentials, pairing material or private-key references;
- confidential target names, headers, PDB contents or contracts;
- held-out corpus contents;
- private trace details;
- unpublished security findings that would increase exploitability;
- personal information.

Confidential Run artifacts remain off public `main`.

---

# 1. Plan tournament

Scores are `1` best and `5` worst.

| Candidate | Description | Contract drift | Blast radius | Migration / rollback | Test burden | Approval burden | Result |
|---|---|---:|---:|---:|---:|---:|---|
| A. Scalar-only release | Protocol v2 plus native C scalar DLL only | 5 | 2 | 3 | 2 | 2 | Rejected as a release; retained only as an internal checkpoint |
| B. Full contract-first sequence | Freeze protocol, identity, dependency placement and receipts; preserve early topology parity; implement all six families; merge atomically | 1 | 4 | 3 | 5 | 4 | **Selected** |
| C. Research-only deferral | Publish ADRs and defer implementation | 3 | 1 | 1 | 2 | 5 | Rejected; the user approved complete implementation |
| D. Parallel JSON/v1 and v2 | Maintain compatibility listeners | 5 | 5 | 4 | 5 | 2 | Rejected; prohibited temporary protocol |
| E. gRPC primary | HTTP/2/gRPC/Protobuf data plane | 3 | 4 | 4 | 4 | 4 | Rejected; no topology-specific advantage |
| F. FlatBuffers primary | FlatBuffers payloads from v2 launch | 2 | 3 | 3 | 4 | 3 | Rejected for v2; no applicable measured need |
| G. Deterministic CBOR | RFC 8949 deterministic CBOR | 2 | 2 | 2 | 3 | 2 | Rejected for ABI traffic; larger generic parser/model than the closed contract requires |
| H. Generated packed codec | Fixed envelope plus generated bounded tagged fields | 1 | 3 | 2 | 4 | 3 | **Selected and immutable for protocol v2** |

## Recommended sequence

**[D] Select B with H.**

Protocol v2 uses the generated packed codec for its entire lifetime. T131 benchmarks performance but cannot replace or negotiate another v2 codec. Any future codec change requires a protocol-major v3 plan, compatibility design, benchmark evidence and independent approval.

---

# 2. Outcome, non-goals and terminology

## 2.1 Outcome

The final release shall provide:

- one encrypted, persistent, multiplexed framed-TCP protocol for Mac/Wine to Windows VM communication;
- admission and execution of exact, immutable Whiny-generated bundles only;
- pinned `whiny.adapter-contract.v3`, `whiny.adapter-bundle.v1` and
  `whiny.dispatch.v1` compatibility;
- exact target, dispatcher and dependency hashes plus controlled load paths;
- separate operator admission and actor/operation invocation authorization;
- separate Whiny build/signing evidence and VM runtime-operation receipts;
- runtime support for the target profiles present in admitted frozen bundles,
  without VM-owned target generation;
- complete marshalling for supported types and lifecycle semantics;
- secure one-time pairing, persistent actor identity, grants and revocation;
- durable operation state, diagnostics and tamper-evident receipts;
- real-topology performance evidence;
- package installation, two-command setup wrapper, update rollback and uninstall;
- no product implementation merge to `main` until the full vertical release path passes.

## 2.2 Non-goals

The release shall not claim:

- inspection, semantic inference, canonical contract/IR ownership or code generation;
- arbitrary caller-selected DLLs, exports, assemblies, methods, CLSIDs or commands;
- universal C++ ABI support;
- exported C++ constructors, destructors, copy/move functions or instance methods in the initial C++ subset;
- raw pointer or OS-handle transfer;
- automatic custom `IMarshal`;
- automatic interactive GUI remoting;
- arbitrary process-local IPC or shared-memory remoting;
- kernel-driver, anti-cheat, DRM or licensing bypass;
- mixed-mode C++/CLI;
- gRPC, named pipes, ALPC, UDS, vsock or ivshmem as the canonical cross-VM transport;
- v1 compatibility after v2 release;
- deterministic signed bytes;
- a scaffold, AI packet, TODO, mock or fixture-only result as support;
- that bundle metadata can create or widen an actor grant.

## 2.3 Terminology

- **Physical record:** one `u16`-length-prefixed Noise ciphertext.
- **Physical fragment:** authenticated plaintext inside one physical record.
- **Logical frame:** one reconstructed 80-byte envelope plus payload.
- **Logical chunk:** up to 1 MiB of call/result/transfer data in one logical frame.
- **Stream:** ordered frames for one call, callback, operation query or transfer.
- **Pair transport:** authenticated XXpsk3 transport used only for pairing bootstrap.
- **Application session:** future IK transport that completed application `HELLO/HELLO_ACK`.
- **Actor:** registered client static key and broker-stored roles/grants.
- **Proxy:** caller-side generated DLL, assembly or EXE.
- **Dispatcher:** generated Windows-side typed invocation module.
- **Receipt:** RFC 8785-canonicalized, hash-chained event or build statement.
- **Support:** all applicable tests pass with no unresolved semantics.
- **AI packet:** escaped, non-executable specification for unresolved work; never support.

---

# 3. Cutover inventory and disposition

The following binding split records the completed atomic cutover. The Whiny
validator package and frozen native/managed bundle vectors were independently
verified, the runtime consumer/admission suite passed, and MOVE/DROP paths were
then removed in the same checkpoint.

| Pre-cutover path | Disposition | Completed runtime cutover |
|---|---|---|
| `crates/wvb-ir/**` | **MOVE to Whiny** | Replace with pinned `whiny-contract` v0.3.0 / `whiny.adapter-contract.v3`; delete only in the atomic cutover |
| `crates/wvb-inspect/**` | **MOVE to Whiny** | Whiny owns all native inspection and evidence; remove after validator parity |
| `crates/wvb-generate/**` | **MOVE to Whiny** | Whiny owns all proxy/dispatcher/project/package generation; remove after frozen bundle consumer tests pass |
| `sdk/abi_inspect.py` | **MOVE to Whiny** | Preserve only until Whiny inspection parity is recorded |
| `sdk/adapter.schema.json` | **MOVE to Whiny** | Superseded by `whiny.adapter-contract.v3`; no VM schema fork |
| `sdk/generate.py` | **MOVE to Whiny** | Delete at atomic cutover |
| `sdk/templates/**` | **MOVE to Whiny** | Templates and AI packets are source-plane artifacts |
| `sdk/README.md` | **MOVE to Whiny** | Replace VM documentation with frozen-bundle consumption guidance |
| `sdk/__init__.py` | **DROP after cutover** | Python package marker is unnecessary after the source-plane SDK moves |
| `examples/inspection/vendor.h` | **MOVE to Whiny** | Inspection fixture belongs with Whiny validator tests |
| `examples/example-math/adapter.json` | **MOVE to Whiny** | Old schema fixture; replace with a pinned frozen bundle vector |
| `examples/managed-scalar/adapter.json` | **MOVE to Whiny** | Old schema fixture; replace with a pinned frozen managed bundle vector |
| `managed/tools/Wvb.ManagedInspector/**` | **MOVE to Whiny** | Managed inspection is not runtime execution |
| `managed/fixtures/unsupported-managed-instance/**` | **MOVE to Whiny** | Expected-stop inspection fixture |
| `managed/fixtures/example-managed-math/{Proxy.generated.cs,Dispatcher.generated.cs,*.csproj,contract.canonical.json}` | **DROP after cutover** | Generated source ownership ends; consume an immutable Whiny bundle instead |
| `native/fixtures/c-dll/adapter.json` | **MOVE to Whiny** | Old generator input; replace with the frozen native bundle descriptor |
| `native/fixtures/c-dll/{vendor.c,test_app.c,runtime_stub.c}` | **KEEP runtime** | Local target/oracle/runtime fixture remains useful after its generator input is replaced |
| `native/fixtures/c-dll/build-and-test.sh` | **DROP and replace after cutover** | Current script invokes `wvb-generate`; replace with a frozen-bundle consumer/oracle script |
| `managed/fixtures/vendor-managed-math/**` | **KEEP runtime** | Runtime target fixture, not inspection or generation logic |
| `managed/fixtures/vendor-managed-math-local/**` | **KEEP runtime** | Fresh-process local differential oracle |
| `managed/fixtures/managed-dispatch-oracle/**` | **KEEP runtime** | Runtime dispatcher-host acceptance oracle |
| `tests/test_sdk.py` | **MOVE then DROP** | Port inspection/generator cases to Whiny; retain only unrelated legacy runtime coverage until replacement |
| `tests/test-portable.sh` | **KEEP runtime** | Remove source-plane checks only in the atomic cutover; add frozen-bundle consumer checks |
| `native/managed-host/**`, `crates/wvb-managed-host/**` | **KEEP runtime** | Generic CLR dispatcher host and controlled loader |
| `native/macos-keychain/**` | **KEEP runtime** | OS-backed client identity consumption |
| `native/macos-keychain/tests/**` | **KEEP runtime** | Keychain identity fixtures and negative tests |
| `native/managed-host/tests/**` | **KEEP runtime** | CLR host configuration and round-trip runtime tests |
| `native/wine-unixlib/tests/**` | **KEEP conditionally** | Retain as evidence for the failed route and replacement configuration tests |
| `native/wine-unixlib/**` | **KEEP conditionally** | Current by-name route is a failed experiment; replace only with a newly evidenced supported mechanism |

The previous rows below remain historical migration context. Where they
conflict with this table, this table governs.

| Existing path | Current status | Final disposition |
|---|---|---|
| `.github/workflows/ci.yml` | old portable and Windows proof jobs | Replace with pinned deterministic matrix |
| `.gitignore` | ignores caches, generic tokens/secrets and local config, but not `runtime.key` | Keep and extend before any key generation |
| `CONTRIBUTING.md` | basic adapter guidance | Replace |
| `LICENSE` | Apache-2.0 | Keep |
| `NOTICE` | trademark/distribution notice | Keep and update provenance references |
| `README.md` | proof implementation claims | Replace only at final release |
| `SECURITY.md` | short allowlist guidance | Replace |
| `config.example.yml` | v1 host/port/capability file | Delete after migration |
| `setup-mac.sh` | Git/Python/plaintext capability setup | Replace with signed package wrapper |
| `setup-windows.ps1` | Git/Python/scheduled task/plain capability | Replace with signed package wrapper |
| `adapters/example-math.yaml` | duplicate v1 YAML | Delete |
| `bin/winapi-vm-bridge` | shell/Python CLI | Replace with native `wvb` |
| `docs/*.md` | conceptual proof documentation | Migrate or replace as assigned |
| `docs/community.md` | promotional text | Remove from normative tree |
| `docs/evidence.md` | historical evidence | Preserve under `docs/historical/` |
| `docs/assets/bridge-overview.svg` | old architecture diagram | Replace |
| `examples/example-math/adapter.json` | v1 placeholder-hash fixture | Replace |
| `examples/inspection/vendor.h` | useful inspection fixture | Keep and expand |
| `mac/doctor.sh` | unconditional success output | Delete/replace |
| `sdk/abi_inspect.py` | useful Clang proof | Port with parity, then delete |
| `sdk/adapter.schema.json` | incomplete schema v1 | Replace atomically |
| `sdk/generate.py` | non-compilable skeleton generator | Delete after canonical parity |
| `sdk/templates/*` | generic v1 templates | Replace |
| `tests/test-portable.sh` | old proof gate | Replace |
| `tests/test_sdk.py` | old proof tests | Port, then delete |
| `tests/windows-roundtrip.ps1` | real old topology proof | Retain until T005/T026 parity |
| `winapi_vm_bridge/*` | Python JSON/v1 proof | Delete after v2 parity |
| `windows/doctor.ps1` | unconditional success output | Delete/replace |
| `**/__pycache__/**`, `*.pyc` | generated cache | Delete; never package |

Before generating any runtime identity:

```gitignore
runtime.key
*.runtime.key
.architrave/private/
```

shall be added. Production keys remain in external OS-backed stores and are never stored as repository files. If prior exposure cannot be conclusively ruled out, all affected development keys are treated as compromised and rotated before use.

---

# 4. Final architecture and source tree

## 4.1 Architecture

```text
Whiny validator/freezer
  → immutable contract + bundle + dispatcher package
  → operator approval and VM Bridge admission store
  → controlled runtime load paths and hash re-verification
Application under Wine
  → admitted immutable proxy
  → guarded local ABI marshalling
  → libwvb_client
  → persistent TCP with TCP_NODELAY
  → Noise physical records/fragments
  → protocol-v2 packed logical frames
  → Windows service broker
  → actor ACL + bounded operation queue
  → exact-hash admitted dispatcher
  → exact-hash target dependency subtree
  → result/callback/operation/receipt
```

## 4.2 Canonical source tree

```text
/
├── .github/workflows/{ci.yml,fuzz.yml,reproducible.yml,release.yml}
├── Cargo.toml
├── Cargo.lock
├── crates/
│   ├── wvb-admission/
│   ├── wvb-protocol/
│   ├── wvb-crypto/
│   ├── wvb-authz/
│   ├── wvb-client/
│   ├── wvb-client-ffi/
│   ├── wvb-broker/
│   ├── wvb-state/
│   ├── wvb-session/
│   ├── wvb-call/
│   ├── wvb-lifecycle/
│   ├── wvb-runtime/
│   ├── wvb-marshal/
│   ├── wvb-managed-host/
│   └── wvb-exe/
├── native/
│   ├── include/wvb_client.h
│   ├── macos-keychain/
│   ├── managed-host/
│   ├── wine-unixlib/
│   └── fixtures/
├── managed/
│   ├── runtime-host/
│   └── fixtures/
├── packaging/{macos,windows,manifests}
├── benchmarks/{topology.toml,baselines}
├── tests/{unit,property,compatibility,chaos,e2e,clean-machine,fuzz,scripts}
├── docs/
│   ├── implementation-ledger.md
│   ├── architecture.md
│   ├── protocol-v2.md
│   ├── bundle-consumption.md
│   ├── security.md
│   ├── privacy.md
│   ├── operations.md
│   ├── setup-macos.md
│   ├── setup-windows.md
│   ├── rollback-uninstall.md
│   ├── support-matrix.md
│   ├── reproducible-builds.md
│   ├── performance.md
│   ├── research-sources.md
│   ├── release.md
│   └── historical/evidence.md
├── external/
│   └── pinned Whiny package and bundle coordinates recorded by digest
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── NOTICE
```

`crates/wvb-ir`, `crates/wvb-inspect`, `crates/wvb-generate`, the source-plane
SDK, Python v1 proof and generated fixtures are no longer present. Runtime
acceptance consumes the pinned files under `external/whiny/v0.3.0/`.

No UI or IaC product is introduced.

---

# 5. Protocol layering and pairing bootstrap

## 5.1 TCP bootstrap preface

Every TCP connection begins with an unencrypted, non-secret 12-byte preface:

| Offset | Field | Type | Values |
|---:|---|---|---|
| 0 | magic | `[u8;4]` | `WVBN` |
| 4 | major | `u8` | `2` |
| 5 | minor | `u8` | `0` |
| 6 | mode | `u8` | `1=PAIR`, `2=SESSION` |
| 7 | flags | `u8` | zero |
| 8 | reserved | `u32 BE` | zero |

The preface selects a Noise pattern only. It contains no actor ID, key, code, platform or capability.

- `PAIR` is accepted only while a local administrator-opened pairing window is active.
- `SESSION` uses the future-session IK path.
- Invalid prefaces close without a detailed oracle.

Noise handshake messages use:

```text
handshakeCiphertextLength:u16 BE
handshakeCiphertext[handshakeCiphertextLength]
```

No application envelope is accepted until the Noise handshake succeeds.

## 5.2 Initial XXpsk3 pairing

Pattern:

```text
Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s
```

Knowledge before TCP:

| Peer | Knows |
|---|---|
| Broker | broker static private key; one-time PSK; pairing-window ID/expiry/requested maximum grants |
| Client | one-time PSK entered out of band; its newly generated static key |
| Neither | actor ID, active session epoch or final grants |

After XXpsk3 completes:

- client knows and authenticates broker static public key through PSK-authenticated XX;
- broker knows and authenticates client static public key;
- both have a provisional encrypted pair transport;
- no actor exists yet;
- `connectionEpoch=0`;
- only pair-control messages are legal;
- application `HELLO`, calls, transfers, callbacks and handles are forbidden.

Pair-control messages use the ordinary logical envelope with
`connectionEpoch=0`, control `streamId=0`, and pair-message schema IDs. They do
not use `HELLO/HELLO_ACK`, do not contain `actorId`, and are accepted only on a
`PAIR` connection after the Noise handshake. `PAIR_ACCEPT` is the first message
that contains the committed actor ID. The pair connection closes immediately
after `PAIR_COMPLETE` and never becomes an application session.

### Pair transaction

1. Client sends `PAIR_REQUEST`.
2. Broker validates:
   - window active;
   - PSK unused;
   - client key not already active/revoked without recovery;
   - requested roles do not exceed window policy.
3. Broker creates an in-memory provisional actor and sends `PAIR_OFFER`.
4. Client stores:
   - broker static key;
   - broker audit key;
   - provisional actor ID;
   - offer hash;
   in Keychain as `pending`.
5. Client sends `PAIR_COMMIT` containing the exact offer hash.
6. Broker atomically:
   - inserts/activates actor;
   - inserts grants;
   - consumes pairing window and PSK;
   - appends pair audit event;
   - updates trusted rollback anchor;
   - commits the transaction.
7. Broker sends `PAIR_ACCEPT`.
8. Client marks its Keychain record active and erases PSK.
9. Broker erases PSK and closes the pair transport with `PAIR_COMPLETE`.

If `PAIR_ACCEPT` is lost after broker commit:

- the client already has broker/client static identities and pending actor ID;
- it erases the PSK after sending `PAIR_COMMIT`;
- it reconnects using `SESSION`/IK;
- the broker identifies the now-active actor from the client static key;
- successful `HELLO_ACK` promotes the local pending record to active.

If failure occurs before broker commit:

- no actor is active;
- the window remains usable until expiry unless policy closes it;
- provisional actor state is discarded;
- the client deletes its pending actor record;
- the one-time PSK remains valid only if the broker confirms it was not consumed.

## 5.3 Future IK application session

Pattern:

```text
Noise_IK_25519_ChaChaPoly_BLAKE2s
```

Ordering:

1. TCP preface `mode=SESSION`.
2. IK handshake:
   - client already pins broker static key;
   - broker authenticates client static key;
   - broker maps key to active, non-revoked actor.
3. Both enter encrypted pre-session state with:
   - `connectionEpoch=0`;
   - independent physical sequences at zero;
   - no application streams.
4. Client sends application `HELLO` in a provisional logical control frame.
5. Broker validates protocol/features/platform and sends `HELLO_ACK` with:
   - active actor ID;
   - active broker epoch;
   - random nonzero connection epoch;
   - selected features and limits.
6. The physical fragment and logical envelope carrying `HELLO_ACK` still use
   `connectionEpoch=0`. The nonzero returned epoch becomes active only after the
   complete `HELLO_ACK` has been authenticated, decoded and accepted.
7. Both atomically promote the connection to `ACTIVE`.
8. Physical fragments and logical envelopes after `HELLO_ACK` use the active connection epoch.
9. Calls and non-control streams may now begin.

No XX fallback exists for normal future sessions. Recovery or key rotation uses a newly authorized pairing window, not silent pattern downgrade.

---

# 6. Physical fragmentation, sequencing and drain

## 6.1 Noise size limits

A Noise transport ciphertext is at most 65,535 bytes. ChaChaPoly uses a 16-byte tag.

```text
maximum plaintext = 65,535 − 16 = 65,519 bytes
```

TCP transport record:

```text
ciphertextLength:u16 BE
noiseCiphertext[ciphertextLength]
```

Decrypted physical-fragment header is exactly 32 bytes:

| Offset | Field | Type |
|---:|---|---|
| 0 | magic=`WVF2` | `[u8;4]` |
| 4 | connectionEpoch | `u64 LE` |
| 12 | physicalSequence | `u64 LE` |
| 20 | logicalFrameId | `u64 LE` |
| 28 | fragmentIndex | `u16 LE` |
| 30 | fragmentCount | `u16 LE` |

Maximum body:

```text
65,519 − 32 = 65,487 bytes
```

Maximum logical frame:

```text
80 + 1,048,576 = 1,048,656 bytes
ceil(1,048,656 / 65,487) = 17 fragments
```

## 6.2 Per-sender ownership

Each sender independently owns:

- `physicalSequence`, starting at `0`;
- `logicalFrameId`, starting at `1`;
- its stream-ID parity;
- its per-stream `streamSequence`.

Client and broker values may be numerically equal because direction is part of identity.

Rules:

- `physicalSequence` increments for every encrypted physical record sent by that peer.
- `logicalFrameId` increments once per logical frame created by that peer.
- Fragments for one logical frame are contiguous and not interleaved.
- `fragmentIndex` starts at zero and advances exactly.
- `fragmentCount` is `1..17`.
- Duplicates, gaps, reorder, conflicting counts or wrong epoch close the connection.
- Reassembly timeout is ten monotonic seconds.
- No more than one partial incoming logical frame exists per direction.

## 6.3 Wrap and GOAWAY

A peer must begin drain before any owned counter reaches exhaustion:

- physical sequence threshold: `2^64−1024`;
- logical frame threshold: `2^64−1024`;
- stream ID threshold: next allocatable ID would exceed parity maximum;
- stream sequence threshold: `2^32−1024`.

At threshold:

1. send `GOAWAY(SEQUENCE_EXHAUSTED)` while counters remain valid;
2. stop opening new streams;
3. drain accepted streams for at most 30 monotonic seconds;
4. close and establish a fresh IK session.

Counters never wrap or reset inside one connection.

## 6.4 Exact 65,536 rejection tests

A 65,536-byte ciphertext cannot be represented by the `u16` wire length.

Required tests are therefore:

1. sender API given a Noise plaintext of 65,520 bytes, which would require 65,536 ciphertext bytes, returns `PhysicalMessageTooLarge` before writing any socket byte;
2. sender accepts at most 65,519 plaintext bytes;
3. authenticated ciphertext of exactly 65,535 bytes is accepted;
4. malicious TCP prefix `0x0000` is rejected as `PHYSICAL_LENGTH_INVALID`, not interpreted as 65,536;
5. truncated `0xFFFF` record is rejected on EOF/timeout;
6. no test claims a receiver can directly encode or receive a `u16` length value of 65,536.

---

# 7. Logical envelope, flags, features and stream rules

## 7.1 Envelope

| Offset | Field | Type | Rule |
|---:|---|---|---|
| 0 | magic | `[u8;4]` | `WVB2` |
| 4 | headerBytes | `u16` | `80` |
| 6 | major | `u8` | `2` |
| 7 | minor | `u8` | selected minor |
| 8 | messageType | `u16` | registry value |
| 10 | flags | `u16` | registry value |
| 12 | connectionEpoch | `u64` | zero only for pair/pre-session control |
| 20 | streamId | `u32` | zero control, otherwise parity-owned |
| 24 | streamSequence | `u32` | sender sequence on stream |
| 28 | messageId | `[u8;16]` | unique random/UUIDv7-compatible bytes |
| 44 | correlationId | `[u8;16]` | request message ID or zero |
| 60 | remainingBudgetMs | `u64` | monotonic remaining budget |
| 68 | payloadLength | `u32` | `0..1,048,576` |
| 72 | logicalLength | `u32` | equals payload length in v2.0 |
| 76 | reserved | `u32` | zero |

### Monotonic deadlines

- Senders derive `remainingBudgetMs` from local monotonic time.
- Receivers start a local monotonic deadline at receipt.
- Queueing and forwarding subtract locally elapsed monotonic time.
- Wall clocks never determine timeout expiration.
- Child callbacks/transfers inherit the smaller of parent remaining budget and their contract maximum.
- `remainingBudgetMs=0` is allowed only for pairing, `HELLO`, `PING/PONG`, `GOAWAY`, `WINDOW_UPDATE`, `GENERIC_ACK` and protocol errors.
- Wall-clock skew is reported by readiness using diagnostic timestamps. It never extends a call deadline.
- Clock skew over five minutes yields readiness `warning`; over 24 hours yields `blocked` for signing/update operations but not ordinary monotonic RPC.

## 7.2 Flags

| Value | Symbol |
|---:|---|
| `0x0001` | `REQUEST` |
| `0x0002` | `RESPONSE` |
| `0x0004` | `END_STREAM` |
| `0x0008` | `OPTIONAL_MESSAGE` |
| `0x0010` | `ACK_REQUIRED` |
| `0x0020` | `CONTROL_PRIORITY` |
| `0x0040` | `SENSITIVE` |
| `0x0080` | `RETRY` |
| `0x0100` | `FINAL_CHUNK` |
| `0x0200–0x8000` | reserved |

`REQUEST` and `RESPONSE` are mutually exclusive. Unknown flag bits fail the frame.

## 7.3 Optional and acknowledgment behavior

- Unknown message without `OPTIONAL_MESSAGE`: send `PROTOCOL_ERROR(MESSAGE_UNKNOWN_REQUIRED)` and close.
- Unknown message with `OPTIONAL_MESSAGE` and no `ACK_REQUIRED`: validate envelope/bounds, consume sequence and ignore.
- Unknown message with both flags: reply `GENERIC_ACK` with `UNSUPPORTED_OPTIONAL`, then ignore.
- Known message with `ACK_REQUIRED`: its defined response is the acknowledgment. If it has no defined response, send `GENERIC_ACK`.
- `GENERIC_ACK` never has `ACK_REQUIRED`.
- An acknowledgment references the original `messageId` through `correlationId`.
- Lack of required acknowledgment before deadline fails the requesting operation, not necessarily the whole connection.
- An optional message may never mutate state unless the feature registry explicitly declares that mutation understood by both peers.

## 7.4 Features

| Bit | Feature |
|---:|---|
| `0x0001` | `PACKED_FIELDS_V1`, mandatory and immutable |
| `0x0002` | `FLOW_CONTROL_V1`, mandatory |
| `0x0004` | `CANCELLATION_V1` |
| `0x0008` | `CALLBACKS_V1` |
| `0x0010` | `HANDLES_V1` |
| `0x0020` | `DURABLE_OPERATIONS_V1` |
| `0x0040` | `AUDIT_CHECKPOINTS_V1` |
| `0x0080` | `TRANSFER_STREAMS_V1` |
| `0x0100` | `COM_IDENTITY_V1` |
| `0x0200` | `REVERSE_DEPENDENCY_V1`, conditional |
| `0x0400` | `UNKNOWN_OPTIONAL_MESSAGES_V1`, mandatory |
| remaining | reserved |

## 7.5 Stream ownership

- Stream `0`: control only.
- Client-created streams: odd IDs `1..0xFFFFFFFD`.
- Broker-created streams: even IDs `2..0xFFFFFFFE`.
- IDs increase monotonically by two and are never reused.
- First sender frame has `streamSequence=0`; each later frame by that sender increments exactly.
- A response may use the same stream with the opposite sender’s own stream sequence.
- After either side sends GOAWAY, no new streams are opened.
- GOAWAY carries last accepted odd and even stream IDs.
- Accepted streams drain for at most 30 monotonic seconds.
- Callback executor shutdown:
  1. stops registration;
  2. rejects new callback streams;
  3. unregisters leases;
  4. drains accepted invocations;
  5. terminates remaining invocations as `CALLBACK_GONE`;
  6. permits connection drain.

---

# 8. Packed codec and complete message schemas

## 8.1 Field format

Payload prefix:

```text
schemaId:u32 LE
schemaVersion:u16 LE
fieldCount:u16 LE
```

Field:

```text
tag:u16 LE
wireType:u8
fieldFlags:u8
length:u32 LE
value[length]
```

Wire types:

| ID | Type |
|---:|---|
| 1 | `u8` |
| 2 | `u16` |
| 3 | `u32` |
| 4 | `u64` |
| 5 | `i32` |
| 6 | `i64` |
| 7 | `f32` |
| 8 | `f64` |
| 9 | bool, one byte `0|1` |
| 10 | bytes |
| 11 | UTF-8 |
| 12 | UUID/128-bit |
| 13 | nested message |
| 14 | repeated nested message |

Field flags:

| Value | Meaning |
|---:|---|
| `0x01` | required |
| `0x02` | repeated |
| `0x04` | sensitive |
| others | reserved |

Fields are emitted in ascending tag order. Unknown fields are skipped after bounds validation. Duplicate known non-repeated fields fail.

Top-level payload schema IDs are derived without a registry decision:

```text
schemaId = 0x20000000 | messageType
schemaVersion = 1
```

Nested schemas use the fixed `0x1001..0x10FF` registry below. A message ID,
top-level schema ID or nested schema ID is never reused with different
semantics. A compatible additive change increments `schemaVersion`; an
incompatible change requires a protocol-major revision.

Unknown numeric enum values are rejected for required closed enums. Bit-flag
fields may preserve unknown bits only when their field contract explicitly sets
`preserveUnknownBits=true`; otherwise unknown bits are rejected. Optional
messages carrying unknown enums follow their message ACK policy and never
silently become accepted operations.

## 8.2 Numeric enum registry

### Peer kind

| Value | Symbol |
|---:|---|
| 1 | `CLIENT_CLI` |
| 2 | `CLIENT_PROXY` |
| 3 | `BROKER` |
| 4 | `BROKER_WORKER` |

### Role

| Value | Symbol |
|---:|---|
| 1 | `INVOKE` |
| 2 | `OPERATOR` |
| 3 | `ADAPTER_ADMIN` |
| 4 | `PAIRING_ADMIN` |
| 5 | `AUDITOR` |
| 6 | `SERVICE_ADMIN` |

### Platform OS

| Value | Symbol |
|---:|---|
| 1 | `MACOS` |
| 2 | `WINDOWS` |

### Architecture

| Value | Symbol |
|---:|---|
| 1 | `ARM64` |
| 2 | `X86_64` |
| 3 | `X86` |
| 4 | `ARM64EC` |

### Readiness status

| Value | Symbol |
|---:|---|
| 1 | `PASS` |
| 2 | `WARNING` |
| 3 | `BLOCKED` |
| 4 | `FAIL` |
| 5 | `UNKNOWN` |

### Native status domain

| Value | Symbol |
|---:|---|
| 0 | `NONE` |
| 1 | `HRESULT` |
| 2 | `WIN32` |
| 3 | `NTSTATUS` |
| 4 | `C_RETURN` |
| 5 | `SEH` |
| 6 | `CPP_EXCEPTION_MAPPED` |
| 7 | `DOTNET_EXCEPTION` |
| 8 | `PROCESS_EXIT` |

### Operation status

| Value | Symbol |
|---:|---|
| 1 | `QUEUED` |
| 2 | `WAITING` |
| 3 | `RUNNING` |
| 4 | `BLOCKED` |
| 5 | `CANCELING` |
| 6 | `CANCELED` |
| 7 | `SUCCEEDED` |
| 8 | `FAILED` |
| 9 | `PARTIAL` |
| 10 | `EXPIRED` |
| 11 | `UNKNOWN` |

### Deduplication mode

| Value | Symbol |
|---:|---|
| 1 | `READ_ONLY_REPLAYABLE` |
| 2 | `BROKER_DEDUPLICATED` |
| 3 | `TARGET_IDEMPOTENT` |
| 4 | `NOT_RETRYABLE` |

### Cancel disposition

| Value | Symbol |
|---:|---|
| 1 | `ACCEPTED` |
| 2 | `TOO_LATE` |
| 3 | `UNSUPPORTED` |
| 4 | `UNKNOWN_TARGET` |
| 5 | `ALREADY_TERMINAL` |

### ACK disposition

| Value | Symbol |
|---:|---|
| 1 | `ACCEPTED` |
| 2 | `IGNORED_OPTIONAL` |
| 3 | `UNSUPPORTED_OPTIONAL` |
| 4 | `REJECTED` |

### Callback ordering/executor

| Value | Symbol |
|---:|---|
| ordering 1 | `SERIAL` |
| ordering 2 | `PARALLEL` |
| executor 1 | `WORKER` |
| executor 2 | `STA` |
| executor 3 | `CALLER_RENDEZVOUS` |
| executor 4 | `EVENT_LOOP` |

### Transfer kind

| Value | Symbol |
|---:|---|
| 1 | `CALL_INPUT` |
| 2 | `CALL_OUTPUT` |
| 3 | `FILE_INPUT` |
| 4 | `FILE_OUTPUT` |
| 5 | `STDIN` |
| 6 | `STDOUT` |
| 7 | `STDERR` |
| 8 | `DIAGNOSTIC_ARTIFACT` |

### Transfer terminal status

| Value | Symbol |
|---:|---|
| 1 | `COMPLETE` |
| 2 | `CANCELED` |
| 3 | `FAILED` |
| 4 | `HASH_MISMATCH` |
| 5 | `LIMIT_EXCEEDED` |

### Event kind

| Value | Symbol |
|---:|---|
| 1 | `CREATED` |
| 2 | `QUEUED` |
| 3 | `STARTED` |
| 4 | `STAGE_CHANGED` |
| 5 | `PROGRESS` |
| 6 | `CANCEL_REQUESTED` |
| 7 | `CANCELED` |
| 8 | `SUCCEEDED` |
| 9 | `FAILED` |
| 10 | `UNKNOWN_OUTCOME` |
| 11 | `RECONCILED` |
| 12 | `AUDIT_CHECKPOINTED` |

### Disconnect policy

| Value | Symbol |
|---:|---|
| 1 | `CANCEL_ON_DISCONNECT` |
| 2 | `CONTINUE_AS_DURABLE_OPERATION` |
| 3 | `FINISH_IN_FLIGHT_NO_NEW_CALLBACKS` |

### Sensitivity / privacy class

| Value | Symbol |
|---:|---|
| 1 | `PUBLIC` |
| 2 | `INTERNAL` |
| 3 | `PERSONAL` |
| 4 | `CREDENTIAL` |
| 5 | `SECRET` |

### GOAWAY reason

| Value | Symbol |
|---:|---|
| 1 | `NORMAL_DRAIN` |
| 2 | `SERVER_SHUTDOWN` |
| 3 | `PROTOCOL_VIOLATION` |
| 4 | `SEQUENCE_EXHAUSTED` |
| 5 | `AUTHORIZATION_CHANGED` |
| 6 | `RESOURCE_PRESSURE` |

### Pair close/reject reason

| Value | Symbol |
|---:|---|
| 1 | `PAIR_COMPLETE_NORMAL` |
| 2 | `WINDOW_CLOSED` |
| 3 | `PSK_INVALID_OR_CONSUMED` |
| 4 | `OFFER_MISMATCH` |
| 5 | `POLICY_DENIED` |
| 6 | `ROLLBACK_DETECTED` |

### Cancellation reason

| Value | Symbol |
|---:|---|
| 1 | `CALLER_REQUESTED` |
| 2 | `DEADLINE_EXPIRED` |
| 3 | `DISCONNECT_POLICY` |
| 4 | `BROKER_SHUTDOWN` |
| 5 | `DEPENDENCY_FAILED` |
| 6 | `RESOURCE_LIMIT` |

### Handle disposition

| Value | Symbol |
|---:|---|
| 1 | `CLOSED` |
| 2 | `ALREADY_CLOSED` |
| 3 | `STALE` |
| 4 | `OWNER_MISMATCH` |
| 5 | `TYPE_MISMATCH` |

### Receipt-query disposition

| Value | Symbol |
|---:|---|
| 1 | `FOUND_TERMINAL` |
| 2 | `FOUND_RUNNING` |
| 3 | `UNKNOWN` |
| 4 | `CONFLICT` |

### Callback unregister reason

| Value | Symbol |
|---:|---|
| 1 | `CALLER_UNREGISTERED` |
| 2 | `LEASE_EXPIRED` |
| 3 | `SESSION_CLOSED` |
| 4 | `TARGET_RELEASED` |
| 5 | `POLICY_REVOKED` |

### Audit signature algorithm

| Value | Symbol |
|---:|---|
| 1 | `TPM_ECDSA_P256_SHA256` |
| 2 | `TPM_ED25519` |

## 8.3 Nested schemas

### `UuidValueV1`, schema `0x100B`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | value | UUID | yes |

### `StringValueV1`, schema `0x100C`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | value | UTF-8 | yes |

### `HashValueV1`, schema `0x100D`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | algorithm | `u16` (`1=SHA256`) | yes |
| 2 | value | bytes (exactly 32 for SHA-256) | yes |

### `RoleGrantV1`, schema `0x1001`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | role | `u16` | yes |
| 2 | adapterContractHash | bytes | no |
| 3 | operationId | `u32` | no |
| 4 | expiresAtUnixMs | `u64` | no |

### `PlatformV1`, schema `0x1002`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | os | `u16` | yes |
| 2 | osVersion | UTF-8 | yes |
| 3 | architecture | `u16` | yes |
| 4 | wineVersion | UTF-8 | no |
| 5 | runtimeVersion | UTF-8 | no |
| 6 | buildFingerprint | bytes | yes |

### `ReadinessCheckV1`, schema `0x1003`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | checkId | UTF-8 | yes |
| 2 | scope | UTF-8 | yes |
| 3 | status | `u16` | yes |
| 4 | source | UTF-8 | yes |
| 5 | checkedAtUnixMs | `u64` | yes |
| 6 | reason | UTF-8 | yes |
| 7 | remediation | UTF-8 | no |
| 8 | evidenceId | UUID | no |

### `ReadinessV1`, schema `0x1004`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | overallStatus | `u16` | yes |
| 2 | checks | repeated `ReadinessCheckV1` | yes |
| 3 | generatedAtUnixMs | `u64` | yes |
| 4 | sourceVersion | UTF-8 | yes |

### `NativeStatusV1`, schema `0x1005`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | domain | `u16` | yes |
| 2 | code | `i64` | yes |
| 3 | secondaryCode | `i64` | no |
| 4 | exceptionType | UTF-8 | no |
| 5 | redactedMessage | UTF-8 | no |
| 6 | retryable | bool | yes |
| 7 | diagnosticId | UUID | no |

### `StageV1`, schema `0x1006`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | stageId | UTF-8 | yes |
| 2 | ordinal | `u32` | yes |
| 3 | status | `u16` | yes |
| 4 | startedAtUnixMs | `u64` | no |
| 5 | completedAtUnixMs | `u64` | no |
| 6 | message | UTF-8 | no |
| 7 | nativeStatus | `NativeStatusV1` | no |
| 8 | evidenceIds | repeated `UuidValueV1` | no |

### `OperationV1`, schema `0x1007`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | operationUuid | UUID | yes |
| 2 | operationType | UTF-8 | yes |
| 3 | actorId | UUID | yes |
| 4 | targetIds | repeated `StringValueV1` | yes |
| 5 | status | `u16` | yes |
| 6 | createdAtUnixMs | `u64` | yes |
| 7 | startedAtUnixMs | `u64` | no |
| 8 | updatedAtUnixMs | `u64` | yes |
| 9 | completedAtUnixMs | `u64` | no |
| 10 | stages | repeated `StageV1` | yes |
| 11 | progressCompleted | `u64` | no |
| 12 | progressTotal | `u64` | no |
| 13 | attempt | `u32` | yes |
| 14 | cancelable | bool | yes |
| 15 | retryable | bool | yes |
| 16 | rerunnable | bool | yes |
| 17 | traceId | UUID | no |
| 18 | terminalReceiptHash | bytes | no |
| 19 | nativeStatus | `NativeStatusV1` | no |

### `EventV1`, schema `0x1008`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | eventSequence | `u64` | yes |
| 2 | operationUuid | UUID | no |
| 3 | kind | `u16` | yes |
| 4 | occurredAtUnixMs | `u64` | yes |
| 5 | actorId | UUID | no |
| 6 | stageId | UTF-8 | no |
| 7 | message | UTF-8 | no |
| 8 | nativeStatus | `NativeStatusV1` | no |
| 9 | previousEventHash | bytes | yes |
| 10 | eventHash | bytes | yes |
| 11 | evidenceIds | repeated `UuidValueV1` | no |

### `ReceiptV1`, schema `0x1009`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | receiptId | UUID | yes |
| 2 | receiptType | UTF-8 | yes |
| 3 | actorId | UUID | no |
| 4 | adapterContractHash | bytes | no |
| 5 | operationId | `u32` | no |
| 6 | operationUuid | UUID | no |
| 7 | requestHash | bytes | no |
| 8 | terminalStatus | `u16` | yes |
| 9 | createdAtUnixMs | `u64` | yes |
| 10 | eventSequence | `u64` | yes |
| 11 | eventHash | bytes | yes |
| 12 | checkpointSequence | `u64` | no |
| 13 | checkpointSignature | bytes | no |
| 14 | artifactHashes | repeated `HashValueV1` | no |
| 15 | privacyClass | `u16` | yes |

### `ProtocolFailureV1`, schema `0x100A`

| Tag | Field | Type | Required |
|---:|---|---|---|
| 1 | code | `u32` | yes |
| 2 | stage | UTF-8 | yes |
| 3 | diagnosticId | UUID | yes |
| 4 | retryable | bool | yes |
| 5 | retryAfterMs | `u32` | no |

## 8.4 Top-level messages

### Pairing and session

| ID | Message | Fields |
|---:|---|---|
| `0x0010` | `PAIR_REQUEST` | `1 clientFingerprint:bytes R`, `2 label:utf8 R`, `3 requestedGrants:repeated RoleGrantV1 R`, `4 platform:PlatformV1 R`, `5 pairingWindowId:uuid R` |
| `0x0011` | `PAIR_OFFER` | `1 provisionalActorId:uuid R`, `2 grantedRoles:repeated RoleGrantV1 R`, `3 brokerFingerprint:bytes R`, `4 brokerAuditKey:bytes R`, `5 offerHash:bytes R`, `6 expiresAtUnixMs:u64 R` |
| `0x0012` | `PAIR_COMMIT` | `1 provisionalActorId:uuid R`, `2 offerHash:bytes R`, `3 clientCommitNonce:uuid R` |
| `0x0013` | `PAIR_ACCEPT` | `1 actorId:uuid R`, `2 grantedRoles:repeated RoleGrantV1 R`, `3 pairedAtUnixMs:u64 R`, `4 auditCheckpoint:ReceiptV1 R` |
| `0x0014` | `PAIR_REJECT` | `1 failure:ProtocolFailureV1 R` |
| `0x0015` | `PAIR_COMPLETE` | `1 actorId:uuid R`, `2 closeReason:u16 R` |
| `0x0001` | `HELLO` | `1 peerKind:u16 R`, `2 minMinor:u16 R`, `3 maxMinor:u16 R`, `4 features:u64 R`, `5 maxLogicalPayload:u32 R`, `6 maxStreams:u32 R`, `7 initialConnectionCredit:u64 R`, `8 clientInstance:uuid R`, `9 platform:PlatformV1 R`, `10 clientWallUnixMs:u64 R` |
| `0x0002` | `HELLO_ACK` | `1 selectedMinor:u16 R`, `2 features:u64 R`, `3 maxLogicalPayload:u32 R`, `4 maxStreams:u32 R`, `5 initialConnectionCredit:u64 R`, `6 connectionEpoch:u64 R`, `7 brokerEpoch:uuid R`, `8 actorId:uuid R`, `9 readiness:ReadinessV1 R`, `10 brokerWallUnixMs:u64 R` |
| `0x0003` | `PING` | `1 senderMonotonicNs:u64 R`, `2 nonce:u64 R` |
| `0x0004` | `PONG` | `1 senderMonotonicNs:u64 R`, `2 nonce:u64 R`, `3 receiverMonotonicNs:u64 R` |
| `0x0005` | `GOAWAY` | `1 reason:u32 R`, `2 lastAcceptedClientStream:u32 R`, `3 lastAcceptedBrokerStream:u32 R`, `4 drainBudgetMs:u32 R`, `5 diagnosticId:uuid O` |
| `0x0006` | `WINDOW_UPDATE` | `1 targetStreamId:u32 R`, `2 additionalBytes:u64 R` |
| `0x0007` | `PROTOCOL_ERROR` | `1 failure:ProtocolFailureV1 R` |
| `0x0008` | `GENERIC_ACK` | `1 acknowledgedMessageId:uuid R`, `2 disposition:u16 R`, `3 failure:ProtocolFailureV1 O` |

### Calls

| ID | Message | Fields |
|---:|---|---|
| `0x0100` | `CALL_BEGIN` | `1 adapterHash:bytes R`, `2 operationId:u32 R`, `3 requestSchemaId:u32 R`, `4 deduplicationMode:u16 R`, `5 idempotencyKey:uuid O`, `6 requestHash:bytes R`, `7 disconnectPolicy:u16 R`, `8 sensitivity:u16 R` |
| `0x0101` | `CALL_DATA` | `1 chunkIndex:u32 R`, `2 offset:u64 R`, `3 logicalTotal:u64 R`, `4 chunkHash:bytes R`, `5 data:bytes R` |
| `0x0102` | `CALL_END` | `1 chunkCount:u32 R`, `2 totalHash:bytes R` |
| `0x0110` | `RESULT_BEGIN` | `1 responseSchemaId:u32 R`, `2 operationUuid:uuid O`, `3 nativeStatus:NativeStatusV1 R`, `4 logicalTotal:u64 R` |
| `0x0111` | `RESULT_DATA` | same tags as `CALL_DATA` |
| `0x0112` | `RESULT_END` | `1 chunkCount:u32 R`, `2 totalHash:bytes R`, `3 receipt:ReceiptV1 R`, `4 terminalStatus:u16 R` |
| `0x0120` | `CANCEL` | `1 targetMessageId:uuid O`, `2 targetOperationUuid:uuid O`, `3 targetTransferId:uuid O`, `4 reason:u16 R`; exactly one target required |
| `0x0121` | `CANCEL_ACK` | `1 disposition:u16 R`, `2 nativeCancelInvoked:bool R`, `3 operationStatus:u16 O`, `4 receipt:ReceiptV1 O` |

### Transfers

| ID | Message | Fields |
|---:|---|---|
| `0x0130` | `TRANSFER_BEGIN` | `1 transferId:uuid R`, `2 kind:u16 R`, `3 parentMessageId:uuid O`, `4 parentOperationUuid:uuid O`, `5 declaredLength:u64 R`, `6 contentHash:bytes R`, `7 mediaType:utf8 O`, `8 fileName:utf8 O`, `9 sensitivity:u16 R` |
| `0x0131` | `TRANSFER_DATA` | `1 transferId:uuid R`, `2 chunkIndex:u32 R`, `3 offset:u64 R`, `4 chunkHash:bytes R`, `5 data:bytes R` |
| `0x0132` | `TRANSFER_END` | `1 transferId:uuid R`, `2 chunkCount:u32 R`, `3 totalLength:u64 R`, `4 totalHash:bytes R`, `5 terminalStatus:u16 R`, `6 receipt:ReceiptV1 R` |
| `0x0133` | `TRANSFER_CANCEL` | `1 transferId:uuid R`, `2 reason:u16 R` |
| `0x0134` | `TRANSFER_CANCEL_ACK` | `1 transferId:uuid R`, `2 disposition:u16 R`, `3 receipt:ReceiptV1 O` |
| `0x0135` | `TRANSFER_RECEIPT` | `1 transferId:uuid R`, `2 receipt:ReceiptV1 R` |

### Callbacks, handles and operations

| ID | Message | Fields |
|---:|---|---|
| `0x0200` | `CALLBACK_REGISTER` | `1 callbackId:uuid R`, `2 contractHash:bytes R`, `3 leaseBudgetMs:u64 R`, `4 ordering:u16 R`, `5 maxConcurrency:u16 R`, `6 reentrant:bool R`, `7 executor:u16 R` |
| `0x0201` | `CALLBACK_INVOKE` | `1 callbackId:uuid R`, `2 invocationId:uuid R`, `3 payloadSchemaId:u32 R`, `4 parentCallId:uuid O`, `5 payload:bytes R` |
| `0x0202` | `CALLBACK_RESULT` | `1 invocationId:uuid R`, `2 nativeStatus:NativeStatusV1 R`, `3 payload:bytes O` |
| `0x0203` | `CALLBACK_UNREGISTER` | `1 callbackId:uuid R`, `2 reason:u16 R`, `3 drain:bool R` |
| `0x0300` | `HANDLE_CLOSE` | `1 brokerEpoch:uuid R`, `2 ownerActorId:uuid R`, `3 slot:u32 R`, `4 generation:u32 R`, `5 handleType:u32 R` |
| `0x0301` | `HANDLE_STATUS` | `1 disposition:u16 R`, `2 nativeStatus:NativeStatusV1 O`, `3 receipt:ReceiptV1 O` |
| `0x0400` | `OPERATION_QUERY` | `1 operationUuid:uuid R`, `2 afterEventSequence:u64 O` |
| `0x0401` | `OPERATION_STATE` | `1 operation:OperationV1 R`, `2 events:repeated EventV1 O`, `3 nextEventSequence:u64 R` |
| `0x0402` | `RECEIPT_QUERY` | `1 idempotencyKey:uuid R`, `2 adapterHash:bytes R`, `3 operationId:u32 R` |
| `0x0403` | `RECEIPT_RESULT` | `1 disposition:u16 R`, `2 operationUuid:uuid O`, `3 receipt:ReceiptV1 O` |
| `0x0410` | `AUDIT_CHECKPOINT` | `1 checkpointSequence:u64 R`, `2 eventSequence:u64 R`, `3 eventHash:bytes R`, `4 databaseGeneration:u64 R`, `5 signatureAlgorithm:u16 R`, `6 signingKeyGeneration:u64 R`, `7 signature:bytes R`, `8 signerFingerprint:bytes R` |

The actor context for every application message is derived exclusively from the
authenticated Noise session and broker actor registry. It is not caller
supplied in `CALL_BEGIN` or any other invocation message.

---

# 9. Errors, flow control and state rollback

## 9.1 Error registry

| Code | Symbol |
|---:|---|
| 1 | `PHYSICAL_LENGTH_INVALID` |
| 2 | `PHYSICAL_MESSAGE_TOO_LARGE` |
| 3 | `PHYSICAL_AUTH_FAILED` |
| 4 | `PHYSICAL_SEQUENCE_INVALID` |
| 5 | `FRAGMENT_HEADER_INVALID` |
| 6 | `FRAGMENT_ORDER_INVALID` |
| 7 | `FRAGMENT_TIMEOUT` |
| 8 | `LOGICAL_FRAME_TOO_LARGE` |
| 9 | `ENVELOPE_INVALID` |
| 10 | `VERSION_UNSUPPORTED` |
| 11 | `FEATURE_REQUIRED_UNSUPPORTED` |
| 12 | `FLAGS_INVALID` |
| 13 | `MESSAGE_UNKNOWN_REQUIRED` |
| 14 | `REQUIRED_FIELD_MISSING` |
| 15 | `FIELD_DUPLICATE` |
| 16 | `FIELD_TYPE_INVALID` |
| 17 | `FIELD_BOUNDS_EXCEEDED` |
| 18 | `STREAM_INITIATOR_INVALID` |
| 19 | `STREAM_REUSED` |
| 20 | `STREAM_UNKNOWN` |
| 21 | `STREAM_CLOSED` |
| 22 | `STREAM_SEQUENCE_INVALID` |
| 23 | `SEQUENCE_EXHAUSTED` |
| 24 | `FLOW_CONTROL_EXCEEDED` |
| 25 | `DEADLINE_EXCEEDED` |
| 26 | `AUTHENTICATION_FAILED` |
| 27 | `ACTOR_REVOKED` |
| 28 | `AUTHORIZATION_DENIED` |
| 29 | `PAIRING_WINDOW_CLOSED` |
| 30 | `PAIRING_PSK_CONSUMED` |
| 31 | `PAIRING_COMMIT_MISMATCH` |
| 32 | `PAIRING_STATE_ROLLBACK` |
| 33 | `ADAPTER_NOT_INSTALLED` |
| 34 | `CONTRACT_HASH_MISMATCH` |
| 35 | `OPERATION_NOT_ALLOWED` |
| 36 | `IDEMPOTENCY_CONFLICT` |
| 37 | `RESOURCE_EXHAUSTED` |
| 38 | `HANDLE_STALE` |
| 39 | `HANDLE_OWNER_MISMATCH` |
| 40 | `CALLBACK_GONE` |
| 41 | `CANCEL_TOO_LATE` |
| 42 | `OUTCOME_UNKNOWN` |
| 43 | `TARGET_IDENTITY_MISMATCH` |
| 44 | `DEPENDENCY_LAYOUT_INVALID` |
| 45 | `TRANSFER_HASH_MISMATCH` |
| 46 | `TRANSFER_LIMIT_EXCEEDED` |
| 47 | `KEYSTORE_UNAVAILABLE` |
| 48 | `AUDIT_CHAIN_INVALID` |
| 49 | `DATABASE_CORRUPT` |
| 50 | `INTERNAL_INVARIANT_FAILED` |

## 9.2 Flow-control state machine

Credits count decrypted logical payload bytes, excluding physical-fragment and
logical-envelope headers.

- `HELLO/HELLO_ACK` negotiates:
  - connection data credit: 8 MiB;
  - per-stream data credit: 2 MiB;
  - control reserve: 64 KiB.
- Sending `CALL_DATA`, `RESULT_DATA` or `TRANSFER_DATA` debits both connection
  and stream credit before the first byte is written.
- Control messages debit only the control reserve. A peer replenishes control
  reserve automatically after parsing a valid control message, capped at
  64 KiB. More than 1,024 control messages/second without data progress is
  `RESOURCE_EXHAUSTED`.
- `WINDOW_UPDATE(targetStreamId=0)` adds connection credit. Nonzero
  `targetStreamId` adds that stream's credit. `additionalBytes` must be
  `1..16 MiB`; overflow beyond negotiated maxima is
  `FLOW_CONTROL_EXCEEDED`.
- A sender with zero data credit queues no more than the negotiated bounded
  queue and writes no data bytes until credit arrives or the deadline expires.
- The receiver sends updates only after bytes are consumed, persisted to the
  bounded transfer file, or rejected and discarded.
- Closing/resetting a stream discards its remaining credit; stream credit is
  never transferred to another stream.
- Credit counters are unsigned 64-bit values; underflow, overflow or data
  received without credit closes the connection.

## 9.3 Call lifecycle

```text
NEW
 → CALL_BEGIN
 → REQUEST_OPEN
 → CALL_DATA* (contiguous chunkIndex/offset)
 → CALL_END (count/hash verified)
 → QUEUED
 → RUNNING
 → RESULT_BEGIN
 → RESULT_DATA*
 → RESULT_END
 → TERMINAL
```

Rules:

- One `CALL_BEGIN` per client-initiated odd stream.
- `CALL_DATA` indices begin at zero; offsets are contiguous; duplicate chunks
  are accepted only when index, offset, length and hash match exactly.
- `CALL_END` verifies chunk count, logical length and SHA-256 before dispatch.
- No result message precedes successful request verification.
- Exactly one terminal message exists: `RESULT_END`, terminal
  `PROTOCOL_ERROR`, or connection-loss reconciliation to `UNKNOWN`.
- `CANCEL` before dispatch removes the queued call. During execution it invokes
  only a contract-approved cancellation mechanism. A completion/cancel race is
  resolved by the broker's first committed terminal event; later messages get
  `ALREADY_TERMINAL`/`TOO_LATE`.
- Temporary request/result files are removed after terminal receipt retention
  no longer requires them; startup reconciliation removes orphaned uncommitted
  files.

## 9.4 Transfer lifecycle

```text
NEW
 → TRANSFER_BEGIN
 → TRANSFER_DATA* (contiguous offset)
 → TRANSFER_END
 → HASH_VERIFIED
 → RECEIPTED
 → CLOSED
```

- `declaredLength` and SHA-256 are mandatory before any data.
- `chunkIndex` starts at zero; `offset` must equal bytes already accepted.
- Exact duplicates are ignored idempotently; conflicting duplicates terminate
  with `TRANSFER_HASH_MISMATCH`.
- `TRANSFER_END` succeeds only when count, total length and total hash match.
- `TRANSFER_CANCEL` races use the same first-committed-terminal rule as calls.
- Interrupted transfers remain incomplete operations, never successful files.
- Startup reconciliation deletes unreceipted temp files and records a redacted
  cleanup event.
- `TRANSFER_RECEIPT` is emitted only after the final file/stream is durably
  placed under its declared path/content policy.

## 9.5 Limits

| Limit | Value |
|---|---:|
| Physical ciphertext | 65,535 bytes |
| Physical plaintext | 65,519 bytes |
| Fragment data | 65,487 bytes |
| Fragments/logical frame | 17 |
| Logical payload | 1,048,576 bytes |
| Ordinary request/result | 16 MiB each |
| Explicit transfer | 1 GiB |
| Streams/connection | 128 |
| Queued calls/actor | 256 |
| Callbacks/actor | 1,024 |
| Handles/actor | 65,536 |
| Initial connection credit | 8 MiB |
| Initial stream credit | 2 MiB |
| Control reserve | 64 KiB |
| Nesting depth | 32 |
| Fields/message | 4,096 |
| Pair/handshake timeout | 10 monotonic seconds |
| Fragment timeout | 10 monotonic seconds |
| Drain timeout | 30 monotonic seconds |
| Ordinary deadline maximum | 300 seconds |
| Contract-authorized EXE maximum | 24 hours |

## 9.6 Deduplication and crash windows

Modes:

- `READ_ONLY_REPLAYABLE`;
- `BROKER_DEDUPLICATED`;
- `TARGET_IDEMPOTENT`;
- `NOT_RETRYABLE`.

No “exactly once” claim exists.

For broker deduplication:

1. commit accepted request/key/hash;
2. invoke target;
3. commit result receipt.

A crash after target invocation but before result commit produces `UNKNOWN` unless authoritative target reconciliation is available. Such a call is not automatically replayed.

---

# 10. Actor authorization and trusted rollback anchor

## 10.1 Actor lifecycle

Actor record:

```text
actorId
clientStaticPublicKey
fingerprint
label
createdAt
roles[]
adapterGrants[]
revision
status
revokedAt?
revokedReason?
```

Roles:

- `INVOKE`;
- `OPERATOR`;
- `ADAPTER_ADMIN`;
- `PAIRING_ADMIN`;
- `AUDITOR`;
- `SERVICE_ADMIN`.

No bearer capability token or remote role delegation exists in v2.

Every operation checks:

```text
active actor
AND active session
AND required role
AND exact adapter/operation grant
AND target capability
AND dependency readiness
AND resource/rate limit
AND any required local administrative approval
```

Revocation rejects future IK sessions, drains active sessions with GOAWAY, blocks new calls, invalidates handles/callbacks and applies each running operation’s declared revocation policy.

## 10.2 Independent trusted rollback anchor

The trusted rollback anchor is independent of SQLite, broker configuration files and broker metadata.

Initial Windows support requires a functioning TPM 2.0/vTPM.

The broker creates:

1. a non-exportable TPM-backed Ed25519-compatible audit-signing key or, where the Windows CNG TPM provider cannot expose Ed25519, a non-exportable TPM-backed ECDSA P-256 audit key;
2. a TPM NV anchor containing:
   - anchor schema version;
   - database generation;
   - latest checkpoint sequence;
   - latest event sequence;
   - latest event hash;
   - actor-registry revision;
   - broker-identity-key generation.

The exact supported TPM algorithm is frozen by T010 after capability probing
and becomes a blocking platform input. It is not silently changed. Every
checkpoint carries `signatureAlgorithm`, `signingKeyGeneration`, signer
fingerprint and signature.

SQLite appends and signs every event in the broker hash chain, but TPM NV is
not written for every ordinary call. A TPM anchor is updated:

1. immediately for pairing commit, actor/grant/revocation changes, broker or
   audit-key rotation, update activation, migration and destructive actions;
2. after each 256 ordinary terminal events;
3. at least every 60 seconds while new events exist;
4. on clean service shutdown.

An ordinary call may return a signed receipt before the next TPM anchor. That
receipt states `anchorState=PENDING`, the last anchored checkpoint and the
current event hash. Paired clients persist the highest observed signed event
hash in Keychain and therefore act as an independent rollback witness. An
administrative/effecting operation reports durable success only after its
immediate TPM anchor succeeds.

T024 must measure TPM NV latency/endurance on the supported TPM/vTPM and may
increase the ordinary-event batch interval only through a ledger update and
security review. The gate requires:

- 100,000 simulated ordinary events without exceeding the vendor endurance
  budget extrapolated for five years;
- p99 immediate administrative anchor latency recorded;
- crash tests before/after DB commit, signature, and TPM write;
- no readiness when TPM state and the signed chain cannot be reconciled.

Startup compares database chain and metadata against TPM NV:

- database behind TPM: block readiness as rollback;
- database ahead of TPM: recover only from fully signed contiguous events, then advance TPM;
- hash mismatch: block;
- TPM unavailable: pairing/admin/update blocked; invocation policy defaults to blocked for effecting operations.

Paired Mac clients also pin the audit public key and highest observed checkpoint, providing an additional external witness.

The client witness contains broker fingerprint, signing-key generation,
checkpoint sequence, event sequence and event hash. Recovery requires at least
one of:

- TPM anchor consistent with the signed chain;
- a previously pinned client witness consistent with the signed chain and local
  administrator confirmation;
- a separately stored signed recovery bundle.

Restoring the database and broker metadata together cannot silently pass if all
independent anchors disagree or are unavailable.

## 10.3 Recovery and key rotation

Recovery requires local administrator presence and a signed recovery bundle containing:

- latest valid audit checkpoint;
- actor registry export without private keys;
- package/catalog hashes;
- database generation;
- prior broker/audit key fingerprints.

Recovery procedure:

1. verify chain to trusted checkpoint;
2. create new broker identity and audit keys;
3. increment TPM database/key generations;
4. append a signed discontinuity/recovery event;
5. revoke all active sessions;
6. require clients to confirm changed broker fingerprint through a new pairing;
7. never copy old private keys into source or general files.

If exposure status of any `runtime.key`, development identity or signing material is unknown, it is treated as exposed and rotated. No key is committed. Secret scanning includes Git history before release.

---

# 11. Adapter contract, canonicalization and dependency layout

**Ownership notice:** this section defines the runtime facts VM Bridge requires
from Whiny. Whiny owns the schema, canonicalization, validation, dependency
description and freezing. VM Bridge consumes the exact validated bytes and
hashes; it does not implement or extend the schema.

## 11.1 Canonicalization

Hash-bearing JSON uses:

- UTF-8 I-JSON;
- RFC 8785 JCS;
- duplicate keys rejected before parsing;
- no NaN/infinities;
- integers outside interoperable IEEE-754 range encoded as decimal strings;
- schema-defined sorting for set-like arrays;
- no post-parse Unicode normalization beyond RFC 8785 behavior.

## 11.2 External Whiny contract

The current Whiny-owned identifier is `whiny.adapter-contract.v3`, major 3.
The old illustrative VM schema below is retained only as historical context
until atomic cutover and is not a VM-owned compatibility contract.

```json
{
  "schemaVersion": 2,
  "adapterId": "vendor.product",
  "adapterVersion": "1.2.3",
  "family": "native-c-dll",
  "platforms": [],
  "packageRoots": [],
  "modules": [],
  "types": [],
  "operations": [],
  "security": {},
  "runtime": {},
  "evidence": {},
  "tests": {},
  "support": {}
}
```

Every operation defines identity, signature, ownership, nullability, aliasing, bounds, allocator, error behavior, roles, timeout, cancellation, disconnect, deduplication, callbacks, handles, async behavior and exact tests.

## 11.3 External Whiny bundle and dependency facts

The current Whiny-owned bundle identifier is `whiny.adapter-bundle.v1`, major
1. The dispatcher ABI identifier is `whiny.dispatch.v1`, major 1. VM Bridge
requires exact descriptor bytes and digest, contract bytes and digest, one
dispatcher, one target, dependency paths and hashes, operation IDs/schema
mappings and an explicit supported profile.

Package root:

```text
packageRootId
environment: mac|windows
installBasePolicy
layoutHash
```

Module:

```text
moduleId
kind
placement
packageRootId
relativePath
sha256
architecture
abi
loadOrder
dependencies[]
fallback
sourceEvidenceIds[]
```

Placements:

- `mac-local`;
- `mac-proxy`;
- `windows-real`;
- `windows-proxy-to-mac`.

Path rules:

- relative forward-slash paths only;
- no absolute, drive, UNC, NUL, `.` or `..`;
- reject Unicode-equivalent and Windows case-fold collisions;
- reject duplicates and path escape;
- reject escaping symlinks/reparse points;
- reject unexpected executable files;
- verify architecture, ABI, imports, exports, hashes and loaded canonical paths.

The required graph is acyclic. Fallbacks are explicit and hash-pinned.

## 11.4 Finalization order

Dependency schema and validation land early, but package layout is not finalized until all family generators have emitted their actual module/dependency requirements.

- T012 establishes schema and generic validation.
- Native, C++, COM/WinRT, managed and EXE generators produce family dependency facts.
- T105 performs final cross-family graph resolution, relative-layout generation and load-order validation.
- Packaging tasks depend on T105, not on a premature native-only layout.

## 11.5 Conditional reverse dependency

`windows-proxy-to-mac` is not baseline support.

T086 evaluates the trigger after static inspection, family generation and authorized tracing. T087 always completes with exactly one signed outcome:

1. `implemented` — real evidence required reverse execution and the adapter/tests passed; or
2. `not-applicable` — no real target trace/inspection established the need, feature remains disabled.

T140 depends on T087, so no OR-dependency or unowned branch remains.

---

# 12. Static inspection, dynamic inference and AI packets

**Whiny-owned source-plane section.** VM Bridge consumes only frozen outcomes.
No task in this section authorizes inspection, tracing, semantic inference,
evidence promotion or AI-packet generation in this repository.

## 12.1 Static inspection

Inputs:

- C/C++ headers and pinned Clang options;
- PE exports/imports/load configuration;
- PDB symbols/types;
- CLR ECMA-335 metadata and portable/Windows PDBs;
- IDL, TLB/ITypeInfo and WinMD;
- exact target hashes and architectures.

Confidence:

- `authoritative`;
- `structural`;
- `observed`;
- `inferred`;
- `unknown`.

Observed/inferred evidence never silently becomes authoritative.

## 12.2 Dynamic tracing

- Explicitly authorized and target-hash-bound.
- Detours for native Windows probes.
- Frida only when explicitly activated.
- Collects pseudonymous pointer identity, sizes, aliases, mutation ranges, allocator pairing, callback ordering, thread/apartment, handles, async/cancel sequence and loaded-path/hash evidence.
- Excludes payload bodies, credentials, pairing material, account/profile IDs, signatures, tokens and private keys by default.
- Contradictions block generation.

## 12.3 Prompt-injection-safe AI packet

Packet sections:

1. trusted version-controlled instructions;
2. target identity and contract hash;
3. typed unresolved questions;
4. exact files/symbols/functions;
5. tests and deterministic commands;
6. privacy/security constraints;
7. hard stops;
8. untrusted attachments.

All inspected comments, names, metadata, documentation, paths and trace strings are untrusted data.

They are:

- JSON-escaped under `untrustedAttachments[]`;
- base64-encoded if invalid UTF-8;
- bounded and redacted;
- prefixed by a fixed warning;
- rendered using generated delimiters unrelated to content;
- never copied into the trusted instruction section;
- interpreted only through typed IR.

Malicious comments, Markdown fences, shell commands, Unicode controls and instruction-like metadata are mandatory tests.

---

# 13. Target-family generation contracts

**Whiny-owned source-plane section.** These target-family requirements constrain
the immutable bundles VM Bridge may consume. VM Bridge implements generic
runtime execution and loaders for the declared dispatcher ABI only; it does not
generate native, managed, EXE, C++, COM or WinRT artifacts.

## 13.1 Native C

- Exact export names/ordinals/calling convention.
- Exact target architecture.
- Struct packing/layout and scalar widths.
- Generated proxy and dispatcher compile without manual edits.
- Fresh-process local versus remote differential oracle.

## 13.2 Native C++ initial subset

Supported:

- Windows x64 MSVC ABI only;
- exact pinned v143 compiler and `/MD` CRT;
- decorated exported free functions;
- decorated exported static member functions that do not depend on object state;
- POD/standard-layout parameters and results;
- explicit opaque remote handles created through separately exported C-like factory functions;
- no STL types across the boundary;
- no caller-visible exception propagation.

Rejected before generation:

- exported constructors or destructors;
- copy/move constructors or assignment operators;
- non-static instance methods, including implicit `this`;
- virtual methods and vtables;
- multiple or virtual inheritance;
- RTTI/`dynamic_cast` dependence;
- member-pointer ABI;
- shared allocator ownership;
- STL strings/containers;
- coroutine frames;
- C++ exceptions expected by the caller.

Inspection still records constructors, destructors, instance methods and vtables. Their presence produces a precise stop/AI packet. They are not partially proxied.

Target exceptions are caught only inside the Windows dispatcher and mapped to a contract-declared native status. If no truthful mapping exists, generation stops.

## 13.3 COM

Caller proxy:

- registration-free manifest;
- `DllGetClassObject`;
- `DllCanUnloadNow`;
- generated `IClassFactory`;
- aggregation rejected with `CLASS_E_NOAGGREGATION` unless explicitly proved.

Identity:

- one remote object ID per controlling `IUnknown`;
- all QI-derived interfaces share controlling identity;
- only declared IIDs;
- unsupported IID returns `E_NOINTERFACE`.

Refcount:

- default local reference aggregation with one broker lease per controlling identity;
- final release closes broker lease;
- exact per-`AddRef/Release` mode only when required and tested.

Apartments:

- dedicated STA executor/message pump;
- bounded MTA pool;
- authoritative apartment declaration required;
- custom `IMarshal` or undocumented pumping stops.

Broker activation:

- exact-hash registration-free activation context or exact class-factory export;
- out-of-process server requires an EXE process contract.

## 13.4 WinRT

- Generated `DllGetActivationFactory`.
- Runtime classes/IIDs from exact WinMD.
- Exact HSTRING and `IInspectable` semantics.
- Broker activation through pinned package activation context and `RoGetActivationFactory` or exact export.
- Async completion/cancellation follows protocol state machines.

## 13.5 .NET assembly

Initial hosts:

- `.NET Framework 4.8.1`;
- `.NET 8.0 Windows`.

Unsupported initially:

- Mono caller runtime;
- mixed-mode C++/CLI;
- reflection-only undocumented API;
- unsupported NativeAOT reflection behavior.

Public API reproduction includes types, constructors, methods, properties, events, generics, nullable metadata and async methods.

### Field policy

Supported fields are limited to:

1. compile-time constants (`literal`/`const`) copied exactly from metadata;
2. local immutable metadata fields whose value is fully present in metadata or generated constants and does not depend on remote runtime state;
3. private generated implementation fields not part of the target public API.

Rejected before generation:

- public/protected mutable instance fields;
- public/protected mutable static fields;
- instance `readonly` fields that represent target object state;
- static `readonly` fields initialized by target code, configuration, environment, time, I/O or native calls;
- fields requiring synchronization with a remote object;
- thread-static/context-static fields;
- field-backed state observed directly by caller IL.

Such APIs require a contract redesign or exact custom implementation packet. The generator must not replace remotely stateful fields with stale local copies.

### Binding and strong names

- `net481`: application-local proxy and tested binding redirect only when authorized.
- `net8.0-windows`: application-local `.deps.json`/runtimeconfig and isolated `AssemblyLoadContext`.
- All dependencies hash-pinned.
- Original public-key token requires authorized private strong-name key.
- Without key, stop unless a new identity plus binding redirect is explicitly authorized and proven against the real caller.
- Strong-name signing is distinct from Authenticode.

## 13.6 Native and .NET EXEs

Proxy preserves only declared:

- command-line quoting and argv;
- environment allowlist;
- working-directory policy;
- stdin/stdout/stderr;
- exit code;
- timeout/cancellation;
- child process tree.

Windows execution uses a Job Object with kill-on-close and resource limits. Interactive GUI/process-local IPC/shared memory requires a separate adapter.

---

# 14. Guarded copying under Wine

Generated PE proxies use a dedicated native layer:

```text
wvb_guarded_copy_in
wvb_guarded_copy_out
wvb_guarded_read_scalar
wvb_guarded_write_scalar
```

Mechanism:

1. Build the proxy as a PE DLL with the pinned clang-cl/MSVC-compatible toolchain.
2. Use `VirtualQuery` only for preliminary range/protection checks; never treat it as race-free validation.
3. Snapshot input with `memcpy` inside Windows structured exception handling:
   ```c
   __try { memcpy(...); }
   __except(EXCEPTION_EXECUTE_HANDLER) { ... }
   ```
4. Perform network work only on broker-owned snapshots.
5. Stage complete output in proxy-owned memory.
6. Copy output once through the same SEH boundary after full validation.
7. Map access violations to the exact contract-declared error, normally `ERROR_NOACCESS`, `E_POINTER` or family-specific equivalent.
8. Never use `IsBadReadPtr`/`IsBadWritePtr`.
9. Never hold loader lock while copying or calling the network.

TOCTOU cannot be eliminated when another thread concurrently changes mappings. Therefore:

- SEH is the authoritative fault containment;
- an output copy may have partially modified caller memory before a cross-page fault;
- contracts requiring atomic no-change-on-invalid-pointer semantics stop unless a target-specific safe mechanism is proved;
- concurrent caller mutation during input snapshot is undefined unless the source API defines synchronization.

Mandatory tests:

- null pointer;
- zero length;
- valid one-page buffer;
- buffer crossing readable pages;
- crossing into `PAGE_NOACCESS`;
- decommitted second page;
- guard page;
- integer overflow in pointer+length;
- concurrent `VirtualProtect`/decommit race;
- output fault after staged result;
- fault-to-native-error parity under Wine;
- no broker invocation after failed input snapshot.

---

# 15. Marshalling matrix

| Category | Canonical policy | Stop condition |
|---|---|---|
| Scalar | explicit width/sign/IEEE bits | architecture-dependent width unknown |
| Enum/flags | underlying width and unknown policy | missing width |
| Record | size/alignment/packing/offsets | incomplete layout |
| Union | explicit discriminator and arm | unknown active arm |
| Bitfield | exact compiler layout | source spelling only |
| UTF-8/ANSI | byte count/terminator/code page | unspecified code page |
| UTF-16/BSTR/HSTRING | code units/embedded null/allocator | conflated forms |
| Buffer | direction/capacity/required length/maximum | unbounded pointer |
| Pointer graph | IDs, aliases, ownership, node/edge limits | unresolved graph |
| Allocator | named allocation/free in same environment | unknown owner |
| Handle | epoch/actor/slot/generation/type/close | raw handle transfer |
| Callback | lease/thread/order/reentrancy/unregister | unknown lifetime/thread |
| Async | begin/completion/result/cancel | timeout treated as completion |
| COM | controlling identity/IIDs/ref/apartment | custom marshaling unresolved |
| Exception | declared mapping only | caller-visible C++ exception |
| `GetLastError` | immediate capture and caller-thread restore | intervening call |
| File | content-addressed transfer | arbitrary path exposure |
| Shared buffer | copied/chunked semantics | zero-copy claim |
| Sensitive data | explicit privacy class | unauthorized export |

---

# 16. Runtime, operations, setup and migration

## 16.1 Mac/Wine runtime

- One process-wide connection pool per broker identity.
- No network/blocking work in `DllMain`.
- Guarded ABI copies as §14.
- Thread-local last-error restore.
- Explicit callback executors.
- Forked child discards inherited session.
- Bounded queues and honest resource errors.

## 16.2 Windows broker

- Least-privileged service.
- Exact package ACLs.
- Reparse/path escape rejection.
- Pre-load and post-load path/hash verification.
- Typed dispatcher boundary.
- Worker isolation where required.
- SQLite WAL with bounded writer queue.
- Startup reconciliation and distinct health/readiness.

## 16.3 Frozen-bundle admission and controlled loading

Admission consumes a runtime-owned operator approval record plus exact immutable
Whiny contract and bundle-descriptor bytes. It does not parse, infer or extend
the Whiny schema.

The approval record pins:

- contract identifier and major: `whiny.adapter-contract.v3`, major 3;
- bundle identifier and major: `whiny.adapter-bundle.v1`, major 1;
- dispatcher ABI identifier and major: `whiny.dispatch.v1`, major 1;
- exact contract and bundle-descriptor SHA-256 values;
- exactly one dispatcher and one target;
- every dependency relative path and SHA-256;
- the admitted operation IDs and schema mappings;
- the explicit supported bundle profile.

Admission requires a pre-existing, unexpired `AdapterAdmin` grant scoped to the
contract hash. Bundle contents cannot create actors, roles or grants. Invocation
separately requires the caller's `Invoke` grant for the exact contract hash and
operation ID.

Load paths are portable relative forward-slash paths only. Admission rejects
absolute, drive, UNC, backslash, NUL, empty, dot and dot-dot components;
case-fold collisions; duplicate dispatcher/target roles; symlinks, junctions
and other reparse points; non-regular files; path escapes; incompatible majors;
and contract, descriptor or file hash mismatches. The runtime returns only
canonical verified paths and re-verifies file identity immediately before and
after module load. Ambient `PATH`, current-directory and registry-based library
resolution are prohibited.

Whiny bundle v1 descriptor and dispatcher vectors are an external hold. The
selected identifiers may be pinned now, but old generator/fixture removal and
production activation wait for Whiny's exact bytes, digests and artifact
coordinates.

## 16.4 Durable operation schema

Every long-running/effecting operation includes:

- operation UUID/type;
- actor and targets;
- created/started/updated/completed times;
- full status enum;
- ordered stages;
- honest progress;
- attempt and idempotency-key hash;
- retry/cancel/rerun flags;
- error/evidence/artifacts;
- trace ID and terminal receipt.

## 16.5 Two-command setup wrapper

After obtaining the signed release wrapper/package through the documented release channel, canonical clean-machine setup is accepted only if these two operator commands are sufficient:

**Windows VM, elevated:**

```powershell
wvb-bootstrap-windows setup
```

This command:

- verifies the signed release manifest;
- installs the MSI;
- creates service/firewall/TPM anchor;
- starts the service;
- opens a ten-minute pairing window;
- displays the one-time pairing code locally.

**Mac:**

```bash
wvb-bootstrap-macos setup --broker <guest-address>
```

This command:

- verifies the signed/notarized package;
- installs CLI/runtime;
- prompts interactively for the pairing code without placing it in argv, shell history or logs;
- completes pairing;
- runs doctor and the real core call.

Acceptance requires no manual file copy, service editing, firewall editing, config editing or UTM protocol substitution. If the topology requires an explicit UTM port-forward, the wrapper must detect and provide one exact preflight instruction; setup is not declared two-command-ready until the supported UTM network mode needs no undisclosed manual step.

The wrappers are convenience orchestrators over the same receipted package operations, not alternate installers or protocols.

The bootstrap is not package content and cannot authenticate itself. Production
distribution signs/notarizes the bootstrap separately through the platform
channel. Only that trusted external launcher verifies `release-manifest.json`;
the envelope then covers every package-supplied executable before execution.
Unsigned archives are development/review artifacts and intentionally contain
no bootstrap binary.

## 16.6 Platform/toolchain matrix

Product classes are frozen now:

- Apple Silicon host;
- macOS 15 family;
- UTM/QEMU backend;
- Windows 11 24H2 x64 guest with TPM 2.0/vTPM;
- Wine x86_64 environment;
- MSVC v143;
- Windows SDK 10.0.26100 family;
- .NET Framework 4.8.1;
- .NET 8 LTS;
- pinned Rust/CMake/Ninja.

Exact patch versions, package hashes, compiler binaries, SDK hashes, UTM/QEMU build IDs, Wine build and OS patch versions are blocking T010 inputs. T010 cannot pass, and no toolchain/platform receipt may be claimed, until those values are observed, selected, downloaded from approved sources and recorded. No placeholder is accepted in a release receipt.

## 16.7 Migration and hard stops

- Back up v1 state.
- Pair v2 from scratch.
- Never import or derive from the v1 capability secret.
- Import only validated non-secret preferences.
- Verify v2 and restoration backup.
- Preflight old-secret deletion.
- Delete plaintext v1 secret with presence-only destruction receipt.
- Never run v1 and v2 simultaneously.
- After deletion, v1 rollback requires fresh v1 pairing.

Hard stops:

- do not retry the occupied official Windows forwarding path without a newly
  identified isolated port or explicit maintenance authorization;
- do not retry the CrossOver by-name unixlib route with the unchanged
  `NtQueryVirtualMemory`/`STATUS_INVALID_INFO_CLASS` hypothesis;
- do not consume the paused native-EXE candidate except through its explicit
  clean migration artifact or a later commit from its owner;
- do not activate native, managed, EXE, C++, COM or WinRT profiles before their
  frozen Whiny bundle and dispatcher vectors are admitted;
- do not substitute shared memory, vsock, gRPC, GUI remoting, kernel/driver
  execution, anti-cheat bypass, ambient path loading or untraced reverse
  dependency proxying for the approved runtime architecture.

Offline OOBE recovery was investigated against the exact suspended VM and
official Microsoft mechanisms. A host-side Windows 11 x64 ISO was observed at
SHA-256 `bd4307df32bc8af33b39ccecb1174aeb345386630f89a2b86c7a4e36b55ea650`,
but was not attached or booted. Supported `LocalAccounts` unattend requires
password material in the answer file, violating the explicit no-secret-on-media
hold. `RunSynchronous` and `SetupComplete.cmd` apply during earlier setup
passes and are not a deterministic supported recovery hook for an installation
already at OOBE. Offline SAM/authentication-binary edits remain prohibited.
Therefore no offline disk write was performed. The VM is suspended with
snapshot `wvb-pre-acceptance-20261018`; the minimal safe resume action remains
manual `start ms-cxh:localonly`, local admin creation, OOBE completion and the
mounted UTM guest-tools UAC approval.

## 16.8 Runtime Owner convergence surface

VM Bridge owns only typed runtime operations:

- install, activate and roll back an already-frozen bundle;
- execute one admitted operation;
- query a runtime receipt;
- collect runtime diagnostics.

Host capability discovery records readiness, architecture, authority, supported
profiles, payload bounds and capability revision. Selection prefers a ready
local Windows ARM64 host for compatible non-authoritative work and routes x64
or authoritative requirements to the authoritative Windows x64 host.

Every workload attempt has a workload UUID, attempt UUID, selected host,
bundle hash, optional operation ID and terminal receipt ID. The canonicalized
correlation is stored in the durable operation detail and its hash is the
idempotency key. `whiny.runtime-receipt.v1` remains unchanged; correlation is
joined by durable receipt ID rather than adding VM-owned fields to Whiny's
schema.

VM Bridge does not own AI policy, blocker interpretation, contract inference,
campaign policy, semantic review or generation.

---

# 17. Audit integrity and privacy

## 17.1 Hash chain

```text
eventHash = SHA-256(
  "WVB-AUDIT-V1" ||
  previousEventHash ||
  sequence_u64_be ||
  RFC8785(eventWithoutHashFields)
)
```

Signed checkpoints occur at:

- pairing/actor/grant/key mutations;
- every terminal effecting operation;
- every 1,024 events;
- before update/uninstall;
- release/export.

Checkpoint includes event hash, sequence, database generation and TPM signature. TPM NV anchor is updated before durable success is reported.

## 17.2 Privacy

| Class | Examples | Handling |
|---|---|---|
| Public | schemas, public ledger, public tool versions | publishable |
| Internal | hashes, relative logical paths, timings | restricted; redact public export |
| Confidential | private contracts, headers, PDB metadata, traces, AI packets, held-out data | encrypted restricted storage |
| Secret | keys, pairing code, credentials, tokens, sensitive payloads | OS secret store/memory only |

Default retention:

- logs 14 days;
- audit/receipts 90 days;
- diagnostic bundles 30 days;
- traces 7 days;
- AI packets 30 days or until resolved;
- private contract evidence while adapter installed plus 30 days;
- held-out corpus while maintained;
- pairing PSK until commit/expiry only.

Destruction creates a signed presence-only receipt.

---

# 18. Security, testing and performance

## 18.1 Security controls

- Boundary validation before allocation and target invocation.
- Actor ACL on every operation.
- Pair attempts: five/source/ten minutes, twenty globally.
- Per-actor calls/bytes/callbacks/diagnostics limits.
- Exact target/load-path/hash checks.
- Dependency lockfiles, advisory/license/source checks.
- SPDX SBOM and provenance.
- Signing keys referenced externally.
- `runtime.key` ignored and forbidden from commits.
- Unknown exposure causes rotation.

## 18.2 Test classes

| Layer | Acceptance |
|---|---|
| Unit | all protocol/authz/dependency/state/canonicalization logic passes |
| Property | 100,000 cases per frozen seed set |
| Fuzz | sanitizer-clean, eight CPU-hours/target before release |
| Contract | every supported contract has zero unresolved semantics |
| Differential | fresh-process local and remote parity |
| Compatibility | advertised v2 minors only |
| Chaos | disconnect, suspend/resume, DB corruption, disk full, keystore denial, worker crash |
| E2E | real Wine process consumes real Windows result |
| Reproducibility | two isolated unsigned builds byte-identical |
| Clean machine | two-command setup through uninstall |
| Security | replay/downgrade/path/DLL/packet-injection attacks rejected |

## 18.3 Held-out sets

### Expected-supported

- Frozen before evaluation.
- Entirely inside documented supported subsets.
- **100%** must generate compilable artifacts without manual source edits.
- **100%** must pass family contract/export/API tests.
- At least one held-out target per required family must complete applicable E2E.
- Any false stop or false support blocks release.

### Expected-stop

- **100%** stop before support artifact generation.
- **100%** emit exact valid AI packets.
- **100%** preserve prompt-injection boundary.
- Any unsupported case labeled supported blocks release.

## 18.4 Performance

T131 is a release dependency and measures:

- tiny, 4 KiB, 64 KiB and 1 MiB;
- cold/warm;
- p50/p95/p99;
- CPU, allocation and bytes;
- callback and cancellation;
- native/managed EXE streams.

First release:

- correctness and bounded-resource gates are mandatory;
- results from three complete topology runs are published;
- no external threshold is invented;
- accepted results become the signed v2.0 baseline.

The packed codec is immutable for v2. FlatBuffers or another codec may be benchmarked only as research for a separately approved v3 proposal. T131 cannot alter v2 negotiation, schemas or implementation.

---

# 19. Deterministic builds and gates

## 19.1 Canonical build records

Hash-bearing JSON uses RFC 8785. Deterministic epoch is the newest committed source input timestamp. Wall-clock build time exists only in an outer execution receipt.

Unsigned artifacts record:

- source/input hashes;
- exact toolchain package hashes;
- contract/dependency graph hashes;
- compiler/linker flags;
- virtualized paths;
- target/API/export hashes;
- generated/object/final hashes;
- tests;
- unresolved list.

Strong-name signing is part of managed identity when authorized. Authenticode/notarization is separate.

## 19.2 Exact planned commands

No command is claimed green until a matching gate receipt exists.

```bash
python3 tools/run_gate.py validate .architrave/runs/wvb-canonical-v2/architrave.run.v2.json
python3 tools/gate.py schemas
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo deny check
cmake --preset windows-x64-release
cmake --build --preset windows-x64-release
ctest --preset windows-x64-release --output-on-failure
dotnet restore managed/Wvb.sln --locked-mode
dotnet build managed/Wvb.sln -c Release --no-restore
dotnet test managed/Wvb.sln -c Release --no-build
python3 tools/gate.py protocol-golden
python3 tools/gate.py dependency-layout
python3 tools/gate.py guarded-copy
python3 tools/gate.py prompt-injection
python3 tools/gate.py audit-anchor
python3 tools/gate.py receipts
python3 tools/verify_reproducible.py --preset release
python3 tools/gate.py differential
python3 tools/gate.py chaos
python3 tools/gate.py held-out
python3 tools/gate.py topology-benchmark
python3 tools/gate.py clean-machine
python3 tools/gate.py secret-scan --include-history
python3 tools/gate.py release
```

---

# 20. Durable Run and phase ledger

## 20.1 Run artifacts

```text
.architrave/runs/wvb-canonical-v2/
  architrave.run.v2.json
  intake.md
  acceptance-matrix.json
  tournament.md
  candidate-ledger.md
  ledger-reconciliation.json
  owner-approval.json
  reviews/review-loop-1-revise.md
  reviews/review-loop-2-revise.md
  reviews/follow-up-pass.md
  events.jsonl
  holds.json
  gates/
  receipts/
  summary.md
```

The Run records user approval timestamp, candidate hash, public ledger hash, live-status reconciliation hashes, review receipts, exact task graph and phase state.

Typed events:

```text
run-created
ledger-candidate-recorded
owner-approved
review-revise
review-pass
ledger-published
hold-created
hold-released
phase-started
task-started
task-blocked
task-completed
gate-started
gate-passed
gate-failed
checkpoint
release-candidate
main-integrated
```

## 20.2 Phase ledger

| Phase | Current status | Exit |
|---|---|---|
| P0 runtime ownership and admission architecture | `in-progress` | independent review PASS and focused gates |
| P1 durable admission/state/receipts | `ready` | crash-safe admit/revoke/query and audit gates |
| P2 transfer/handle/callback/async integration | `ready` | lifecycle, cancellation, replay and resource gates |
| P3 generic native/CLR/process execution hosts | `partially-held` | frozen Whiny vectors plus host/process gates |
| P4 pairing/key storage/Wine configuration | `partial` | OS-backed identity and supported Wine configuration evidence |
| P5 broker service/readiness/diagnostics | `ready` | least privilege, reconciliation and truthful diagnostics |
| P6 setup/update/rollback/uninstall | `pending` | clean lifecycle and restoration gates |
| P7 resilience/fuzz/performance/provenance | `pending` | abuse, crash, benchmark, SBOM and signing-separation gates |
| P8 Windows VM and clean-machine acceptance | `topology-hold` | isolated authorized forward, exact commands and real evidence |
| P9 atomic Whiny cutover | `external-hold` | frozen native+managed bundle vectors and consumer PASS |
| P10 final integration review | `pending` | full configured gates and independent PASS |

---

# 21. Dependency-safe task graph

## 21.1 Binding runtime-only graph and deferred-scope inventory

Statuses describe repository evidence at Revision 5. `external-hold` means VM
Bridge code may prepare the consumer/runtime side but cannot claim integration.

| ID | Runtime-owned deliverable | Owner | Dependencies | Acceptance gate | Status |
|---|---|---|---|---|---|
| R000 | Runtime ledger/ADR and exact ownership map | VM Bridge | verified baseline `d5b8e89`; Whiny ownership decision | one canonical ledger, path map complete, independent adversarial review | implementation complete; T000 durable reconciliation and current ledger review pending |
| R010 | Frozen-bundle admission, compatibility and controlled loader | VM Bridge | `R000`; Whiny identifiers | negative ACL/path/hash/ABI/symlink/reparse tests; pre-load reverify | complete |
| R011 | Durable admission store and operator lifecycle | VM Bridge | `R010`, state/audit chain | authorized admit/revoke, crash rollback, startup reconciliation, no bundle-granted ACL | complete |
| R020 | Pair transaction, IK session recovery and OS-backed key consumption | VM Bridge | existing crypto/session/authz; Keychain/Windows keystore policy | pairing crash windows, rotation/revocation, no plaintext secret, keystore denial tests | partial |
| R030 | Compound transfer integration | VM Bridge | protocol transfer states, broker/client multiplexing, receipts | begin/data/end/cancel/receipt, bounds/hash/replay/disconnect tests | protocol codec, bounded registry and broker stream integration complete |
| R031 | Guarded runtime copy and native error containment | VM Bridge | admitted native profile; Whiny marshalling declarations | SEH/TOCTOU/buffer/HRESULT/Win32/NTSTATUS/last-error tests under Wine | external-hold |
| R040 | Handle ownership, generation and restart invalidation | VM Bridge | `R020`, `R011` | actor/epoch/type/generation/close/restart/crash tests | primitives and exact handle close/status protocol complete; dispatcher integration waits for frozen profiles |
| R041 | Callback reverse RPC lifecycle | VM Bridge | `R030`, `R040` | thread/order/reentrancy/unregister/disconnect/resource-bound tests | exact protocol codec and actor/epoch/lease/thread/concurrency service complete; broker reverse-stream integration pending |
| R042 | Async cancellation and unknown-outcome receipts | VM Bridge | `R041`, `R011` | first terminal outcome wins; cancel races; disconnect/crash remains `unknown` | durable transitions plus exact cancel/operation/receipt/audit protocol controls complete |
| R050 | Native dispatcher host and generic `whiny.dispatch.v1` loader | VM Bridge | `R010`; frozen native vector | exact export/ABI/load-path/hash and pre/post-load checks | generic loader and deterministic frozen native CrossOver oracle complete |
| R051 | CLR dispatcher host and generic `whiny.dispatch.v1` loader | VM Bridge | `R010`; existing CLR host; frozen managed vector | host/runtime/dispatcher/target hashes, binding and crash isolation | frozen bundle admitted and encrypted CLR host CrossOver round trip complete |
| R052 | Native/.NET process execution and Job Object lifecycle | VM Bridge | `R011`, `R020`; clean native-EXE migration artifact | argv/env/stdin/stdout/stderr/exit/timeout/cancel/tree-kill/receipt tests | native codec/broker/CrossOver Job Object oracle complete; managed process pending |
| R060 | Broker service composition and bounded queues | VM Bridge | `R011`, `R030`–`R052` | least privilege, package ACL, worker containment, restart reconciliation | ready |
| R061 | Readiness, health and redacted diagnostics | VM Bridge | `R060`, receipt store | truthful distinct states, source versions, no unconditional success, privacy tests | readiness/resource controls and runtime doctor complete; service export pending |
| R062 | Runtime receipts, audit anchor, retention and privacy | VM Bridge | `R011`, `whiny.runtime-receipt.v1` | hash chain, independent rollback anchor, query/export/redaction/retention tests | domain-separated JCS audit chain, anchored-prefix recovery, atomic Runtime Owner terminal receipt signing/persistence/correlation, audited retention redaction and exact `whiny.runtime-receipt.v1\\0 || RFC8785` compatibility complete |
| R070 | macOS Keychain identity consumption | VM Bridge | `R020` | `SecItem` store/load/delete, access denial, zeroization, no argv/log secret | partial |
| R071 | Safe Wine automatic configuration alternative | VM Bridge | `R070`; new evidence beyond failed by-name route | supported API/process boundary, exact bottle identity, no plaintext registry secret | official source confirms loader-initialized unixlib handle direction; implementation held because Wine build tooling/bundle is unavailable |
| R080 | Windows service/MSI/firewall and macOS package setup | VM Bridge | `R060`, `R070`, admitted bundle catalog | clean install/pair/doctor/core call with receipted rollback | fail-closed bootstrap wrappers and runtime doctor complete; deterministic platform installers pending |
| R081 | Update, rollback and uninstall | VM Bridge | `R080`, `R062` | inactive staging, health-gated activation, snapshot restoration, impact preflight | deterministic package core complete; platform installers pending |
| R090 | Resilience, fuzzing, replay and resource bounds | VM Bridge | all runtime handlers | deterministic negative suites, fuzz/sanitizer budgets, disk/DB/keystore/worker crash | replay/rate/resource negatives, deterministic malformed corpora and AddressSanitizer/libFuzzer runtime-parser target complete; local campaign completed 5,305,588 executions without a crash; extended chaos duration remains a release-environment gate |
| R091 | Topology benchmark | VM Bridge | `R090`, admitted profiles | three complete runs for tiny/4 KiB/64 KiB/1 MiB plus callback/cancel/process | process-local benchmark harness complete; real topology hold |
| R100 | SBOM, provenance and signing separation | VM Bridge | reproducible runtime packages, `R081`, `R090` | SPDX/provenance; unsigned reproducibility; external signing receipts only | two isolated checkout builds with compiler path remapping reproduced source archive SHA-256 `cea9bedd…dd7a2`; final macOS tar `6d5fa6ba…dc9a4` and Windows tar `5ac33ea2…33b03` include embedded SPDX, authenticated release envelopes and artifact-bound provenance; separately authenticated bootstraps and signing remain external |
| R110 | Windows VM acceptance controls | VM Bridge | `R080`–`R100`; isolated forward or maintenance grant | exact reproducible commands, target identity, no unrelated VM/service mutation | exact UUID verified, snapshot created and VM safely suspended at OOBE; supported offline provisioning rejected because it requires secret-bearing unattend or nondeterministic/prohibited offline authentication edits; manual OOBE/guest-tools step required |
| R111 | Clean-machine acceptance | VM Bridge | `R110`, frozen release inputs | setup through update/rollback/uninstall on clean supported hosts | deterministic packages and lifecycle controls ready; live Windows clean-machine run blocked on guest-agent/login control |
| R120 | Atomic Whiny cutover and duplicate-source removal | VM Bridge + Whiny | frozen native+managed vectors; `R010`, `R050`, `R051`, consumer tests | pin artifact coordinates/digests; remove MOVE/DROP paths in one change; vertical paths green | complete at Whiny commit `870da868`; pinned package SHA-256 `e95244e9…7a6f` |
| R125 | Runtime Owner operations, host capability selection and workload correlation | VM Bridge | `R011`, `R081`, `R120` | typed operations; local ARM64 vs authoritative x64 selection; durable workload/attempt/receipt join | runtime-owner library and deterministic selection/correlation tests complete |
| R130 | Final deterministic/security/reality gates and independent review | VM Bridge | `R011`–`R125` | configured quality/build/test, real evidence, zero blocking review findings | receipt binding/privacy review PASS at `170590b`, fuzz/evidence delta adversarial PASS at `f3f0e96`, and isolated package reproducibility review PASS at `07e15bc`; T161 remains held behind T160 and canonical Run reconciliation |

Rejected or conditional scope:

| Item | Decision |
|---|---|
| Shared memory, ivshmem or vsock replacement | **REJECTED** for v2; no supported Mac/UTM/Windows topology evidence |
| gRPC replacement | **REJECTED** for v2; the canonical framed transport remains |
| GUI remoting | **REJECTED** |
| Kernel/driver execution | **REJECTED** |
| Anti-cheat or DRM bypass | **REJECTED** |
| Ambient `PATH`/current-directory DLL loading | **REJECTED** |
| Reverse dependency proxying | **CONDITIONAL** only after explicit Whiny evidence and an admitted frozen bundle; never inferred by VM Bridge |

## 21.2 Historical full-stack graph

The table below is retained only for provenance. Whiny-owned inspection,
contract, inference and generation rows are external dependencies, not VM Bridge
implementation tasks. Section 21.1 is the binding executable graph.

| ID | Files/owner | Dependencies | Acceptance | Rollback/risk |
|---|---|---|---|---|
| T000 | Run candidate, approval, reconciliation | none | record this ledger hash, user approval, review-loop receipts, current live-status hash and hold | revise artifacts only |
| T001 | `docs/research-sources.md`, source receipt | T000 | stable URLs/versions/dates and Whiny source hashes recorded | docs-only |
| T002 | public `docs/implementation-ledger.md` | T000,T001 | redacted ledger-only commit on `main` records three review loops, consolidated corrections and owner continuation decision; no implementation files | revert with new public commit, never rewrite |
| T005 | old real topology proof receipt | T002 | current real `GetTickCount64` path captured before replacement | stop rewrite if unavailable |
| T010 | toolchain/platform locks, `.gitignore`, build files | T005 | exact patch versions/hashes frozen; `runtime.key` ignored before key creation | revert foundation |
| T011 | schemas and canonical IR | T010 | RFC 8785 and complete adapter/type schemas | no activation |
| T012 | dependency schema/validator | T011 | path, collision, duplicate, cycle, architecture and placement tests | reject invalid graph |
| T020 | physical protocol | T011 | exact Noise fragmentation/sequence tests | no fallback |
| T021 | logical protocol | T020 | all messages/nested schemas/enums/flags/features/errors golden | revert protocol unit |
| T022 | pairing/session crypto | T020,T010 | XXpsk3 bootstrap, IK sessions, pending recovery, key rotation | no plaintext fallback |
| T023 | actor authorization | T022,T011 | roles/grants/revocation/ACL tests | deny by default |
| T024 | state/audit/TPM anchor | T010,T011,T023 | crash windows, chain, signed checkpoints, rollback detection | restore unactivated DB |
| T025 | core client/broker | T021–T024 | persistent connection, bounded queues and readiness | atomically revert peers |
| T026 | early v2 topology parity | T025,T005 | v2 real `GetTickCount64` matches reference semantics | keep old proof until pass |
| T030 | PE/Clang/PDB inspection | T011 | parity plus target-layout evidence | branch-only old inspector |
| T031 | CLR/TLB/WinMD inspection | T030 | deterministic managed/COM evidence | stop malformed input |
| T032 | confidence/evidence graph | T030,T031 | no inferred auto-promotion | block generation |
| T040 | native C generator | T026,T030 | compilable exact scalar proxy/dispatcher | internal checkpoint only |
| T041 | reproducible receipts | T040,T024 | two identical isolated unsigned builds | block support |
| T043 | generated DLL topology path | T041 | Wine app loads proxy and consumes real result | no family claims if fail |
| T050 | compound types | T043 | records/enums/unions/bitfields parity | reject unsupported type |
| T051 | strings/buffers/transfers | T050,T021 | null/bounds/insufficient/1 MiB tests | reject unbounded type |
| T052 | guarded copy | T043,T010 | exact SEH/TOCTOU/error tests under Wine | block native support |
| T053 | native error mapping | T050,T052 | HRESULT/Win32/NTSTATUS/SEH/last-error parity | no generic collapse |
| T060 | handles | T024,T053 | owner/epoch/generation/restart tests | invalidate safely |
| T070 | callbacks | T060,T021 | executor/order/reentrancy/shutdown tests | unregister/close |
| T071 | async/cancel/reconciliation | T070,T024 | cancel races and crash windows truthful | unknown remains unknown |
| T075 | native C++ | T050,T053,T060,T071 | exact free/static subset; constructor/instance/vtable stops | unsupported yields packet |
| T080 | COM | T031,T070 | class factory/QI/ref/apartment suite | family unsupported |
| T081 | WinRT | T080 | activation factory/HSTRING/async suite | family unsupported |
| T090 | .NET assembly | T031,T071 | host/binding/API/field/strong-name suite | stop on identity/state |
| T100 | native EXE | T025,T024 | argv/env/I/O/exit/Job Object suite | kill job and receipt |
| T101 | .NET EXE | T090,T100 | managed host/process suite | family unsupported |
| T105 | final cross-family dependency layout | T012,T075,T081,T090,T100,T101 | complete module graph, relative placement and load gates | reject package |
| T110 | tracing/redaction | T032,T071,T105 | authorized probes and privacy tests | uninstall/delete traces |
| T111 | inference merger | T110 | contradictions preserved | discard inference |
| T112 | AI packet generator | T032,T111 | exact packets and malicious metadata tests | packet only |
| T086 | reverse trigger evaluator | T105,T110 | signed trigger result from real evidence | default no assumption |
| T087 | reverse outcome | T086,T070,T112 | either fully implemented/tested or signed `not-applicable`; always terminal | feature disabled if N/A |
| T120 | Windows MSI/service/firewall | T105,T024,T087 | least-privileged install and rollback | MSI rollback |
| T121 | macOS package/Keychain | T105,T022 | signed package and identity storage | package rollback |
| T122 | setup/pair/doctor/catalog/two wrappers | T120,T121,T023 | exact two-command clean setup and truthful checks | no unreceipted mutation |
| T123 | operations/diagnostics/audit | T024,T122 | operation fields, audit verification and redacted export | read-only safe |
| T124 | update/rollback/uninstall | T120–T123 | inactive update, health activation, restoration and impact preflight | restore snapshot |
| T130 | fuzz/security/rate limits | T020–T124 | complete abuse/security suite | block release |
| T131 | topology benchmark | T051,T071,T075,T081,T090,T101,T124 | three-run v2 baseline; advisory only for possible v3 codec research | no v2 codec change |
| T132 | SBOM/provenance/signing | T041,T124,T130 | unsigned reproducibility then separate signatures | withdraw/revoke |
| T140 | full E2E/compat/chaos | T075,T081,T090,T101,T112,T124,T130,T087 | six-family and reverse-outcome complete | no partial support |
| T141 | held-out assessment | T140,T112 | 100% expected-supported and 100% expected-stop | any miss blocks |
| T150 | v2 migration/backup | T124,T140,T141,T131 | fresh pair, non-secret preference import, restore test | restore v1 snapshot |
| T151 | old-secret deletion | T150 | explicit preflight and presence-only destruction receipt | v1 re-pair after deletion |
| T152 | remove superseded source/docs | T151 | no Python v1, scaffold, fake doctor or stale support claim | revert cleanup before merge |
| T153 | final docs/examples/support matrix | T152,T141,T131 | every claim maps to receipt | docs-only rollback |
| T160 | clean-machine release candidate | T132,T153 | full two-command lifecycle on frozen matrix | withdraw candidate |
| T161 | final independent review | T160 | zero Blockers/Majors and all gate receipts valid | return to owner task |
| T162 | product integration to `main` | T161 | product implementation merged atomically after ledger already public | new revert commit/package withdrawal only |

---

# 22. Release gates and definition of done

Runtime release requires the following. Whiny-owned contract, inspection and
generation evidence is satisfied only by pinned Whiny package/bundle receipts,
never by duplicate VM Bridge implementation:

1. follow-up independent `PASS` on this ledger;
2. Run validation and ledger/status reconciliation;
3. public ledger-only commit on `main`;
4. exact toolchain/platform hashes;
5. preserved old topology proof;
6. coherent XXpsk3 pair transaction;
7. future IK session and HELLO activation;
8. exact physical fragmentation and sequence ownership;
9. all schemas/enums/errors/golden vectors;
10. monotonic deadlines and skew diagnostics;
11. actor ACL/revocation;
12. independent TPM rollback anchor;
13. tamper-evident receipts;
14. exact dependency layout and loaded-path gates;
15. native C and bounded native C++ support;
16. guarded-copy parity under Wine;
17. COM/WinRT activation and identity;
18. .NET field/binding/strong-name honesty;
19. native/.NET EXE process contracts;
20. handles/callbacks/async/cancellation;
21. exact transfer lifecycle;
22. injection-safe AI packets;
23. signed reverse-adapter outcome;
24. 100% expected-supported held-out results;
25. 100% expected-stop packet results;
26. complete fuzz/security/chaos suite;
27. T131 topology baseline;
28. deterministic unsigned outputs;
29. separate signing receipts;
30. two-command clean-machine setup;
31. safe update/rollback/uninstall;
32. fresh v2 pairing and no v1 secret import;
33. removal of v1/scaffolds/false claims;
34. final independent implementation `PASS`;
35. only then atomic product merge to `main`.

---

# 23. Rejected alternatives

| Alternative | Decision |
|---|---|
| Noise plaintext above 65,519 bytes | Rejected; physical fragmentation required |
| JSON/v1 compatibility listener | Rejected |
| Multiple v2 codecs | Rejected; packed codec immutable |
| gRPC primary | Rejected |
| FlatBuffers negotiated in v2 | Rejected; possible v3 research only |
| Generic CBOR ABI plane | Rejected |
| Named pipe/ALPC/UDS cross-VM | Rejected |
| QEMU macOS vsock/ivshmem | Rejected for initial topology |
| OpenCode polling transport | Rejected |
| Arbitrary export invocation | Rejected |
| Automatic ownership inference | Rejected |
| Automatic custom `IMarshal` | Rejected |
| C++ constructors/destructors/instance methods/vtables | Rejected in initial subset |
| C++ exception propagation | Rejected |
| Remotely stateful .NET fields | Rejected |
| Strong-name spoofing | Rejected |
| Raw pointer/HANDLE/shared-memory transfer | Rejected |
| Automatic reverse dependency proxy | Rejected; evidence-triggered only |
| Forced thread termination | Rejected |
| Partial scalar product merge | Rejected |
| Key files in repository | Rejected |
| Imported v1 pairing secret | Rejected |
| Rewriting published signed history | Rejected |

---

# 24. Human approval and hold checklist

## 24.1 Recorded owner approval

T000 shall record:

- source timestamp: `2026-10-18T17:45:31.294+03:00`;
- scope: complete Revision 3 canonical implementation;
- authorized phases: P1–P16 after independent follow-up `PASS`;
- implementation location: integration branch;
- public exception: ledger-only `docs/implementation-ledger.md` commit to `main` after follow-up `PASS`;
- no ordinary phase-by-phase approval;
- mandatory re-review only for:
  - protocol-major change;
  - new codec or transport;
  - scope expansion;
  - unspecified destructive migration;
  - unavailable identity/signing authority;
  - confidential-data policy expansion;
  - any `[STOP]`.

## 24.2 Checklist

- [x] Full corrected canonical program is user-approved.
- [x] Run ID is exactly `wvb-canonical-v2`.
- [x] Three adversarial review loops completed; consolidated findings are binding.
- [x] Owner explicitly directed implementation to continue after corrections.
- [x] P1 remains held until T000 proves consolidated blocker closure and reconciles the Run.
- [x] Public ledger destination is exact and ledger-only.
- [x] Live-status and ledger hashes require durable reconciliation.
- [x] Pairing bootstrap and future session ordering are complete.
- [x] Per-sender sequence/logical ownership is complete.
- [x] Nested schemas and enum registries are complete.
- [x] Transfer begin/data/end/cancel/receipt are specified.
- [x] Optional/ACK behavior is specified.
- [x] Trusted rollback anchor is independent of database and broker metadata.
- [x] .NET stateful fields are rejected.
- [x] Held-out acceptance is 100% for both classes.
- [x] Packed codec is immutable for v2.
- [x] Reverse-adapter outcome is dependency-safe.
- [x] `runtime.key` is ignored before key creation and no key may be committed.
- [x] C++ constructors/destructors/copy/instance methods are rejected.
- [x] Guarded Wine copy and TOCTOU tests are exact.
- [x] Final dependency layout follows all family generation.
- [x] Deadlines use monotonic budgets.
- [x] Toolchain patch versions/hashes are blocking T010 inputs.
- [x] Exact 65,536 rejection semantics are specified.
- [x] Two-command wrapper acceptance is specified.
- [x] Pairing/session bootstrap has no actor/epoch cycle.
- [x] Top-level/nested schema IDs and enum compatibility rules are frozen.
- [x] Flow-control, call and transfer state machines are executable.
- [x] Audit algorithm/key generation and sustainable TPM anchor cadence are explicit.
- [x] T000 records the exhausted review-loop evidence and deterministic blocker closure.
- [ ] T000 records the approved ledger hash and reconciled live-status hashes.
- [x] T002 publishes the redacted ledger-only commit.
- [ ] P1 hold is released.
- [ ] All implementation and release receipts pass.
- [ ] Final independent implementation review returns `PASS`.
- [ ] Product implementation merges atomically to `main`.

**Current decision:** `USER-APPROVED; REVIEW LOOPS EXHAUSTED; P0 CORRECTION ACTIVE; P1–P16 HELD FOR T000 CLOSURE`