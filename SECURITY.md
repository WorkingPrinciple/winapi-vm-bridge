# Security

Report vulnerabilities privately through GitHub's security-advisory interface.
Do not open a public issue containing credentials, account identifiers, tokens,
signatures, pairing material, private keys, target contracts or response bodies.

## Trust boundaries

- Whiny contracts, bundle descriptors and generated files are untrusted until
  admitted by VM Bridge.
- Admission requires an exact `AdapterAdmin` grant scoped to the contract hash.
- Invocation separately requires an exact actor `Invoke` grant scoped to both
  contract hash and operation ID.
- Bundle data cannot create or widen actors, roles or grants.
- Arbitrary caller-selected DLLs, assemblies, exports, methods, commands and
  paths are rejected.

## Artifact loading

- Contract, descriptor, dispatcher, target and dependency hashes are pinned.
- Only portable relative paths under a configured package root are accepted.
- Absolute, drive, UNC, traversal, case-colliding, symlink, junction and
  reparse-point paths are rejected.
- Paths and hashes are re-verified before loading.
- Ambient `PATH` and current-directory library resolution are prohibited.
- Windows loaders must use explicit paths and secure `LoadLibraryEx` search
  flags.

## Identity and transport

- Pairing and application sessions use the canonical Noise transport.
- Private identity material is stored in OS-backed stores and never in the
  repository, Wine registry, argv or logs.
- Actor revocation and exact operation ACLs are enforced independently of
  transport authentication.
- Message replay windows, bounded queues and per-actor call/byte/callback/
  diagnostics limits fail closed.

## Runtime lifecycle

- Transfers are bounded, ordered, content-addressed and receipted.
- Handles are bound to actor, epoch, generation and type.
- Callbacks enforce leases, thread/executor policy, reentrancy, concurrency and
  unregister/disconnect semantics.
- Process execution uses bounded argv/environment/I/O and Windows Job Object
  containment.
- Completion, cancellation and unknown outcomes are never conflated.

## Audit and packages

- State-changing events and receipts are hash chained.
- Rollback-anchor state is independent of broker database metadata.
- Runtime packages use deterministic unsigned manifests and inactive staging,
  health-gated activation, rollback and uninstall preflight.
- SBOM and provenance are unsigned deterministic evidence. Authenticode and
  notarization are separate external receipts; signing secrets are never
  materialized by repository tooling.

## Unsupported security claims

The project does not support kernel drivers, anti-cheat/DRM bypass, arbitrary
GUI remoting, ambient DLL loading, undocumented ABI guessing or automatic
reverse dependency proxying.
