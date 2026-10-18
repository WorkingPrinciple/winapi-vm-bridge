# Canonical ledger adversarial review — loop 3

**Verdict:** REVISE  
**Reviewer:** independent Architrave adversarial judge  
**Disposition:** final permitted revise loop; findings consolidated below.

## Architectural blockers reported

1. Initial pairing actor/epoch bootstrap had to be explicit.
2. Top-level schema IDs, wrapper schemas and remaining enum registries had to be fixed.
3. `CALL_BEGIN.actorContextId` had no issuance path.
4. Mandatory flow-control debit/replenishment behavior was incomplete.
5. Call and transfer ordering/cancellation/cleanup state machines were incomplete.
6. Audit signature algorithm/key generation and TPM anchor cadence needed executable rules.

## Evidence/control blockers reported

1. The canonical Run and live status did not yet match ledger revision 3.
2. The Run contained only the initial freeze/research/parity tasks.
3. Deterministic P0 receipts and current review evidence were incomplete.
4. `runtime.key` custody had to be proven and ignored.

## Major concerns reported

- C++ instance lifecycle needed an explicit rejection/support boundary.
- .NET remotely stateful fields had to be rejected.
- Guarded pointer copying needed an exact Wine/PE mechanism.
- Dependency layout needed finalization after all family generators.
- Monotonic deadline/skew handling, public ledger publication, exact toolchain
  pinning, two-command setup wording and the 65,536-byte rejection harness
  needed explicit definitions.

## Resolution

Ledger revision 4 incorporates the architectural corrections:

- pair-control and provisional/active epoch ordering;
- deterministic schema ID mapping, wrappers and enum policy;
- session-derived actor identity;
- complete flow-control, call and transfer state machines;
- audit signature metadata and batched/independent TPM anchoring;
- bounded C++/.NET support and guarded-copy rules;
- corrected dependency/task/release gates.

The owner explicitly directed implementation to continue after correction of
the consolidated findings. No fourth micro-review is opened. T000 must record
the corrected ledger hash, Run/status reconciliation and deterministic closure
before P1 starts. Final independent implementation review remains mandatory at
T161.
