# Adapter inference

Complex adapters can be partly generated when the tool has authorized access
to both sides, but observation does not replace an ABI contract.

## Pipeline

```text
headers / IDL / type library / PDB / exports
                    ↓
          static type inspection
                    ↓
       generated Windows + Wine probes
                    ↓
  Windows-local trace ↔ Wine caller trace
                    ↓
      inferred manifest + confidence
                    ↓
        generated marshalling + tests
```

## What can be inferred

- scalar and enum types;
- record layout when authoritative debug/type metadata exists;
- pointer values that consistently pair with explicit lengths;
- nullability and in/out behavior across test cases;
- handle creation/use/close sequences;
- callback ordering, thread, reentrancy, and cancellation;
- async begin/completion/result-size/result lifecycles.

## What still needs review

- ownership and allocator rules not expressed by the ABI;
- legal input ranges not reached by tests;
- aliasing and nested pointer graphs;
- callbacks that occur only on rare failures;
- COM apartment/threading requirements;
- undocumented security and authorization assumptions.

The generator must emit confidence and unresolved fields. It must never turn an
observed correlation into a guaranteed contract without evidence.

## Commands

Static inspection:

```bash
winapi-vm-bridge inspect --header vendor.h --dll vendor.dll --out inspection.json
```

Generate an adapter task from reviewed metadata:

```bash
winapi-vm-bridge generate adapter.json --out generated
```

Future trace mode will generate purpose-built probes from `inspection.json`,
run them on both sides, and merge only redacted shape/lifecycle evidence.

