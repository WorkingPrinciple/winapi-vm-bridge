# Adapter SDK

The SDK turns an authoritative Windows DLL ABI description into a reviewable
adapter patch. It deliberately does not guess pointer ownership or callback
behavior.

```bash
winapi-vm-bridge inspect --header vendor.h --dll vendor.dll --out inspection.json
python3 sdk/generate.py examples/example-math/adapter.json --out generated
python3 -m unittest tests.test_sdk
```

Generated output:

- normalized `contract.json`;
- Wine shim skeleton with the original exports;
- Windows dispatcher skeleton with allowlisted DLL/export metadata;
- conformance checklist;
- an AI implementation prompt scoped to the unresolved marshalling work.

Scalar-only functions are marked `generated`; pointer, callback, COM, handle,
shared-memory, and async types are marked `customMarshallerRequired`. A human
or coding agent implements only those explicit gaps and adds parity tests.

`inspect` uses Clang AST metadata and DLL hashing to create an evidence file.
Future dynamic probes can refine unresolved direction, length, lifetime,
callback, handle, and async annotations from authorized observations on both
Windows and Wine.

## Workflow

1. Copy `sdk/templates/adapter.json` or run:

   ```bash
   winapi-vm-bridge init vendor.library
   ```

2. Fill it from a trusted header/documentation source.
3. Generate the patch:

   ```bash
   winapi-vm-bridge generate adapter.json --out generated
   ```

4. Give `generated/IMPLEMENTATION_TASK.md` to a coding agent.
5. Require local mock parity and a real application operation before claiming
   support.
