# Research sources

Validated: 2026-10-18. Sources are evidence inputs, not copied acceptance
thresholds. Performance must be measured on the actual Mac/UTM/Windows topology.

## Transport and serialization

| Topic | Source | Use |
|---|---|---|
| gRPC benchmarking | https://grpc.io/docs/guides/benchmarking/ | Official benchmark method; no frozen universal latency numbers |
| gRPC performance/cold channels | https://learn.microsoft.com/aspnet/core/grpc/performance | Connection reuse, channel setup and performance guidance |
| gRPC flow control | https://grpc.io/docs/guides/flow-control/ | Streaming flow-control behavior and deadlock risk |
| FlatBuffers benchmarks | https://flatbuffers.dev/benchmarks/ | Decode/allocation evidence; dated hardware, not topology acceptance |
| Cap'n Proto RPC | https://capnproto.org/rpc.html | Promise pipelining and cancellation model |
| MessagePack | https://msgpack.org/ | Format/tooling reference; no official topology benchmark found |
| Kafka protocol | https://kafka.apache.org/protocol | Mature versioned framed-protocol precedent |
| Nagle/TCP behavior | https://datatracker.ietf.org/doc/html/rfc896 | Basis for testing `TCP_NODELAY` on small RPC calls |

## VM and IPC constraints

| Topic | Source | Finding |
|---|---|---|
| QEMU ivshmem | https://www.qemu.org/docs/master/system/devices/ivshmem.html | No canonical macOS/QEMU Windows path for this project |
| Virtio-vsock | https://wiki.qemu.org/Features/VirtioVsock | QEMU vhost-vsock depends on Linux host facilities |
| Apple virtual sockets | https://developer.apple.com/documentation/virtualization/vzvirtiosocketdevice | Relevant only to Virtualization.framework; Windows/UTM support remains unproven |
| UTM directory sharing | https://docs.getutm.app/guest-support/sharing/directory/ | Windows guest sharing constraints; not a low-latency RPC transport |
| Windows named pipes | https://learn.microsoft.com/windows/win32/ipc/named-pipes | Local/SMB IPC; does not cross the VM boundary without another bridge |
| Windows RPC protocol sequences | https://learn.microsoft.com/windows/win32/rpc/protocol-sequence-constants | Fixed protocol sequence set; no supported custom transport registration |

## Windows ABI, COM and inspection

| Topic | Source | Use |
|---|---|---|
| `ITypeInfo` | https://learn.microsoft.com/windows/win32/api/oaidl/nn-oaidl-itypeinfo | Type-library function/type metadata |
| `IMarshal` | https://learn.microsoft.com/windows/win32/api/objidl/nn-objidl-imarshal | Custom COM marshaling is invisible to ordinary TLB inspection |
| Microsoft Detours | https://github.com/microsoft/Detours | Authorized Windows call-boundary tracing |
| Rust bindgen | https://rust-lang.github.io/rust-bindgen/ | Mechanical signature/layout generation and its limits |
| SWIG | https://www.swig.org/Doc4.3/ | Binding generation precedent; ownership/lifetime still needs policy |
| Wine unixlib | https://github.com/wine-mirror/wine/blob/master/include/wine/unixlib.h | Efficient local PE→Unix call pattern; not a cross-VM transport |

## Security and broker design

| Topic | Source | Use |
|---|---|---|
| seL4 capabilities | https://dl.acm.org/doi/10.1145/1629575.1629596 | Capability-model reference and least-authority framing |
| gVisor production guide | https://gvisor.dev/docs/production_guide/ | Default-deny syscall/surface-minimization reference |
| Noise Protocol Framework | https://noiseprotocol.org/noise.html | Handshake, cipher-state and transport-message constraints |
| RFC 8785 JCS | https://www.rfc-editor.org/rfc/rfc8785 | Canonical JSON for contract/receipt hashing |
| Windows DLL security | https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-security | Reject current-directory/ambient-path loading and use explicit controlled paths |
| `SetDefaultDllDirectories` | https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories | Restrict process DLL search locations |
| `AddDllDirectory` | https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-adddlldirectory | Add only admitted package directories when dependency loading requires it |
| Windows reparse points | https://learn.microsoft.com/windows/win32/fileio/reparse-points | Treat junctions and other reparse points as path-identity hazards |
| Windows Job Objects | https://learn.microsoft.com/windows/win32/procthread/job-objects | Process-tree containment, limits and termination |
| Apple Keychain items | https://developer.apple.com/documentation/security/keychain-items | OS-backed generic-password/key storage model |
| `SecItemCopyMatching` | https://developer.apple.com/documentation/security/secitemcopymatching(_:_:) | Exact Keychain lookup behavior |
| Adding a Keychain password | https://developer.apple.com/documentation/security/adding-a-password-to-the-keychain | `kSecClassGenericPassword`, service/account and secret data pattern |

## Performance references

| Topic | Source | Limitation |
|---|---|---|
| LMAX Disruptor | https://lmax-exchange.github.io/disruptor/ | Same-process queue benchmark, not VM evidence |
| Eclipse iceoryx benchmark | https://iceoryx.io/v1.0.0/benchmark.html | Same-host shared-memory benchmark, not available topology |
| .NET gRPC improvements | https://devblogs.microsoft.com/dotnet/grpc-performance-improvements-in-net-5/ | Demonstrates runtime/allocation sensitivity, not Mac↔VM ranking |

## Whiny repository evidence

Repository: `dragoshont/whiny`, reviewed at
`21f378bac2fdf53bff7f1deb1002c1bb89c073c5`.

| Pattern | Source |
|---|---|
| Bounded subprocess/API result validation | `whiny/opencode.py:30-81` |
| Default-deny permissions and explicit interruption | `whiny/opencode.py:83-297` |
| POSIX process groups and Windows suspended-child/Job Object lifecycle | `whiny/processes.py:10-187`; `tests/test_processes.py:43-136` |
| Locked append-only ledger, bounded queue and reconciliation | `whiny/cli.py:195-227,287-299,403-596` |
| Exact contract/evidence envelope and immutable handoff | `whiny/provenance.py:11-205` |
| PE/CLR static inspection with partial/untrusted receipts | `whiny/binary.py:18-88,148-220,278-389,392-581,636-668` |
| Loaded path/hash runtime approval | `whiny/runtime.py:16-166` |
| Fresh-process native differential oracle | `whiny/comparison.py:29-233` |
| Managed fresh-process differential oracle | `whiny/managed_comparison.py:16-231` |
| Deterministic candidate build receipts | `whiny/candidate_build.py:120-340` |
| Immutable development/held-out assessment | `whiny/refinement.py:15-131` |
| CI and package smoke | `.github/workflows/tests.yml:11-51` |

Whiny does **not** provide the bridge transport. It contains no shipped
gRPC/protobuf, cross-VM shared memory, vsock, callback RPC, COM marshaling,
pairing/encryption or RPC performance benchmark. Its reusable value is lifecycle,
evidence, inspection, differential testing, receipts and release discipline.
