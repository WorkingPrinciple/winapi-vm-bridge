#!/usr/bin/env python3
"""Generate a reviewable adapter patch skeleton from a strict JSON manifest."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SCALARS = {"i32", "u32", "i64", "u64", "f32", "f64", "bool", "hresult"}
BOUNDED = {"utf8", "utf16", "bytes"}
TYPES = SCALARS | BOUNDED | {"opaque_handle", "custom"}
RETURNS = SCALARS | {"void", "custom"}
CONVENTIONS = {"cdecl", "stdcall", "winapi"}
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ADAPTER = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$")
EXPORT = re.compile(r"^[A-Za-z_][A-Za-z0-9_@]*$")


def fail(message: str) -> None:
    raise ValueError(message)


def validate(data: dict) -> list[str]:
    if set(data) != {"schemaVersion", "adapter", "windows", "operations"}:
        fail("manifest has missing or unknown top-level fields")
    if data["schemaVersion"] != 1 or not ADAPTER.fullmatch(data["adapter"]):
        fail("invalid schemaVersion or adapter name")
    windows = data["windows"]
    if set(windows) != {"dll", "sha256"} or "/" in windows["dll"] or "\\" in windows["dll"] or not windows["dll"].lower().endswith(".dll"):
        fail("windows.dll must be a file name, not a path")
    digest = windows["sha256"]
    if digest != "replace-at-install" and not re.fullmatch(r"[0-9a-f]{64}", digest):
        fail("windows.sha256 must be lowercase SHA-256 or replace-at-install")
    if not isinstance(data["operations"], dict) or not data["operations"]:
        fail("operations must be a non-empty object")
    custom = []
    for op_name, op in data["operations"].items():
        if not NAME.fullmatch(op_name):
            fail(f"invalid operation name: {op_name}")
        required = {"export", "callingConvention", "timeoutMs", "parameters", "returns"}
        if not required <= set(op) or set(op) - required - {"notes"}:
            fail(f"{op_name}: missing or unknown fields")
        if not EXPORT.fullmatch(op["export"]) or op["callingConvention"] not in CONVENTIONS:
            fail(f"{op_name}: invalid export or calling convention")
        if not isinstance(op["timeoutMs"], int) or not 1 <= op["timeoutMs"] <= 300000:
            fail(f"{op_name}: invalid timeout")
        if op["returns"] not in RETURNS or not isinstance(op["parameters"], list):
            fail(f"{op_name}: invalid return or parameter list")
        seen = set()
        needs_custom = op["returns"] == "custom"
        for param in op["parameters"]:
            required_param = {"name", "type", "direction"}
            if not required_param <= set(param) or set(param) - required_param - {"maxBytes", "notes"}:
                fail(f"{op_name}: invalid parameter fields")
            if not NAME.fullmatch(param["name"]) or param["name"] in seen:
                fail(f"{op_name}: invalid/duplicate parameter name")
            seen.add(param["name"])
            if param["type"] not in TYPES or param["direction"] not in {"in", "out", "inout"}:
                fail(f"{op_name}.{param['name']}: invalid type/direction")
            if param["type"] in BOUNDED:
                if not isinstance(param.get("maxBytes"), int) or not 1 <= param["maxBytes"] <= 16 * 1024 * 1024:
                    fail(f"{op_name}.{param['name']}: bounded type needs maxBytes")
            elif "maxBytes" in param:
                fail(f"{op_name}.{param['name']}: maxBytes only applies to bounded types")
            needs_custom |= param["type"] in {"opaque_handle", "custom"}
        if needs_custom:
            custom.append(op_name)
    return custom


def render_shim(data: dict, custom: list[str]) -> str:
    lines = [
        "/* Generated review skeleton. Do not ship before implementing bridge_runtime_call. */",
        "#include <stdint.h>",
        '#include "bridge_runtime.h"',
        "",
        f'/* Adapter: {data["adapter"]}; real DLL: {data["windows"]["dll"]} */',
    ]
    for name, op in data["operations"].items():
        lines += [
            "",
            f"/* Export {op['export']}; convention={op['callingConvention']}; timeout={op['timeoutMs']}ms.",
            f" * customMarshallerRequired={'true' if name in custom else 'false'} */",
            f"/* TODO: declare exact ABI from authoritative header and call",
            f' * bridge_runtime_call("{data["adapter"]}", "{name}", ...). */',
        ]
    return "\n".join(lines) + "\n"


def render_dispatch(data: dict, custom: list[str]) -> str:
    registrations = []
    for name, op in data["operations"].items():
        registrations.append(
            f'  {{"{name}", "{op["export"]}", {op["timeoutMs"]}, '
            f'{"true" if name in custom else "false"}}},'
        )
    return (
        "/* Generated allowlist metadata; invocation/marshalling must be reviewed. */\n"
        "struct Operation { const char *name, *exportName; unsigned timeoutMs; bool custom; };\n"
        f'static const char kDll[] = "{data["windows"]["dll"]}";\n'
        "static const Operation kOperations[] = {\n" + "\n".join(registrations) + "\n};\n"
    )


def render_implementation_task(data: dict, custom: list[str]) -> str:
    lines = [
        f"# Implement adapter `{data['adapter']}`",
        "",
        "This task is generated from the normalized adapter contract. Do not broaden it.",
        "",
        "## Frozen target",
        "",
        f"- DLL: `{data['windows']['dll']}`",
        f"- Expected SHA-256: `{data['windows']['sha256']}`",
        f"- Schema version: `{data['schemaVersion']}`",
        "",
        "## Operations",
        "",
    ]
    for name, operation in data["operations"].items():
        lines += [
            f"### `{name}` → `{operation['export']}`",
            "",
            f"- Calling convention: `{operation['callingConvention']}`",
            f"- Timeout: `{operation['timeoutMs']} ms`",
            f"- Return: `{operation['returns']}`",
            f"- Custom marshaller required: `{'yes' if name in custom else 'no'}`",
            "",
            "| Parameter | ABI type | Direction | Bound | Generated? | Required evidence |",
            "|---|---|---|---:|---|---|",
        ]
        for parameter in operation["parameters"]:
            needs_custom = parameter["type"] in {"opaque_handle", "custom"}
            bound = parameter.get("maxBytes", "")
            evidence = parameter.get("notes") or (
                "Resolve ownership/lifetime/identity" if needs_custom else "Manifest contract")
            lines.append(
                f"| `{parameter['name']}` | `{parameter['type']}` | "
                f"`{parameter['direction']}` | `{bound}` | "
                f"{'no' if needs_custom else 'yes'} | {evidence} |")
        if operation.get("notes"):
            lines += ["", f"Notes: {operation['notes']}"]
        lines.append("")
    lines += [
        "## Required implementation",
        "",
        "1. Preserve export name, calling convention, structure packing and native errors.",
        "2. Complete only the unresolved marshalling listed above.",
        "3. Keep DLL path/export allowlisted from the installed manifest.",
        "4. Bound all payloads and preserve null/insufficient-buffer semantics.",
        "5. Model remote handles with owner, generation, close and restart invalidation.",
        "6. Preserve async begin/completion/result/cancellation and callback threading.",
        "7. Never log credentials, capabilities, identifiers, profile values or payloads.",
        "",
        "## Required tests",
        "",
        "- generated contract/schema validation;",
        "- Windows-local oracle for every operation;",
        "- Wine shim ↔ VM dispatcher parity;",
        "- minimum/maximum/null/malformed/insufficient-buffer cases;",
        "- timeout, cancellation, disconnect, restart and stale-handle cases;",
        "- callback ordering/reentrancy/threading where applicable;",
        "- deterministic unsigned build and input/output hash receipt;",
        "- one real application operation end to end.",
        "",
        "## Stop conditions",
        "",
        "Stop and report the exact blocker instead of guessing when ownership, allocator, "
        "packing, callback thread, COM apartment, handle lifetime, authorization, or "
        "security semantics cannot be established from authoritative metadata or "
        "approved runtime evidence.",
        "",
    ]
    if custom:
        lines += [
            "## Unresolved operations",
            "",
            *[f"- `{name}` requires custom marshalling." for name in custom],
            "",
        ]
    else:
        lines += [
            "## Unresolved operations",
            "",
            "None from the manifest type model. Runtime parity is still required.",
            "",
        ]
    return "\n".join(lines)


def generate(manifest: Path, out: Path) -> None:
    data = json.loads(manifest.read_text())
    custom = validate(data)
    target = out / data["adapter"].replace(".", "-")
    target.mkdir(parents=True, exist_ok=True)
    (target / "contract.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    (target / "shim.generated.c").write_text(render_shim(data, custom))
    (target / "dispatch.generated.cpp").write_text(render_dispatch(data, custom))
    (target / "IMPLEMENTATION_TASK.md").write_text(
        render_implementation_task(data, custom))
    checklist = [
        "# Conformance checklist",
        "",
        f"- [ ] Verify SHA-256 for `{data['windows']['dll']}` at install.",
        "- [ ] Compile shim with authoritative headers/calling conventions.",
        "- [ ] Compile Windows dispatcher with allowlisted DLL/export only.",
        "- [ ] Test malformed, bounds, timeout, cancellation, disconnect, restart.",
        "- [ ] Test local/mock parity for every operation.",
        "- [ ] Capture one real application operation end to end.",
    ]
    for name in custom:
        checklist.append(f"- [ ] Implement and review custom marshaller for `{name}`.")
    (target / "CHECKLIST.md").write_text("\n".join(checklist) + "\n")
    print(target)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, default=Path("generated"))
    args = parser.parse_args()
    try:
        generate(args.manifest, args.out)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
