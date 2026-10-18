#!/usr/bin/env python3
"""Inspect authorized DLL/header inputs and emit adapter-generation evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

SCALARS = {
    "void", "bool", "char", "signed char", "unsigned char", "short",
    "unsigned short", "int", "unsigned int", "long", "unsigned long",
    "long long", "unsigned long long", "float", "double",
}


def walk(node: dict):
    yield node
    for child in node.get("inner", []):
        yield from walk(child)


def classify(type_name: str) -> dict:
    normalized = " ".join(type_name.replace("const", "").split())
    if "(*" in normalized or normalized.endswith(")"):
        return {"kind": "callback-or-function", "generated": False,
                "reason": "callback invocation, thread, lifetime, and reentrancy need tracing"}
    if "*" in normalized:
        return {"kind": "pointer", "generated": False,
                "reason": "direction, length, ownership, nullability, and pointee graph are unresolved"}
    if normalized in SCALARS or normalized.startswith("enum "):
        return {"kind": "scalar", "generated": True}
    if normalized.startswith(("struct ", "union ")):
        return {"kind": "record", "generated": False,
                "reason": "packing, nested pointers, and by-value layout need verification"}
    return {"kind": "named-or-platform-type", "generated": False,
            "reason": "resolve typedef and platform ABI before generation"}


def inspect_header(header: Path, clang: str) -> list[dict]:
    command = [
        clang, "-x", "c", "-fsyntax-only", "-Xclang", "-ast-dump=json",
        str(header),
    ]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    ast = json.loads(completed.stdout)
    functions = []
    for node in walk(ast):
        if node.get("kind") != "FunctionDecl" or not node.get("name"):
            continue
        location = node.get("loc", {})
        source_file = location.get("file")
        if source_file and Path(source_file).resolve() != header.resolve():
            continue
        parameters = []
        for child in node.get("inner", []):
            if child.get("kind") != "ParmVarDecl":
                continue
            type_info = child.get("type", {})
            spelling = type_info.get("qualType", "")
            type_name = type_info.get("desugaredQualType", spelling)
            parameters.append({
                "name": child.get("name", ""),
                "type": type_name,
                "spelling": spelling,
                "analysis": classify(type_name),
            })
        function_info = node.get("type", {})
        function_spelling = function_info.get("qualType", "")
        function_type = function_info.get("desugaredQualType", function_spelling)
        return_type = function_type.split("(", 1)[0].strip()
        functions.append({
            "name": node["name"],
            "type": function_type,
            "spelling": function_spelling,
            "returnType": return_type,
            "returnAnalysis": classify(return_type),
            "parameters": parameters,
            "source": "clang-ast",
        })
    return functions


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect an authorized header/DLL for adapter generation.")
    parser.add_argument("--header", type=Path, required=True)
    parser.add_argument("--dll", type=Path)
    parser.add_argument("--clang", default=shutil.which("clang") or "clang")
    parser.add_argument("--out", type=Path, default=Path("inspection.json"))
    args = parser.parse_args()
    if not args.header.is_file():
        parser.error("header does not exist")
    if args.dll and not args.dll.is_file():
        parser.error("DLL does not exist")
    try:
        functions = inspect_header(args.header, args.clang)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        parser.error(f"Clang inspection failed: {exc}")
    result = {
        "schemaVersion": 1,
        "header": {
            "name": args.header.name,
            "sha256": sha256(args.header),
        },
        "dll": None if not args.dll else {
            "name": args.dll.name,
            "sha256": sha256(args.dll),
        },
        "functions": functions,
        "summary": {
            "functions": len(functions),
            "fullyGeneratedCandidates": sum(
                f["returnAnalysis"]["generated"] and
                all(p["analysis"]["generated"] for p in f["parameters"])
                for f in functions),
            "requiresTraceOrAnnotation": sum(
                not (f["returnAnalysis"]["generated"] and
                     all(p["analysis"]["generated"] for p in f["parameters"]))
                for f in functions),
        },
        "limitations": [
            "A declaration does not establish pointer ownership or buffer length.",
            "Callbacks require execution-context and lifetime tracing.",
            "COM requires IDL/type-library interface identity and reference semantics.",
            "Only authorized headers, DLLs, symbols, and runtime observations may be used.",
        ],
    }
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(args.out)


if __name__ == "__main__":
    main()
