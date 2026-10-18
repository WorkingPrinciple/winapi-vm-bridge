from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .client import call


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    invoke = sub.add_parser("call")
    invoke.add_argument("operation")
    invoke.add_argument("--json", action="store_true")
    args = parser.parse_args()
    adapter, separator, operation = args.operation.rpartition(".")
    if not separator:
        parser.error("operation must be adapter.operation")
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    capability_file = Path(os.environ.get(
        "WVB_CAPABILITY_FILE", config_home / "winapi-vm-bridge" / "capability"))
    capability = capability_file.read_text().strip()
    host = os.environ.get("WVB_HOST", "127.0.0.1")
    port = int(os.environ.get("WVB_PORT", "47802"))
    result = call(host, port, capability, adapter, operation, {})
    print(json.dumps(result, separators=(",", ":")) if args.json else result)


if __name__ == "__main__":
    main()

