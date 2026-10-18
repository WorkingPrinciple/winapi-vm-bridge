#!/bin/sh
set -eu
repo="${HOME}/Library/Application Support/WinApiVmBridge"
command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
if [ -d "$repo/.git" ]; then
  git -C "$repo" fetch --quiet origin main
  git -C "$repo" reset --hard origin/main
else
  mkdir -p "$(dirname "$repo")"
  git clone --depth 1 https://github.com/dragoshont/winapi-vm-bridge.git "$repo"
fi
"$repo/mac/doctor.sh"
config="${XDG_CONFIG_HOME:-$HOME/.config}/winapi-vm-bridge"
mkdir -p "$config"

check_pairing() {
  PYTHONPATH="$repo${PYTHONPATH:+:$PYTHONPATH}" \
    WVB_CAPABILITY_FILE="$config/capability" \
    python3 - <<'PY'
import os
import sys
from pathlib import Path
from winapi_vm_bridge.client import call

path = Path(os.environ["WVB_CAPABILITY_FILE"])
try:
    capability = path.read_text().strip()
    result = call(
        os.environ.get("WVB_HOST", "127.0.0.1"),
        int(os.environ.get("WVB_PORT", "47802")),
        capability, "core", "ping", {}, timeout=5)
    if result.get("ok") is not True:
        raise RuntimeError("core ping failed")
except PermissionError:
    sys.exit(3)
except (ConnectionError, OSError, TimeoutError):
    sys.exit(4)
except Exception:
    sys.exit(3)
PY
}

paired=false
if [ -s "$config/capability" ]; then
  if check_pairing; then
    echo "Existing Mac ↔ Windows VM pairing verified."
    paired=true
  else
    status=$?
    if [ "$status" -eq 4 ]; then
      echo "Windows broker is unreachable; existing pairing was not changed." >&2
      echo "Check the VM and Mac 127.0.0.1:47802 → guest TCP 47801 forwarding, then rerun." >&2
      exit 1
    fi
    echo "Stored pairing was rejected; a replacement code is required." >&2
  fi
fi

if [ "$paired" = false ]; then
  printf "Paste the Windows PAIRING CODE: " > /dev/tty
  IFS= read -r pairing < /dev/tty
  case "$pairing" in
    *[!0-9A-Fa-f]*|'') echo "Invalid pairing code" >&2; exit 1 ;;
  esac
  [ "${#pairing}" -eq 64 ] || { echo "Pairing code must be 64 hex characters" >&2; exit 1; }
  umask 077
  printf '%s\n' "$pairing" > "$config/capability"
  if ! check_pairing; then
    echo "Pairing code was saved, but the broker round trip did not succeed." >&2
    echo "Check the Windows broker and UTM forwarding, then rerun setup." >&2
    exit 1
  fi
  echo "Mac ↔ Windows VM pairing verified."
fi
mkdir -p "$HOME/.local/bin"
ln -sf "$repo/bin/winapi-vm-bridge" "$HOME/.local/bin/winapi-vm-bridge"
echo "Mac setup ready. Ensure ~/.local/bin is on PATH."
echo "Verify UTM forwards Mac 127.0.0.1:47802 to guest TCP 47801."
echo "Rollback: rm -rf \"$repo\" \"$HOME/.local/bin/winapi-vm-bridge\""
