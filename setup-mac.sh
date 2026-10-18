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
if [ ! -s "$config/capability" ]; then
  printf "Paste the Windows PAIRING CODE: " >&2
  IFS= read -r pairing
  case "$pairing" in
    *[!0-9A-Fa-f]*|'') echo "Invalid pairing code" >&2; exit 1 ;;
  esac
  [ "${#pairing}" -eq 64 ] || { echo "Pairing code must be 64 hex characters" >&2; exit 1; }
  umask 077
  printf '%s\n' "$pairing" > "$config/capability"
fi
mkdir -p "$HOME/.local/bin"
ln -sf "$repo/bin/winapi-vm-bridge" "$HOME/.local/bin/winapi-vm-bridge"
echo "Mac setup ready. Ensure ~/.local/bin is on PATH."
echo "Verify UTM forwards Mac 127.0.0.1:47802 to guest TCP 47801."
echo "Rollback: rm -rf \"$repo\" \"$HOME/.local/bin/winapi-vm-bridge\""
