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
mkdir -p "$HOME/.local/bin"
ln -sf "$repo/bin/winapi-vm-bridge" "$HOME/.local/bin/winapi-vm-bridge"
echo "Mac setup ready. Ensure ~/.local/bin is on PATH."
echo "Rollback: rm -rf \"$repo\" \"$HOME/.local/bin/winapi-vm-bridge\""

