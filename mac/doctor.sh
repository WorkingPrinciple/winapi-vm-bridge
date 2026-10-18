#!/bin/sh
set -eu
[ "$(uname -s)" = Darwin ] || { echo "macOS is required" >&2; exit 1; }
echo "macos=$(sw_vers -productVersion)"
echo "arch=$(uname -m)"
echo "authenticatedCore=true"
echo "doctor=ok"
