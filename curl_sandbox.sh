#!/usr/bin/env bash
# scripts/curl_sandbox.sh
# Usage: scripts/curl_sandbox.sh [curl-args...]
set -euo pipefail

# Ensure directory exists
mkdir -p /tmp/curl_downloads

# Use env_shim only for curl process
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export LD_PRELOAD="$ROOT/env_shim.so"
exec curl "$@"

