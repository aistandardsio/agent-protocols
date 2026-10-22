#!/usr/bin/env bash
# Regenerate aauth.walkthrough.json, the walkthrough the AAuth Explorer
# page shows, from the AAuth PIDL document.
#
# Requires pidl v0.9.0 or later
# (go install github.com/grokify/pidl/cmd/pidl@latest).
set -euo pipefail
cd "$(dirname "$0")"

src=../../../aauth/pidl/aauth_protocol.json
pidl validate -q "$src"
pidl generate -f walkthrough-json -o aauth.walkthrough.json "$src"
