#!/usr/bin/env bash
# Regenerate the SVG diagrams for docs/aauth/oauth-comparison.md.
#
#   *.pidl.json  -> pidl generate -f d2 -> *.d2 -> d2 -> *.svg
#   hand-written *.d2 (no .pidl.json sibling)  -> d2 -> *.svg
#
# Requires pidl v0.7.0 or later (go install github.com/grokify/pidl/cmd/pidl@latest)
# and d2.
set -euo pipefail
cd "$(dirname "$0")"

D2_FLAGS=(--theme 0 --dark-theme 200)

for src in *.pidl.json; do
  name="${src%.pidl.json}"
  pidl validate -q "$src"
  pidl generate -f d2 -o "$name.d2" "$src"
done

for src in *.d2; do
  name="${src%.d2}"
  d2 "${D2_FLAGS[@]}" "$src" "$name.svg"
done
