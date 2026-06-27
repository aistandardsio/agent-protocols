#!/bin/bash
# generate.sh - Generate Go client from OpenAPI spec using ogen
#
# Prerequisites:
#   go install github.com/ogen-go/ogen/cmd/ogen@latest
#
# Usage:
#   ./generate.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Generating Go client from OpenAPI spec..."

# Run ogen to generate the client
ogen \
    --package api \
    --target internal/api \
    --clean \
    openapi/scim-agent-extension.yaml

echo "Running go mod tidy..."
cd ..
go mod tidy

echo "Verifying build..."
go build ./scimext/...

echo "Done! Generated client is in scimext/internal/api/"
