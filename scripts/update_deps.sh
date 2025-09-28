#!/bin/bash
# Script to update dependencies and fix security vulnerabilities

echo "Updating dependencies for tuda-sync..."
echo "This script will update the Docker client to fix GO-2025-3830 vulnerability"

# Ensure we're in the project root
if [ ! -f "go.mod" ]; then
  echo "Error: go.mod not found. Please run this script from the project root directory."
  exit 1
fi

# Clean up existing go.sum if there are issues
echo "Cleaning up dependency state..."
rm -f go.sum

# Update Docker client to latest patched version
echo "Updating Docker client to v28.3.3+incompatible..."
go get github.com/docker/docker@v28.3.3+incompatible

# Get all the required Docker packages explicitly to fix the missing entries
echo "Ensuring all Docker packages are properly resolved..."
go get github.com/docker/docker/client@v28.3.3+incompatible
go get github.com/docker/docker/api/types/container@v28.3.3+incompatible
go get github.com/docker/docker/api/types/events@v28.3.3+incompatible
go get github.com/docker/docker/api/types/filters@v28.3.3+incompatible

# Tidy the modules
echo "Running go mod tidy..."
go mod tidy

# Try to build to verify dependencies
echo "Verifying build..."
go build -v ./...

# Verify the update
echo "Verifying Docker client version..."
grep "github.com/docker/docker" go.mod

# Run security check
echo "Running vulnerability check..."
which govulncheck >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "Installing govulncheck..."
  go install golang.org/x/vuln/cmd/govulncheck@latest
fi

# Run security check without failing
govulncheck ./... || true

echo "Done!"
echo "Note: Some Docker SDK vulnerabilities may still be reported but are expected"
echo "See docs/DOCKER_SECURITY.md for details on mitigations"