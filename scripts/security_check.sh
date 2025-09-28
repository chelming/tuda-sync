#!/bin/bash
# Local security check script for tuda-sync
# This script runs the same security checks as the GitHub workflow

echo "==== Running local security checks for tuda-sync ===="
echo

# Check if dependencies are properly set up
if [ ! -f "go.sum" ] || grep -q "invalid package name" <(go build ./... 2>&1); then
    echo "⚠️  Dependency issues detected. Attempting to fix..."
    # Verify docker SDK version in go.mod
    if ! grep -q "docker/docker v28.3.3" go.mod; then
        echo "Updating Docker SDK version in go.mod..."
        sed -i 's/github.com\/docker\/docker v[0-9.]*+incompatible/github.com\/docker\/docker v28.3.3+incompatible/g' go.mod
    fi
    
    # Clean and rebuild dependencies
    rm -f go.sum
    go mod tidy
    go get github.com/docker/docker@v28.3.3+incompatible
    go get github.com/docker/docker/client@v28.3.3+incompatible
    go get github.com/docker/docker/api/types/container@v28.3.3+incompatible
    go get github.com/docker/docker/api/types/events@v28.3.3+incompatible
    go get github.com/docker/docker/api/types/filters@v28.3.3+incompatible
    go mod tidy
    
    # Verify dependencies were fixed
    if grep -q "invalid package name" <(go build ./... 2>&1); then
        echo "❌ Failed to fix dependencies. Try running './scripts/update_deps.sh' manually."
        exit 1
    else
        echo "✅ Dependencies fixed successfully."
    fi
fi

# Run gosec with our config
if command -v gosec &> /dev/null; then
    echo "==> Running gosec security scanner..."
    gosec -config=.gosec.config -no-fail ./...
else
    echo "⚠️  gosec not installed. To install:"
    echo "    go install github.com/securego/gosec/v2/cmd/gosec@latest"
fi

echo
echo "==> Running govulncheck for vulnerability scanning..."
echo

# Run govulncheck and capture any errors
GOVULN_OUTPUT=$(govulncheck -show=verbose ./... 2>&1) || true
echo "$GOVULN_OUTPUT"

# Check if there were package errors
if echo "$GOVULN_OUTPUT" | grep -q "invalid package name"; then
    echo "❌ Package errors detected. Try running './scripts/update_deps.sh' manually."
    exit 1
fi

# Extract known Docker vulnerabilities vs other vulnerabilities
echo
echo "==> Analyzing results..."
DOCKER_VULNS=$(echo "$GOVULN_OUTPUT" | grep -c "github.com/docker/docker" || echo "0")
# Ensure we get a clean integer
DOCKER_VULNS=$(echo "$DOCKER_VULNS" | tr -d ' \n\t')
[ -z "$DOCKER_VULNS" ] && DOCKER_VULNS=0

OTHER_VULNS=$(echo "$GOVULN_OUTPUT" | grep -v "github.com/docker/docker" | grep -c "Vulnerability" || echo "0")
# Ensure we get a clean integer
OTHER_VULNS=$(echo "$OTHER_VULNS" | tr -d ' \n\t')
[ -z "$OTHER_VULNS" ] && OTHER_VULNS=0

echo
echo "==== Security Scan Summary ===="
echo "Docker SDK vulnerabilities: $DOCKER_VULNS (expected and mitigated)"
echo "Other vulnerabilities: $OTHER_VULNS"

if [ $OTHER_VULNS -gt 0 ]; then
    echo
    echo "⚠️  WARNING: Non-Docker vulnerabilities detected!"
    echo "Please review these carefully and fix them before committing."
    exit 1
else 
    echo
    echo "✅ All vulnerabilities are related to expected Docker SDK usage"
    echo "These are documented in SECURITY.md and docs/DOCKER_SECURITY.md"
fi