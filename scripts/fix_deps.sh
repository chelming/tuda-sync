#!/bin/bash
# Dependency fix script - uses vendor directory to ensure consistency

echo "==== Fixing Docker SDK dependencies ===="
echo

# Remove any existing vendor directory
if [ -d "vendor" ]; then
  echo "Removing existing vendor directory..."
  rm -rf vendor
fi

# Remove go.sum to start fresh
echo "Removing go.sum to start fresh..."
rm -f go.sum

# Update go.mod with the fixed version
echo "Updating Docker SDK version in go.mod..."
sed -i 's/github.com\/docker\/docker v[0-9.]*+incompatible/github.com\/docker\/docker v28.3.3+incompatible/g' go.mod

# Vendor dependencies
echo "Vendoring dependencies..."
go mod vendor

# Tidy the modules
echo "Running go mod tidy..."
go mod tidy

# Test build
echo "Testing build..."
go build -v ./... || {
  echo "❌ Build failed. Trying more aggressive approach..."
  
  # More aggressive fix
  echo "Resetting dependency state..."
  rm -f go.mod go.sum
  rm -rf vendor
  
  # Create new go.mod
  echo "Creating new go.mod..."
  go mod init github.com/chelming/tuda-sync
  
  # Add explicit dependencies
  echo "Adding dependencies..."
  go get github.com/docker/docker@v28.3.3+incompatible
  go get github.com/prometheus/client_golang@v1.17.0
  go get github.com/rs/zerolog@v1.31.0
  
  # Get Docker SDK sub-packages
  go get github.com/docker/docker/api/types/container@v28.3.3+incompatible
  go get github.com/docker/docker/api/types/events@v28.3.3+incompatible
  go get github.com/docker/docker/api/types/filters@v28.3.3+incompatible
  go get github.com/docker/docker/client@v28.3.3+incompatible
  
  # Tidy again
  go mod tidy
  
  # Test build again
  go build -v ./...
}

echo
echo "Done! Dependencies should now be fixed."
echo
echo "You can run './scripts/security_check.sh' to verify."