# Contributing to tuda-sync

Thank you for your interest in contributing to tuda-sync! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites

- Go 1.25 or later
- Docker for building and testing container images

### Local Development

1. Clone the repository
   ```bash
   git clone https://github.com/chelming/tuda-sync.git
   cd tuda-sync
   ```

2. Install dependencies
   ```bash
   go mod download
   ```

3. Build the application
   ```bash
   go build
   ```

4. Run tests
   ```bash
   go test ./...
   ```

5. Run security checks locally
   ```bash
   # Install required tools (one-time setup)
   go install golang.org/x/vuln/cmd/govulncheck@latest
   go install github.com/securego/gosec/v2/cmd/gosec@latest
   
   # Run the security check script
   ./scripts/security_check.sh
   ```

6. Troubleshooting dependency issues
   ```bash
   # If you encounter dependency issues with the Docker SDK
   ./scripts/fix_deps.sh
   
   # For more comprehensive dependency updates (including security fixes)
   ./scripts/update_deps.sh
   ```

## Building the Container

The project uses a multi-stage Docker build to create a highly optimized (~12MB) and secure container image.

```bash
docker build -t tuda-sync .
```

### Build Optimizations

The Docker image is built with several security and size optimizations:

- Static compilation with CGO disabled for portability
- UPX compression for minimal binary size
- Minimal scratch-based container with only essential components
- No shell or unnecessary utilities in the final image
- Includes only CA certificates for HTTPS connections

## Continuous Integration

### Build Process

The project uses GitHub Actions for continuous integration and delivery. The Docker image is automatically built and published to GitHub Container Registry in several ways:

#### Automatic Builds

1. **Push to Main Branch**: Any push to the `main` or `master` branch triggers a build and publishes a `nightly` tag
2. **Release Tags**: Creating a release or tag (e.g., `v2025.09.28`) builds and publishes versioned images
3. **Pull Requests**: PRs against the main branch are built but not published (for testing)

#### Manual Builds

You can trigger a build manually from the GitHub Actions tab:

1. Navigate to your repository on GitHub
2. Click the "Actions" tab
3. Select the "Build and Publish Docker Image" workflow
4. Click "Run workflow" dropdown on the right
5. Select the branch and click "Run workflow"

### Image Tagging

The CI process automatically creates several tags:

- **Latest**: Points to the most recent stable release (`latest`)
- **Nightly**: The most recent build from the main branch (`nightly`)
- **Version**: For release tags (e.g., `v2025.09.28` → `2025.09.28`, `v2025.09` → `2025.09`, etc.)
- **Commit SHA**: Every build includes a tag with the full Git commit SHA
- **Branch**: Builds from branches get tagged with the branch name

Images are published to: `ghcr.io/chelming/tuda-sync`

## Creating Releases and Tags

You can create releases and tags using either the GitHub web interface or the Git command line:

### Using GitHub Web Interface (Recommended)

1. Navigate to your repository on GitHub
2. Click on "Releases" in the right sidebar
3. Click "Create a new release"
4. Enter a tag version (e.g., `v2025.09.28`)
5. Write a title and description for your release
6. Click "Publish release"

This will automatically trigger the workflow to build and publish a tagged image.

### Using Git Command Line

```bash
# Create a tag locally with today's date
git tag v$(date +%Y.%m.%d)

# Push the tag to GitHub 
git push origin v$(date +%Y.%m.%d)

# Example (specific date):
# git tag v2025.09.28
# git push origin v2025.09.28
```

### Versioning Conventions

This project uses date-based versioning:

**Date-based versioning** (e.g., `v2025.09.28`):
- Good for projects with frequent updates
- Clearly communicates when a release was made
- Works well with the Docker tagging system
- Example format: `v[YEAR].[MONTH].[DAY]`

The workflow will automatically create appropriate Docker tags from this format. Just make sure to prefix your version with `v` (e.g., `v2025.09.28`).

## Code Style and Guidelines

- Follow standard Go code formatting and style
- Add comments for exported functions and complex logic
- Include tests for new functionality
- Ensure all builds and tests pass before submitting PRs

## Pull Request Process

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to your branch
5. Open a Pull Request

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [Non-Commercial License](LICENSE).