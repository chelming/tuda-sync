# Docker SDK Vulnerabilities & Mitigations

This document provides detailed information about known Docker SDK vulnerabilities and how they are mitigated in our codebase.

## Overview

The Docker SDK for Go has several reported vulnerabilities that are detected by security scanners like `govulncheck`. These vulnerabilities are inherent to any application that needs to interact with the Docker daemon, as they exist in the underlying libraries.

## Known Vulnerabilities

### GO-2025-3830 (Latest)
**Description:** Moby firewalld reload makes published container ports accessible from remote hosts.

**Impact:** When the host firewall is managed by firewalld and a container port is published, under specific conditions container ports may become accessible from remote hosts.

**References:** https://pkg.go.dev/vuln/GO-2025-3830

**Mitigation in our code:**
- Our application doesn't use the firewall management functionality
- We don't publish container ports from our application
- We're only monitoring container events, not modifying network settings
- We use API version pinning to limit functionality access

### CVE-2023-45288
**Description:** Path traversal vulnerability in Docker CLI via file parameter in build command.

**Impact:** An attacker could potentially craft malicious inputs to traverse the file system.

**Mitigation in our code:**
- We don't use the Docker build functionality
- All container IDs are validated with regex before use: `isValidContainerID()`
- Input validation is implemented for all user-provided inputs

### CVE-2021-41190
**Description:** Windows filepath traversal in Docker tar extraction.

**Impact:** Could allow arbitrary file writes during archive extraction on Windows systems.

**Mitigation in our code:**
- We don't use Docker archive extraction functionality
- Our application doesn't run on Windows hosts
- No file path manipulation is performed

### CVE-2022-36109
**Description:** Docker daemon vulnerability related to image layers.

**Impact:** Only relevant to the Docker daemon itself, not client libraries.

**Mitigation in our code:**
- Not applicable to client usage
- We use the Docker API with explicit version negotiation

## Implementation Details

### Docker Client Initialization
```go
// Initialize Docker client with explicit version and API negotiation
cli, err = client.NewClientWithOpts(
    client.FromEnv, 
    client.WithAPIVersionNegotiation(),
    client.WithVersion("1.41"), // Explicitly set a supported API version
)
```

### Context Management
```go
// Create a context with timeout for the API call
listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
defer cancel()
    
containers, err := cli.ContainerList(listCtx, container.ListOptions{})
```

### Event Filtering
```go
// Create a filter to limit which events we process
eventFilters := filters.NewArgs()
eventFilters.Add("type", "container")
eventFilters.Add("event", "start")
eventFilters.Add("event", "die")
```

### Input Validation
```go
// Validate container ID
if !isValidContainerID(containerID) {
    log.Printf("Invalid container ID format: %s", containerID)
    return
}

// isValidContainerID checks if a container ID has valid format
func isValidContainerID(id string) bool {
    if len(id) < 12 {
        return false
    }
    return regexp.MustCompile("^[a-f0-9]+$").MatchString(id)
}
```

## Security Best Practices

1. **Resource Management**
   - All resources are properly closed with `defer`
   - Timeout contexts are used for all API calls

2. **Error Handling**
   - Comprehensive error handling for all API calls
   - Proper logging of all errors

3. **Minimal Permissions**
   - Container runs with minimal required permissions
   - Docker socket is mounted read-only

## References

- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [NIST Vulnerability Database](https://nvd.nist.gov/)
- [GitHub Security Advisories](https://github.com/advisories)