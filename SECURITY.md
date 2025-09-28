# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in tuda-sync, please send an email to the project maintainers. We will acknowledge your report within 48 hours and work with you to understand and address the issue.

## Security Considerations

### Docker Client Security

This application requires access to the Docker socket to monitor container events. The Go security scanner `govulncheck` identifies several potential vulnerabilities in the Docker SDK, which are unavoidable for applications that need to interact with Docker.

### Known Vulnerabilities

The Go security scanner (`govulncheck`) identifies several potential vulnerabilities in the Docker SDK, which are expected when using Docker client libraries.

#### Docker SDK Vulnerabilities
- **GO-2025-3830**: Moby firewalld reload makes published container ports accessible from remote hosts
  - Not exploitable in our application as we don't interact with firewall functionality
  - Fixed in github.com/docker/docker@v28.3.3+incompatible (we've updated our dependency)
  - References: https://pkg.go.dev/vuln/GO-2025-3830
  - **Update available**: Run `./scripts/update_deps.sh` to update your Docker client

- **CVE-2023-45288**: Path traversal in Docker CLI via file parameter in build command
  - Not exploitable in our use case (we don't use Docker build API)
  - References: https://github.com/advisories/GHSA-hmfx-3pcx-653p

- **CVE-2021-41190**: Improper path sanitization in archive extraction
  - Not exploitable in our context (we don't extract archives)
  - References: https://github.com/advisories/GHSA-mc8h-8q98-g5hr

- **CVE-2022-36109**: Docker daemon can be attacked via malicious image layers
  - Only relevant to daemon, not client usage
  - References: https://nvd.nist.gov/vuln/detail/CVE-2022-36109

#### Flagged Functions
The security scanner will flag the following functions:
- `client.NewClientWithOpts` - Used for Docker client initialization
- `client.Client.Events` - Used to monitor container events
- `client.Client.ContainerList` - Used to list running containers
- `client.Client.Close` - Used to properly close resources
- `http.Client.Do` - Used for API requests
- `client.CheckRedirect` - Used for safe redirect handling
- Various initialization functions - Indirect dependencies

For detailed information about Docker SDK vulnerabilities and our specific mitigations, see [docs/DOCKER_SECURITY.md](docs/DOCKER_SECURITY.md).

### Mitigations Implemented

The following mitigations are in place:

1. **Restricted Docker Client Functionality**:
   - Explicit API version setting (`WithVersion("1.41")`)
   - No interaction with container network or firewall configuration (mitigates GO-2025-3830)
   - Limited to monitoring events only, not modifying container configuration

2. **Proper Resource Management**:
   - All resources are properly closed with `defer`
   - Timeout contexts are used for all API calls

3. **Input Validation**:
   - Container IDs are validated with regex before use
   - Hostnames are validated against DNS naming rules
   - Labels are checked for existence before use

4. **Secure HTTP Client Configuration**:
   - TLS 1.2+ enforced
   - Connection pooling with timeouts
   - Redirect limits implemented

5. **Error Handling**:
   - Comprehensive error handling for all API calls
   - Proper logging of all errors without exposing sensitive information

## Security Scanning Configuration

We use several security scanners in our CI/CD pipeline:

1. **Gosec**: Configuration in `.gosec.config`
   - Excluded rules:
     - G107: URL provided to HTTP request - Safe with our validation
     - G204: Command execution - Not used in our context
     - G304: File access via variable - Not applicable

2. **Govulncheck**: Configured to warn but not fail on Docker client vulnerabilities

### Best Practices for Deployment

When deploying this application:

1. **Docker Socket Access**:
   - Consider using a Docker socket proxy like [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
   - Mount the Docker socket as read-only: `-v /var/run/docker.sock:/var/run/docker.sock:ro`

2. **Least Privilege Principle**:
   - Run the container with minimal required permissions
   - Use container user namespaces when possible

3. **Regular Updates**:
   - Keep the application updated to benefit from security improvements

4. **Network Security**:
   - TLS connections enforce minimum TLS 1.2
   - Certificate validation is enforced by default (can be disabled with `--opnsense-insecure`)
   - Timeouts are set on all network operations