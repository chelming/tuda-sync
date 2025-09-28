# OPNsense/Unbound Traefik Integration (tuda-sync)

[![Build Status](https://github.com/chelming/tuda-sync/actions/workflows/docker-build.yml/badge.svg)](https://github.com/chelming/tuda-sync/actions/workflows/docker-build.yml)
[![Go Security](https://github.com/chelming/tuda-sync/actions/workflows/go-security.yml/badge.svg)](https://github.com/chelming/tuda-sync/actions/workflows/go-security.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/chelming/tuda-sync)](https://github.com/chelming/tuda-sync/blob/main/go.mod)
[![License](https://img.shields.io/badge/license-Non%20Commercial-blue)](https://github.com/chelming/tuda-sync/blob/main/LICENSE)
[![Container Size](https://img.shields.io/badge/container%20size-~12MB-brightgreen)](https://github.com/chelming/tuda-sync/pkgs/container/tuda-sync)

> **tuda-sync**: **T**raefik **U**nbound **D**ocker **A**lias Synchronization

This tool monitors Docker events for containers configured with Traefik host rules and automatically creates or deletes **Unbound DNS Aliases** on your OPNsense firewall. This allows internal clients using Unbound (your OPNsense resolver) to correctly resolve the hostnames of your Traefik-managed services.

## 🚀 Container Images

Pre-built container images are available from GitHub Container Registry:

```bash
# Latest stable release (recommended for production)
docker pull ghcr.io/chelming/tuda-sync:latest

# Latest development build
docker pull ghcr.io/chelming/tuda-sync:nightly

# Specific date-based version
docker pull ghcr.io/chelming/tuda-sync:2025.09.28
```

## 👩‍💻 Contributing

Interested in contributing to tuda-sync? Check out our [contribution guidelines](CONTRIBUTING.md) for:

- Building from source
- Development setup
- Creating releases
- Container build process
- Versioning conventions

## 🔒 Security

This application requires access to the Docker socket and uses the Docker API to monitor container events. The following security considerations are important:

- **Docker Socket Access**: The container requires access to the Docker socket, which grants significant privileges
  - **Best Practice**: Mount the socket as read-only: `/var/run/docker.sock:/var/run/docker.sock:ro`
  - **Advanced**: Consider using a Docker socket proxy like `tecnativa/docker-socket-proxy` for production use

- **Security Scanning**: We use multiple security scanners:
  - **Gosec**: Static analysis with custom configuration in `.gosec.config`
  - **Govulncheck**: Vulnerability scanning for Go dependencies (Docker SDK vulnerabilities documented)
  - **Trivy**: Container vulnerability scanning
  - **Local Scanning**: Run `./scripts/security_check.sh` to check for vulnerabilities locally

- **Security Tools**:
  - `./scripts/security_check.sh`: Run security scans locally
  - `./scripts/update_deps.sh`: Update dependencies to fix vulnerabilities

- **Security Mitigations**:
  - Input validation for all hostnames and container IDs
  - TLS 1.2+ enforcement for OPNsense API communication
  - Proper error handling and resource management

For detailed information about security considerations and mitigations, see our [SECURITY.md](SECURITY.md) file.

***

## 📄 License

tuda-sync is released under a custom **Non-Commercial License**. This means:

- ✅ Free for personal use
- ✅ Free for educational use
- ✅ Free for non-profit use
- ✅ Free for internal use in organizations
- ❌ Not for commercial distribution or sale

For commercial licensing inquiries, please contact the copyright holder. See the [LICENSE](LICENSE) file for details.

***

## 📝 Prerequisites

1.  **OPNsense API Access:** An API key/secret pair generated under **System > Access > Users**.
2.  **Unbound Host Override:** A primary **Host Override** entry in OPNsense (**Services > Unbound DNS > Host Overrides**) pointing your Traefik/Reverse Proxy hostname to its local IP address.
    * **Crucially, this tool uses the UUID of this Host Override to link all dynamic aliases.**
    * If you're reverse proxying Traefik itself, it's recommended to create a separate host override for the Traefik API to avoid circular dependencies.

***

## ⚙️ Configuration

The application is configured exclusively using **environment variables**, which are set via `docker run` or `docker-compose`.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `OPNSENSE_HOST` | | **Required:** OPNsense API host or IP. |
| `OPNSENSE_API_KEY` | | **Required:** OPNsense API Key. |
| `OPNSENSE_API_SECRET` | | **Required:** OPNsense API Secret. |
| `DEFAULT_PROXY_HOST_UUID` | | **Required:** UUID of the Unbound Host Override that points to your Traefik proxy's IP. |
| `BASE_DOMAIN` | | **Optional:** Domain used to replace `{$BASE_DOMAIN}` templates in Traefik rules. |
| `OPNSENSE_PROTOCOL` | `https` | Protocol for API access (`http` or `https`). |
| `OPNSENSE_INSECURE` | `false` | Set to `true` to skip TLS verification (e.g., if using self-signed certs). |
| `CLEAN_ON_START` | `false` | If set to `true`, deletes **ALL** Unbound Aliases on startup. See **Best Practice** below. |
| **`TRAEFIK_API_URL`** | | **NEW:** URL to the Traefik API (e.g., `http://traefik:8080/api`). |
| **`TRAEFIK_USE_API`** | **`false`** | **NEW:** Set to `true` to enable fetching routing rules directly from Traefik API. |
| **`TRAEFIK_API_USERNAME`** | | **NEW:** Username for Traefik API basic authentication (if enabled). |
| **`TRAEFIK_API_PASSWORD`** | | **NEW:** Password for Traefik API basic authentication (if enabled). |
| **`TRAEFIK_CACHE_DURATION`** | **`30s`** | **NEW:** Duration to cache Traefik API responses (e.g., `30s`, `2m`, `1h`). |
| **`DEBUG_CACHE`** | **`false`** | **NEW:** Set to `true` to enable cache operation debugging. |

***

## 🚀 Docker Deployment

The container must run with access to the Docker socket to monitor events.

> **Note:** The container image is highly optimized (~12MB) and runs with minimal privileges for enhanced security.

### Docker Compose Example
```yaml
version: '3.7'
services:
  tuda-sync:
    image: ghcr.io/chelming/tuda-sync
    container_name: tuda-sync
    restart: unless-stopped
    volumes:
      # Required for monitoring Docker events
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      # Required OPNsense credentials
      - OPNSENSE_HOST=192.168.1.1
      - OPNSENSE_API_KEY=YOUR_API_KEY
      - OPNSENSE_API_SECRET=YOUR_API_SECRET
      
      # Required proxy UUID
      - DEFAULT_PROXY_HOST_UUID=4b2c18b0-b255-4071-8447-c99f802ab69c

      # Optional features
      # Deletes all aliases on container start (RECOMMENDED, see Best Practice)
      - CLEAN_ON_START=true 
      # Optional: Domain templating
      # - BASE_DOMAIN=example.com
```

### Docker Run Example
```bash
docker run -d \
  --name tuda-sync \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e OPNSENSE_HOST='192.168.1.1' \
  -e OPNSENSE_API_KEY='YOUR_API_KEY' \
  -e OPNSENSE_API_SECRET='YOUR_API_SECRET' \
  -e DEFAULT_PROXY_HOST_UUID='4b2c18b0-b255-4071-8447-c99f802ab69c' \
  -e CLEAN_ON_START='true' \
  ghcr.io/chelming/tuda-sync
```

***

## ⭐ Best Practice: Using `CLEAN_ON_START` Safely

The `CLEAN_ON_START=true` environment variable is powerful but deletes **ALL** Unbound aliases. To prevent accidentally deleting manual DNS entries, we strongly recommend creating a dedicated "anchor" host override.

### Recommended Setup Steps:
1. Create a Dedicated Alias Anchor ⚓

   In OPNsense, create a new Host Override entry:
   - Host: docker-aliases
   - Domain: local (or your actual domain)
   - IP: The IP address of your Traefik proxy.
   - Save the UUID of this specific entry.

2. Configure the Tool

   Set your DEFAULT_PROXY_HOST_UUID to the UUID of this NEW anchor entry 
   and ensure CLEAN_ON_START=true is set in your environment variables.

   Result: 
   The tool will now ONLY manage (create, delete, and clear) aliases that 
   are linked to this specific "anchor" UUID, leaving any manually configured, 
   unlinked aliases completely untouched. This ensures robust and safe dynamic DNS management.

***

## 🌐 Traefik API Integration (New!)

This tool can now fetch routing rules directly from the Traefik API instead of parsing container labels. This provides more reliable rule detection, especially for containers that use Traefik but don't have explicit Host rules in their labels.

### Configuration:

```yaml
environment:
  # Enable Traefik API integration
  - TRAEFIK_API_URL=http://traefik:8080/api
  - TRAEFIK_USE_API=true
  # Optional: For Traefik API with basic authentication
  - TRAEFIK_API_USERNAME=admin
  - TRAEFIK_API_PASSWORD=password
```

### Benefits:
- More accurate detection of routing rules
- Support for containers without explicit Host rules in labels
- Detects routes created dynamically or through Traefik's file provider
- Falls back to label parsing if API is unavailable

### Notes:
1. Ensure Traefik has its API enabled. For example in your Traefik configuration:

```yaml
api:
  dashboard: true
  insecure: true  # Only use in trusted networks
```

2. If your Traefik API is protected with basic authentication (you're getting HTTP 401 errors), provide credentials:

```yaml
environment:
  - TRAEFIK_API_USERNAME=your-username
  - TRAEFIK_API_PASSWORD=your-password
```

3. **Important:** If you're reverse proxying Traefik itself (e.g., accessing Traefik through another reverse proxy), make sure to create a separate host override for the Traefik API endpoint. This ensures that tuda-sync can access the Traefik API directly without going through another proxy layer, which could cause connectivity issues or circular dependencies.