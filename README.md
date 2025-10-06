# OPNsense/Unbound Traefik Integration (tuda-sync)

[![Build Status](https://github.com/chelming/tuda-sync/actions/workflows/docker-build.yml/badge.svg)](https://github.com/chelming/tuda-sync/actions/workflows/docker-build.yml)
[![Go Security](https://github.com/chelming/tuda-sync/actions/workflows/go-security.yml/badge.svg)](https://github.com/chelming/tuda-sync/actions/workflows/go-security.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/chelming/tuda-sync)](https://github.com/chelming/tuda-sync/blob/main/go.mod)
[![License](https://img.shields.io/badge/license-Non%20Commercial-blue)](https://github.com/chelming/tuda-sync/blob/main/LICENSE)
[![Container Size](https://img.shields.io/badge/container%20size-~12MB-brightgreen)](https://github.com/chelming/tuda-sync/pkgs/container/tuda-sync)

> **tuda-sync**: **T**raefik **U**nbound **D**ocker **A**lias Synchronization

This tool monitors Docker events and uses the Traefik API to automatically create or delete **Unbound DNS Aliases** on your OPNsense firewall. This allows internal clients using Unbound (your OPNsense resolver) to correctly resolve the hostnames of your Traefik-managed services.

## 📖 How It Works

tuda-sync uses a streamlined API-first approach:

1. **Docker Event Monitoring**: The tool listens for container start/stop events from Docker
2. **Traefik API Integration**: When a container event is detected, it triggers a scan of all Traefik routes via the Traefik API
3. **Hostname Discovery**: The tool extracts hostnames from the Traefik routing rules
4. **DNS Configuration**: It automatically creates or updates Unbound DNS aliases in OPNsense for each discovered hostname
5. **Continuous Monitoring**: The process continues to run, monitoring for container changes and periodically scanning all Traefik routes

## 🔑 Key Features

- **API-First Approach**: Directly uses the Traefik API to get all routing rules, eliminating the need to inspect individual containers
- **Event-Triggered**: Container events simply act as triggers for scanning the Traefik API
- **Periodic Scanning**: Can be configured to periodically scan all Traefik routes to catch any changes
- **Support for File-Based Configurations**: Works with Traefik's file provider in addition to Docker labels
- **Host Override Management**: Automatically creates and removes DNS aliases in OPNsense Unbound
- **Flexible Deployment**: Can run as a standalone application or as a Docker container

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
    * **Required Permissions:**
      * `Services: Unbound (MVC)` - Required to use the reconfigure endpoint
      * `Services: Unbound DNS: Edit Host and Domain Override` - Required to manage DNS entries
2.  **Unbound Host Override:** A primary **Host Override** entry in OPNsense (**Services > Unbound DNS > Host Overrides**) pointing your Traefik/Reverse Proxy hostname to its local IP address.
    * **Crucially, this tool uses the UUID of this Host Override to link all dynamic aliases.**
    * If you're reverse proxying Traefik itself, it's recommended to create a separate host override for the Traefik API to avoid circular dependencies.
3.  **Traefik API Access:** Access to the Traefik API is required for the tool to function properly.
    * The Traefik API must be enabled in your Traefik configuration
    * The tool must be able to reach the Traefik API endpoint

***

## ⚙️ Configuration

The application is configured exclusively using **environment variables**, which are set via `docker run` or `docker-compose`.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `OPNSENSE_HOST` | | **Required:** OPNsense API host or IP. |
| `OPNSENSE_API_KEY` | | **Required:** OPNsense API Key. |
| `OPNSENSE_API_SECRET` | | **Required:** OPNsense API Secret. |
| `DEFAULT_PROXY_HOST_UUID` | | **Required:** UUID of the Unbound Host Override that points to your Traefik proxy's IP. |
| **`TRAEFIK_API_URL`** | | **Required:** URL to the Traefik API (e.g., `http://traefik:8080/api`). |
| **`TRAEFIK_USE_API`** | **`false`** | **Required:** Must be set to `true` to enable Traefik integration. |
| `BASE_DOMAIN` | | **Optional:** Domain used to replace `{$BASE_DOMAIN}` templates in Traefik rules. |
| `OPNSENSE_PROTOCOL` | `https` | Protocol for API access (`http` or `https`). |
| `OPNSENSE_INSECURE` | `false` | Set to `true` to skip TLS verification (e.g., if using self-signed certs). |
| `CLEAN_ON_START` | `false` | If set to `true`, deletes **ALL** Unbound Aliases on startup. See **Best Practice** below. |
| **`TRAEFIK_API_USERNAME`** | | **NEW:** Username for Traefik API basic authentication (if enabled). |
| **`TRAEFIK_API_PASSWORD`** | | **NEW:** Password for Traefik API basic authentication (if enabled). |
| **`TRAEFIK_CACHE_DURATION`** | **`30s`** | **NEW:** Duration to cache Traefik API responses (e.g., `30s`, `2m`, `1h`). |
| **`DEBUG_CACHE`** | **`false`** | **NEW:** Set to `true` to enable cache operation debugging. |
| **`SCAN_ALL_ROUTES`** | **`false`** | **NEW:** Set to `true` to scan all Traefik routes (including file-based configs) periodically. |
| **`ROUTE_SCAN_INTERVAL`** | **`5m`** | **NEW:** Interval for scanning all Traefik routes when SCAN_ALL_ROUTES is enabled. |
| **`DELAYED_ROUTER_CHECKS`** | **`false`** | **NEW:** Set to `true` to enable delayed router checks after container start. |
| **`DELAYED_CHECK_INITIAL_DELAY`** | **`5s`** | **NEW:** Initial delay before first check after container start. |
| **`DELAYED_CHECK_MAX_DELAY`** | **`60s`** | **NEW:** Maximum delay between checks. |
| **`DELAYED_CHECK_MAX_DURATION`** | **`5m`** | **NEW:** Maximum total duration for delayed checks. |
| **`DELAYED_CHECK_COUNT`** | **`5`** | **NEW:** Number of delayed checks to perform. |
| **`DELAYED_CHECK_USE_EXPONENTIAL`** | **`true`** | **NEW:** Use exponential backoff between delayed checks. |
| **`DELAYED_CHECK_JITTER`** | **`0.2`** | **NEW:** Jitter factor (0-1) to add randomness to delays. |

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
      
      # Required Traefik API settings
      - TRAEFIK_API_URL=http://traefik:8080/api
      - TRAEFIK_USE_API=true

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
  -e TRAEFIK_API_URL='http://traefik:8080/api' \
  -e TRAEFIK_USE_API='true' \
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

## 🌐 Traefik API Integration

tuda-sync now uses a pure API-first approach to discover all Traefik routes:

### Configuration:

```yaml
environment:
  # Required Traefik API integration
  - TRAEFIK_API_URL=http://traefik:8080/api
  - TRAEFIK_USE_API=true
  
  # Optional: For Traefik API with basic authentication
  - TRAEFIK_API_USERNAME=admin
  - TRAEFIK_API_PASSWORD=password
```

### Benefits:
- **Pure API-First Approach**: No longer relies on container labels for route discovery
- **Comprehensive Coverage**: Detects routes from all providers (Docker, file-based configs, etc.)
- **Simplified Logic**: Container events merely act as triggers for API scanning
- **Improved Efficiency**: Directly fetches routes from the Traefik API rather than inspecting each container
- **Better Reliability**: Works with all Traefik configuration methods and automatically adapts to changes

### Service Information Tracking:

tuda-sync captures complete information about routes directly from the Traefik API:

1. **Complete Router Data**: All router information comes directly from the Traefik API
2. **Provider Information**: Each DNS entry includes the provider type (docker, file, etc.)
3. **Service Name Tracking**: The service name is stored in the DNS alias description

For example, when Traefik has routers with services like:
   - A router using service `zorgbee` from a Docker container
   - A router using service `custom-api` from a file configuration

The DNS entries would include this provider and service information in their descriptions, making it easier to track which service is associated with each DNS entry.

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

### 📄 Efficient Scanning Strategy

tuda-sync uses an efficient API-first scanning approach:

1. **Event-Based Scanning**: Docker events (container start/stop) act as triggers to scan the Traefik API
2. **Full Route Discovery**: Each scan fetches ALL routes directly from the Traefik API
3. **Periodic Background Scanning**: Optionally scan all routes at regular intervals (for catching file-based changes)

This ensures that all routes are discovered regardless of how they're defined or which container created them. Docker events simply serve as efficient triggers for the scanning process.

You can enable additional periodic scanning with:

```yaml
environment:
  # Required Traefik API integration
  - TRAEFIK_API_URL=http://traefik:8080/api
  - TRAEFIK_USE_API=true
  
  # Optional: Enable additional periodic scanning
  - SCAN_ALL_ROUTES=true           # Enable periodic scanning
  - ROUTE_SCAN_INTERVAL=5m         # Check interval (default: 5m)
```

This approach ensures DNS aliases are created for all **enabled** routes, regardless of source.

### 🕒 Delayed Router Checks

Some containers need time to initialize before registering their routes with Traefik. You can enable delayed router checks to catch routes that appear after a container starts:

```yaml
environment:
  # Enable delayed router checking
  - DELAYED_ROUTER_CHECKS=true      # Enable delayed router checks
  - DELAYED_CHECK_COUNT=5           # Number of checks to perform
  - DELAYED_CHECK_MAX_DURATION=5m   # Maximum total check duration
```

This will perform multiple checks after a container starts to catch any routes that appear during initialization. See [Delayed Router Checks](docs/DELAYED_CHECKS.md) for more details and advanced configuration options.

- Docker container labels
- Static configurations in Traefik's file provider
- Routes defined in docker-compose.yml
- Any other providers supported by Traefik

> **Note:** Only routers with `status: "enabled"` will have DNS aliases created. Disabled routers are automatically skipped.