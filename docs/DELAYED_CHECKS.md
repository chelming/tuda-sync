### 📈 Delayed Router Checks

Some containers take time to fully initialize and register their routes with Traefik. When a container starts, its routers might not be immediately available through the Traefik API. To address this, tuda-sync implements a delayed checking mechanism that can perform multiple scans after a container starts.

#### How Delayed Router Checks Work:

1. When a container starts, tuda-sync immediately performs a first scan
2. If delayed checks are enabled, a separate process monitors for new routers appearing over time
3. Multiple checks are performed with increasing delays between them
4. Each check looks for any new routers that weren't detected in previous scans

This ensures that even slow-starting containers eventually have their routers discovered and DNS aliases created.

#### Configuring Delayed Router Checks:

```yaml
environment:
  # Basic delayed check configuration
  - DELAYED_ROUTER_CHECKS=true      # Enable delayed router checks
  
  # Advanced configuration (optional)
  - DELAYED_CHECK_INITIAL_DELAY=5s  # Initial delay before first check
  - DELAYED_CHECK_MAX_DELAY=60s     # Maximum delay between checks
  - DELAYED_CHECK_MAX_DURATION=5m   # Maximum total duration for delayed checks
  - DELAYED_CHECK_COUNT=5           # Number of checks to perform
  - DELAYED_CHECK_USE_EXPONENTIAL=true  # Use exponential backoff
  - DELAYED_CHECK_JITTER=0.2        # Add randomness to delays (0-1)
```

By default, delayed checks use an exponential backoff strategy with jitter to spread out API requests:

- First check: ~5 seconds after container start
- Second check: ~10 seconds after first check
- Third check: ~20 seconds after second check
- And so on, up to the maximum delay

This ensures that slow-starting containers will have their routes discovered while avoiding excessive API calls.