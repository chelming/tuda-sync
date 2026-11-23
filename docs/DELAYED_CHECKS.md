### 📈 Follow-up Scans (Delayed Router Checks)

When a container starts, its routers are not immediately available through the Traefik API: Traefik reads the same Docker event tuda-sync does and builds the router a moment later. The same happens in reverse when a container stops, as its router lingers briefly. The scan that tuda-sync runs inside the event handler therefore usually sees the *old* router set.

Without follow-up scans, a new container would only get its DNS alias at the next periodic scan (`ROUTE_SCAN_INTERVAL`, 5 minutes by default), and a stopped container would keep its alias until then.

#### How follow-up scans work:

1. A container `start` or `die` event drops the cached Traefik router list and runs an immediate scan.
2. A series of follow-up scans is scheduled. Each one bypasses the router cache, fetches the current routers and runs the full scan, so it **creates** aliases for routers that have appeared and **deletes** aliases whose routers are gone.
3. The scans are spaced with exponential backoff and jitter. By default: ~5s, ~10s, ~20s, ~40s and ~60s after the event.
4. A newer container event restarts the series, so a burst of events (a `docker compose up`, a Watchtower sweep) costs one series, not one per event.
5. Scans never overlap, and Unbound is reconfigured only when an alias actually changed (or an earlier reconfigure failed and is still pending).

Follow-up scans are **enabled by default**.

#### Configuring follow-up scans:

```yaml
environment:
  # Disable the follow-up scans (default: true)
  - DELAYED_ROUTER_CHECKS=false

  # Advanced configuration (optional)
  - DELAYED_CHECK_INITIAL_DELAY=5s  # Delay before the first follow-up scan
  - DELAYED_CHECK_MAX_DELAY=60s     # Maximum delay between scans
  - DELAYED_CHECK_MAX_DURATION=5m   # Maximum total duration of one series
  - DELAYED_CHECK_COUNT=5           # Number of follow-up scans
  - DELAYED_CHECK_USE_EXPONENTIAL=true  # Use exponential backoff
  - DELAYED_CHECK_JITTER=0.2        # Add randomness to delays (0-1)
```

The periodic scan (`ROUTE_SCAN_INTERVAL`) still runs as a backstop.
