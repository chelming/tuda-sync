package main

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// DelayedCheckOptions contains configuration for the follow-up scans that run
// after a container start/stop event
type DelayedCheckOptions struct {
	// Initial delay before first check (defaults to 5s)
	InitialDelay time.Duration

	// Maximum delay between checks (defaults to 60s)
	MaxDelay time.Duration

	// Maximum total time to keep checking (defaults to 5m)
	MaxTotalDuration time.Duration

	// Number of checks to perform (defaults to 5)
	MaxChecks int

	// Whether to use exponential backoff between checks (defaults to true)
	UseExponentialBackoff bool

	// Jitter factor to add randomness to delays (0-1, defaults to 0.2)
	JitterFactor float64
}

// DefaultDelayedCheckOptions returns the default options for follow-up scans
func DefaultDelayedCheckOptions() DelayedCheckOptions {
	return DelayedCheckOptions{
		InitialDelay:          5 * time.Second,
		MaxDelay:              60 * time.Second,
		MaxTotalDuration:      5 * time.Minute,
		MaxChecks:             5,
		UseExponentialBackoff: true,
		JitterFactor:          0.2,
	}
}

// applyJitter adds random jitter to a delay
func applyJitter(delay time.Duration, jitterFactor float64) time.Duration {
	if jitterFactor <= 0 {
		return delay
	}

	// Apply jitter between -jitterFactor/2 and +jitterFactor/2
	jitterRange := float64(delay) * jitterFactor
	jitterAmount := (rand.Float64() - 0.5) * jitterRange

	return delay + time.Duration(jitterAmount)
}

// nextFollowUpDelay returns the wait before the check after the one at index
// `completed` (0-based), before jitter
func nextFollowUpDelay(options DelayedCheckOptions, completed int) time.Duration {
	var next time.Duration
	if options.UseExponentialBackoff {
		next = options.InitialDelay * time.Duration(1<<completed) // initial * 2^completed
	} else {
		next = options.InitialDelay * time.Duration(completed+2) // +2: the first check is index 0
	}
	if next > options.MaxDelay {
		next = options.MaxDelay
	}
	return next
}

// followUp tracks the newest follow-up series. A new container event starts a
// new series and supersedes the one still running, so a burst of events (a
// compose up, a Watchtower sweep) costs one series instead of one per event.
var followUp struct {
	mu  sync.Mutex
	gen uint64
}

// scheduleFollowUpScans re-scans the Traefik routes a few times after a
// container start/stop event.
//
// The scan that runs inside the event handler cannot be relied on: Traefik
// learns about a new container from the same Docker event and takes a moment
// to build its router, so that scan usually still sees the old router set. A
// container that starts gets its alias late, one that stops keeps it until the
// next periodic scan. The follow-up scans bypass the router cache and use the
// full scan, so they both create aliases for routers that have appeared and
// delete the ones whose routers have gone.
func scheduleFollowUpScans(containerName, action string, opnsenseClient *OpnsenseClient) {
	if !enableDelayedChecks {
		logger.Debug().Str("container", containerName).Msg("Skipping follow-up scans (disabled by config)")
		return
	}

	followUp.mu.Lock()
	followUp.gen++
	gen := followUp.gen
	followUp.mu.Unlock()

	go runFollowUpScans(containerName, action, opnsenseClient, gen, delayedRouterChecks)
}

func followUpSuperseded(gen uint64) bool {
	followUp.mu.Lock()
	defer followUp.mu.Unlock()
	return followUp.gen != gen
}

func runFollowUpScans(containerName, action string, opnsenseClient *OpnsenseClient, gen uint64, options DelayedCheckOptions) {
	ctx, cancel := context.WithTimeout(context.Background(), options.MaxTotalDuration)
	defer cancel()

	logger.Debug().
		Str("container", containerName).
		Str("action", action).
		Dur("initialDelay", options.InitialDelay).
		Int("maxChecks", options.MaxChecks).
		Msg("Starting follow-up scans")

	delay := applyJitter(options.InitialDelay, options.JitterFactor)
	for i := 0; i < options.MaxChecks; i++ {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}

		// A newer event started its own series
		if followUpSuperseded(gen) {
			logger.Debug().Str("container", containerName).Int("check", i+1).Msg("Follow-up scans superseded by a newer event")
			return
		}

		invalidateRouterCache()
		if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
			logger.Warn().Err(err).Str("container", containerName).Int("check", i+1).Msg("Follow-up scan failed")
		}

		delay = applyJitter(nextFollowUpDelay(options, i), options.JitterFactor)
	}

	logger.Debug().Str("container", containerName).Msg("Completed follow-up scans")
}
