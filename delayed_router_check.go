package main

import (
	"context"
	"math/rand"
	"strings"
	"time"
)

// DelayedCheckOptions contains configuration for delayed router checks
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

// DefaultDelayedCheckOptions returns the default options for delayed router checks
func DefaultDelayedCheckOptions() DelayedCheckOptions {
	return DelayedCheckOptions{
		InitialDelay:         5 * time.Second,
		MaxDelay:             60 * time.Second,
		MaxTotalDuration:     5 * time.Minute,
		MaxChecks:            5,
		UseExponentialBackoff: true,
		JitterFactor:         0.2,
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

// monitorContainerStartRouters performs multiple delayed checks for new routers
// after a container start event to catch routers that appear after container initialization
func monitorContainerStartRouters(containerName string, opnsenseClient *OpnsenseClient) {
	// Skip if delayed checks are disabled
	if !enableDelayedChecks {
		logger.Debug().Str("container", containerName).Msg("Skipping delayed router checks (disabled by config)")
		return
	}
	
	// Use the configured options
	options := delayedRouterChecks
	
	logger.Debug().
		Str("container", containerName).
		Dur("initialDelay", options.InitialDelay).
		Dur("maxDuration", options.MaxTotalDuration).
		Int("maxChecks", options.MaxChecks).
		Bool("exponentialBackoff", options.UseExponentialBackoff).
		Float64("jitter", options.JitterFactor).
		Msg("Starting delayed router checks for container")
		
	// Run checks in a separate goroutine
	go performDelayedChecks(containerName, opnsenseClient, options)
}

// performDelayedChecks executes the actual delayed router checks
func performDelayedChecks(containerName string, opnsenseClient *OpnsenseClient, options DelayedCheckOptions) {
	ctx, cancel := context.WithTimeout(context.Background(), options.MaxTotalDuration)
	defer cancel()
	
	// Initial delay before first check
	initialDelay := applyJitter(options.InitialDelay, options.JitterFactor)
	time.Sleep(initialDelay)
	
	// Keep track of when we started
	startTime := time.Now()
	
	// Track unique FQDNs we've already seen
	seenFQDNs := make(map[string]struct{})
	
	// Keep track of iteration count
	for iteration := 0; iteration < options.MaxChecks; iteration++ {
		// Check if we've exceeded our total duration
		if time.Since(startTime) > options.MaxTotalDuration {
			logger.Debug().
				Str("container", containerName).
				Dur("elapsed", time.Since(startTime)).
				Msg("Delayed router checks exceeded max duration")
			return
		}
		
		// Check if context is done
		if ctx.Err() != nil {
			return
		}
		
		// Fetch current routers
		routers, err := fetchTraefikRouters()
		if err != nil {
			logger.Warn().
				Err(err).
				Str("container", containerName).
				Int("iteration", iteration+1).
				Msg("Failed to fetch routers during delayed check")
			continue
		}
		
		// Count new routers found
		newRoutersFound := 0
		
		// Process each router
		for _, router := range routers {
			// Skip disabled routers
			if router.Status != "enabled" {
				continue
			}
			
			// Skip routers without Host rules
			if !strings.Contains(router.Rule, "Host(") {
				continue
			}
			
			// Extract FQDN from router rule
			fqdn := extractFQDN(router.Rule)
			if fqdn == "" {
				continue
			}
			
			// Check if we've already seen this FQDN
			if _, exists := seenFQDNs[fqdn]; exists {
				continue
			}
			
			// New FQDN found
			seenFQDNs[fqdn] = struct{}{}
			
			// Skip internal domains
			if strings.HasSuffix(fqdn, ".internal") || strings.HasSuffix(fqdn, ".local") {
				continue
			}
			
			// Queue the alias creation
			if err := opnsenseClient.CreateAlias(fqdn, defaultProxyHostUUID, router.Provider, router.Service); err != nil {
				logger.Warn().
					Err(err).
					Str("fqdn", fqdn).
					Str("container", containerName).
					Msg("Failed to create alias during delayed check")
				continue
			}
			
			logger.Info().
				Str("fqdn", fqdn).
				Str("container", containerName).
				Str("router", router.Name).
				Int("checkIteration", iteration+1).
				Msg("Created new DNS alias from delayed router check")
				
			newRoutersFound++
		}
		
		// Log results of this check iteration
		logger.Debug().
			Str("container", containerName).
			Int("iteration", iteration+1).
			Int("newRouters", newRoutersFound).
			Int("totalSeen", len(seenFQDNs)).
			Msg("Completed delayed router check iteration")
		
		// If we found new routers, reconfigure Unbound
		if newRoutersFound > 0 {
			scheduleReconfigure(opnsenseClient)
		}
		
		// Exit if this was the last iteration
		if iteration == options.MaxChecks-1 {
			break
		}
		
		// Calculate delay for next check
		var nextDelay time.Duration
		if options.UseExponentialBackoff {
			// Use exponential backoff: initialDelay * 2^iteration
			backoffFactor := 1 << iteration // 2^iteration
			nextDelay = options.InitialDelay * time.Duration(backoffFactor)
			
			// Cap at max delay
			if nextDelay > options.MaxDelay {
				nextDelay = options.MaxDelay
			}
		} else {
			// Use linear delay
			nextDelay = options.InitialDelay * time.Duration(iteration+2) // +2 because we start at iteration 0
			
			// Cap at max delay
			if nextDelay > options.MaxDelay {
				nextDelay = options.MaxDelay
			}
		}
		
		// Apply jitter to avoid thundering herd
		nextDelay = applyJitter(nextDelay, options.JitterFactor)
		
		// Sleep until next check
		logger.Debug().
			Str("container", containerName).
			Dur("nextDelay", nextDelay).
			Int("nextIteration", iteration+2).
			Msg("Sleeping before next router check")
		
		select {
		case <-time.After(nextDelay):
			// Continue to next iteration
		case <-ctx.Done():
			return
		}
	}
	
	logger.Debug().
		Str("container", containerName).
		Int("totalFQDNs", len(seenFQDNs)).
		Dur("totalDuration", time.Since(startTime)).
		Msg("Completed all delayed router checks")
}