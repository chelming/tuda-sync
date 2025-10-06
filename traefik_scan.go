package main

import (
	"context"
	"fmt"
	"strings"
	"time"
	
	// We use the logger declared in main.go
)

// Function to scan all Traefik routers and create DNS aliases for them
// This function handles routes from ALL sources, including:
// - Docker container labels
// - File-based configurations
// - Other providers (e.g., Kubernetes CRDs if Traefik is running in a Kubernetes cluster)
func scanAllTraefikRoutes(ctx context.Context, opnsenseClient *OpnsenseClient) error {
	// Log what we're doing
	logger.Debug().Msg("Scanning all Traefik routes for Host rules...")

	// Fetch all routers from Traefik API
	routers, err := fetchTraefikRouters()
	if err != nil {
		return fmt.Errorf("failed to fetch Traefik routers: %w", err)
	}

	logger.Debug().Int("count", len(routers)).Msg("Found Traefik routers")

	// Track statistics
	var aliasCount int
	var skipCount int
	aliasMap := make(map[string]struct{}) // Use a map to track unique aliases
	
	// Get existing aliases to clean up stale ones later
	existingAliases, err := opnsenseClient.GetAllAliases()
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to fetch existing aliases for cleanup")
	}

	// Process each router
	for _, router := range routers {
		// Skip disabled routers
		if router.Status != "enabled" {
			logger.Debug().Str("router", router.Name).Msg("Skipping disabled router")
			skipCount++
			continue
		}

		// Skip routers without Host rules
		if !strings.Contains(router.Rule, "Host(") {
			logger.Debug().Str("router", router.Name).Msg("Skipping router: No Host rule found")
			skipCount++
			continue
		}

		// Extract FQDN from router rule
		fqdn := extractFQDN(router.Rule)
		if fqdn == "" {
			logger.Debug().Str("router", router.Name).Str("rule", router.Rule).Msg("Skipping router: Could not extract FQDN from rule")
			skipCount++
			continue
		}

		// Skip if we've already processed this FQDN
		if _, exists := aliasMap[fqdn]; exists {
			logger.Debug().Str("fqdn", fqdn).Msg("Skipping duplicate FQDN")
			skipCount++
			continue
		}

		// Add to our tracking map
		aliasMap[fqdn] = struct{}{}
		
		// Log the provider for informational purposes
		if router.Provider == "file" || strings.HasPrefix(router.Provider, "kubernetes") {
			// For file-based configurations or k8s, we want to provide more detailed logging
			logger.Debug().Str("router", router.Name).Str("fqdn", fqdn).Str("provider", router.Provider).Msg("Found non-docker router with Host rule")
		}

		// Check if this is an internal service (no need for DNS alias)
		if strings.HasSuffix(fqdn, ".internal") || strings.HasSuffix(fqdn, ".local") {
			logger.Debug().Str("fqdn", fqdn).Msg("Skipping internal service FQDN")
			skipCount++
			continue
		}

		// Queue the alias creation (without reconfiguring each time)
		logger.Debug().Str("fqdn", fqdn).Str("router", router.Name).Str("provider", router.Provider).Str("service", router.Service).Msg("Queueing alias for Traefik route")
		if err := opnsenseClient.CreateAlias(fqdn, defaultProxyHostUUID, router.Provider, router.Service); err != nil {
			logger.Warn().Err(err).Str("fqdn", fqdn).Msg("Failed to create alias")
			continue
		}

		aliasCount++
	}

	// Clean up stale aliases (those that no longer have a corresponding router)
	var deletedCount int
	if existingAliases != nil {
		for fqdn := range existingAliases {
			// Skip if this alias is still valid (exists in our current router set)
			if _, exists := aliasMap[fqdn]; exists {
				continue
			}
			
			// This alias no longer has a corresponding router, delete it
			logger.Debug().Str("fqdn", fqdn).Msg("Deleting stale alias without matching router")
			if err := opnsenseClient.DeleteAlias(fqdn); err != nil {
				logger.Warn().Err(err).Str("fqdn", fqdn).Msg("Failed to delete stale alias")
			} else {
				deletedCount++
			}
		}
	}
	
	// Only reconfigure once after all aliases have been processed (created and deleted)
	needsReconfigure := aliasCount > 0 || deletedCount > 0
	
	if needsReconfigure {
		logger.Info().Int("created", aliasCount).Int("deleted", deletedCount).Int("skipped", skipCount).Msg("Processed Traefik router aliases")
		logger.Debug().Msg("Reconfiguring Unbound with all alias changes...")
		if err := opnsenseClient.Reconfigure(); err != nil {
			return fmt.Errorf("failed to reconfigure Unbound after processing aliases: %w", err)
		}
		logger.Debug().Msg("Unbound reconfiguration complete")
	} else {
		logger.Info().Int("skipped", skipCount).Msg("No alias changes needed")
	}

	return nil
}

// Function to periodically scan all Traefik routes
func startTraefikRoutesScanner(ctx context.Context, opnsenseClient *OpnsenseClient, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger.Info().Dur("interval", interval).Msg("Starting Traefik routes scanner")

	// Scan immediately on startup
	if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
		logger.Error().Err(err).Msg("Failed to scan Traefik routes")
	}

	// Then scan periodically
	for {
		select {
		case <-ticker.C:
			if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
				logger.Error().Err(err).Msg("Failed to scan Traefik routes")
			}
		case <-ctx.Done():
			logger.Debug().Msg("Traefik routes scanner stopped")
			return
		}
	}
}