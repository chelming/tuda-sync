package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// Function to scan all Traefik routers and create DNS aliases for them
// This function will handle routes from file-based configs or other non-Docker sources
func scanAllTraefikRoutes(ctx context.Context, opnsenseClient *OpnsenseClient) error {
	// Log what we're doing
	log.Println("Scanning all Traefik routes for Host rules...")

	// Fetch all routers from Traefik API
	routers, err := fetchTraefikRouters()
	if err != nil {
		return fmt.Errorf("failed to fetch Traefik routers: %w", err)
	}

	log.Printf("Found %d total Traefik routers", len(routers))

	// Track statistics
	var aliasCount int
	var skipCount int
	aliasMap := make(map[string]struct{}) // Use a map to track unique aliases

	// Process each router
	for _, router := range routers {
		// Skip routers without Host rules
		if !strings.Contains(router.Rule, "Host(") {
			log.Printf("Skipping router %s: No Host rule found", router.Name)
			skipCount++
			continue
		}

		// Extract FQDN from router rule
		fqdn := extractFQDN(router.Rule)
		if fqdn == "" {
			log.Printf("Skipping router %s: Could not extract FQDN from rule: %s", router.Name, router.Rule)
			skipCount++
			continue
		}

		// Skip if we've already processed this FQDN
		if _, exists := aliasMap[fqdn]; exists {
			log.Printf("Skipping duplicate FQDN: %s", fqdn)
			skipCount++
			continue
		}

		// Add to our tracking map
		aliasMap[fqdn] = struct{}{}

		// Check if this is an internal service (no need for DNS alias)
		if strings.HasSuffix(fqdn, ".internal") || strings.HasSuffix(fqdn, ".local") {
			log.Printf("Skipping internal service FQDN: %s", fqdn)
			skipCount++
			continue
		}

		// Create the alias in OPNsense
		log.Printf("Creating alias for Traefik route: %s (Router: %s)", fqdn, router.Name)
		if err := opnsenseClient.CreateAlias(fqdn, defaultProxyHostUUID); err != nil {
			log.Printf("WARNING: Failed to create alias for %s: %v", fqdn, err)
			continue
		}

		aliasCount++
	}

	// Apply changes if we created any aliases
	if aliasCount > 0 {
		log.Printf("Created %d aliases from Traefik routers (skipped %d)", aliasCount, skipCount)
		if err := opnsenseClient.Reconfigure(); err != nil {
			return fmt.Errorf("failed to reconfigure Unbound after creating aliases: %w", err)
		}
	} else {
		log.Printf("No new aliases created from Traefik routes (skipped %d)", skipCount)
	}

	return nil
}

// Function to periodically scan all Traefik routes
func startTraefikRoutesScanner(ctx context.Context, opnsenseClient *OpnsenseClient, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("Starting Traefik routes scanner with interval: %v", interval)

	// Scan immediately on startup
	if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
		log.Printf("ERROR: Failed to scan Traefik routes: %v", err)
	}

	// Then scan periodically
	for {
		select {
		case <-ticker.C:
			if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
				log.Printf("ERROR: Failed to scan Traefik routes: %v", err)
			}
		case <-ctx.Done():
			log.Println("Traefik routes scanner stopped")
			return
		}
	}
}