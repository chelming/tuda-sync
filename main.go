package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

// Define the Traefik label key used to extract the FQDN from container labels.
const traefikRuleLabel = "traefik.http.routers.web.rule"

// Global constants and variables derived from command-line arguments and environment variables
var (
	opnsenseHost   string
	opnsenseKey    string
	opnsenseSecret string
	opnsenseInsecure bool
	opnsenseProtocol string
	
	defaultProxyHostUUID string
	baseDomain           string
	
	// Traefik API settings
	traefikApiUrl string
	traefikApiEnabled bool
	traefikApiUsername string
	traefikApiPassword string
	
	// Traefik API cache
	traefikRouterCache struct {
		routers []TraefikRouter
		lastFetched time.Time
		mutex sync.RWMutex
	}
	traefikCacheDuration time.Duration = 30 * time.Second // Cache Traefik API responses for 30 seconds by default
	
	// Debug settings
	debugCache bool // Whether to print debug messages about cache operations
	
	// Flags for operation mode
	clearOnStart bool
	scanOnly bool
	scanAllRoutes bool
	routeScanInterval time.Duration
	
	// Reconfiguration debounce mechanism
	reconfigureMutex sync.Mutex
	reconfigurePending bool
	reconfigureTimer *time.Timer
	
	// Prometheus metrics
	aliasCreations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tuda_sync_alias_creations_total",
		Help: "Total number of DNS aliases created",
	})
	aliasDeletions = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tuda_sync_alias_deletions_total", 
		Help: "Total number of DNS aliases deleted",
	})
	reconfigureFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tuda_sync_reconfigure_failures_total",
		Help: "Total number of Unbound reconfigure failures",
	})
	
	// Multiple Traefik instances support
	traefikInstances = map[string]string{
		"traefik.enable": "", // Default traefik label
	}
)

// Helper function to check for "true" string in environment variable
func getEnvBool(key string) bool {
	return strings.ToLower(os.Getenv(key)) == "true"
}

// Helper function to get a duration from an environment variable with a default
func getEnvDuration(key string, defaultDuration time.Duration) time.Duration {
	if envValue := os.Getenv(key); envValue != "" {
		if parsed, err := time.ParseDuration(envValue); err == nil {
			return parsed
		}
		log.Printf("WARNING: Invalid duration format for %s, using default: %v", key, defaultDuration)
	}
	return defaultDuration
}

func init() {
	// Configure structured logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
	
	// 1. OPNsense Connection Flags
	flag.StringVar(&opnsenseHost, "opnsense-host", os.Getenv("OPNSENSE_HOST"), "OPNsense API host/IP. (Env: OPNSENSE_HOST)")
	flag.StringVar(&opnsenseKey, "opnsense-key", os.Getenv("OPNSENSE_API_KEY"), "OPNsense API Key. (Env: OPNSENSE_API_KEY)")
	flag.StringVar(&opnsenseSecret, "opnsense-secret", os.Getenv("OPNSENSE_API_SECRET"), "OPNsense API Secret. (Env: OPNSENSE_API_SECRET)")
	flag.BoolVar(&opnsenseInsecure, "opnsense-insecure", getEnvBool("OPNSENSE_INSECURE"), "Skip TLS verification for OPNsense. (Env: OPNSENSE_INSECURE=true)")
	flag.StringVar(&opnsenseProtocol, "opnsense-protocol", os.Getenv("OPNSENSE_PROTOCOL"), "OPNsense API protocol (http/https). (Env: OPNSENSE_PROTOCOL, default: https)")
	
	// Parse cache duration from environment if available
	if cacheDur := os.Getenv("TRAEFIK_CACHE_DURATION"); cacheDur != "" {
		if parsed, err := time.ParseDuration(cacheDur); err == nil {
			traefikCacheDuration = parsed
			log.Printf("Set Traefik cache duration to %v from environment", traefikCacheDuration)
		}
	}
	
	// Enable cache debugging if requested
	debugCache = getEnvBool("DEBUG_CACHE")

	// 2. Application Logic Flags
	flag.StringVar(&defaultProxyHostUUID, "proxy-uuid", os.Getenv("DEFAULT_PROXY_HOST_UUID"), "UUID of the OPNsense Host Override for the Traefik proxy. (Env: DEFAULT_PROXY_HOST_UUID)")
	flag.StringVar(&baseDomain, "base-domain", os.Getenv("BASE_DOMAIN"), "The base domain to use for Traefik FQDN lookups. (Env: BASE_DOMAIN)")
	
	// 3. Traefik API Flags
	flag.StringVar(&traefikApiUrl, "traefik-api", os.Getenv("TRAEFIK_API_URL"), "URL for the Traefik API (e.g., http://traefik:8080/api). (Env: TRAEFIK_API_URL)")
	flag.BoolVar(&traefikApiEnabled, "use-traefik-api", getEnvBool("TRAEFIK_USE_API"), "Whether to use the Traefik API to get routing rules. (Env: TRAEFIK_USE_API=true)")
	flag.StringVar(&traefikApiUsername, "traefik-username", os.Getenv("TRAEFIK_API_USERNAME"), "Username for Traefik API basic authentication. (Env: TRAEFIK_API_USERNAME)")
	flag.StringVar(&traefikApiPassword, "traefik-password", os.Getenv("TRAEFIK_API_PASSWORD"), "Password for Traefik API basic authentication. (Env: TRAEFIK_API_PASSWORD)")
	
	// 4. Flags for operation modes
	flag.BoolVar(&clearOnStart, "clear-on-start", getEnvBool("CLEAN_ON_START"), "If set, deletes ALL existing Unbound aliases on application startup. (Env: CLEAN_ON_START=true)")
	flag.BoolVar(&scanOnly, "scan-only", getEnvBool("SCAN_ONLY"), "If set, only scans existing containers and exits. (Env: SCAN_ONLY=true)")
	flag.BoolVar(&scanAllRoutes, "scan-all-routes", getEnvBool("SCAN_ALL_ROUTES"), "Scan all Traefik routes (including file-based configs). (Env: SCAN_ALL_ROUTES=true)")
	flag.DurationVar(&routeScanInterval, "route-scan-interval", getEnvDuration("ROUTE_SCAN_INTERVAL", 5*time.Minute), "How often to scan all Traefik routes. (Env: ROUTE_SCAN_INTERVAL, default: 5m)")

	// Set default protocol if not provided
	if opnsenseProtocol == "" {
		opnsenseProtocol = "https"
	}

	// Check for custom traefik label
	traefikLabel := os.Getenv("TRAEFIK_LABEL_NAME")
	if traefikLabel != "" {
		traefikInstances[traefikLabel] = ""
	}
	
	// Parse additional Traefik instances from environment if provided
	traefikInstancesEnv := os.Getenv("TRAEFIK_INSTANCES")
	if traefikInstancesEnv != "" {
		for _, instance := range strings.Split(traefikInstancesEnv, ",") {
			parts := strings.SplitN(instance, ":", 2)
			if len(parts) == 2 {
				label, domain := parts[0], parts[1]
				traefikInstances[strings.TrimSpace(label)] = strings.TrimSpace(domain)
			}
		}
	}
	
	// Override log output format
	log.Info().Msg("Initializing tuda-sync")
}

// cleanupExpiredCaches periodically removes expired entries from the container FQDN cache
func cleanupExpiredCaches() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		containerFQDNCache.mutex.Lock()
		
		removed := 0
		// Check each container's expiration time
		for container, expiry := range containerFQDNCache.expiration {
			if now.After(expiry) {
				// Remove expired entries
				delete(containerFQDNCache.cache, container)
				delete(containerFQDNCache.expiration, container)
				removed++
			}
		}
		
		// Also purge router cache periodically
		if !traefikRouterCache.lastFetched.IsZero() && time.Since(traefikRouterCache.lastFetched) > traefikCacheDuration {
			traefikRouterCache.routers = nil
			log.Printf("Cleared expired global router cache")
		}
		
		containerFQDNCache.mutex.Unlock()
		
		if removed > 0 {
			log.Printf("Cache cleanup: removed %d expired container entries", removed)
		}
	}
}

func main() {
	// Command parsing
	flag.Parse()
	
	// The first argument not consumed by flags is treated as a command
	command := flag.Arg(0)

	// Validate required credentials
	if opnsenseHost == "" || opnsenseKey == "" || opnsenseSecret == "" {
		log.Fatal("ERROR: OPNsense connection details are required. Set OPNSENSE_HOST, OPNSENSE_API_KEY, and OPNSENSE_API_SECRET environment variables or use corresponding flags.")
	}

	// Start cache cleanup goroutine
	go cleanupExpiredCaches()

	// Initialize OPNsense Client (Assumes opnsense_api.go exists)
	opnsenseClient := NewOpnsenseClient(opnsenseProtocol, opnsenseHost, opnsenseKey, opnsenseSecret, opnsenseInsecure)

	// Start a simple HTTP server for health checks and metrics
	go func() {
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})
		http.Handle("/metrics", promhttp.Handler())
		
		serverAddr := ":8080"
		log.Printf("Starting health and metrics server on %s", serverAddr)
		if err := http.ListenAndServe(serverAddr, nil); err != nil {
			log.Printf("Health/metrics server error: %v", err)
		}
	}()

	// --- Handle 'list' command ---
	if command == "list" {
		if err := opnsenseClient.ListHostOverrides(); err != nil {
			log.Fatalf("Failed to list host overrides: %v", err)
		}
		return
	}

	// --- Handle scan-only mode ---
	if command == "scan" || scanOnly {
		log.Println("Running in scan-only mode")
		ctx := context.Background()
		if err := scanExistingContainers(ctx, opnsenseClient); err != nil {
			log.Fatalf("Error scanning existing containers: %v", err)
		}
		return
	}
	
	// --- Handle scan-routes-only mode ---
	if command == "scan-routes" {
		log.Println("Running in scan-routes-only mode")
		ctx := context.Background()
		if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
			log.Fatalf("Error scanning Traefik routes: %v", err)
		}
		return
	}

	// --- Handle main monitor loop ---
	if command == "" {
		// Create a parent context that we can cancel on shutdown
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		
		// Set up signal handling for graceful shutdown
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		
		go func() {
			sig := <-sigCh
			log.Printf("Received signal %v, shutting down...", sig)
			cancel()
		}()
		
		// Start the Docker monitor
		go runDockerMonitor(opnsenseClient)
		
		// If enabled, also start the Traefik routes scanner
		if scanAllRoutes && traefikApiEnabled {
			log.Printf("Starting Traefik routes scanner with %v interval", routeScanInterval)
			go startTraefikRoutesScanner(ctx, opnsenseClient, routeScanInterval)
		}
		
		// Wait for signal
		<-ctx.Done()
		log.Println("Shutdown complete")
		return
	}

	// --- Handle unknown command ---
	fmt.Printf("Unknown command: %s\n", command)
	flag.Usage()
}

func runDockerMonitor(opnsenseClient *OpnsenseClient) {
	// Validate proxy UUID for the main loop
	if defaultProxyHostUUID == "" {
		log.Fatal("ERROR: DEFAULT_PROXY_HOST_UUID environment variable or --proxy-uuid flag is required to run the monitor.")
	}

	// Create a context for this monitor
	ctx := context.Background()
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// 1. Initial Cleanup
	if clearOnStart {
		log.Println("Clearing existing DNS aliases...")
		if err := opnsenseClient.ClearAllAliases(); err != nil {
			log.Fatalf("Fatal error during alias cleanup: %v", err)
		}
	}

	// 2. Setup Docker Client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}

	log.Println("Successfully connected to Docker and OPNsense. Monitoring for Traefik containers...")
	log.Printf("Base Domain: %s, Proxy UUID: %s", baseDomain, defaultProxyHostUUID)
	
	// Scan for existing containers and create DNS entries for them
	if err := scanExistingContainers(ctx, opnsenseClient); err != nil {
		log.Printf("WARNING: Error scanning existing containers: %v", err)
	}

	// 3. Start Docker Event Monitoring
	msgs, errs := cli.Events(ctx, events.ListOptions{})

	for {
		select {
		case <-ctx.Done():
			log.Println("Context canceled, shutting down...")
			return
		case err := <-errs:
			if err != nil {
				if ctx.Err() != nil {
					// Context was canceled, this is expected
					return
				}
				log.Fatalf("Docker event monitoring failed: %v", err)
			}
			// If error channel closes without error, exit gracefully
			return
		case msg := <-msgs:
			handleDockerEvent(opnsenseClient, msg)
		}
	}
}

func handleDockerEvent(opnsenseClient *OpnsenseClient, msg events.Message) {
	// Only care about container start/stop events
	if msg.Type != "container" {
		return
	}
	
	// Filter out exec and health check related events
	actionStr := string(msg.Action)
	if strings.HasPrefix(actionStr, "exec_") || strings.HasPrefix(actionStr, "health_") {
		return
	}

	// Extract container information
	labels := msg.Actor.Attributes
	containerName := strings.TrimPrefix(labels["name"], "/")
	
	// Log all event information for debugging purposes
	containerID := msg.ID
	log.Printf("Handling Docker event for container %s (ID: %s, Action: %s)", containerName, containerID, msg.Action)
	
	// If this container has a Docker Compose service name, log it and use it for lookup
	var composeService string
	var hasComposeService bool
	if composeServiceVal, exists := labels["com.docker.compose.service"]; exists {
		composeService = composeServiceVal
		hasComposeService = true
		if composeService != containerName {
			log.Printf("Container %s has Docker Compose service name: %s", containerName, composeService)
		}
	}
	
	// For 'start' events, check if this container has the tuda.ignore label
	if actionStr == "start" {
		// Check if container should be ignored based on its labels
		if val, exists := labels["tuda.ignore"]; exists &&
		   (val == "true" || val == "1" || val == "yes") {
			log.Printf("Container %s has tuda.ignore=true, skipping DNS alias creation", containerName)
			return
		}
	}
	
	// First check if this container has traefik enabled
	hasTraefikLabel := false
	for labelKey := range traefikInstances {
		if value, exists := labels[labelKey]; exists {
			// Accept various forms of "true" value
			if value == "true" || value == "1" || value == "yes" || value == "on" {
				hasTraefikLabel = true
				break
			}
		}
	}
	
	if !hasTraefikLabel {
		// Not a container managed by Traefik
		log.Printf("Skipping container %s - not managed by Traefik (no traefik.enable=true label)", containerName)
		return
	}
	
	// If this is a 'die' event, invalidate the container cache entry
	if actionStr == "die" {
		containerFQDNCache.mutex.Lock()
		delete(containerFQDNCache.cache, containerName)
		delete(containerFQDNCache.expiration, containerName)
		containerFQDNCache.mutex.Unlock()
	}
	
	// Try Traefik API first if enabled
	var fqdn string
	if traefikApiEnabled && traefikApiUrl != "" {
		var lookupNames []string
		
		// Prepare lookup names with different variations to try
		if hasComposeService && composeService != "" {
			// Add service name as primary lookup
			lookupNames = append(lookupNames, composeService)
			
			// Also try with -docker suffix if it doesn't already have it
			if !strings.HasSuffix(composeService, "-docker") {
				lookupNames = append(lookupNames, composeService+"-docker")
			}
			
			// And try without -docker suffix if it has it
			if strings.HasSuffix(composeService, "-docker") {
				baseName := strings.TrimSuffix(composeService, "-docker")
				lookupNames = append(lookupNames, baseName)
			}
			
			log.Printf("Using Docker Compose service name variations for lookup: %v", lookupNames)
		} else {
			lookupNames = []string{containerName}
		}
		
		// Try each lookup name until we find a match
		for _, lookupName := range lookupNames {
			fqdns, err := getTraefikRoutersForContainer(lookupName)
				if err == nil && len(fqdns) > 0 {
				// Use the first FQDN found
				fqdn = fqdns[0]
				log.Printf("Found route for '%s' using lookup name '%s'", fqdn, lookupName)
				break // Exit the loop once we find a match
			}
		}
		
		// If we didn't find anything with all our lookups, log it
		if fqdn == "" && hasComposeService {
			log.Printf("WARNING: Could not find Traefik routes for service '%s' or any of its variations", composeService)
			
			// As a last resort, try the container name if different from service name
			if containerName != composeService {
				log.Printf("Falling back to container name '%s' for Traefik API lookup", containerName)
				fqdns, err := getTraefikRoutersForContainer(containerName)
				if err == nil && len(fqdns) > 0 {
					fqdn = fqdns[0]
				}
			}
		}
	}
	
	// If API didn't return anything, look for explicit Host rule in labels
	if fqdn == "" {
		for k, v := range labels {
			if strings.Contains(k, ".rule") && strings.Contains(v, "Host(") {
				// Extract FQDN from the Traefik rule, assuming the format: Host(`subdomain.domain.com`)
				fqdn = extractFQDN(v)
				if fqdn != "" {
					log.Printf("Found Host rule in container labels for %s: %s", containerName, fqdn)
					break
				}
			}
		}
	}
	
	// No special cases for container names
	
	// If no explicit Host rule found, use the proper name
	if fqdn == "" {
		if baseDomain != "" {
			// Determine the best name to use based on container or service name
			fqdnName := containerName
			
			// Use Docker Compose service name if available
			if hasComposeService && composeService != "" {
				fqdnName = composeService
				log.Printf("Using Docker Compose service name '%s' for DNS alias", composeService)
			}
			
			fqdn = fqdnName + "." + baseDomain
			log.Printf("No Host rule found, using generated name: %s", fqdn)
		} else {
			// Only log this once for each container - subsequent events will be silently skipped
			// This reduces log spam while still providing the necessary information
			if actionStr == "start" {
				log.Printf("Container %s has no Host rule and no BASE_DOMAIN is set, skipping", containerName)
			}
			return
		}
	}

	// Resolve any templated domain part (e.g., test.{$BASE_DOMAIN})
	if baseDomain != "" {
		fqdn = strings.ReplaceAll(fqdn, "{$BASE_DOMAIN}", baseDomain)
	}

	switch actionStr {
	case "start":
		log.Printf("Container START: Adding DNS Alias for %s", fqdn)
		if err := opnsenseClient.CreateAlias(fqdn, defaultProxyHostUUID); err != nil {
			log.Printf("ERROR: Failed to create alias %s: %v", fqdn, err)
			return
		}
		aliasCreations.Inc()
		scheduleReconfigure(opnsenseClient)

	case "die":
		log.Printf("Container DIE: Deleting DNS Alias for %s", fqdn)
		if err := opnsenseClient.DeleteAlias(fqdn); err != nil {
			log.Printf("ERROR: Failed to delete alias %s: %v", fqdn, err)
			return
		}
		aliasDeletions.Inc()
		scheduleReconfigure(opnsenseClient)
	}
}

// extractFQDN parses the FQDN from a Traefik Host rule string (e.g., "Host(`test.example.com`)")
func extractFQDN(rule string) string {
	// Handle backtick format: Host(`example.com`)
	start := strings.Index(rule, "`")
	if start != -1 {
		end := strings.LastIndex(rule, "`")
		if end != -1 && end > start {
			return rule[start+1 : end]
		}
	}
	
	// Handle double-quote format: Host("example.com")
	start = strings.Index(rule, "\"")
	if start != -1 {
		end := strings.LastIndex(rule, "\"")
		if end != -1 && end > start {
			return rule[start+1 : end]
		}
	}
	
	// Handle single-quote format: Host('example.com')
	start = strings.Index(rule, "'")
	if start != -1 {
		end := strings.LastIndex(rule, "'")
		if end != -1 && end > start {
			return rule[start+1 : end]
		}
	}
	
	// If we couldn't match any of the standard formats, try a regex approach
	regex := regexp.MustCompile(`Host\([^)]*[\'"\` + "`" + `]([^\'"\` + "`" + `]+)[\'"\` + "`" + `][^)]*\)`)
	matches := regex.FindStringSubmatch(rule)
	if len(matches) > 1 {
		return matches[1]
	}
	
	return ""
}

// TraefikRouter represents the structure of a router in Traefik API
type TraefikRouter struct {
	Service  string            `json:"service"`
	Rule     string            `json:"rule"`
	Status   string            `json:"status"`
	Using    []string          `json:"using"`
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
}

// fetchTraefikRouters fetches all routers from Traefik API or returns cached results if available
func fetchTraefikRouters() ([]TraefikRouter, error) {
	if traefikApiUrl == "" {
		return nil, fmt.Errorf("Traefik API URL is not set")
	}
	
	// Check if we have a valid cached response
	traefikRouterCache.mutex.RLock()
	cacheValid := !traefikRouterCache.lastFetched.IsZero() &&
		time.Since(traefikRouterCache.lastFetched) < traefikCacheDuration &&
		len(traefikRouterCache.routers) > 0
	
	if cacheValid {
		routers := traefikRouterCache.routers
		traefikRouterCache.mutex.RUnlock()
		// Uncomment for debug logging
		// log.Printf("Using cached Traefik routers (age: %v)", time.Since(traefikRouterCache.lastFetched))
		return routers, nil
	}
	traefikRouterCache.mutex.RUnlock()
	
	// No valid cache, fetch from API
	traefikRouterCache.mutex.Lock()
	defer traefikRouterCache.mutex.Unlock()
	
	// Double-check that another goroutine hasn't updated the cache while we were waiting for the lock
	if !traefikRouterCache.lastFetched.IsZero() &&
	   time.Since(traefikRouterCache.lastFetched) < traefikCacheDuration &&
	   len(traefikRouterCache.routers) > 0 {
		return traefikRouterCache.routers, nil
	}
	
	// Create HTTP client and request
	client := &http.Client{}
	apiUrl := fmt.Sprintf("%s/http/routers", strings.TrimSuffix(traefikApiUrl, "/"))
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request for Traefik API: %w", err)
	}
	
	// Add basic auth if credentials are provided
	if traefikApiUsername != "" && traefikApiPassword != "" {
		req.SetBasicAuth(traefikApiUsername, traefikApiPassword)
	}
	
	// Call the HTTP API
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Traefik API: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get routers from Traefik API: HTTP %d", resp.StatusCode)
	}
	
	// Parse the JSON response as array
	var routers []TraefikRouter
	if err := json.NewDecoder(resp.Body).Decode(&routers); err != nil {
		return nil, fmt.Errorf("failed to decode Traefik API response: %w", err)
	}
	
	// Update cache
	traefikRouterCache.routers = routers
	traefikRouterCache.lastFetched = time.Now()
	
	log.Printf("Fetched %d routers from Traefik API", len(routers))
	return routers, nil
}

// Container FQDN cache to avoid repetitive lookups for the same container
var containerFQDNCache = struct {
	cache map[string][]string  // Map of container name -> FQDNs
	expiration map[string]time.Time // Expiration times
	mutex sync.RWMutex
	lastAccess map[string]time.Time // Last time each cache entry was accessed (for debugging)
	hits int // Number of cache hits (for debugging)
	misses int // Number of cache misses (for debugging)
}{
	cache: make(map[string][]string),
	expiration: make(map[string]time.Time),
	lastAccess: make(map[string]time.Time),
}

// getTraefikRoutersForContainer returns all routers that match a container name
func getTraefikRoutersForContainer(containerName string) ([]string, error) {
	if !traefikApiEnabled || traefikApiUrl == "" {
		return nil, fmt.Errorf("Traefik API is not enabled or URL not set")
	}
	
	// Normalize container name to ensure consistent cache lookup
	normalizedName := strings.TrimPrefix(containerName, "/")
	
	// Check container-specific cache first
	containerFQDNCache.mutex.RLock()
	expiry, hasExpiry := containerFQDNCache.expiration[normalizedName]
	if hasExpiry && time.Now().Before(expiry) && containerFQDNCache.cache[normalizedName] != nil {
		// Cache is still valid
		fqdns := containerFQDNCache.cache[normalizedName]
		containerFQDNCache.hits++
		containerFQDNCache.lastAccess[normalizedName] = time.Now()
		containerFQDNCache.mutex.RUnlock()
		
		if debugCache {
			log.Printf("CACHE HIT: Using cached FQDNs for container %s (hits: %d, misses: %d)", normalizedName, 
				containerFQDNCache.hits, containerFQDNCache.misses)
		}
		return fqdns, nil
	}
	containerFQDNCache.misses++
	containerFQDNCache.mutex.RUnlock()
	
	if debugCache {
		log.Printf("CACHE MISS: No valid cache for container %s (hits: %d, misses: %d)", normalizedName, 
			containerFQDNCache.hits, containerFQDNCache.misses)
	}
	
	// Get routers from cache or API
	routers, err := fetchTraefikRouters()
	if err != nil {
		return nil, err
	}
	
	// Look for routers associated with this container
	result := []string{}
	containerNameWithoutSlash := normalizedName
	
	// Look for routers that match this container's name in various ways
	// First, try direct matching on router name
	containerRouters := []TraefikRouter{}
	
	// We need to check multiple patterns since Traefik can generate router names in different ways
	possibleMatches := []string{
		containerNameWithoutSlash,                  // Direct container name
		"default-" + containerNameWithoutSlash,     // Default prefix
		containerNameWithoutSlash + "-",            // Container name as prefix
		"-" + containerNameWithoutSlash,            // Container name as suffix
		"@docker",                                  // Docker provider indicator
		containerNameWithoutSlash + "@docker",      // Common Docker provider pattern: servicename@docker
		containerNameWithoutSlash + "-docker@docker", // Common Docker provider pattern: servicename-docker@docker
		"opds-" + containerNameWithoutSlash,        // Common pattern with service prefix
		containerNameWithoutSlash + "-" + "service", // Common pattern with service suffix
	}
	
	// Add variations for the container name
	if strings.HasSuffix(containerNameWithoutSlash, "-docker") {
		// If name has -docker suffix, also try without it
		baseName := strings.TrimSuffix(containerNameWithoutSlash, "-docker")
		possibleMatches = append(possibleMatches, baseName)
		possibleMatches = append(possibleMatches, baseName + "@docker")
	} else {
		// If name doesn't have -docker suffix, try with it
		possibleMatches = append(possibleMatches, containerNameWithoutSlash + "-docker")
	}

	// Check for service labels that might indicate the service name in Traefik
	serviceNameRegex := regexp.MustCompile(`traefik\.http\.services\.([^.]+)\.`)
	
	// Look through service labels in the container to find service names
	// We need to get the container from Docker API
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err == nil {
		defer cli.Close()
		
		// Get container info
		containerInfo, err := cli.ContainerInspect(context.Background(), containerNameWithoutSlash)
		if err == nil {
			// First, check for Docker Compose service name which is often used as the router name in Traefik
			if composeService, exists := containerInfo.Config.Labels["com.docker.compose.service"]; exists && composeService != "" {
				possibleMatches = append(possibleMatches, composeService)
				possibleMatches = append(possibleMatches, composeService + "-docker@docker")
				possibleMatches = append(possibleMatches, composeService + "@docker")
				log.Printf("Found Docker Compose service name for %s: %s", normalizedName, composeService)
			}
			
			// Look for service name patterns in labels
			for labelName, labelValue := range containerInfo.Config.Labels {
				matches := serviceNameRegex.FindStringSubmatch(labelName)
				if len(matches) > 1 {
					serviceName := matches[1]
					possibleMatches = append(possibleMatches, serviceName)
					possibleMatches = append(possibleMatches, serviceName + "-docker@docker")
					possibleMatches = append(possibleMatches, serviceName + "@docker")
					log.Printf("Found potential service name in labels for %s: %s", normalizedName, serviceName)
				}
				
				// Also look for any router rules that might be defined in the labels
				if strings.Contains(labelName, ".rule") && strings.Contains(labelValue, "Host(") {
					fqdn := extractFQDN(labelValue)
					if fqdn != "" {
						// We found a direct host rule in the labels, add it to results immediately
						log.Printf("Found Host rule in container labels for %s: %s", normalizedName, fqdn)
						
						// Update container-specific cache
						containerFQDNCache.mutex.Lock()
						containerFQDNCache.cache[normalizedName] = []string{fqdn}
						containerFQDNCache.expiration[normalizedName] = time.Now().Add(traefikCacheDuration)
						containerFQDNCache.mutex.Unlock()
						
						return []string{fqdn}, nil
					}
				}
			}
		}
	}
	
	log.Printf("Looking for Traefik routes for container %s", normalizedName)
	
	for _, router := range routers {
		// Check if any of our patterns match the router name
		matched := false
		
		// Check for direct container name match in router name
		for _, pattern := range possibleMatches {
			if strings.Contains(router.Name, pattern) {
				matched = true
				log.Printf("DEBUG: Router %s matches pattern %s for container %s", router.Name, pattern, normalizedName)
				break
			}
		}
		
		// If we have a service name from the router, check that too
		// This helps with containers that use explicit service names
		if router.Service != "" { 
			// Check if service name matches any of our patterns
			for _, pattern := range possibleMatches {
				if strings.Contains(router.Service, pattern) {
					matched = true
					log.Printf("DEBUG: Router service %s matches pattern %s for container %s", router.Service, pattern, normalizedName)
					break
				}
			}
			
			// Check for prefix match in service name (handles cases where service has a suffix)
			serviceParts := strings.Split(router.Service, "-")
			if len(serviceParts) > 0 {
				serviceName := serviceParts[0]
				
				// Simple direct matching for first part of service name
				if serviceName == containerNameWithoutSlash || 
				   containerNameWithoutSlash == serviceName {
					matched = true
					log.Printf("DEBUG: Service prefix %s matches container %s", 
						serviceName, containerNameWithoutSlash)
				}
			}
		}
		
		if matched && strings.Contains(router.Rule, "Host(") {
			containerRouters = append(containerRouters, router)
			fqdn := extractFQDN(router.Rule)
			if fqdn != "" {
				result = append(result, fqdn)
				log.Printf("Found route in Traefik API for container %s: %s", normalizedName, fqdn)
			}
		}
	}
	
	// If no routers found, try more advanced matching techniques
	if len(containerRouters) == 0 {
		log.Printf("No direct routes found for container %s in Traefik API", normalizedName)
		
		// Try to find Docker service names by inspecting the container
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err == nil {
			defer cli.Close()
			
			containerInfo, err := cli.ContainerInspect(context.Background(), normalizedName)
			if err == nil {
				// Try to extract service name from Docker Compose labels
				composeService, hasComposeService := containerInfo.Config.Labels["com.docker.compose.service"]
				if hasComposeService && composeService != "" {
					log.Printf("Found Docker Compose service name for %s: %s", normalizedName, composeService)
					
					// Common Traefik router naming patterns based on service names
					servicePatterns := []string{
						composeService,                     // Direct service name match
						composeService + "-docker@docker",  // Service-docker@docker pattern
						composeService + "@docker",         // Service@docker pattern
					}
					
					// Look for routers with these service name patterns
					for _, router := range routers {
						for _, pattern := range servicePatterns {
							if strings.Contains(router.Name, pattern) || 
							   strings.Contains(router.Service, composeService) {
								if strings.Contains(router.Rule, "Host(") {
									fqdn := extractFQDN(router.Rule)
									if fqdn != "" {
										result = append(result, fqdn)
										log.Printf("Found route via Docker Compose service for %s: %s (from %s)", 
											normalizedName, fqdn, composeService)
										break
									}
								}
							}
						}
					}
				}
			}
		}
		
		// As a last resort, search for all routers with a matching rule that contains the container name
		if len(result) == 0 {
			log.Printf("Trying last resort approach - looking for Host rules containing %s", normalizedName)
			for _, router := range routers {
				if strings.Contains(router.Rule, "Host(") {
					fqdn := extractFQDN(router.Rule)
					if fqdn != "" && strings.HasPrefix(fqdn, normalizedName + ".") {
						result = append(result, fqdn)
						log.Printf("Found matching Host rule for %s: %s", normalizedName, fqdn)
					}
				}
			}
		}
	}
	
	// If we still have no result but have a base domain, generate one
	if len(result) == 0 && baseDomain != "" {
		// Create a fallback FQDN using the container name
		fallbackFQDN := normalizedName + "." + baseDomain
		result = append(result, fallbackFQDN)
		log.Printf("No routes found in Traefik API for %s, using fallback FQDN: %s", normalizedName, fallbackFQDN)
	}
	
	// Update container-specific cache
	containerFQDNCache.mutex.Lock()
	containerFQDNCache.cache[normalizedName] = result
	containerFQDNCache.expiration[normalizedName] = time.Now().Add(traefikCacheDuration)
	containerFQDNCache.mutex.Unlock()
	
	if len(result) > 0 {
		log.Printf("Cached %d FQDNs for container %s: %v", len(result), normalizedName, result)
	} else {
		// Always log this since it helps with debugging
		log.Printf("Container %s has no explicit Host rule and no base domain is set, skipping", normalizedName)
	}
	
	return result, nil
}

// scheduleReconfigure batches reconfiguration requests to prevent excessive API calls
func scheduleReconfigure(opnsenseClient *OpnsenseClient) {
	reconfigureMutex.Lock()
	defer reconfigureMutex.Unlock()
	
	if reconfigureTimer != nil {
		reconfigureTimer.Stop()
	}
	
	reconfigurePending = true
	reconfigureTimer = time.AfterFunc(5*time.Second, func() {
		reconfigureMutex.Lock()
		defer reconfigureMutex.Unlock()
		
		if reconfigurePending {
			log.Println("Batch reconfiguring Unbound...")
			if err := opnsenseClient.Reconfigure(); err != nil {
				log.Printf("ERROR: Failed to reconfigure Unbound: %v", err)
				reconfigureFailures.Inc()
			}
			reconfigurePending = false
		}
	})
}

// scanExistingContainers looks for running containers with Traefik labels and adds DNS aliases for them
func scanExistingContainers(ctx context.Context, opnsenseClient *OpnsenseClient) error {
	log.Println("Scanning for existing Traefik-enabled containers...")
	
	// Setup Docker Client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("Failed to create Docker client: %v", err)
	}
	defer cli.Close()
	
	// List all running containers
	containers, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: filters.NewArgs(filters.Arg("status", "running")),
	})
	if err != nil {
		return fmt.Errorf("Failed to list containers: %v", err)
	}
	
	aliasCount := 0
	
	// Process each container
	processedContainers := make(map[string]bool)
	for _, c := range containers {
		log.Printf("Checking container: %s (Image: %s)", c.Names[0], c.Image)
		
		// Normalize container name to prevent duplicates
		containerName := strings.TrimPrefix(c.Names[0], "/")
		
		// Skip if we've already processed this container
		if processedContainers[containerName] {
			continue
		}
		
		// Check if container has the tuda.ignore label
		if val, exists := c.Labels["tuda.ignore"]; exists &&
		   (val == "true" || val == "1" || val == "yes") {
			log.Printf("Container %s has tuda.ignore=true, skipping DNS alias creation", containerName)
			continue
		}
		
		// Mark container as processed immediately to avoid repeated processing
		processedContainers[containerName] = true
		
		// For each defined Traefik instance label
		for labelKey, baseDomainOverride := range traefikInstances {
			// Check if the container has this Traefik label
			if _, exists := c.Labels[labelKey]; exists {
				log.Printf("Container %s has Traefik label: %s", c.Names[0], labelKey)
				
				// Try to get router rules from Traefik API first if enabled
				if traefikApiEnabled && traefikApiUrl != "" {
				var lookupNames []string
				
				// Check for Docker Compose service name
				if composeService, exists := c.Labels["com.docker.compose.service"]; exists && composeService != "" {
					// Add service name as primary lookup
					lookupNames = append(lookupNames, composeService)
					
					// Also try with -docker suffix if it doesn't already have it
					if !strings.HasSuffix(composeService, "-docker") {
						lookupNames = append(lookupNames, composeService+"-docker")
					}
					
					// And try without -docker suffix if it has it
					if strings.HasSuffix(composeService, "-docker") {
						baseName := strings.TrimSuffix(composeService, "-docker")
						lookupNames = append(lookupNames, baseName)
					}
					
					log.Printf("Using Docker Compose service name variations for lookup: %v", lookupNames)
				} else {
					lookupNames = []string{containerName}
				}
				
				// Try each lookup name until we find a match
				var fqdns []string
				var err error
				for _, lookupName := range lookupNames {
					log.Printf("Using Traefik API to look up routes for %s", lookupName)
					result, err := getTraefikRoutersForContainer(lookupName)
					if err == nil && len(result) > 0 {
						fqdns = result
						log.Printf("Found routes for '%s'", lookupName)
						break
					}
				}
				
				// Continue with the found FQDNs or empty list
				if err != nil {
					log.Printf("WARNING: Failed to get routes from Traefik API: %v", err)
					// Fall back to label parsing if API fails
				} else if len(fqdns) > 0 {
						// Process FQDNs from Traefik API
						for _, fqdn := range fqdns {
							log.Printf("Found route in Traefik API for container %s: %s", containerName, fqdn)
							
							// Check if this alias already exists in cache
							if uuid, exists := opnsenseClient.getCachedAlias(fqdn); exists {
								log.Printf("Alias for %s already exists with UUID %s", fqdn, uuid)
								continue
							}
							
							// Create DNS alias
							if err := opnsenseClient.CreateAlias(fqdn, defaultProxyHostUUID); err != nil {
								log.Printf("ERROR: Failed to create alias for existing container %s: %v", fqdn, err)
							} else {
								aliasCount++
								aliasCreations.Inc()
							}
						}
						
						// Skip label parsing since we got rules from API
						continue
				} else {
					log.Printf("No routes found for container %s in Traefik API", containerName)
					// Fall back to label parsing
				}
				}
				
				// Check if we should use the container name as FQDN
				hasExplicitHostRule := false
				for k, v := range c.Labels {
					if strings.Contains(k, "traefik.http.routers.") && strings.Contains(k, ".rule") && strings.Contains(v, "Host(") {
						hasExplicitHostRule = true
						break
					}
				}
				
				// If no explicit Host rule found, use the proper name as FQDN
				if !hasExplicitHostRule {
					// Determine the best name to use
					fqdnName := containerName
					
					// Check for Docker Compose service name as an alternative
					if composeService, exists := c.Labels["com.docker.compose.service"]; exists && composeService != "" {
						// Use the service name directly
						fqdnName = composeService
						log.Printf("Using Docker Compose service name '%s' for DNS alias", composeService)
					}
					
					fqdn := fqdnName
					if effectiveBaseDomain := baseDomain; effectiveBaseDomain != "" {
						if baseDomainOverride != "" {
							effectiveBaseDomain = baseDomainOverride
						}
						// Use name with base domain
						fqdn = fqdnName + "." + effectiveBaseDomain
						
						log.Printf("Container %s has no explicit Host rule, using name with domain: %s", containerName, fqdn)
						
						// Check if this alias already exists in cache
						if uuid, exists := opnsenseClient.getCachedAlias(fqdn); exists {
							log.Printf("Alias for %s already exists with UUID %s", fqdn, uuid)
						} else if baseDomain != "" { // Only create alias if base domain is set
							// Create DNS alias if it doesn't exist
							if err := opnsenseClient.CreateAlias(fqdn, defaultProxyHostUUID); err != nil {
								log.Printf("ERROR: Failed to create alias for existing container %s: %v", fqdn, err)
							} else {
								aliasCount++
								aliasCreations.Inc()
							}
						} else {
							log.Printf("Container %s has no base domain set, skipping automatic alias creation", containerName)
						}
					} else {
						log.Printf("Container %s has no explicit Host rule and no base domain is set, skipping", containerName)
					}
				}
				
				// Now look for explicit Host rules
				for k, v := range c.Labels {
					if strings.Contains(k, "traefik.http.routers.") && strings.Contains(k, ".rule") && strings.Contains(v, "Host(") {
						// Extract FQDN from the Traefik rule
						fqdn := extractFQDN(v)
						if fqdn == "" {
							log.Printf("Warning: Could not parse FQDN from rule: %s", v)
							continue
						}
						
						// Apply base domain if needed
						effectiveBaseDomain := baseDomain
						if baseDomainOverride != "" {
							effectiveBaseDomain = baseDomainOverride
						}
						
						if effectiveBaseDomain != "" {
							fqdn = strings.ReplaceAll(fqdn, "{$BASE_DOMAIN}", effectiveBaseDomain)
						}
						
						log.Printf("Found existing container with host rule: %s", fqdn)
						
						// Check if this alias already exists in cache
						if uuid, exists := opnsenseClient.getCachedAlias(fqdn); exists {
							log.Printf("Alias for %s already exists with UUID %s", fqdn, uuid)
							continue
						}
						
						// Create DNS alias if it doesn't exist
						if err := opnsenseClient.CreateAlias(fqdn, defaultProxyHostUUID); err != nil {
							log.Printf("ERROR: Failed to create alias for existing container %s: %v", fqdn, err)
						} else {
							aliasCount++
							aliasCreations.Inc()
						}
					}
				}
			}
		}
	}
	
	// Trigger reconfiguration if we found any containers
	if aliasCount > 0 {
		log.Printf("Added %d aliases for existing containers", aliasCount)
		scheduleReconfigure(opnsenseClient)
	} else if len(processedContainers) > 0 {
		log.Printf("Scanned %d Traefik-enabled containers, no new aliases needed", len(processedContainers))
	} else {
		log.Println("No existing Traefik-enabled containers found")
	}
	
	return nil
}
