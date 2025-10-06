package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

// Constants for application operation
const (
	// No longer need traefik label constants as we're using API-first approach
)

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
	
	// Delayed router check configuration
	delayedRouterChecks DelayedCheckOptions
	enableDelayedChecks bool // Whether to perform delayed checks for routers after container start
	
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
	
	// We no longer use traefik label detection as we're using a pure API approach
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
		logger.Warn().Str("key", key).Dur("default", defaultDuration).Msg("Invalid duration format, using default")
	}
	return defaultDuration
}

// logger is the global logger instance
var logger zerolog.Logger

func init() {
	// Configure structured logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	
	// Set log level from environment variable (if provided)
	// Possible values: trace, debug, info, warn, error, fatal, panic
	// Default: info
	logLevel := os.Getenv("LOG_LEVEL")
	var level zerolog.Level = zerolog.InfoLevel // Default to InfoLevel
	
	if logLevel != "" {
		switch strings.ToLower(logLevel) {
		case "trace":
			level = zerolog.TraceLevel
		case "debug":
			level = zerolog.DebugLevel
		case "info":
			level = zerolog.InfoLevel
		case "warn", "warning":
			level = zerolog.WarnLevel
		case "error":
			level = zerolog.ErrorLevel
		case "fatal":
			level = zerolog.FatalLevel
		case "panic":
			level = zerolog.PanicLevel
		default:
			// If invalid value, warn but use default
			fmt.Printf("Invalid LOG_LEVEL value: %s, using 'info'\n", logLevel)
		}
	}
	
	// Set the global log level
	zerolog.SetGlobalLevel(level)
	
	// Create logger with console output
	logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
	
	// Override standard logger to use zerolog
	log.SetFlags(0)
	log.SetOutput(logger)
	
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
			logger.Info().Dur("duration", traefikCacheDuration).Msg("Set Traefik cache duration from environment")
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
	
	// 5. Delayed router check configuration
	flag.BoolVar(&enableDelayedChecks, "delayed-checks", getEnvBool("DELAYED_ROUTER_CHECKS"), "Whether to perform delayed checks for new routers after container start. (Env: DELAYED_ROUTER_CHECKS=true)")
	
	// Initialize delayed check options with defaults
	delayedRouterChecks = DefaultDelayedCheckOptions()
	
	// Allow overriding via environment variables
	if val := os.Getenv("DELAYED_CHECK_INITIAL_DELAY"); val != "" {
		if parsed, err := time.ParseDuration(val); err == nil {
			delayedRouterChecks.InitialDelay = parsed
		}
	}
	if val := os.Getenv("DELAYED_CHECK_MAX_DELAY"); val != "" {
		if parsed, err := time.ParseDuration(val); err == nil {
			delayedRouterChecks.MaxDelay = parsed
		}
	}
	if val := os.Getenv("DELAYED_CHECK_MAX_DURATION"); val != "" {
		if parsed, err := time.ParseDuration(val); err == nil {
			delayedRouterChecks.MaxTotalDuration = parsed
		}
	}
	if val := os.Getenv("DELAYED_CHECK_COUNT"); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			delayedRouterChecks.MaxChecks = parsed
		}
	}
	if val := os.Getenv("DELAYED_CHECK_USE_EXPONENTIAL"); val != "" {
		delayedRouterChecks.UseExponentialBackoff = strings.ToLower(val) == "true"
	}
	if val := os.Getenv("DELAYED_CHECK_JITTER"); val != "" {
		if parsed, err := strconv.ParseFloat(val, 64); err == nil {
			delayedRouterChecks.JitterFactor = parsed
		}
	}

	// Set default protocol if not provided
	if opnsenseProtocol == "" {
		opnsenseProtocol = "https"
	}

	// We no longer need to parse Traefik instance labels since we use the API directly
	
	// Log initialization
	logger.Info().Msg("Initializing tuda-sync")
}

// cleanupExpiredCaches periodically removes expired entries from caches
func cleanupExpiredCaches() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		// Purge router cache periodically
		traefikRouterCache.mutex.Lock()
		if !traefikRouterCache.lastFetched.IsZero() && time.Since(traefikRouterCache.lastFetched) > traefikCacheDuration {
			traefikRouterCache.routers = nil
			logger.Debug().Msg("Cleared expired Traefik router cache")
		}
		traefikRouterCache.mutex.Unlock()
	}
}

func main() {
	// Command parsing
	flag.Parse()
	
	// The first argument not consumed by flags is treated as a command
	command := flag.Arg(0)

	// Validate required credentials
	if opnsenseHost == "" || opnsenseKey == "" || opnsenseSecret == "" {
		logger.Fatal().Msg("OPNsense connection details are required. Set OPNSENSE_HOST, OPNSENSE_API_KEY, and OPNSENSE_API_SECRET environment variables or use corresponding flags")
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
		logger.Info().Str("address", serverAddr).Msg("Starting health and metrics server")
		if err := http.ListenAndServe(serverAddr, nil); err != nil {
			logger.Error().Err(err).Msg("Health/metrics server error")
		}
	}()

	// --- Handle 'list' command ---
	if command == "list" {
		if err := opnsenseClient.ListHostOverrides(); err != nil {
			logger.Fatal().Err(err).Msg("Failed to list host overrides")
		}
		return
	}

	// --- Handle scan-only mode ---
	if command == "scan" || scanOnly {
		logger.Info().Msg("Running in scan-only mode")
		ctx := context.Background()
		if err := initialTraefikScan(ctx, opnsenseClient); err != nil {
			logger.Fatal().Err(err).Msg("Error scanning Traefik routes")
		}
		return
	}
	
	// --- Handle scan-routes-only mode ---
	if command == "scan-routes" {
		logger.Info().Msg("Running in scan-routes-only mode")
		ctx := context.Background()
		if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
			logger.Fatal().Err(err).Msg("Error scanning Traefik routes")
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
			logger.Info().Str("signal", sig.String()).Msg("Received signal, shutting down...")
			cancel()
		}()
		
		// Start the Docker monitor
		go runDockerMonitor(opnsenseClient)
		
		// If enabled, also start the Traefik routes scanner
		if scanAllRoutes && traefikApiEnabled {
			logger.Info().Dur("interval", routeScanInterval).Msg("Starting Traefik routes scanner")
			go startTraefikRoutesScanner(ctx, opnsenseClient, routeScanInterval)
		}
		
		// Wait for signal
		<-ctx.Done()
		logger.Info().Msg("Shutdown complete")
		return
	}

	// --- Handle unknown command ---
	fmt.Printf("Unknown command: %s\n", command)
	flag.Usage()
}

func runDockerMonitor(opnsenseClient *OpnsenseClient) {
	// Validate proxy UUID for the main loop
	if defaultProxyHostUUID == "" {
		logger.Fatal().Msg("DEFAULT_PROXY_HOST_UUID environment variable or --proxy-uuid flag is required to run the monitor")
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
		logger.Info().Str("signal", sig.String()).Msg("Received signal, shutting down...")
		cancel()
	}()

	// 1. Initial Cleanup
	if clearOnStart {
		logger.Info().Msg("Clearing existing DNS aliases...")
		if err := opnsenseClient.ClearAllAliases(); err != nil {
			logger.Fatal().Err(err).Msg("Fatal error during alias cleanup")
		}
	}

	// 2. Setup Docker Client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create Docker client")
	}

	logger.Info().Msg("Successfully connected to Docker and OPNsense. Monitoring for Traefik containers...")
	logger.Info().Str("domain", baseDomain).Str("proxyUUID", defaultProxyHostUUID).Msg("Configuration")
	
	// Scan Traefik routes and create DNS entries for them
	if err := initialTraefikScan(ctx, opnsenseClient); err != nil {
		logger.Warn().Err(err).Msg("Error performing initial Traefik scan")
	}

	// 3. Start Docker Event Monitoring
	msgs, errs := cli.Events(ctx, events.ListOptions{})

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("Context canceled, shutting down...")
			return
		case err := <-errs:
			if err != nil {
				if ctx.Err() != nil {
					// Context was canceled, this is expected
					return
				}
				logger.Fatal().Err(err).Msg("Docker event monitoring failed")
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

	// We only care about container start/stop events
	if actionStr != "start" && actionStr != "die" {
		return
	}

	// Basic logging
	containerName := strings.TrimPrefix(msg.Actor.Attributes["name"], "/")
	logger.Debug().Str("action", actionStr).Str("container", containerName).Msg("Received Docker event")
	
	// If this is a 'die' event, invalidate the router cache
	if actionStr == "die" {
		// Clear the router cache to force a fresh fetch
		traefikRouterCache.mutex.Lock()
		traefikRouterCache.routers = nil
		traefikRouterCache.lastFetched = time.Time{}
		traefikRouterCache.mutex.Unlock()
		
		logger.Debug().Msg("Container stop event detected, cleared Traefik router cache")
	}

	// For any container event, scan all Traefik routes immediately
	// We don't need to check if the container is Traefik-enabled
	// since we're using a pure API approach
	logger.Info().Msg("Docker event detected: Scanning all Traefik routes")
	
	if traefikApiEnabled && traefikApiUrl != "" {
		ctx := context.Background()
		
		// Scan all Traefik routes and update DNS aliases
		if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
			logger.Error().Err(err).Msg("Failed to scan Traefik routes")
		} else {
			logger.Debug().Msg("Successfully updated DNS aliases based on Traefik routes")
		}
		
		// For container start events, set up delayed monitoring to catch routers
		// that appear after container initialization
		if actionStr == "start" {
			logger.Debug().Str("container", containerName).Msg("Setting up delayed router checks for started container")
			monitorContainerStartRouters(containerName, opnsenseClient)
		}
	} else {
		logger.Warn().Msg("Traefik API not enabled or configured. Set TRAEFIK_USE_API=true and TRAEFIK_API_URL to enable scanning")
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
		// Debug logging for cache hits
		if debugCache {
			logger.Debug().Dur("age", time.Since(traefikRouterCache.lastFetched)).Msg("Using cached Traefik routers")
		}
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
	
	// Create HTTP client
	client := &http.Client{}
	baseApiUrl := strings.TrimSuffix(traefikApiUrl, "/")
	
	// Log the base URL for debugging
	logger.Debug().Str("baseUrl", baseApiUrl).Msg("Using Traefik API base URL")
	
	// Create a slice to hold all routers across pages
	var allRouters []TraefikRouter
	currentPage := 1
	perPage := 100  // Fetch 100 items per page for efficiency
	
	for {
		// Build the URL with pagination parameters - using the correct path format
		// Avoid duplicating /api/ in the URL by checking if baseApiUrl already contains it
		apiUrl := ""
		if strings.HasSuffix(baseApiUrl, "/api") {
			apiUrl = fmt.Sprintf("%s/http/routers?page=%d&per_page=%d", baseApiUrl, currentPage, perPage)
		} else {
			apiUrl = fmt.Sprintf("%s/api/http/routers?page=%d&per_page=%d", baseApiUrl, currentPage, perPage)
		}
		logger.Debug().Int("page", currentPage).Msg("Fetching Traefik routers page")
		logger.Debug().Str("url", apiUrl).Msg("Making GET request")
		
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
		
		if resp.StatusCode != http.StatusOK {
			// Try to read error body for better diagnostics
			errorBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("failed to get routers from Traefik API: HTTP %d - %s", 
				resp.StatusCode, string(errorBody))
		}
		
		// Parse the JSON response as array
		var pageRouters []TraefikRouter
		if err := json.NewDecoder(resp.Body).Decode(&pageRouters); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode Traefik API response: %w", err)
		}
		
		// Add this page's routers to our collection
		allRouters = append(allRouters, pageRouters...)
		
		// Check if there are more pages
		nextPage := resp.Header.Get("X-Next-Page")
		resp.Body.Close()
		
		// If no more pages, this page was empty, or next page is the same as current page, we're done
		if nextPage == "" || len(pageRouters) == 0 || nextPage == fmt.Sprintf("%d", currentPage) {
			break
		}
		
		// Move to the next page - try to parse the next page number directly
		nextPageNum, err := strconv.Atoi(nextPage)
		if err == nil && nextPageNum > currentPage {
			currentPage = nextPageNum
		} else {
			currentPage++
		}
	}
	
	// Update cache
	traefikRouterCache.routers = allRouters
	traefikRouterCache.lastFetched = time.Now()
	
	logger.Debug().Int("count", len(allRouters)).Msg("Fetched routers from Traefik API")
	return allRouters, nil
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
			logger.Debug().Msg("Batch reconfiguring Unbound...")
			if err := opnsenseClient.Reconfigure(); err != nil {
				logger.Error().Err(err).Msg("Failed to reconfigure Unbound")
				reconfigureFailures.Inc()
			}
			reconfigurePending = false
		}
	})
}

// initialTraefikScan initiates an initial scan of all Traefik routes
func initialTraefikScan(ctx context.Context, opnsenseClient *OpnsenseClient) error {
	logger.Debug().Msg("Performing initial scan of Traefik routes...")
	
	// Check if Traefik API is properly configured
	if !traefikApiEnabled || traefikApiUrl == "" {
		return fmt.Errorf("Traefik API is not enabled or URL not set. Set TRAEFIK_USE_API=true and TRAEFIK_API_URL to enable API scanning")
	}
	
	// Scan all Traefik routes
	if err := scanAllTraefikRoutes(ctx, opnsenseClient); err != nil {
		return fmt.Errorf("Failed to scan Traefik routes: %v", err)
	}
	
	logger.Debug().Msg("Initial Traefik route scan completed successfully")
	return nil
}
