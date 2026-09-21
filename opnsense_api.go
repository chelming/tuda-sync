package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type OpnsenseClient struct {
	client *http.Client
	url    string
	key    string
	secret string
	aliasCache map[string]string // Maps FQDN to UUID
	cacheMutex sync.RWMutex
}

type Alias struct {
	UUID string `json:"uuid"`
	Host string `json:"host"`
	Domain string `json:"domain"`
	HostOverride string `json:"host_override"`
}

func NewOpnsenseClient(protocol, host, key, secret string, insecure bool) *OpnsenseClient {
	// Create a secure transport with proper settings
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
			MinVersion: tls.VersionTLS12, // Enforce minimum TLS version
		},
		ForceAttemptHTTP2: true,
		MaxIdleConns: 10,
		IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	
	client := &OpnsenseClient{
		client: &http.Client{
			Timeout: 10 * time.Second, 
			Transport: tr,
			// Implement safe redirect handling
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Limit redirect depth to prevent redirect loops
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		// Base URL should include the controller path: https://<host>/api/unbound/settings
		url:    fmt.Sprintf("%s://%s/api/unbound/settings", protocol, host),
		key:    key,
		secret: secret,
		aliasCache: make(map[string]string),
	}
	
	logger.Debug().Str("baseUrl", client.url).Msg("OPNsense API base URL")
	
	// Pre-populate cache from existing records
	err := client.loadHostAliasesIntoCache()
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to load existing host aliases into cache")
		logger.Warn().Msg("Continuing with empty cache. This may cause duplicate alias issues")
	}
	
	return client
}

// makeRequest handles authenticated API calls to OPNsense
func (o *OpnsenseClient) makeRequest(method, endpoint string, payload interface{}) (map[string]interface{}, error) {
	// Create context with timeout for the request
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling payload: %w", err)
	}
    
	// Ensure endpoint doesn't start with a slash
	if strings.HasPrefix(endpoint, "/") {
		endpoint = endpoint[1:]
	}
	
	// Build the full URL
	fullURL := o.url
	if !strings.HasSuffix(fullURL, "/") {
		fullURL += "/"
	}
	fullURL += endpoint
	
	// Ensure we have proper trailing slash only for POST requests
	if method == http.MethodPost && !strings.HasSuffix(fullURL, "/") {
		fullURL += "/"
	}

	logger.Debug().Str("method", method).Str("url", fullURL).Msg("Making request")
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(o.key, o.secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "tls: failed to verify certificate") {
			return nil, fmt.Errorf("API request to %s failed: %w. To bypass certificate verification, set OPNSENSE_INSECURE=true or use --opnsense-insecure flag", fullURL, err)
		}
		return nil, fmt.Errorf("API request to %s failed: %w", fullURL, err)
	}
	defer resp.Body.Close()

	// Read the response body first for debugging
	respBody, _ := io.ReadAll(resp.Body) 
	
	// --- LOGGING/ERROR CHECK: Check HTTP status code first ---
	if resp.StatusCode != http.StatusOK {
		// Print the beginning of the response to help with debugging
		previewLen := min(len(respBody), 150)
		previewText := string(respBody[:previewLen])
		logger.Error().Str("status", resp.Status).Str("response", previewText).Msg("API call failed")
		return nil, fmt.Errorf("API request failed with HTTP status: %s", resp.Status)
	}

	// --- LOGGING: Parse JSON from the already read response body ---
	var result map[string]interface{}

	// Re-create a reader from the already read body
	if err := json.NewDecoder(bytes.NewReader(respBody)).Decode(&result); err != nil {
        // Print the beginning of the response to help with debugging
        previewLen := min(len(respBody), 150)
        logger.Debug().Str("response", string(respBody)[:previewLen]).Msg("Failed to decode JSON")
        
        return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// This check catches JSON responses that contain an explicit API failure message.
	// Accept "OK", "saved", and "deleted" as valid results
	if result["result"] != nil && 
	   result["result"] != "OK" && 
	   result["result"] != "saved" && 
	   result["result"] != "deleted" {
		return nil, fmt.Errorf("OPNsense API reported failure: %v", result)
	}

	return result, nil
}

// loadHostAliasesIntoCache fetches all host aliases from OPNsense and adds them to the cache
func (o *OpnsenseClient) loadHostAliasesIntoCache() error {
	logger.Debug().Msg("Loading existing host aliases into cache...")

	// Use the specific search payload structure required by OPNsense
	payload := map[string]interface{}{
        "current": 1,
        "rowCount": 500, // Fetch up to 500 records
        "sort": map[string]interface{}{},
    }
	
	result, err := o.makeRequest(http.MethodPost, "search_host_alias", payload)
	if err != nil {
		return fmt.Errorf("failed to search host aliases: %w", err)
	}
	
	// The search endpoints return the list under the "rows" key.
	hostsData, ok := result["rows"].([]interface{})
	if !ok {
		return fmt.Errorf("failed to parse host aliases list: expected 'rows' key")
	}
	
	// Clear existing cache and repopulate
	o.cacheMutex.Lock()
	defer o.cacheMutex.Unlock()
	
	o.aliasCache = make(map[string]string)
	count := 0
	
	for _, item := range hostsData {
		hostMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		
		// Extract the necessary fields
		uuid, ok1 := hostMap["uuid"].(string)
		hostname, ok2 := hostMap["hostname"].(string)
		domain, ok3 := hostMap["domain"].(string)
		
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		
		// Create FQDN and add to cache
		fqdn := hostname + "." + domain
		o.aliasCache[fqdn] = uuid
		count++
	}
	
	logger.Debug().Int("count", count).Msg("Loaded host aliases into cache")
	return nil
}

// ListHostOverrides fetches and prints all configured Host Overrides (Host, Domain, IP, UUID).
func (o *OpnsenseClient) ListHostOverrides() error {
	logger.Info().Msg("Fetching Unbound Host Overrides from OPNsense...")

	// Use the specific search payload structure required by OPNsense
	payload := map[string]interface{}{
        "current": 1,
        "rowCount": 100, // Fetch up to 100 records
        "sort": map[string]interface{}{},
    }

	result, err := o.makeRequest(http.MethodPost, "search_host_override", payload)
	if err != nil {
		return err
	}

	// The search endpoints return the list under the "rows" key.
	hostsData, ok := result["rows"].([]interface{})
	if !ok {
		return fmt.Errorf("failed to parse host overrides list: expected 'rows' key")
	}

	logger.Info().Msg("\n--- OPNsense Unbound Host Overrides ---")
	// Header: UUID | ENABLED | HOST.DOMAIN | IP ADDRESS
    fmt.Printf("%-40s | %-8s | %-30s | %s\n", "UUID", "ENABLED", "HOST.DOMAIN", "IP ADDRESS")
	// Separator line must match the width of the header (101 characters wide)
    fmt.Println(strings.Repeat("-", 101))

	for _, item := range hostsData {
		hostMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Use safe comma-ok idiom and correct JSON keys (hostname, server)
		uuid, ok := hostMap["uuid"].(string)
		if !ok {
			logger.Warn().Msg("Skipping Host Override record due to missing or invalid 'uuid'")
			continue
		}

		host, ok := hostMap["hostname"].(string)
		if !ok { continue }

		domain, ok := hostMap["domain"].(string)
		if !ok { continue }

		ip, ok := hostMap["server"].(string)
		if !ok { continue }

		// Determine status using symbols
		enabled, _ := hostMap["enabled"].(string)
		rawStatus := "✓"
		if enabled != "1" {
			rawStatus = "x"
		}

        // Center the status symbol (1 character) within the 8-character column.
        centeredStatus := fmt.Sprintf("   %s    ", rawStatus)


		// Print the row
		fmt.Printf("%-40s | %s | %-30s | %s\n", uuid, centeredStatus, fmt.Sprintf("%s.%s", host, domain), ip)
	}

	// Print the final separator without a timestamp.
	fmt.Println(strings.Repeat("-", 101))
	return nil
}

// ListAll shows host overrides with their child aliases in a tree format.
func (o *OpnsenseClient) ListAll() error {
	logger.Info().Msg("Fetching Unbound Host Overrides and Aliases from OPNsense...")

	// Fetch host overrides
	overridePayload := map[string]interface{}{
		"current":  1,
		"rowCount": 100,
		"sort":     map[string]interface{}{},
	}
	overrideResult, err := o.makeRequest(http.MethodPost, "search_host_override", overridePayload)
	if err != nil {
		return fmt.Errorf("failed to fetch host overrides: %w", err)
	}
	overridesData, ok := overrideResult["rows"].([]interface{})
	if !ok {
		return fmt.Errorf("failed to parse host overrides list")
	}

	// Fetch aliases
	aliasPayload := map[string]interface{}{
		"current":  1,
		"rowCount": 500,
		"sort":     map[string]interface{}{},
	}
	aliasResult, err := o.makeRequest(http.MethodPost, "search_host_alias", aliasPayload)
	if err != nil {
		return fmt.Errorf("failed to fetch aliases: %w", err)
	}
	aliasesData, ok := aliasResult["rows"].([]interface{})
	if !ok {
		return fmt.Errorf("failed to parse aliases list")
	}

	// Build a map of override UUID -> override info
	type OverrideInfo struct {
		UUID   string
		Host   string
		Domain string
		IP     string
		Enabled string
	}
	overrides := make(map[string]*OverrideInfo)
	var overrideOrder []string

	for _, item := range overridesData {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		uuid, _ := m["uuid"].(string)
		host, _ := m["hostname"].(string)
		domain, _ := m["domain"].(string)
		ip, _ := m["server"].(string)
		enabled, _ := m["enabled"].(string)
		if uuid == "" {
			continue
		}
		overrides[uuid] = &OverrideInfo{UUID: uuid, Host: host, Domain: domain, IP: ip, Enabled: enabled}
		overrideOrder = append(overrideOrder, uuid)
	}

	// Build a map of override UUID -> list of aliases
	type AliasInfo struct {
		FQDN string
		UUID string
		Desc string
	}
	aliasMap := make(map[string][]*AliasInfo)

	for _, item := range aliasesData {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		hostOverrideUUID, _ := m["host"].(string)
		hostname, _ := m["hostname"].(string)
		domain, _ := m["domain"].(string)
		uuid, _ := m["uuid"].(string)
		desc, _ := m["description"].(string)
		if hostname == "" || domain == "" {
			continue
		}
		fqdn := hostname + "." + domain
		aliasMap[hostOverrideUUID] = append(aliasMap[hostOverrideUUID], &AliasInfo{
			FQDN: fqdn, UUID: uuid, Desc: desc,
		})
	}

	// Collect orphans (aliases not linked to any known override)
	var orphans []*AliasInfo
	for hoUUID, aliases := range aliasMap {
		if _, exists := overrides[hoUUID]; !exists {
			orphans = append(orphans, aliases...)
		}
	}

	// Print
	fmt.Println("\n--- OPNsense Unbound DNS ---")
	totalAliases := 0

	for _, uuid := range overrideOrder {
		info := overrides[uuid]
		status := "[on]"
		if info.Enabled != "1" {
			status = "[off]"
		}
		aliases := aliasMap[uuid]
		totalAliases += len(aliases)

		fmt.Printf("\n  %s %s.%s -> %s  %s\n", status, info.Host, info.Domain, info.IP, info.UUID)

		if len(aliases) > 0 {
			// Sort aliases by FQDN for deterministic output
			sort.Slice(aliases, func(i, j int) bool {
				return aliases[i].FQDN < aliases[j].FQDN
			})
			for _, a := range aliases {
				fmt.Printf("    + %s\n", a.FQDN)
			}
		} else {
			fmt.Printf("    (no aliases)\n")
		}
	}

	// Print orphans
	if len(orphans) > 0 {
		fmt.Printf("\n  [orphaned aliases - no matching host override]\n")
		sort.Slice(orphans, func(i, j int) bool {
			return orphans[i].FQDN < orphans[j].FQDN
		})
		for _, a := range orphans {
			fmt.Printf("    + %s\n", a.FQDN)
		}
	}

	fmt.Printf("\n  Total: %d host overrides, %d aliases\n", len(overrides), totalAliases)
	return nil
}

// ClearManagedAliases deletes only the Unbound aliases linked to the given Host
// Override UUID -- the "anchor" entry tuda-sync manages. Aliases attached to any
// other host override, including manually created ones, are left untouched.
func (o *OpnsenseClient) ClearManagedAliases(proxyHostUUID string) error {
	if proxyHostUUID == "" {
		return fmt.Errorf("refusing to clear aliases: no host override UUID configured (set DEFAULT_PROXY_HOST_UUID or --proxy-uuid)")
	}

	logger.Info().Str("proxyUUID", proxyHostUUID).Msg("Clearing Unbound aliases managed by tuda-sync...")

	// 1. Get the list of all aliases
	payload := map[string]interface{}{
		"current":  1,
		"rowCount": 500,
		"sort":     map[string]interface{}{},
	}

	result, err := o.makeRequest(http.MethodPost, "search_host_alias", payload)
	if err != nil {
		return fmt.Errorf("failed to fetch aliases for clearing: %w", err)
	}

	// 2. Extract the aliases list
	aliases, ok := result["rows"].([]interface{})
	if !ok || len(aliases) == 0 {
		logger.Debug().Msg("No aliases found to clear")
		return nil
	}

	logger.Debug().Int("count", len(aliases)).Msg("Found existing aliases. Selecting managed ones...")

	// 3. Iterate and delete only the aliases linked to our host override
	var deleted, preserved int
	for _, item := range aliases {
		aliasMap, ok := item.(map[string]interface{})
		if !ok { continue }

		uuid, ok := aliasMap["uuid"].(string)
		if !ok { continue }

		// Leave anything not linked to our anchor override alone.
		if linkedHost, _ := aliasMap["host"].(string); linkedHost != proxyHostUUID {
			preserved++
			continue
		}

		// Attempt to delete - append UUID to the endpoint path
		// OPNsense expects the UUID in the URL path, not the request body
		if _, err := o.makeRequest(http.MethodPost, "del_host_alias/"+uuid, map[string]interface{}{}); err != nil {
			logger.Warn().Str("uuid", uuid).Err(err).Msg("Failed to delete alias")
			continue
		}

		hostname, _ := aliasMap["hostname"].(string)
		domain, _ := aliasMap["domain"].(string)
		logger.Debug().Str("hostname", hostname).Str("domain", domain).Str("uuid", uuid).Msg("Deleted alias")

		// Remove from cache if present
		o.removeCachedAlias(hostname + "." + domain)
		deleted++
	}

	logger.Info().Int("deleted", deleted).Int("preserved", preserved).Msg("Alias clearing complete")

	// A configured UUID that matches nothing usually means DEFAULT_PROXY_HOST_UUID
	// points at the wrong host override. Say so loudly rather than silently no-op.
	if deleted == 0 && preserved > 0 {
		logger.Warn().Str("proxyUUID", proxyHostUUID).Int("preserved", preserved).
			Msg("No aliases were linked to the configured host override. Verify DEFAULT_PROXY_HOST_UUID against 'tuda-sync list'")
	}

	// 4. Nothing was removed, so Unbound does not need to be reloaded
	if deleted == 0 {
		return nil
	}

	// 5. Trigger Unbound reconfiguration once all deletions are complete
	if err := o.Reconfigure(); err != nil {
		return fmt.Errorf("failed to reconfigure Unbound after clearing aliases: %w", err)
	}

	return nil
}

// CreateAlias adds a new alias, linked to the specified Host Override UUID
func (o *OpnsenseClient) CreateAlias(fqdn string, proxyHostUUID string, provider string, service string) error {
	host, domain := splitFQDN(fqdn)
	
	// Check if this alias already exists (to avoid duplicates)
	existingUUID, exists := o.getCachedAlias(fqdn)
	if exists {
		logger.Debug().Str("fqdn", fqdn).Str("uuid", existingUUID).Msg("Alias already exists, skipping creation")
		return nil
	}
	
	// Generate a descriptive comment with provider and service info if available
	description := "Auto-generated by tuda-sync"
	if provider != "" {
		if service != "" {
			description = fmt.Sprintf("Provider: %s, Service: %s", provider, service)
		} else {
			description = fmt.Sprintf("Provider: %s", provider)
		}
	}
	
	// Based on the curl example, the correct payload structure is:
	payload := map[string]interface{}{
		"alias": map[string]string{
			"enabled": "1",
			"host": proxyHostUUID, // This is the Host Override UUID
			"hostname": host,    // The hostname part of the FQDN
			"domain": domain,    // The domain part of the FQDN
			"description": description,
		},
	}
	
	logger.Debug().Interface("payload", payload["alias"]).Msg("Creating alias")
	
	// Use the add_host_alias endpoint as seen in the curl example
	response, err := o.makeRequest(http.MethodPost, "add_host_alias", payload)
	if err != nil {
		if strings.Contains(err.Error(), "403 Forbidden") {
			return fmt.Errorf("permission denied (403 Forbidden): the API key/secret may not have sufficient privileges to create aliases or access unbound settings. Check your OPNsense user permissions")
		}
		if strings.Contains(err.Error(), "400 Bad Request") {
			return fmt.Errorf("bad request (400): the OPNsense API rejected the request format. Payload: %v", payload)
		}
		return err
	}
	
	// Extract UUID from the response
	if uuid, ok := response["uuid"].(string); ok && uuid != "" {
		o.setCachedAlias(fqdn, uuid)
		logger.Debug().Str("fqdn", fqdn).Str("uuid", uuid).Msg("Added alias to cache")
	} else if savedData, ok := response["saved"]; ok && savedData != nil {
		// Some OPNsense versions might return different response format
		logger.Warn().Str("fqdn", fqdn).Msg("Alias created but no UUID returned. Using FQDN as cache key")
		o.setCachedAlias(fqdn, fqdn) // Use FQDN as a placeholder UUID
	} else {
		logger.Warn().Str("fqdn", fqdn).Interface("response", response).Msg("Created alias but could not extract UUID from response")
	}
	
	return nil
}

// GetAllAliases returns a map of all existing aliases (FQDN -> UUID)
func (o *OpnsenseClient) GetAllAliases() (map[string]string, error) {
	// Prepare request payload
	payload := map[string]interface{}{
		"current": 1,
		"rowCount": 500,
		"sort": map[string]interface{}{},
	}
	
	// Fetch all aliases from the API
	result, err := o.makeRequest(http.MethodPost, "search_host_alias", payload)
	if err != nil {
		return nil, fmt.Errorf("failed to search host aliases: %w", err)
	}
	
	// Parse the result
	aliases, ok := result["rows"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse aliases list")
	}
	
	// Build a map of FQDN -> UUID
	aliasMap := make(map[string]string)
	for _, item := range aliases {
		aliasData, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		
		hostname, hostOk := aliasData["hostname"].(string)
		domain, domainOk := aliasData["domain"].(string)
		uuid, uuidOk := aliasData["uuid"].(string)
		
		if hostOk && domainOk && uuidOk {
			fqdn := hostname + "." + domain
			aliasMap[fqdn] = uuid
			
			// Update our cache
			o.setCachedAlias(fqdn, uuid)
		}
	}
	
	logger.Debug().Int("count", len(aliasMap)).Msg("Retrieved current aliases")
	return aliasMap, nil
}

// DeleteAlias is complex, requiring a lookup for the alias's UUID first.
func (o *OpnsenseClient) DeleteAlias(fqdn string) error {
	// 1. Check cache first for the UUID
	if cachedUUID, exists := o.getCachedAlias(fqdn); exists {
		// Attempt to delete using cached UUID
		_, err := o.makeRequest(http.MethodPost, "del_host_alias/"+cachedUUID, map[string]interface{}{})
		if err == nil {
			// Success - remove from cache
			o.removeCachedAlias(fqdn)
			logger.Debug().Str("fqdn", fqdn).Str("uuid", cachedUUID).Msg("Deleted alias using cached UUID")
			return nil
		}
		// If we get here, the cached UUID was invalid, fall back to lookup
		logger.Debug().Str("fqdn", fqdn).Str("uuid", cachedUUID).Msg("Cached UUID failed, falling back to lookup")
	}

	// 2. If no cache hit or cache failed, get the list of all host aliases
	payload := map[string]interface{}{
		"current": 1,
		"rowCount": 500,
		"sort": map[string]interface{}{},
	}
	
	result, err := o.makeRequest(http.MethodPost, "search_host_alias", payload)
	if err != nil {
		return fmt.Errorf("failed to search host aliases: %w", err)
	}
	
	// 3. Find the UUID of the alias matching the FQDN (search endpoints use "rows")
	aliases, ok := result["rows"].([]interface{})
	if !ok {
		return fmt.Errorf("failed to parse aliases list")
	}

	host, domain := splitFQDN(fqdn)
	targetUUID := ""
	
	for _, item := range aliases {
		aliasMap, ok := item.(map[string]interface{})
		if !ok { continue }
		
		// Match by hostname and domain
        aliasHost, hostOk := aliasMap["hostname"].(string)
        aliasDomain, domainOk := aliasMap["domain"].(string)

		if hostOk && domainOk && aliasHost == host && aliasDomain == domain {
			if uuid, ok := aliasMap["uuid"].(string); ok {
				targetUUID = uuid
				break
			}
		}
	}
	
	if targetUUID == "" {
		logger.Debug().Str("fqdn", fqdn).Msg("Alias not found in OPNsense configuration. Assuming already deleted")
		return nil // Not found, treat as success
	}

	// 3. Delete the alias using its UUID - append UUID to the endpoint path
	// OPNsense expects the UUID in the URL path, not the request body
	_, err = o.makeRequest(http.MethodPost, "del_host_alias/"+targetUUID, map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to delete host alias %s (UUID: %s): %w", fqdn, targetUUID, err)
	}
	
	// Remove from cache
	o.removeCachedAlias(fqdn)
	return nil
}

// Reconfigure restarts the Unbound service to apply changes
func (o *OpnsenseClient) Reconfigure() error {
	logger.Debug().Msg("Applying changes by reconfiguring Unbound...")
	
	// Create context with timeout for the request
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	// The reconfigure endpoint is under the service module, not settings
	serviceURL := strings.Replace(o.url, "/settings", "/service", 1)
	fullURL := serviceURL + "/reconfigure"
	
	logger.Debug().Str("url", fullURL).Msg("Making POST request")
	
	body, _ := json.Marshal(map[string]interface{}{})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.SetBasicAuth(o.key, o.secret)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reconfigure Unbound: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		previewLen := min(len(respBody), 150)
		logger.Error().Str("status", resp.Status).Str("response", string(respBody)[:previewLen]).Msg("Reconfigure API call failed")
		return fmt.Errorf("failed to reconfigure Unbound: API request failed with HTTP status: %s", resp.Status)
	}
	
	logger.Info().Msg("Unbound reconfigured successfully")
	return nil
}

func splitFQDN(fqdn string) (string, string) {
	parts := strings.Split(fqdn, ".")
	if len(parts) > 1 {
		host := parts[0]
		domain := strings.Join(parts[1:], ".")
		return host, domain
	}
	return fqdn, ""
}

// Helper function needed for logging print limits
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// getCachedAlias retrieves an alias UUID from cache by FQDN
func (o *OpnsenseClient) getCachedAlias(fqdn string) (string, bool) {
	o.cacheMutex.RLock()
	defer o.cacheMutex.RUnlock()
	uuid, exists := o.aliasCache[fqdn]
	return uuid, exists
}

// setCachedAlias adds or updates an alias in the cache
func (o *OpnsenseClient) setCachedAlias(fqdn, uuid string) {
	o.cacheMutex.Lock()
	defer o.cacheMutex.Unlock()
	o.aliasCache[fqdn] = uuid
}

// removeCachedAlias removes an alias from the cache
func (o *OpnsenseClient) removeCachedAlias(fqdn string) {
	o.cacheMutex.Lock()
	defer o.cacheMutex.Unlock()
	delete(o.aliasCache, fqdn)
}

// ListAliases fetches and prints all configured Host Aliases (FQDN, description, UUID).
func (o *OpnsenseClient) ListAliases() error {
	logger.Info().Msg("Fetching Unbound Host Aliases from OPNsense...")

	payload := map[string]interface{}{
		"current":  1,
		"rowCount": 500,
		"sort":     map[string]interface{}{},
	}

	result, err := o.makeRequest(http.MethodPost, "search_host_alias", payload)
	if err != nil {
		return err
	}

	aliases, ok := result["rows"].([]interface{})
	if !ok {
		return fmt.Errorf("failed to parse host aliases list: expected 'rows' key")
	}

	logger.Info().Msg("\n--- OPNsense Unbound Host Aliases ---")
	fmt.Printf("%-40s | %-35s | %s\n", "FQDN", "DESCRIPTION", "UUID")
	fmt.Println(strings.Repeat("-", 101))

	for _, item := range aliases {
		aliasMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		hostname, _ := aliasMap["hostname"].(string)
		domain, _ := aliasMap["domain"].(string)
		uuid, _ := aliasMap["uuid"].(string)
		description, _ := aliasMap["description"].(string)

		fqdn := hostname + "." + domain
		if description == "" {
			description = "-"
		}

		fmt.Printf("%-40s | %-35s | %s\n", fqdn, description, uuid)
	}

	fmt.Println(strings.Repeat("-", 101))
	return nil
}

// GetAliasesForDiff returns a set of FQDNs currently on OPNsense (for diff comparison)
func (o *OpnsenseClient) GetAliasesForDiff() (map[string]struct{}, error) {
	payload := map[string]interface{}{
		"current":  1,
		"rowCount": 500,
		"sort":     map[string]interface{}{},
	}

	result, err := o.makeRequest(http.MethodPost, "search_host_alias", payload)
	if err != nil {
		return nil, err
	}

	aliases, ok := result["rows"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse host aliases list")
	}

	fqdnSet := make(map[string]struct{})
	for _, item := range aliases {
		aliasMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		hostname, _ := aliasMap["hostname"].(string)
		domain, _ := aliasMap["domain"].(string)
		if hostname != "" && domain != "" {
			fqdnSet[hostname+"."+domain] = struct{}{}
		}
	}

	return fqdnSet, nil
}

// checkHostOverrideExists verifies that a host override UUID exists in OPNsense
func (o *OpnsenseClient) checkHostOverrideExists(uuid string) (bool, error) {
	if uuid == "" {
		return false, fmt.Errorf("empty host override UUID provided")
	}
	
	// Use the search_host_override endpoint to get all overrides
	// Then search through them to find the one with matching UUID
	payload := map[string]interface{}{
		"current": 1,
		"rowCount": 500,
		"sort": map[string]interface{}{},
	}
	
	result, err := o.makeRequest(http.MethodPost, "search_host_override", payload)
	if err != nil {
		return false, fmt.Errorf("failed to search host overrides: %w", err)
	}
	
	// The search endpoints return the list under the "rows" key
	hostsData, ok := result["rows"].([]interface{})
	if !ok {
		return false, fmt.Errorf("failed to parse host overrides list")
	}
	
	// Look for a host override with matching UUID
	for _, item := range hostsData {
		hostMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		
		if hostUUID, ok := hostMap["uuid"].(string); ok && hostUUID == uuid {
			// Found a matching host override
			return true, nil
		}
	}
	
	// No matching UUID found
	logger.Warn().Str("uuid", uuid).Msg("Host override not found in OPNsense")
	return false, nil
}
