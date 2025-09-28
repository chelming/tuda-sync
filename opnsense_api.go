package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io" 
	"log"
	"net/http"
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
	
	log.Printf("DEBUG: OPNsense API base URL: %s", client.url)
	
	// Pre-populate cache from existing records
	err := client.loadHostAliasesIntoCache()
	if err != nil {
		log.Printf("WARNING: Failed to load existing host aliases into cache: %v", err)
		log.Println("Continuing with empty cache. This may cause duplicate alias issues.")
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

	log.Printf("DEBUG: Making %s request to %s", method, fullURL)
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
		log.Printf("ERROR: API call failed. Status: %s. Response body start: %s", 
            resp.Status, string(respBody)[:previewLen]) 
        
		return nil, fmt.Errorf("API request failed with HTTP status: %s", resp.Status)
	}

	// --- LOGGING: Parse JSON from the already read response body ---
	var result map[string]interface{}

	// Re-create a reader from the already read body
	if err := json.NewDecoder(bytes.NewReader(respBody)).Decode(&result); err != nil {
        // Print the beginning of the response to help with debugging
        previewLen := min(len(respBody), 150)
        log.Printf("DEBUG: Failed to decode JSON. Raw response start: %s", string(respBody)[:previewLen])
        
        return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// This check catches JSON responses that contain an explicit API failure message.
	if result["result"] != nil && result["result"] != "OK" {
		return nil, fmt.Errorf("OPNsense API reported failure: %v", result)
	}

	return result, nil
}

// loadHostAliasesIntoCache fetches all host aliases from OPNsense and adds them to the cache
func (o *OpnsenseClient) loadHostAliasesIntoCache() error {
	log.Println("Loading existing host aliases into cache...")

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
	
	log.Printf("Loaded %d host aliases into cache", count)
	return nil
}

// ListHostOverrides fetches and prints all configured Host Overrides (Host, Domain, IP, UUID).
func (o *OpnsenseClient) ListHostOverrides() error {
	log.Println("Fetching Unbound Host Overrides from OPNsense...")

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

	log.Println("\n--- OPNsense Unbound Host Overrides ---")
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
			log.Println("WARNING: Skipping Host Override record due to missing or invalid 'uuid'.")
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

// ClearAllAliases fetches all currently configured Unbound Aliases and deletes them.
// This is intended to run on service startup to prevent stale entries.
func (o *OpnsenseClient) ClearAllAliases() error {
	log.Println("Clearing all existing Unbound Aliases...")

	// 1. Get the list of all aliases
	payload := map[string]interface{}{
		"current": 1,
		"rowCount": 500,
		"sort": map[string]interface{}{},
	}
	
	result, err := o.makeRequest(http.MethodPost, "search_host_alias", payload)
	if err != nil {
		return fmt.Errorf("failed to fetch aliases for clearing: %w", err)
	}
	
	// 2. Extract UUIDs from the aliases list
	aliases, ok := result["rows"].([]interface{})
	if !ok || len(aliases) == 0 {
		log.Println("No aliases found to clear.")
		return nil
	}
	
	log.Printf("Found %d existing alias(es). Deleting...", len(aliases))

	// 3. Iterate and delete each alias by UUID
	for _, item := range aliases {
		aliasMap, ok := item.(map[string]interface{})
		if !ok { continue }
		
		uuid, ok := aliasMap["uuid"].(string)
		if !ok { continue }
		
		// Attempt to delete
		delPayload := map[string]interface{}{
			"uuid": uuid,
		}
		
		_, err := o.makeRequest(http.MethodPost, "del_host_alias", delPayload)
		if err != nil {
			log.Printf("WARNING: Failed to delete alias with UUID %s: %v", uuid, err)
		} else {
			hostname, _ := aliasMap["hostname"].(string)
			domain, _ := aliasMap["domain"].(string)
			log.Printf("Deleted alias: %s.%s (UUID: %s)", hostname, domain, uuid)
			
			// Remove from cache if present
			fqdn := hostname + "." + domain
			o.removeCachedAlias(fqdn)
		}
	}
    
    // 4. Trigger Unbound reconfiguration once all deletions are complete
    if err := o.Reconfigure(); err != nil {
        return fmt.Errorf("failed to reconfigure Unbound after clearing aliases: %w", err)
    }

	log.Println("Alias clearing complete.")
	return nil
}


// CreateAlias adds a new alias, linked to the specified Host Override UUID
func (o *OpnsenseClient) CreateAlias(fqdn string, proxyHostUUID string) error {
	host, domain := splitFQDN(fqdn)
	
	// Check if this alias already exists (to avoid duplicates)
	existingUUID, exists := o.getCachedAlias(fqdn)
	if exists {
		log.Printf("Alias for %s already exists with UUID %s, skipping creation", fqdn, existingUUID)
		return nil
	}
	
	// Based on the curl example, the correct payload structure is:
	payload := map[string]interface{}{
		"alias": map[string]string{
			"enabled": "1",
			"host": proxyHostUUID, // This is the Host Override UUID
			"hostname": host,    // The hostname part of the FQDN
			"domain": domain,    // The domain part of the FQDN
			"description": fmt.Sprintf("Auto-generated for %s", fqdn),
		},
	}
	
	log.Printf("DEBUG: Creating alias with payload: %+v", payload["alias"])
	
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
		log.Printf("Added alias %s with UUID %s to cache", fqdn, uuid)
	} else if savedData, ok := response["saved"]; ok && savedData != nil {
		// Some OPNsense versions might return different response format
		log.Printf("Alias created for %s, but no UUID was returned. Using FQDN as cache key.", fqdn)
		o.setCachedAlias(fqdn, fqdn) // Use FQDN as a placeholder UUID
	} else {
		log.Printf("WARNING: Created alias for %s but could not extract UUID from response: %v", fqdn, response)
	}
	
	return nil
}

// DeleteAlias is complex, requiring a lookup for the alias's UUID first.
func (o *OpnsenseClient) DeleteAlias(fqdn string) error {
	// 1. Get the list of all host aliases
	payload := map[string]interface{}{
		"current": 1,
		"rowCount": 500,
		"sort": map[string]interface{}{},
	}
	
	result, err := o.makeRequest(http.MethodPost, "search_host_alias", payload)
	if err != nil {
		return fmt.Errorf("failed to search host aliases: %w", err)
	}
	
	// 2. Find the UUID of the alias matching the FQDN (search endpoints use "rows")
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
		log.Printf("Alias %s not found in OPNsense configuration. Assuming already deleted.", fqdn)
		return nil // Not found, treat as success
	}

	// 3. Delete the alias using its UUID
	delPayload := map[string]interface{}{
		"uuid": targetUUID,
	}
	
	_, err = o.makeRequest(http.MethodPost, "del_host_alias", delPayload)
	if err != nil {
		return fmt.Errorf("failed to delete host alias %s (UUID: %s): %w", fqdn, targetUUID, err)
	}
	
	// Remove from cache
	o.removeCachedAlias(fqdn)
	return nil
}

// Reconfigure restarts the Unbound service to apply changes
func (o *OpnsenseClient) Reconfigure() error {
	log.Println("Applying changes by reconfiguring Unbound...")
	
	// The reconfigure endpoint is under the service module
	_, err := o.makeRequest(http.MethodPost, "reconfigure", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to reconfigure Unbound: %w", err)
	}
	
	log.Println("Unbound reconfigured successfully.")
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
	log.Printf("WARNING: Host override with UUID %s not found in OPNsense", uuid)
	return false, nil
}
