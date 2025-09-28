package main

import (
    "context"
    "log"
    "regexp"
    "strings"
    "time"

    "github.com/docker/docker/api/types/container"
    "github.com/docker/docker/api/types/events"
    "github.com/docker/docker/client"
    "github.com/docker/docker/api/types/filters"
)

// Global Docker client instance
var cli *client.Client

// MonitorDockerEvents watches for container start/stop events
func MonitorDockerEvents(ctx context.Context, opnClient *OpnsenseClient, defaultUUID, domain, traefikLabel, traefikRule, uuidLabel string) error {
    var err error
    
    // Initialize Docker client with explicit version and API negotiation
    cli, err = client.NewClientWithOpts(
        client.FromEnv, 
        client.WithAPIVersionNegotiation(),
        client.WithVersion("1.41"), // Explicitly set a supported API version
    )
    if err != nil {
        return err
    }
    
    // Ensure client is properly closed when function exits
    defer func() {
        if cli != nil {
            if err := cli.Close(); err != nil {
                log.Printf("Error closing Docker client: %v", err)
            }
        }
    }()

    // Process existing containers on startup
    log.Println("Inspecting existing containers...")
    
    // Create a context with timeout for the API call
    listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    
    containers, err := cli.ContainerList(listCtx, container.ListOptions{})
    if err != nil {
        return err
    }
    for _, container := range containers {
        if container.Labels[traefikLabel] == "true" && container.State == "running" {
            processContainer(ctx, opnClient, container.ID, "start", defaultUUID, domain, uuidLabel)
        }
    }

    // Start event loop with proper filtering
    log.Println("Awaiting Docker events...")
    
    // Create a filter to limit which events we process
    eventFilters := filters.NewArgs()
    eventFilters.Add("type", "container")
    eventFilters.Add("event", "start")
    eventFilters.Add("event", "die")
    
    msgs, errs := cli.Events(ctx, events.ListOptions{
        Filters: eventFilters,
    })

    for {
        select {
        case err := <-errs:
            if err != nil {
                log.Printf("Error from Docker events stream: %v", err)
                return err
            }
        case msg := <-msgs:
            // Extra validation of event data
            if msg.Type == "container" && (msg.Action == "start" || msg.Action == "die") {
                if msg.Actor.Attributes[traefikLabel] == "true" {
                    // Create a timeout context for processing
                    processCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
                    processContainer(processCtx, opnClient, msg.ID, string(msg.Action), defaultUUID, domain, uuidLabel)
                    cancel() // Ensure context is canceled after processing
                }
            }
        case <-ctx.Done():
            return ctx.Err()
        }
    }
}

// processContainer handles the logic for a container event
func processContainer(ctx context.Context, opnClient *OpnsenseClient, containerID, action, defaultUUID, domain, uuidLabelName string) {
    // Validate container ID
    if !isValidContainerID(containerID) {
        log.Printf("Invalid container ID format: %s", containerID)
        return
    }
    
    // 1. Get container details (needed for all labels) with timeout context
    inspectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    
    containerInfo, err := cli.ContainerInspect(inspectCtx, containerID)
    if err != nil {
        log.Printf("Error inspecting container %s: %v", containerID, err)
        return
    }
    labels := containerInfo.Config.Labels

    // --- Core UUID Logic: Override > Default ---
    targetUUID := defaultUUID
    
    // Check for the override label
    if overrideUUID, exists := labels[uuidLabelName]; exists && overrideUUID != "" {
        targetUUID = overrideUUID
        log.Printf("Container %s is using OVERRIDE UUID: %s", containerID, targetUUID)
    } else if targetUUID == "" {
        log.Printf("Skipping container %s: No Host UUID defined (missing label %s and DEFAULT_PROXY_HOST_UUID)", containerID, uuidLabelName)
        return
    } else {
        log.Printf("Container %s is using DEFAULT UUID: %s", containerID, targetUUID)
    }
    // ------------------------------------------

    // 2. Extract Hostname
    hostname := extractHostname(labels, traefikRuleLabel, domain)
    if hostname == "" {
        log.Printf("Skipping container %s: Could not extract hostname from Traefik labels.", containerID)
        return
    }
    fqdn := hostname + "." + domain

    if action == "start" {
        log.Printf("Container START: Creating alias for %s (via UUID: %s)", fqdn, targetUUID)
        if err := opnClient.CreateAlias(fqdn, targetUUID); err != nil {
            log.Printf("Error creating alias for %s: %v", fqdn, err)
            return
        }
        opnClient.Reconfigure()
    } else if action == "die" {
        log.Printf("Container DIE: Deleting alias for %s", fqdn)
        if err := opnClient.DeleteAlias(fqdn); err != nil {
            log.Printf("Error deleting alias for %s: %v", fqdn, err)
            return
        }
        opnClient.Reconfigure()
    }
}

// isValidContainerID checks if a container ID has valid format
func isValidContainerID(id string) bool {
    // Full container IDs are 64 hex chars, but Docker often uses shortened versions
    // So we just validate that it's at least 12 chars and hex
    if len(id) < 12 {
        return false
    }
    return regexp.MustCompile("^[a-f0-9]+$").MatchString(id)
}

// isValidHostname checks if a hostname conforms to DNS naming rules
func isValidHostname(hostname string) bool {
    // Implement proper hostname validation
    return regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`).MatchString(hostname)
}

// extractHostname parses the Host(`...`) rule from Traefik labels
func extractHostname(labels map[string]string, ruleLabelPrefix, domain string) string {
    r := regexp.MustCompile(`Host\(\s*[\'\"]?([^.]+)`) // Captures hostname before the first dot

    for key, rule := range labels {
        if strings.HasPrefix(key, ruleLabelPrefix) {
            if matches := r.FindStringSubmatch(rule); len(matches) > 1 {
                hostname := strings.Trim(matches[1], "'\"")
                
                // Validate hostname
                if isValidHostname(hostname) {
                    log.Printf("Extracted valid hostname from rule: %s", hostname)
                    return hostname
                } else {
                    log.Printf("Warning: Invalid hostname detected in rule: %s", hostname)
                }
            }
        }
    }
    return ""
}
