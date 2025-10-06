package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
)

type containerInfo struct {
	Name            string
	Image           string
	State           string
	HasTraefikLabel bool
	HasHostRule     bool
	FQDNs           []string
	Labels          map[string]string
}

func main() {
	// Configuration options - you can customize these
	baseDomain := "hlm.ing" // Default base domain
	if envDomain := os.Getenv("BASE_DOMAIN"); envDomain != "" {
		baseDomain = envDomain
	}
	
	// Connect to Docker
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}
	defer cli.Close()

	// Get all running containers
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Fatalf("Failed to list containers: %v", err)
	}

	fmt.Printf("Found %d running containers\n\n", len(containers))
	
	// Track container information
	var processedContainers []containerInfo
	
	// Process each container
	for _, c := range containers {
		container, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			log.Printf("Failed to inspect container %s: %v", c.ID, err)
			continue
		}
		
		name := strings.TrimPrefix(container.Name, "/")
		
		// Check if container has Traefik enabled
		hasTraefikLabel := false
		for k := range container.Config.Labels {
			if k == "traefik.enable" || k == "traefik.enabled" {
				hasTraefikLabel = true
				break
			}
		}
		
		// Extract Host rules
		hasHostRule := false
		fqdns := []string{}
		
		// First try to find explicit Host rules
		hostPattern := regexp.MustCompile(`Host\(\s*[\'\"]?([^\'\"]+)[\'\"]?\s*\)`)
		for k, v := range container.Config.Labels {
			if strings.Contains(k, ".rule") && strings.Contains(v, "Host(") {
				hasHostRule = true
				
				// Extract all FQDNs from Host rule
				matches := hostPattern.FindAllStringSubmatch(v, -1)
				for _, match := range matches {
					if len(match) > 1 {
						fqdn := match[1]
						// Replace templated domain if needed
						if strings.Contains(fqdn, "{$BASE_DOMAIN}") {
							fqdn = strings.ReplaceAll(fqdn, "{$BASE_DOMAIN}", baseDomain)
						}
						fqdns = append(fqdns, fqdn)
					}
				}
			}
		}
		
		// If no host rule found and we have a base domain, generate FQDN from container name
		if !hasHostRule && baseDomain != "" {
			fqdns = append(fqdns, name+"."+baseDomain)
		}
		
		// Store the container information
		processedContainers = append(processedContainers, containerInfo{
			Name:            name,
			Image:           container.Config.Image,
			State:           container.State.Status,
			HasTraefikLabel: hasTraefikLabel,
			HasHostRule:     hasHostRule,
			FQDNs:           fqdns,
			Labels:          container.Config.Labels,
		})
	}
	
	// Print summary statistics
	var (
		totalWithTraefikLabel = 0
		totalWithHostRules    = 0
		totalWithFQDNs        = 0
		totalRunning          = 0
	)
	
	for _, c := range processedContainers {
		if c.State == "running" {
			totalRunning++
			if c.HasTraefikLabel {
				totalWithTraefikLabel++
			}
			if c.HasHostRule {
				totalWithHostRules++
			}
			if len(c.FQDNs) > 0 {
				totalWithFQDNs++
			}
		}
	}
	
	fmt.Printf("=== Container Summary ===\n")
	fmt.Printf("Total running containers: %d\n", totalRunning)
	fmt.Printf("Containers with traefik.enable: %d\n", totalWithTraefikLabel)
	fmt.Printf("Containers with Host rules: %d\n", totalWithHostRules)
	fmt.Printf("Containers with potential FQDNs: %d\n", totalWithFQDNs)
	fmt.Printf("\n")
	
	fmt.Println("=== Container Details ===")
	fmt.Println("Container Name | Traefik Enabled | Host Rule | FQDNs")
	fmt.Println("---------------|----------------|-----------|------")
	
	for _, c := range processedContainers {
		if c.State == "running" {
			traefik := "❌"
			if c.HasTraefikLabel {
				traefik = "✅"
			}
			
			hostRule := "❌"
			if c.HasHostRule {
				hostRule = "✅"
			}
			
			fqdns := "None"
			if len(c.FQDNs) > 0 {
				fqdns = strings.Join(c.FQDNs, ", ")
			}
			
			fmt.Printf("%-15s | %-14s | %-9s | %s\n", 
				truncateString(c.Name, 15), 
				traefik, 
				hostRule, 
				fqdns)
		}
	}

	// List containers with potential issues
	fmt.Printf("\n=== Containers Missing DNS Aliases ===\n")
	fmt.Printf("These containers might need DNS aliases but could be missed by tuda-sync:\n\n")
	
	for _, c := range processedContainers {
		if c.State == "running" {
			// Check different potential issues
			
			// Case 1: Has traefik.enable but value isn't exactly "true"
			if hasLabelWithKey(c.Labels, "traefik.enable") && c.Labels["traefik.enable"] != "true" {
				fmt.Printf("🚨 %s: Has traefik.enable=%s (not 'true')\n", c.Name, c.Labels["traefik.enable"])
				continue
			}
			
			// Case 2: Using traefik.enabled instead of traefik.enable
			if c.Labels["traefik.enabled"] == "true" && c.Labels["traefik.enable"] != "true" {
				fmt.Printf("🚨 %s: Using traefik.enabled=true instead of traefik.enable=true\n", c.Name)
				continue
			}
			
			// Case 3: Has host rules but no traefik.enable=true
			if c.HasHostRule && !c.HasTraefikLabel {
				fmt.Printf("🚨 %s: Has Host rule but missing traefik.enable=true\n", c.Name)
				continue
			}
			
			// Case 4: Has other Traefik labels but not traefik.enable=true
			hasOtherTraefikLabels := false
			for k := range c.Labels {
				if strings.Contains(k, "traefik.") && k != "traefik.enable" && k != "traefik.enabled" {
					hasOtherTraefikLabels = true
					break
				}
			}
			
			if hasOtherTraefikLabels && !c.HasTraefikLabel {
				fmt.Printf("🚨 %s: Has Traefik labels but missing traefik.enable=true\n", c.Name)
			}
		}
	}
	
	// Provide suggested fixes
	fmt.Printf("\n=== Solution Suggestions ===\n")
	fmt.Println("1. Check for containers using 'traefik.enabled=true' instead of 'traefik.enable=true'")
	fmt.Println("2. Check for containers using 'traefik.enable=1' or other variations instead of 'traefik.enable=true'")
	fmt.Println("3. Check for containers with Host rules but missing the traefik.enable=true label")
	fmt.Println("4. For containers with no explicit Host rule, ensure BASE_DOMAIN is set in tuda-sync config")
	fmt.Println("\nConsider modifying the tuda-sync code to be more flexible with label detection.")
}

// Helper function to check if a label with a certain key exists regardless of value
func hasLabelWithKey(labels map[string]string, key string) bool {
	_, exists := labels[key]
	return exists
}

// Helper function to truncate a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}